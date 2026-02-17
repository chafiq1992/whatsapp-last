from __future__ import annotations

import hashlib
import hmac
import os
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from jose import JWTError, jwt

router = APIRouter()

_SHOP_RE = re.compile(r"([a-z0-9][a-z0-9-]*\.myshopify\.com)")


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _public_base_url(request: Request) -> str:
    """Compute the public base URL (handles Cloud Run behind proxies + custom domains)."""
    try:
        proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc).split(",")[0].strip()
        base = f"{proto}://{host}".rstrip("/")
        return base
    except Exception:
        base = (os.getenv("BASE_URL") or "").strip() or "http://localhost:8080"
        return base.rstrip("/")


def _oauth_scopes() -> str:
    scopes = (os.environ.get("SHOPIFY_OAUTH_SCOPES") or "").strip()
    if not scopes:
        # Keep a safe default; can be overridden in env.
        scopes = "read_products,read_orders,write_orders,read_customers,write_customers"
    return ",".join([s.strip() for s in scopes.split(",") if s.strip()])


def _client_creds() -> tuple[str, str]:
    cid = (os.environ.get("SHOPIFY_CLIENT_ID") or os.environ.get("SHOPIFY_OAUTH_CLIENT_ID") or "").strip()
    sec = (os.environ.get("SHOPIFY_CLIENT_SECRET") or os.environ.get("SHOPIFY_OAUTH_CLIENT_SECRET") or "").strip()
    if not cid or not sec:
        raise HTTPException(status_code=500, detail="SHOPIFY_CLIENT_ID/SHOPIFY_CLIENT_SECRET not configured")
    return cid, sec


def _state_secret() -> str:
    sec = (os.environ.get("OAUTH_STATE_SECRET") or "").strip()
    if sec:
        return sec
    # fall back to app auth secret (keeps behavior consistent across instances)
    sec = (os.environ.get("AGENT_AUTH_SECRET") or os.environ.get("SECRET_KEY") or "").strip()
    if sec:
        return sec
    raise HTTPException(status_code=500, detail="OAUTH_STATE_SECRET (or AGENT_AUTH_SECRET) not configured")


def sign_state(payload: Dict[str, Any]) -> str:
    return jwt.encode(payload, _state_secret(), algorithm="HS256")


def verify_state(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, _state_secret(), algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=400, detail="invalid state")


def normalize_shop_domain(raw: str) -> str:
    s = (raw or "").strip().lower()
    if not s:
        raise HTTPException(status_code=400, detail="missing shop")
    host = s
    try:
        if "://" in s:
            u = urllib.parse.urlparse(s)
            host = (u.netloc or u.path or "").strip().lower()
    except Exception:
        host = s
    host = host.split("/")[0].split("?")[0].split("#")[0].strip().lower()
    m = _SHOP_RE.search(host) or _SHOP_RE.search(s)
    if not m:
        raise HTTPException(status_code=400, detail="invalid shop (expected *.myshopify.com)")
    return m.group(1)


def _canonical_hmac_msg(qp: List[Tuple[str, str]]) -> str:
    keep = [(k, v) for (k, v) in qp if k not in ("hmac", "signature")]
    keep.sort(key=lambda kv: (kv[0], kv[1]))
    return urllib.parse.urlencode(keep, doseq=True)


def _verify_shopify_hmac(*, request: Request, client_secret: str) -> tuple[bool, dict]:
    """
    Verify Shopify OAuth callback HMAC.

    Shopify canonicalization can be sensitive to encoding differences across proxies/frameworks.
    We therefore try a few equivalent canonicalization strategies:
    - urlencode() of decoded params (common approach)
    - raw join of decoded key=value pairs (matches Shopify examples in multiple languages)
    Each with/without the `host` param.
    """
    # Prefer raw query string from ASGI scope to avoid framework re-encoding surprises.
    raw_qs = ""
    try:
        raw_qs = (request.scope.get("query_string") or b"").decode("utf-8", errors="ignore")
    except Exception:
        raw_qs = ""

    # Parse + decode; keep blank values.
    try:
        qp_list = urllib.parse.parse_qsl(raw_qs, keep_blank_values=True)
    except Exception:
        qp_list = []
    if not qp_list:
        # Fallback to Starlette's parsed params
        qp_list = [(k, str(v)) for (k, v) in request.query_params.multi_items()]

    provided = ""
    try:
        provided = (dict(qp_list).get("hmac") or "").strip().lower()
    except Exception:
        provided = (request.query_params.get("hmac") or "").strip().lower()

    keys = sorted({k for (k, _) in qp_list})
    if not provided:
        return False, {"error": "invalid_hmac", "reason": "missing_hmac", "keys": keys, "raw_len": len(raw_qs or "")}

    def _hmac_hex(message: str) -> str:
        return hmac.new(client_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest().lower()

    # Strategy A: urlencode of decoded params (current behavior)
    msg_a = _canonical_hmac_msg(qp_list)
    exp_a = _hmac_hex(msg_a)
    if hmac.compare_digest(exp_a, provided):
        return True, {"ok": True, "method": "urlencode"}

    # Strategy A2: urlencode excluding host
    qp_no_host = [(k, v) for (k, v) in qp_list if k != "host"]
    msg_a2 = _canonical_hmac_msg(qp_no_host)
    exp_a2 = _hmac_hex(msg_a2)
    if hmac.compare_digest(exp_a2, provided):
        return True, {"ok": True, "method": "urlencode", "used_fallback": "exclude_host"}

    # Strategy B: raw join "k=v" with decoded values (Shopify docs examples)
    def _join_pairs(pairs: List[Tuple[str, str]]) -> str:
        keep = [(k, v) for (k, v) in pairs if k not in ("hmac", "signature")]
        keep.sort(key=lambda kv: (kv[0], kv[1]))
        return "&".join([f"{k}={v}" for (k, v) in keep])

    msg_b = _join_pairs(qp_list)
    exp_b = _hmac_hex(msg_b)
    if hmac.compare_digest(exp_b, provided):
        return True, {"ok": True, "method": "join"}

    msg_b2 = _join_pairs(qp_no_host)
    exp_b2 = _hmac_hex(msg_b2)
    if hmac.compare_digest(exp_b2, provided):
        return True, {"ok": True, "method": "join", "used_fallback": "exclude_host"}

    return False, {
        "error": "invalid_hmac",
        "keys": keys,
        "raw_len": len(msg_a or ""),
        "raw_qs_len": len(raw_qs or ""),
    }


def _oauth_enabled_workspaces() -> set[str]:
    raw = (os.environ.get("SHOPIFY_OAUTH_WORKSPACES") or "").strip()
    if not raw:
        return {"irranova"}  # safe default: only irranova uses OAuth
    out: set[str] = set()
    for part in raw.split(","):
        p = (part or "").strip().lower()
        if p:
            out.add(p)
    return out


def _oauth_disabled_workspaces() -> set[str]:
    raw = (os.environ.get("SHOPIFY_OAUTH_DISABLED_WORKSPACES") or "irrakids").strip()
    out: set[str] = set()
    for part in raw.split(","):
        p = (part or "").strip().lower()
        if p:
            out.add(p)
    return out


def _oauth_enabled_for_ws(ws: str) -> bool:
    w = (ws or "").strip().lower()
    if not w:
        return False
    if w in _oauth_disabled_workspaces():
        return False
    enabled = _oauth_enabled_workspaces()
    # Treat derived workspace ids as enabled when they include/startswith a base enabled ws
    return any((w == base) or w.startswith(base) or (base in w) for base in enabled)


async def _get_record(ws: str) -> dict | None:
    try:
        from .main import db_manager, _ws_setting_key  # local import to avoid circular imports
        key = _ws_setting_key("shopify_oauth", ws)
        raw = await db_manager.get_setting(key)
        if not raw:
            return None
        import json as _json
        obj = _json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


async def _set_record(ws: str, rec: dict) -> None:
    from .main import db_manager, _ws_setting_key  # local import to avoid circular imports
    key = _ws_setting_key("shopify_oauth", ws)
    await db_manager.set_setting(key, rec)


async def _clear_record(ws: str) -> None:
    try:
        from .main import db_manager, _ws_setting_key  # local import
        key = _ws_setting_key("shopify_oauth", ws)
        await db_manager.delete_setting(key)
    except Exception:
        return


@router.get("/admin/shopify/oauth/callback")
async def shopify_oauth_callback(
    request: Request,
    state: str = Query(...),
    shop: str = Query(...),
    code: str = Query(...),
):
    shop_norm = normalize_shop_domain(shop)
    st = verify_state(state)
    ws = str(st.get("workspace") or "").strip().lower()
    shop_in_state = normalize_shop_domain(str(st.get("shop") or ""))
    if not ws:
        raise HTTPException(status_code=400, detail="invalid state (missing workspace)")
    if not _oauth_enabled_for_ws(ws):
        raise HTTPException(status_code=400, detail="oauth not enabled for this workspace")
    if not hmac.compare_digest(shop_in_state, shop_norm):
        raise HTTPException(status_code=400, detail="state/shop mismatch")

    cid, client_secret = _client_creds()
    skip_hmac = (os.environ.get("SHOPIFY_OAUTH_SKIP_HMAC") or "0").strip() == "1"
    ok_hmac, debug = _verify_shopify_hmac(request=request, client_secret=client_secret)
    if (not ok_hmac) and (not skip_hmac):
        out = {"error": "invalid_hmac", "shop": shop_norm}
        if isinstance(debug, dict):
            out.update(debug)
        return JSONResponse(out, status_code=400)

    token_url = f"https://{shop_norm}/admin/oauth/access_token"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(token_url, json={"client_id": cid, "client_secret": client_secret, "code": code})
    if resp.status_code >= 400:
        return JSONResponse(
            {
                "error": "token_exchange_failed",
                "status": resp.status_code,
                "shop": shop_norm,
                "body": (resp.text or "")[:2000],
            },
            status_code=502,
        )
    data = resp.json() if resp.content else {}
    access_token = str((data.get("access_token") or "")).strip()
    scopes = str((data.get("scope") or "")).strip()
    if not access_token:
        return JSONResponse({"error": "token_exchange_failed", "shop": shop_norm, "missing": "access_token"}, status_code=502)

    await _set_record(
        ws,
        {
            "shop": shop_norm,
            "access_token": access_token,
            "scopes": scopes,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    # Back to settings UI
    base = _public_base_url(request)
    return RedirectResponse(url=f"{base}/#/settings/stores?connected=1&workspace={urllib.parse.quote(ws)}", status_code=302)


async def _require_admin_proxy(request: Request) -> dict:
    """Admin guard without import-time circular dependencies."""
    from .main import get_current_agent, require_admin  # local import to avoid circular
    agent = await get_current_agent(request)  # type: ignore[arg-type]
    return await require_admin(agent)  # type: ignore[arg-type]


@router.get("/admin/shopify/oauth/status")
async def shopify_oauth_status(
    request: Request,
    workspace: str = Query("", description="Workspace id to inspect (optional)"),
    _: dict = Depends(_require_admin_proxy),
):
    ws = (workspace or (request.headers.get("X-Workspace") or request.headers.get("x-workspace") or "") or "").strip().lower()
    if not ws:
        from .main import get_current_workspace
        ws = get_current_workspace()
    enabled = _oauth_enabled_for_ws(ws)
    if not enabled:
        return {"connected": False, "shop": None, "scopes": None, "oauth_enabled": False}
    rec = await _get_record(ws)
    connected = bool(rec and str(rec.get("access_token") or "").strip() and str(rec.get("shop") or "").strip())
    return {
        "connected": connected,
        "shop": (rec or {}).get("shop") if rec else None,
        "scopes": (rec or {}).get("scopes") if rec else None,
        "oauth_enabled": True,
    }

@router.post("/admin/shopify/oauth/clear")
async def shopify_oauth_clear(
    request: Request,
    workspace: str = Query("", description="Workspace id to clear (optional)"),
    _: dict = Depends(_require_admin_proxy),
):
    ws = (workspace or (request.headers.get("X-Workspace") or request.headers.get("x-workspace") or "") or "").strip().lower()
    if not ws:
        from .main import get_current_workspace
        ws = get_current_workspace()
    await _clear_record(ws)
    return {"ok": True, "workspace": ws}

@router.get("/admin/shopify/oauth/start")
async def shopify_oauth_start(
    request: Request,
    workspace: str = Query(..., description="Workspace id (e.g. irranova)"),
    shop: str = Query(..., description="Shop domain, e.g. irranova.myshopify.com"),
    _: dict = Depends(_require_admin_proxy),
):
    ws = (workspace or "").strip().lower()
    if not ws:
        raise HTTPException(status_code=400, detail="missing workspace")
    if not _oauth_enabled_for_ws(ws):
        raise HTTPException(status_code=400, detail="oauth not enabled for this workspace")
    shop_norm = normalize_shop_domain(shop)
    cid, _client_secret = _client_creds()
    redirect_uri = f"{_public_base_url(request)}/admin/shopify/oauth/callback"
    now = _now_ts()
    state = sign_state(
        {
            "workspace": ws,
            "shop": shop_norm,
            "nonce": os.urandom(16).hex(),
            "iat": now,
            "exp": now + 10 * 60,
        }
    )
    qs = urllib.parse.urlencode(
        {
            "client_id": cid,
            "scope": _oauth_scopes(),
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    url = f"https://{shop_norm}/admin/oauth/authorize?{qs}"
    return RedirectResponse(url=url, status_code=302)

