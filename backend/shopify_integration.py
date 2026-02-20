import httpx
import logging
import os
import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import APIRouter, Body, Query, HTTPException, Header, Request

# ================= CONFIG ==================

def _load_store_config_for_prefix(prefix: str) -> tuple[str, str | None, str, str | None]:
    api_key = os.getenv(f"{prefix}_API_KEY")
    password = os.getenv(f"{prefix}_PASSWORD")
    access_token = os.getenv(f"{prefix}_ACCESS_TOKEN")
    store_url = os.getenv(f"{prefix}_STORE_URL")
    if not store_url:
        domain = os.getenv(f"{prefix}_STORE_DOMAIN")
        if domain:
            store_url = domain if domain.startswith("http") else f"https://{domain}"
    # Prefer token-based auth if provided, else basic auth
    if all([api_key, store_url]) and (password or access_token):
        return api_key, password, store_url, access_token
    raise RuntimeError(f"Missing Shopify environment variables for prefix {prefix}")


def _load_store_config() -> tuple[str, str | None, str, str | None]:
    """Return the first set of Shopify credentials found in the environment.

    Environment variables are checked using known prefixes and any discovered
    prefix that has <PREFIX>_STORE_URL or <PREFIX>_STORE_DOMAIN set.
    """
    prefixes = ["SHOPIFY", "IRRAKIDS", "IRRANOVA"]
    try:
        for k in os.environ.keys():
            if k.endswith("_STORE_URL") or k.endswith("_STORE_DOMAIN"):
                p = k.rsplit("_", 1)[0]
                if p and p not in prefixes:
                    prefixes.append(p)
    except Exception:
        pass

    for prefix in prefixes:
        try:
            api_key, password, store_url, access_token = _load_store_config_for_prefix(prefix)
        except Exception:
            continue
        logging.getLogger(__name__).info("Using Shopify prefix %s", prefix)
        return api_key, password, store_url, access_token

    raise RuntimeError("\u274c\u00a0Missing Shopify environment variables")


try:
    API_KEY, PASSWORD, STORE_URL, ACCESS_TOKEN = _load_store_config()
except Exception as _exc:
    # Defer failure to request time so the router can still be included.
    API_KEY = PASSWORD = STORE_URL = ACCESS_TOKEN = None  # type: ignore[assignment]
    logging.getLogger(__name__).warning("Shopify config missing or invalid: %s", _exc)

API_VERSION = "2023-04"

_STORE_CACHE: dict[str, tuple[str, str | None, str, str | None]] = {}


def _get_store_config(store: str | None = None) -> tuple[str, str | None, str, str | None]:
    """Get Shopify credentials for `store` prefix, or default if store is None."""
    global API_KEY, PASSWORD, STORE_URL, ACCESS_TOKEN

    if store:
        key = str(store).strip().upper()
        if key:
            if key in _STORE_CACHE:
                return _STORE_CACHE[key]
            try:
                cfg = _load_store_config_for_prefix(key)
            except Exception:
                raise HTTPException(status_code=404, detail=f"Unknown or unconfigured Shopify store '{store}'")
            _STORE_CACHE[key] = cfg
            return cfg

    if not STORE_URL:
        try:
            API_KEY, PASSWORD, STORE_URL, ACCESS_TOKEN = _load_store_config()
        except Exception:
            raise HTTPException(status_code=503, detail="Shopify not configured")
    return API_KEY, PASSWORD, STORE_URL, ACCESS_TOKEN  # type: ignore[return-value]


def _resolve_store_from_workspace(store: str | None, x_workspace: str | None) -> str | None:
    """Resolve the Shopify store prefix from either an explicit `store` query param
    or the `X-Workspace` header (multi-workspace frontend).

    - `store` is expected to be an env prefix like IRRAKIDS / IRRANOVA
    - `x_workspace` is expected to be a workspace id like irrakids / irranova

    If the derived prefix is not configured, we fall back to None (default store).
    """
    try:
        if store and str(store).strip():
            return str(store).strip().upper()
    except Exception:
        pass
    try:
        ws = str(x_workspace or "").strip()
        if not ws:
            return None
        ws_up = ws.upper()

        # 1) Direct mapping: workspace id == env prefix (e.g. irrakids -> IRRAKIDS)
        try:
            _load_store_config_for_prefix(ws_up)
            return ws_up
        except Exception:
            pass

        # 1b) Heuristic mapping for derived workspace ids (e.g. "irranovachat" -> "IRRANOVA").
        # This prevents store mismatches when you create new workspaces that are variants of a base store id.
        try:
            ws_low = ws.lower()
            for base in ("irranova", "irrakids"):
                if ws_low.startswith(base) or (base in ws_low):
                    cand = base.upper()
                    try:
                        _load_store_config_for_prefix(cand)
                        return cand
                    except Exception:
                        continue
        except Exception:
            pass

        # 2) Per-workspace override env: SHOPIFY_STORE_PREFIX_<WS>=IRRAKIDS
        try:
            override = (os.getenv(f"SHOPIFY_STORE_PREFIX_{ws_up}", "") or "").strip().upper()
            if override:
                _load_store_config_for_prefix(override)
                return override
        except Exception:
            pass

        # 3) Global map env: SHOPIFY_WORKSPACE_STORE_MAP="irrakids:IRRAKIDS,irranova:IRRANOVA"
        try:
            raw_map = (os.getenv("SHOPIFY_WORKSPACE_STORE_MAP", "") or "").strip()
            if raw_map:
                pairs = [p.strip() for p in raw_map.split(",") if p.strip()]
                mapping = {}
                for p in pairs:
                    if ":" not in p:
                        continue
                    k, v = p.split(":", 1)
                    mapping[str(k).strip().lower()] = str(v).strip().upper()
                mapped = mapping.get(ws.lower())
                if mapped:
                    _load_store_config_for_prefix(mapped)
                    return mapped
        except Exception:
            pass

        # 4) Default fallback store (helps new workspaces behave like the primary one).
        # You can set SHOPIFY_DEFAULT_STORE_PREFIX=IRRAKIDS (or IRRANOVA, etc).
        try:
            default_prefix = (os.getenv("SHOPIFY_DEFAULT_STORE_PREFIX", "") or "").strip().upper()
            if default_prefix:
                _load_store_config_for_prefix(default_prefix)
                return default_prefix
        except Exception:
            pass

        # 5) Last resort: if IRRAKIDS is configured, use it (common single-store deployments).
        try:
            _load_store_config_for_prefix("IRRAKIDS")
            return "IRRAKIDS"
        except Exception:
            pass

        return None
    except Exception:
        return None


def admin_api_base(store: str | None = None) -> str:
    """Return the Admin API base URL for selected store prefix."""
    _api_key, _password, store_url, _access_token = _get_store_config(store)
    return f"{store_url}/admin/api/{API_VERSION}"

def _client_args(headers: dict | None = None, store: str | None = None) -> dict:
    args: dict = {}
    hdrs = dict(headers or {})
    api_key, password, _store_url, access_token = _get_store_config(store)
    # Prefer Admin API access token. If not provided explicitly, detect token in PASSWORD (shpat_...)
    effective_token = access_token or (password if isinstance(password, str) and password.startswith("shpat_") else None)
    if effective_token:
        hdrs["X-Shopify-Access-Token"] = effective_token
        args["headers"] = hdrs
    elif api_key and password:
        args["auth"] = (api_key, password)
        if hdrs:
            args["headers"] = hdrs
    return args


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
_auth_mode = "token" if (ACCESS_TOKEN or (PASSWORD and str(PASSWORD).startswith("shpat_"))) else "basic"
logger.info("Shopify auth mode: %s", _auth_mode)

def _normalize_ws_id(raw: str | None) -> str:
    try:
        return str(raw or "").strip().lower()
    except Exception:
        return ""


def _oauth_enabled_workspaces() -> set[str]:
    raw = (os.environ.get("SHOPIFY_OAUTH_WORKSPACES") or "").strip()
    if not raw:
        return {"irranova"}  # safe default
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
    w = _normalize_ws_id(ws)
    if not w:
        return False
    if w in _oauth_disabled_workspaces():
        return False
    enabled = _oauth_enabled_workspaces()
    return any((w == base) or w.startswith(base) or (base in w) for base in enabled)


async def _get_shopify_oauth_record(ws: str) -> dict | None:
    """Load per-workspace Shopify OAuth record from the app settings DB.

    Stored under settings key: shopify_oauth::<workspace>
    """
    w = _normalize_ws_id(ws)
    if not w:
        return None
    if not _oauth_enabled_for_ws(w):
        return None
    try:
        # Local import to avoid circular dependency at import-time (main imports this router).
        from .main import db_manager, _ws_setting_key  # type: ignore
        key = _ws_setting_key("shopify_oauth", w)
        raw = await db_manager.get_setting(key)
        if not raw:
            return None
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return None
        shop = str(obj.get("shop") or "").strip().lower()
        tok = str(obj.get("access_token") or "").strip()
        if not shop or not tok:
            return None
        return {"shop": shop, "access_token": tok, "scopes": obj.get("scopes")}
    except Exception:
        return None


def _oauth_admin_api_base(shop_domain: str) -> str:
    shop = str(shop_domain or "").strip()
    if not shop:
        raise HTTPException(status_code=500, detail="Missing OAuth shop domain")
    return f"https://{shop}/admin/api/{API_VERSION}"


async def _shopify_http_context(store: str | None, x_workspace: str | None) -> tuple[str, dict, str, str | None]:
    """Resolve the correct Shopify Admin API base + auth args for this request.

    Priority:
    - Workspace OAuth connection (shop domain + token stored in DB settings) if present
    - Else env-based store mapping resolved from store/x-workspace

    Returns: (base, extra_args, store_used, store_prefix)
    """
    ws = _normalize_ws_id(x_workspace)
    if not ws:
        try:
            from .main import get_current_workspace  # type: ignore
            ws = _normalize_ws_id(get_current_workspace())
        except Exception:
            ws = ""
    oauth = await _get_shopify_oauth_record(ws)
    oauth_shop = str((oauth or {}).get("shop") or "").strip().lower()
    oauth_token = str((oauth or {}).get("access_token") or "").strip()
    store = _resolve_store_from_workspace(store, ws or x_workspace)
    if oauth_shop and oauth_token:
        base = _oauth_admin_api_base(oauth_shop)
        extra_args = {"headers": {"X-Shopify-Access-Token": oauth_token}}
        return base, extra_args, f"OAUTH:{oauth_shop}", store
    base = admin_api_base(store)
    extra_args = _client_args(store=store)
    return base, extra_args, (store or "DEFAULT"), store

def normalize_phone(phone):
    if not phone:
        return ""
    phone = str(phone).replace(" ", "").replace("-", "")
    if phone.startswith("+"):
        return phone
    if len(phone) == 12 and phone.startswith("212"):
        return "+" + phone
    if len(phone) == 10 and phone.startswith("06"):
        return "+212" + phone[1:]
    return phone

def _split_name(full_name: str) -> tuple[str, str]:
    full = (full_name or "").strip()
    if not full:
        return "", ""
    parts = full.split(" ", 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]

# =============== FASTAPI ROUTER ===============
router = APIRouter()

_SEGMENTS_FILE = Path(__file__).resolve().parent / "customer_segments.json"
_SEGMENTS_LOCK: float = 0.0  # best-effort local lock (single-process)

# key -> (ts, count, is_estimate)
_COUNT_CACHE: dict[str, tuple[float, int, bool]] = {}
_COUNT_CACHE_TTL_SEC = 5 * 60

_SEGMENT_MEMBER_FIELD_CACHE: dict[str, str] = {}  # deprecated (kept for backwards compat)

def _require_admin_request(request) -> dict:
    """Best-effort admin guard without importing backend.main (avoid circular imports)."""
    try:
        agent = getattr(request, "state", None) and getattr(request.state, "agent", None)
    except Exception:
        agent = None
    if not isinstance(agent, dict) or not agent:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not bool(agent.get("is_admin")):
        raise HTTPException(status_code=403, detail="Forbidden")
    return agent

async def _shopify_graphql(
    *,
    query: str,
    variables: dict | None = None,
    store: str | None = None,
    x_workspace: str | None = None,
    timeout: float = 25.0,
) -> dict:
    """Execute a Shopify Admin GraphQL request using the same auth context as REST helpers."""
    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    url = f"{base}/graphql.json"
    headers = {}
    try:
        hdrs = (extra_args or {}).get("headers") or {}
        if isinstance(hdrs, dict):
            headers.update(hdrs)
    except Exception:
        pass
    headers.setdefault("Content-Type", "application/json")
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json={"query": str(query or ""), "variables": (variables or {})}, headers=headers, **{k: v for k, v in (extra_args or {}).items() if k != "headers"})
        if resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks required scopes or app not installed.")
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=(resp.text or "Shopify error")[:300])
        data = resp.json() or {}
        if isinstance(data, dict) and data.get("errors"):
            # GraphQL top-level errors
            raise HTTPException(status_code=502, detail=str(data.get("errors"))[:300])
        return data if isinstance(data, dict) else {}

async def _segment_member_customer_field(*, store: str | None, x_workspace: str | None) -> str:
    """Deprecated: CustomerSegmentMember is itself the customer profile in 2026-01+.

    Kept only to avoid import-time errors if older code paths still call it.
    """
    return ""

async def _fetch_customers_by_ids(
    *,
    ids: list[str],
    store: str | None,
    x_workspace: str | None,
) -> dict[str, dict]:
    """Fetch Customer nodes by GID and return map id->customer dict."""
    clean = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not clean:
        return {}
    q = """
    query CustomerNodes($ids: [ID!]!) {
      nodes(ids: $ids) {
        ... on Customer {
          id
          firstName
          lastName
          phone
          tags
          defaultAddress { phone }
        }
      }
    }
    """
    payload = await _shopify_graphql(query=q, variables={"ids": clean}, store=store, x_workspace=x_workspace, timeout=20.0)
    nodes = ((payload.get("data") or {}).get("nodes") or []) if isinstance(payload, dict) else []
    out: dict[str, dict] = {}
    for n in (nodes if isinstance(nodes, list) else []):
        if isinstance(n, dict) and n.get("id"):
            out[str(n.get("id"))] = n
    return out


async def _list_shopify_segments(
    *,
    store: str | None,
    x_workspace: str | None,
    first: int = 50,
    after: str | None = None,
) -> tuple[list[dict], str | None]:
    """Return (segments, next_cursor). Each segment is {gid,name,query,createdAt,updatedAt} best-effort."""
    q = """
    query Segments($first:Int!, $after:String) {
      segments(first: $first, after: $after) {
        edges {
          cursor
          node {
            id
            name
            query
            creationDate
            lastEditDate
          }
        }
        pageInfo { hasNextPage }
      }
    }
    """
    payload = await _shopify_graphql(query=q, variables={"first": int(first), "after": after}, store=store, x_workspace=x_workspace, timeout=25.0)
    segs = (((payload.get("data") or {}).get("segments") or {}).get("edges") or []) if isinstance(payload, dict) else []
    out: list[dict] = []
    next_cursor = None
    for e in (segs if isinstance(segs, list) else []):
        if not isinstance(e, dict):
            continue
        node = e.get("node") or {}
        if not isinstance(node, dict):
            continue
        gid = str(node.get("id") or "").strip()
        name = str(node.get("name") or "").strip()
        query_txt = str(node.get("query") or "").strip()
        if not gid or not name:
            continue
        out.append(
            {
                "gid": gid,
                "name": name,
                "query": query_txt,
                "created_at": node.get("creationDate"),
                "updated_at": node.get("lastEditDate"),
            }
        )
        # cursor for pagination
        try:
            next_cursor = str(e.get("cursor") or "") or next_cursor
        except Exception:
            pass
    try:
        has_next = bool((((payload.get("data") or {}).get("segments") or {}).get("pageInfo") or {}).get("hasNextPage"))
    except Exception:
        has_next = False
    return out, (next_cursor if has_next else None)


async def _shopify_segment_members_page(
    *,
    segment_gid: str,
    store: str | None,
    x_workspace: str | None,
    first: int = 100,
    after: str | None = None,
) -> tuple[list[dict], str | None]:
    """Return (customers, next_cursor) for a Shopify Segment (dynamic membership)."""
    gid = str(segment_gid or "").strip()
    if not gid:
        return [], None
    # In Shopify 2026-01, CustomerSegmentMember IS the customer profile.
    # We fetch only ids from the connection, then hydrate via nodes(ids:...) to also get tags/phone.
    q = """
    query SegmentMembers($segmentId: ID!, $first: Int!, $after: String) {
      customerSegmentMembers(segmentId: $segmentId, first: $first, after: $after) {
        edges { cursor node { id } }
        pageInfo { hasNextPage }
      }
    }
    """
    payload = await _shopify_graphql(query=q, variables={"segmentId": gid, "first": int(first), "after": after}, store=store, x_workspace=x_workspace, timeout=25.0)
    edges = (((payload.get("data") or {}).get("customerSegmentMembers") or {}).get("edges") or []) if isinstance(payload, dict) else []
    next_cursor = None
    ids: list[str] = []
    for e in (edges if isinstance(edges, list) else []):
        if not isinstance(e, dict):
            continue
        node = e.get("node") or {}
        if isinstance(node, dict) and node.get("id"):
            ids.append(str(node.get("id")))
        try:
            next_cursor = str(e.get("cursor") or "") or next_cursor
        except Exception:
            pass
    cust_map = await _fetch_customers_by_ids(ids=ids, store=store, x_workspace=x_workspace)
    out = [cust_map[i] for i in ids if i in cust_map]
    try:
        has_next = bool((((payload.get("data") or {}).get("customerSegmentMembers") or {}).get("pageInfo") or {}).get("hasNextPage"))
    except Exception:
        has_next = False
    return out, (next_cursor if has_next else None)

async def _shopify_segment_members_by_query_page(
    *,
    query_text: str,
    store: str | None,
    x_workspace: str | None,
    first: int = 100,
    after: str | None = None,
) -> tuple[list[dict], str | None]:
    """Return (customers, next_cursor) for a Shopify segment query (ShopifyQL).

    Not all Shopify versions support this; callers should be prepared to fall back.
    """
    qtxt = _normalize_shopifyql_query(query_text)
    if not qtxt:
        return [], None
    q = """
    query SegmentMembersByQuery($query: String!, $first: Int!, $after: String) {
      customerSegmentMembers(query: $query, first: $first, after: $after) {
        edges { cursor node { id } }
        pageInfo { hasNextPage }
      }
    }
    """
    payload = await _shopify_graphql(query=q, variables={"query": qtxt, "first": int(first), "after": after}, store=store, x_workspace=x_workspace, timeout=25.0)
    edges = (((payload.get("data") or {}).get("customerSegmentMembers") or {}).get("edges") or []) if isinstance(payload, dict) else []
    next_cursor = None
    ids: list[str] = []
    for e in (edges if isinstance(edges, list) else []):
        if not isinstance(e, dict):
            continue
        node = e.get("node") or {}
        if isinstance(node, dict) and node.get("id"):
            ids.append(str(node.get("id")))
        try:
            next_cursor = str(e.get("cursor") or "") or next_cursor
        except Exception:
            pass
    cust_map = await _fetch_customers_by_ids(ids=ids, store=store, x_workspace=x_workspace)
    out = [cust_map[i] for i in ids if i in cust_map]
    try:
        has_next = bool((((payload.get("data") or {}).get("customerSegmentMembers") or {}).get("pageInfo") or {}).get("hasNextPage"))
    except Exception:
        has_next = False
    return out, (next_cursor if has_next else None)


def _segments_read_file() -> list[dict]:
    try:
        if not _SEGMENTS_FILE.exists():
            return []
        raw = _SEGMENTS_FILE.read_text(encoding="utf-8")
        data = json.loads(raw) if raw else []
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _segments_write_file(items: list[dict]) -> None:
    # atomic write
    tmp = _SEGMENTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_SEGMENTS_FILE)


def _normalize_ws_id(raw: str | None) -> str:
    try:
        return str(raw or "").strip().lower()
    except Exception:
        return ""


def _segments_settings_key(x_workspace: str | None) -> str:
    """Workspace-scoped settings key used to persist segments in DB."""
    try:
        # Local import to avoid circular import at module import time.
        from .main import _ws_setting_key, get_current_workspace  # type: ignore
        ws = _normalize_ws_id(x_workspace) or _normalize_ws_id(get_current_workspace())
        ws = ws or "default"
        return _ws_setting_key("customer_segments", ws)
    except Exception:
        # Last resort: non-namespaced key
        ws = _normalize_ws_id(x_workspace) or "default"
        return f"customer_segments::{ws}"


async def _segments_read(x_workspace: str | None) -> list[dict]:
    """Read segments from DB settings (durable). Fallback to local file for backward-compat,
    and auto-migrate file -> DB if needed.
    """
    key = _segments_settings_key(x_workspace)
    # 1) Auth/settings DB (preferred): durable admin config store
    try:
        from .main import auth_db_manager  # type: ignore
        raw = await auth_db_manager.get_setting(key)
        if raw:
            obj = json.loads(raw)
            if isinstance(obj, list):
                return [x for x in obj if isinstance(x, dict)]
    except Exception:
        pass
    # 2) Legacy DB location (messages DB settings). Keep for backward-compat.
    try:
        from .main import db_manager  # type: ignore
        raw = await db_manager.get_setting(key)
        if raw:
            obj = json.loads(raw)
            if isinstance(obj, list):
                items = [x for x in obj if isinstance(x, dict)]
                # Best-effort migrate into auth DB so future reads persist in the right place.
                try:
                    from .main import auth_db_manager  # type: ignore
                    await auth_db_manager.set_setting(key, items)
                except Exception:
                    pass
                return items
    except Exception:
        pass
    # 2) File fallback (legacy)
    items = _segments_read_file()
    # Best-effort migrate into DB so future reads persist
    if items:
        try:
            from .main import auth_db_manager  # type: ignore
            await auth_db_manager.set_setting(key, items)
        except Exception:
            pass
    return items


async def _segments_write(x_workspace: str | None, items: list[dict]) -> None:
    """Write segments to DB settings (durable). Also best-effort write the legacy file (dev/backups)."""
    key = _segments_settings_key(x_workspace)
    try:
        from .main import auth_db_manager  # type: ignore
        await auth_db_manager.set_setting(key, items)
    except Exception:
        # Backward-compat: try legacy DB location (messages DB settings)
        try:
            from .main import db_manager  # type: ignore
            await db_manager.set_setting(key, items)
        except Exception:
            # If DB unavailable, keep legacy file behavior
            _segments_write_file(items)
            return
    # Best-effort legacy file write (non-critical)
    try:
        _segments_write_file(items)
    except Exception:
        pass


def _days_ago_to_date(days: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=int(days))
    return dt.strftime("%Y-%m-%d")


def compile_segment_dsl_to_shopify_query(dsl: str) -> tuple[str, list[str], str]:
    """
    Compile a Shopify-like segment DSL into a Shopify customer search query.

    Supported:
    - number_of_orders > N  -> orders_count:>N
    - last_order_date < -90d -> last_order_date:<YYYY-MM-DD
    """
    text = str(dsl or "")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    conds: list[str] = []
    human: list[str] = []

    for ln in lines:
        up = ln.upper()
        if up.startswith("WHERE "):
            conds.append(ln[6:].strip())
        elif up.startswith("AND "):
            conds.append(ln[4:].strip())
        elif up.startswith("FROM ") or up.startswith("SHOW ") or up.startswith("ORDER BY"):
            continue
        else:
            # Allow condition-only DSL like: "number_of_orders = 0"
            # (common when users paste just the predicate)
            if any(op in ln for op in (">=", "<=", ">", "<", "=")) and " " in ln:
                conds.append(ln.strip())

    tokens: list[str] = []
    for c in conds:
        # field op value
        parts = c.replace("\t", " ").split()
        if len(parts) < 3:
            continue
        field = parts[0].strip().lower()
        op = parts[1].strip()
        value = " ".join(parts[2:]).strip()

        if field in ("number_of_orders", "orders", "orders_count"):
            try:
                n = int(float(value))
            except Exception:
                continue
            if op not in (">", ">=", "<", "<=", "="):
                continue
            tokens.append(f"orders_count:{op}{n}")
            human.append(f"placed {op} {n} orders".replace(">=", "at least").replace(">", "more than").replace("<=", "at most").replace("<", "less than").replace("= ", ""))
            continue

        if field in ("last_order_date", "last_order"):
            # supports -90d
            vv = value
            if vv.startswith("-") and vv.lower().endswith("d"):
                try:
                    days = int(vv[1:-1])
                    vv = _days_ago_to_date(days)
                except Exception:
                    continue
            # Shopify expects date YYYY-MM-DD
            if op not in (">", ">=", "<", "<=", "="):
                continue
            tokens.append(f"last_order_date:{op}{vv}")
            human.append(f"last order {op} {vv}")
            continue

    query = " ".join(tokens).strip()
    # Description similar to Shopify
    desc = ""
    if human:
        desc = "Customers who have " + " and ".join(human) + "."
        desc = desc.replace("last order < ", "whose last order was placed before ").replace("last order <= ", "whose last order was placed on or before ")
        desc = desc.replace("last order > ", "whose last order was placed after ").replace("last order >= ", "whose last order was placed on or after ")
    return query, conds, desc


def _normalize_shopifyql_query(dsl: str) -> str:
    """Ensure a query is valid ShopifyQL for customerSegmentMembers(query: ...).

    If user provides only conditions (no FROM/SHOW), we wrap it.
    """
    s = str(dsl or "").strip()
    if not s:
        return ""
    up = s.upper()
    if "FROM " in up and "SHOW " in up:
        return s
    # Condition-only -> wrap with a minimal valid segment query
    return "\n".join(
        [
            "FROM customers",
            "SHOW id",
            f"WHERE {s}",
            "ORDER BY updated_at",
        ]
    )


async def _count_customers_for_query(
    *,
    query: str,
    base: str,
    extra_args: dict,
    cache_key_prefix: str = "",
    max_pages: int = 6,
    max_seconds: float = 8.0,
) -> tuple[int, bool]:
    """Best-effort count for a Shopify customers/search query.

    Shopify REST doesn't provide a true count endpoint for search queries. The naive way
    is to page through all results, which can be very slow and cause 504s behind proxies.

    This function returns:
      - (count, False) when we finish paging within budget (exact)
      - (count, True) when we stop early due to time/page budget (estimate / lower bound)
    """
    q = (query or "").strip()
    key = f"{(cache_key_prefix or '').strip()}|{q}"
    now = time.time()
    try:
        ts, cnt, is_est = _COUNT_CACHE.get(key, (0.0, -1, True))
        if cnt >= 0 and (now - ts) < _COUNT_CACHE_TTL_SEC:
            return int(cnt), bool(is_est)
    except Exception:
        pass

    total = 0
    page_info: str | None = None
    pages = 0
    started = time.monotonic()
    is_estimate = False

    # Keep per-request timeouts small; overall budget is enforced by max_seconds.
    async with httpx.AsyncClient() as client:
        while True:
            if pages >= max_pages:
                is_estimate = True
                break
            if (time.monotonic() - started) > max_seconds:
                is_estimate = True
                break

            # IMPORTANT (Shopify cursor pagination): when page_info is present, you must NOT pass other
            # params like query/order. Only limit + page_info are allowed.
            if page_info:
                params = {"limit": 250, "page_info": page_info}
            else:
                params = {"limit": 250, "order": "updated_at desc", "query": q}

            resp = await client.get(
                f"{base}/customers/search.json",
                params=params,
                timeout=10,
                **(extra_args or {}),
            )
            if resp.status_code == 403:
                raise HTTPException(status_code=403, detail="Shopify token lacks read_customers scope or app not installed.")
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=(resp.text or "Shopify error")[:300])
            payload = resp.json() or {}
            customers = payload.get("customers", []) or []
            total += len(customers)
            pages += 1

            # Safety cap (avoid pathological loops)
            if total >= 200000:
                is_estimate = True
                break

            links = _parse_link_header_page_info(resp.headers.get("link") or resp.headers.get("Link"))
            page_info = links.get("next")
            if not page_info:
                break

    try:
        _COUNT_CACHE[key] = (now, int(total), bool(is_estimate))
    except Exception:
        pass
    return int(total), bool(is_estimate)


@router.get("/customer-segments")
async def list_customer_segments(x_workspace: str | None = Header(None, alias="X-Workspace")):
    items = await _segments_read(x_workspace)
    out: list[dict] = []
    for s in (items or []):
        if not isinstance(s, dict):
            continue
        dsl = str(s.get("dsl") or "").strip()
        compiled_query, conds, desc = compile_segment_dsl_to_shopify_query(dsl)
        out.append({**s, "compiled_query": compiled_query, "conditions": conds, "description": desc})
    return out

async def get_customer_segment_by_id(segment_id: str, x_workspace: str | None = None) -> dict | None:
    """Return a saved customer segment entry by id (from DB settings, legacy file fallback)."""
    sid = str(segment_id or "").strip()
    if not sid:
        return None
    try:
        items = await _segments_read(x_workspace)
    except Exception:
        items = []
    for s in items or []:
        try:
            if isinstance(s, dict) and str(s.get("id") or "").strip() == sid:
                return s
        except Exception:
            continue
    return None

async def add_shopify_customer_tag(*, customer_id: str | int, tag: str, store: str | None = None) -> dict:
    """Add a tag to a Shopify customer (best-effort).

    Requires Shopify token with write_customers scope.
    """
    base = admin_api_base(store)
    t = str(tag or "").strip()
    if not t:
        return {"ok": False, "error": "missing_tag"}
    if "," in t:
        return {"ok": False, "error": "tag_contains_comma"}
    cid = str(customer_id or "").strip()
    if not cid:
        return {"ok": False, "error": "missing_customer_id"}
    # Coerce gid://shopify/Customer/123 -> 123
    try:
        if cid.startswith("gid://"):
            cid = cid.rsplit("/", 1)[-1]
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=20.0) as client:
        # Fetch existing tags
        get_endpoint = f"{base}/customers/{cid}.json"
        resp = await client.get(get_endpoint, **_client_args(store=store))
        if resp.status_code == 404:
            return {"ok": False, "error": "not_found"}
        if resp.status_code == 403:
            return {"ok": False, "error": "forbidden", "detail": "Shopify token lacks write_customers scope or app not installed."}
        if resp.status_code >= 400:
            return {"ok": False, "error": "shopify_error", "detail": (resp.text or "")[:300]}
        customer = (resp.json() or {}).get("customer") or {}
        existing_s = str(customer.get("tags") or "")
        existing = [x.strip() for x in existing_s.split(",") if x and x.strip()]
        lower = {x.lower() for x in existing}
        if t.lower() not in lower:
            existing.append(t)
        put_endpoint = f"{base}/customers/{cid}.json"
        payload = {"customer": {"id": int(cid) if cid.isdigit() else cid, "tags": ", ".join(existing)}}
        upd = await client.put(put_endpoint, json=payload, **_client_args(store=store))
        if upd.status_code == 403:
            return {"ok": False, "error": "forbidden", "detail": "Shopify token lacks write_customers scope or app not installed."}
        if upd.status_code >= 400:
            return {"ok": False, "error": "shopify_error", "detail": (upd.text or "")[:300]}
        return {"ok": True, "customer_id": cid, "tags": existing}


@router.post("/customer-segments")
async def save_customer_segment(body: dict = Body(...), x_workspace: str | None = Header(None, alias="X-Workspace")):
    name = str((body or {}).get("name") or "").strip() or "Segment"
    dsl = str((body or {}).get("dsl") or "").strip()
    store = str((body or {}).get("store") or "").strip().upper() or None
    seg_id = str((body or {}).get("id") or "").strip() or str(uuid.uuid4())
    if not dsl:
        raise HTTPException(status_code=400, detail="Missing dsl")
    items = await _segments_read(x_workspace)
    now = datetime.now(timezone.utc).isoformat()
    # IMPORTANT: to keep segments dynamic (Shopify-like), persist ONLY the segment definition.
    # Derived fields (compiled_query/description/conditions) are recomputed at preview/send time.
    entry: dict = {
        "id": seg_id,
        "name": name,
        "store": store,
        "dsl": dsl,
        "updated_at": now,
        "created_at": (next((x.get("created_at") for x in items if x.get("id") == seg_id), None) or now),
    }
    next_items = [x for x in items if x.get("id") != seg_id]
    next_items.insert(0, entry)
    await _segments_write(x_workspace, next_items)
    # Return enriched entry for UI convenience (computed at request time)
    compiled_query, conds, desc = compile_segment_dsl_to_shopify_query(dsl)
    return {**entry, "compiled_query": compiled_query, "conditions": conds, "description": desc}

@router.post("/customer-segments/import-shopify")
async def import_shopify_customer_segments(
    request: Request,
    body: dict = Body({}),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """Import saved Shopify customer segments (dynamic) into our segments list so they can be selected in UI/retargeting.

    Body:
      - store: str (optional) Shopify store prefix override
      - limit: int (optional, default 200)
    """
    _ = _require_admin_request(request)

    store = str((body or {}).get("store") or "").strip().upper() or None
    try:
        limit = int((body or {}).get("limit") or 200)
    except Exception:
        limit = 200
    limit = max(1, min(limit, 2000))

    items = await _segments_read(x_workspace)
    existing_by_gid: dict[str, dict] = {}
    for s in (items or []):
        if not isinstance(s, dict):
            continue
        gid = str(s.get("shopify_segment_gid") or "").strip()
        if gid:
            existing_by_gid[gid] = s

    imported: list[dict] = []
    cursor = None
    seen = 0
    while True:
        segs, cursor = await _list_shopify_segments(store=store, x_workspace=x_workspace, first=50, after=cursor)
        for seg in segs:
            if seen >= limit:
                cursor = None
                break
            gid = str(seg.get("gid") or "").strip()
            name = str(seg.get("name") or "").strip() or "Shopify segment"
            qtxt = str(seg.get("query") or "").strip()
            if not gid:
                continue
            # Stable id in our DB
            seg_id = f"shopify:{gid}"
            now = datetime.now(timezone.utc).isoformat()
            prev = existing_by_gid.get(gid) or {}
            entry = {
                "id": seg_id,
                "name": name,
                "store": store,
                "dsl": qtxt,  # ShopifyQL (may be displayed)
                "source": "shopify",
                "shopify_segment_gid": gid,
                "updated_at": now,
                "created_at": (prev.get("created_at") or now),
            }
            imported.append(entry)
            seen += 1
        if not cursor or seen >= limit:
            break

    # Merge: keep non-Shopify segments + upsert Shopify ones by gid
    next_items: list[dict] = []
    # keep all non-shopify and any shopify that weren't imported this run
    imported_gids = {str(x.get("shopify_segment_gid") or "").strip() for x in imported}
    for s in (items or []):
        if not isinstance(s, dict):
            continue
        if str(s.get("source") or "").strip().lower() == "shopify":
            gid = str(s.get("shopify_segment_gid") or "").strip()
            if gid and gid in imported_gids:
                continue
        next_items.append(s)
    # prepend imported (newest first)
    next_items = list(imported) + next_items

    await _segments_write(x_workspace, next_items)
    return {"ok": True, "imported": len(imported)}

@router.delete("/customer-segments/{segment_id}")
async def delete_customer_segment(segment_id: str, x_workspace: str | None = Header(None, alias="X-Workspace")):
    sid = str(segment_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="Missing segment id")
    items = await _segments_read(x_workspace)
    next_items = [x for x in items if str(x.get("id") or "") != sid]
    await _segments_write(x_workspace, next_items)
    return {"ok": True}


@router.get("/shopify-segment-preview")
async def shopify_segment_preview(
    dsl: str = Query("", description="Segment DSL (Shopify-like FROM/SHOW/WHERE/AND/ORDER BY)"),
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    page_info: str | None = Query(None, description="Cursor for pagination (Shopify page_info)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    dsl = str(dsl or "").strip()
    if not dsl:
        raise HTTPException(status_code=400, detail="Missing dsl")

    compiled_query, conds, desc = compile_segment_dsl_to_shopify_query(dsl)
    # Resolve correct Shopify context (OAuth per-workspace if connected, else env store mapping).
    base, extra_args, store_used, store = await _shopify_http_context(store, x_workspace)

    # base count (fast)
    base_count: int | None = None
    async with httpx.AsyncClient() as client:
        try:
            c_resp = await client.get(f"{base}/customers/count.json", timeout=10, **(extra_args or {}))
            if c_resp.status_code == 200:
                base_count = int((c_resp.json() or {}).get("count") or 0)
        except Exception:
            base_count = None

    # Prefer ShopifyQL segment evaluation via GraphQL (matches Shopify segment builder semantics).
    # If not supported by this shop/API, fall back to REST customer search query compilation.
    try:
        # Count + first page (best-effort sampling)
        total = 0
        pages = 0
        started = time.monotonic()
        cursor: str | None = None
        is_estimate = False
        first_page_customers: list[dict] = []
        while True:
            if pages >= 6 or (time.monotonic() - started) > 8.0:
                is_estimate = True
                break
            customers, cursor = await _shopify_segment_members_by_query_page(
                query_text=dsl,
                store=store,
                x_workspace=x_workspace,
                first=100,
                after=cursor,
            )
            if pages == 0:
                first_page_customers = customers[:50]
            if not customers:
                break
            total += len(customers)
            pages += 1
            if not cursor:
                break

        # Map into UI-friendly rows (best-effort)
        rows = []
        for c in first_page_customers:
            if not isinstance(c, dict):
                continue
            fn = str(c.get("firstName") or "").strip()
            ln = str(c.get("lastName") or "").strip()
            name = (f"{fn} {ln}".strip() or fn or ln or "")
            phone = str(c.get("phone") or "") or str(((c.get("defaultAddress") or {}) if isinstance(c.get("defaultAddress"), dict) else {}).get("phone") or "")
            rows.append(
                {
                    "id": c.get("id"),
                    "customer_name": name,
                    "note": "",
                    "email_subscription_status": "",
                    "location": "",
                    "orders": 0,
                    "amount_spent": {"value": 0, "currency": ""},
                    "phone": phone,
                }
            )

        return {
            "customers": rows,
            "compiled_query": "",  # not applicable for ShopifyQL path
            "conditions": conds,
            "description": desc,
            "segment_count": int(total),
            "segment_count_is_estimate": bool(is_estimate),
            "base_count": base_count,
            "next_page_info": None,
            "prev_page_info": None,
        }
    except HTTPException:
        # fall through to REST path on Shopify error
        pass
    except Exception:
        # fall through to REST path
        pass

    # Fallback: compile into REST search query (limited; may not match ShopifyQL for all conditions)
    if not compiled_query:
        raise HTTPException(status_code=400, detail="Could not compile DSL (no supported conditions found).")

    segment_count, segment_count_is_estimate = await _count_customers_for_query(
        query=compiled_query,
        base=base,
        extra_args=extra_args,
        cache_key_prefix=str(store_used),
        max_pages=6,
        max_seconds=8.0,
    )

    preview = await shopify_customers(store=store, limit=50, page_info=page_info, q=compiled_query, x_workspace=x_workspace)
    preview["compiled_query"] = compiled_query
    preview["conditions"] = conds
    preview["description"] = desc
    preview["segment_count"] = segment_count
    preview["segment_count_is_estimate"] = bool(segment_count_is_estimate)
    preview["base_count"] = base_count
    return preview

@router.get("/shopify-stores")
async def shopify_stores():
    """List configured Shopify store prefixes available to the backend."""
    prefixes = ["SHOPIFY", "IRRAKIDS", "IRRANOVA"]
    try:
        for k in os.environ.keys():
            if k.endswith("_STORE_URL") or k.endswith("_STORE_DOMAIN"):
                p = k.rsplit("_", 1)[0]
                if p and p not in prefixes:
                    prefixes.append(p)
    except Exception:
        pass
    out = []
    for p in prefixes:
        try:
            _api_key, _password, store_url, _access_token = _load_store_config_for_prefix(p)
            out.append({"id": p, "store_url": store_url})
        except Exception:
            continue
    return out

# --- List products, with optional search query ---
@router.get("/shopify-products")
async def shopify_products(
    q: str = Query("", description="Search product titles (optional)"),
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    params = {"title": q} if q else {}
    endpoint = f"{base}/products.json"
    async with httpx.AsyncClient() as client:
        resp = await client.get(endpoint, params=params, **extra_args)
        resp.raise_for_status()
        products = resp.json().get("products", [])
        # Optionally include product_title for variant for UI display
        for p in products:
            for v in p.get("variants", []):
                v["product_title"] = p["title"]
        return products

# --- Lookup a single variant by ID ---
@router.get("/shopify-variant/{variant_id}")
async def shopify_variant(
    variant_id: str,
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    # Prefer OAuth token+shop for this workspace if present (DB-stored via Settings -> Your stores).
    ws = _normalize_ws_id(x_workspace)
    oauth = await _get_shopify_oauth_record(ws)
    store = _resolve_store_from_workspace(store, x_workspace)
    oauth_shop = str((oauth or {}).get("shop") or "").strip()
    oauth_token = str((oauth or {}).get("access_token") or "").strip()
    if oauth_shop and oauth_token:
        endpoint = f"{_oauth_admin_api_base(str(oauth.get('shop') or ''))}/variants/{variant_id}.json"
        extra_args = {"headers": {"X-Shopify-Access-Token": oauth_token}}
    else:
        endpoint = f"{admin_api_base(store)}/variants/{variant_id}.json"
        extra_args = _client_args(store=store)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(endpoint, **extra_args)
        except httpx.RequestError as e:
            logger.warning("Shopify variant request failed: %s", e)
            raise HTTPException(status_code=502, detail="Shopify unreachable")

        if resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks read_products scope or app not installed.")
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Variant not found")
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = (resp.text or "").strip()[:300]
            except Exception:
                detail = "Shopify error"
            raise HTTPException(status_code=resp.status_code, detail=detail or "Shopify error")

        variant = (resp.json() or {}).get("variant")
        # Try to fetch product title and resolve variant image for display (best-effort)
        if variant:
            try:
                product_id = variant.get("product_id")
                if product_id:
                    if oauth_shop and oauth_token:
                        prod_endpoint = f"{_oauth_admin_api_base(oauth_shop)}/products/{product_id}.json"
                        p_resp = await client.get(prod_endpoint, headers={"X-Shopify-Access-Token": oauth_token})
                    else:
                        prod_endpoint = f"{admin_api_base(store)}/products/{product_id}.json"
                        p_resp = await client.get(prod_endpoint, **_client_args(store=store))
                    if p_resp.status_code == 200:
                        prod = (p_resp.json() or {}).get("product") or {}
                        variant["product_title"] = prod.get("title", "")
                        # Resolve image URL for the variant
                        image_src = None
                        image_id = variant.get("image_id")
                        images = prod.get("images") or []
                        if image_id and images:
                            try:
                                match = next((img for img in images if str(img.get("id")) == str(image_id)), None)
                                if match and match.get("src"):
                                    image_src = match["src"]
                            except Exception:
                                image_src = None
                        # Fallbacks: product featured image or first image
                        if not image_src:
                            image_src = (prod.get("image") or {}).get("src") or (images[0].get("src") if images else None)
                        if image_src:
                            variant["image_src"] = image_src
            except Exception as e:
                logger.debug("Variant enrichment failed: %s", e)
        return variant or {}

# =============== CUSTOMER BY PHONE ===============
async def fetch_customer_by_phone(phone_number: str, store: str | None = None, x_workspace: str | None = None):
    try:
        phone_number = normalize_phone(phone_number)
        params = {'query': f'phone:{phone_number}'}
        base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
        async with httpx.AsyncClient() as client:
            # Search customer
            search_endpoint = f"{base}/customers/search.json"
            resp = await client.get(search_endpoint, params=params, timeout=10, **extra_args)
            if resp.status_code == 403:
                logger.error("Shopify API 403 on customers/search. Missing read_customers scope for token or app not installed.")
                return {"error": "Forbidden", "detail": "Shopify token lacks read_customers scope or app not installed.", "status": 403}
            data = resp.json()
            customers = data.get('customers', [])

            # Morocco fallback
            if not customers and phone_number.startswith("+212"):
                alt_phone = "0" + phone_number[4:]
                params = {'query': f'phone:{alt_phone}'}
                resp = await client.get(search_endpoint, params=params, timeout=10, **extra_args)
                if resp.status_code == 403:
                    logger.error("Shopify API 403 on customers/search (fallback). Missing read_customers scope.")
                    return {"error": "Forbidden", "detail": "Shopify token lacks read_customers scope or app not installed.", "status": 403}
                data = resp.json()
                customers = data.get('customers', [])

            if not customers:
                logger.warning(f"No customer found for phone number {phone_number}")
                return None

            c = customers[0]
            customer_id = c["id"]

            # Orders: last + count
            order_params = {
                "customer_id": customer_id,
                "status": "any",
                "limit": 1,
                "order": "created_at desc"
            }
            orders_resp = await client.get(
                f"{base}/orders.json",
                params=order_params,
                timeout=10,
                **extra_args,
            )
            orders_data = orders_resp.json()
            orders_list = orders_data.get('orders', [])

            # Count
            total_orders = c.get('orders_count', 0)

            # Last order details if exists
            last_order = None
            if orders_list:
                o = orders_list[0]
                last_order = {
                    "order_number": o.get("name"),
                    "total_price": o.get("total_price"),
                    "line_items": [
                        {
                            "title": item.get("title"),
                            "variant_title": item.get("variant_title"),
                            "quantity": item.get("quantity")
                        }
                        for item in o.get("line_items", [])
                    ]
                }

            # Build response
            return {
                "customer_id": c["id"],   # <--- ADD THIS LINE
                "name": f"{c.get('first_name', '')} {c.get('last_name', '')}".strip(),
                "email": c.get("email") or "",
                "phone": c.get("phone") or "",
                "address": (c["addresses"][0]["address1"] if c.get("addresses") and c["addresses"] else ""),
                "total_orders": total_orders,
                "last_order": last_order
            }
    except httpx.HTTPStatusError as e:
        logger.exception("HTTP error from Shopify: %s", e)
        return {"error": "HTTP error", "detail": str(e), "status": e.response.status_code if e.response else 500}
    except Exception as e:
        logger.exception(f"Exception occurred: {e}")
        return {"error": str(e), "status": 500}

# =========== FASTAPI ENDPOINT: SEARCH CUSTOMER ============
@router.get("/search-customer")
async def search_customer(
    phone_number: str,
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """
    Fetch customer and order info by phone.
    """
    store = _resolve_store_from_workspace(store, x_workspace)
    data = await fetch_customer_by_phone(phone_number, store=store, x_workspace=x_workspace)
    if not data:
        raise HTTPException(status_code=404, detail="Customer not found")
    if isinstance(data, dict) and data.get("status") == 403:
        raise HTTPException(status_code=403, detail=data.get("detail") or "Forbidden")
    if isinstance(data, dict) and data.get("error"):
        raise HTTPException(status_code=int(data.get("status", 500)), detail=data.get("detail") or data.get("error"))
    return data


# =========== FASTAPI ENDPOINT: SEARCH MULTIPLE CUSTOMERS ============
def _candidate_phones(raw: str) -> list[str]:
    """Generate possible normalized phone variants for broader matching."""
    if not raw:
        return []
    raw = str(raw).strip().replace(" ", "").replace("-", "")
    candidates: set[str] = set()
    # Base normalized
    base = normalize_phone(raw)
    if base:
        candidates.add(base)
    # Try stripping plus
    if base.startswith("+"):
        candidates.add(base[1:])
    # Morocco specific: +212XXXXXXXXX -> 0XXXXXXXXX
    if base.startswith("+212") and len(base) >= 5:
        candidates.add("0" + base[4:])
        candidates.add(base[4:])  # 212XXXXXXXXX
    # If raw starts with 06/07 etc, make +212 variant
    if len(raw) == 10 and raw.startswith("0"):
        candidates.add("+212" + raw[1:])
        candidates.add("212" + raw[1:])
    # If provided already w/o plus but 212 prefix
    if raw.startswith("212"):
        candidates.add("+" + raw)
        candidates.add("0" + raw[3:])
    # Deduplicate
    return [c for c in candidates if c]


@router.get("/search-customers-all")
async def search_customers_all(
    phone_number: str,
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """
    Return all Shopify customers matching multiple phone normalizations.
    Each customer includes minimal profile and primary address if available.
    """
    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    cand = _candidate_phones(phone_number)
    if not cand:
        return []
    results_by_id: dict[str, dict] = {}
    async with httpx.AsyncClient() as client:
        for pn in cand:
            params = {'query': f'phone:{pn}'}
            resp = await client.get(f"{base}/customers/search.json", params=params, timeout=10, **extra_args)
            if resp.status_code == 403:
                raise HTTPException(status_code=403, detail="Shopify token lacks read_customers scope or app not installed.")
            customers = resp.json().get('customers', [])
            for c in customers:
                cid = str(c.get("id"))
                if cid in results_by_id:
                    continue
                # Build compact customer payload
                primary_addr = (c.get("addresses") or [{}])[0] or {}
                results_by_id[cid] = {
                    "customer_id": c.get("id"),
                    "name": f"{c.get('first_name', '')} {c.get('last_name', '')}".strip(),
                    "email": c.get("email") or "",
                    "phone": c.get("phone") or "",
                    "addresses": [
                        {
                            "address1": a.get("address1", ""),
                            "city": a.get("city", ""),
                            "province": a.get("province", ""),
                            "zip": a.get("zip", ""),
                            "phone": a.get("phone", ""),
                            "name": (a.get("name") or f"{c.get('first_name','')} {c.get('last_name','')}").strip(),
                        }
                        for a in (c.get("addresses") or [])
                    ],
                    "primary_address": {
                        "address1": primary_addr.get("address1", ""),
                        "city": primary_addr.get("city", ""),
                        "province": primary_addr.get("province", ""),
                        "zip": primary_addr.get("zip", ""),
                        "phone": primary_addr.get("phone", ""),
                    },
                    "total_orders": c.get("orders_count", 0),
                }
        # Optionally fetch last order for each (best-effort)
        for cid, entry in results_by_id.items():
            order_params = {
                "customer_id": entry["customer_id"],
                "status": "any",
                "limit": 1,
                "order": "created_at desc",
            }
            try:
                orders_resp = await client.get(f"{base}/orders.json", params=order_params, timeout=10, **extra_args)
                orders_list = orders_resp.json().get('orders', [])
                if orders_list:
                    o = orders_list[0]
                    entry["last_order"] = {
                        "order_number": o.get("name"),
                        "total_price": o.get("total_price"),
                        "line_items": [
                            {
                                "title": li.get("title"),
                                "variant_title": li.get("variant_title"),
                                "quantity": li.get("quantity"),
                            }
                            for li in o.get("line_items", [])
                        ],
                    }
            except Exception:
                continue

    return list(results_by_id.values())

def _parse_link_header_page_info(link_header: str | None) -> dict[str, str]:
    """Parse Shopify pagination Link header into {rel: page_info}."""
    out: dict[str, str] = {}
    if not link_header:
        return out
    for part in str(link_header).split(","):
        p = part.strip()
        rel = None
        if 'rel="next"' in p:
            rel = "next"
        elif 'rel="previous"' in p:
            rel = "previous"
        if not rel:
            continue
        lt = p.find("<")
        gt = p.find(">")
        if lt == -1 or gt == -1 or gt <= lt:
            continue
        url = p[lt + 1 : gt]
        idx = url.find("page_info=")
        if idx == -1:
            continue
        token = url[idx + len("page_info=") :]
        token = token.split("&", 1)[0]
        if token:
            out[rel] = token
    return out


@router.get("/shopify-customers")
async def shopify_customers(
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    limit: int = Query(50, ge=1, le=250),
    page_info: str | None = Query(None, description="Cursor for pagination (Shopify page_info)"),
    q: str = Query("", description="Search query (Shopify customers/search query syntax)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """List Shopify customers (paginated), with optional search."""
    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    async with httpx.AsyncClient() as client:
        # IMPORTANT (Shopify cursor pagination): when page_info is present, do not pass other params
        # like "order" or "query". Only "limit" + "page_info".
        if page_info:
            params: dict[str, str | int] = {"limit": int(limit), "page_info": page_info}
            # Keep endpoint stable with the original request: if q exists, we were using /customers/search.json.
            endpoint = f"{base}/customers/search.json" if (q and q.strip()) else f"{base}/customers.json"
        else:
            params = {"limit": int(limit), "order": "updated_at desc"}
            if q and q.strip():
                endpoint = f"{base}/customers/search.json"
                params["query"] = q.strip()
            else:
                endpoint = f"{base}/customers.json"

        resp = await client.get(endpoint, params=params, timeout=20, **(extra_args or {}))
        if resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks read_customers scope or app not installed.")
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=(resp.text or "Shopify error")[:300])

        payload = resp.json() or {}
        customers = payload.get("customers", []) or []

        # Count only for the "all customers" default listing first page.
        total_count: int | None = None
        if (not q or not q.strip()) and (not page_info):
            try:
                c_resp = await client.get(f"{base}/customers/count.json", timeout=10, **(extra_args or {}))
                if c_resp.status_code == 200:
                    total_count = int((c_resp.json() or {}).get("count") or 0)
            except Exception:
                total_count = None

        links = _parse_link_header_page_info(resp.headers.get("link") or resp.headers.get("Link"))
        next_pi = links.get("next")
        prev_pi = links.get("previous")

        def fmt_location(c: dict) -> str:
            addr = c.get("default_address") or {}
            city = str(addr.get("city") or "").strip()
            country = str(addr.get("country") or "").strip()
            if city and country and country.lower() != city.lower():
                return f"{city}, {country}"
            return city or country or ""

        def email_sub_status(c: dict) -> str:
            emc = c.get("email_marketing_consent") or {}
            state = str(emc.get("state") or "").strip()
            if state:
                return state
            if c.get("accepts_marketing") is True:
                return "subscribed"
            if c.get("accepts_marketing") is False:
                return "not_subscribed"
            return "-"

        out = []
        for c in customers:
            first = str(c.get("first_name") or "").strip()
            last = str(c.get("last_name") or "").strip()
            name = (f"{first} {last}").strip() or (c.get("email") or "") or "(no name)"
            currency = str(c.get("currency") or "").strip() or "MAD"
            spent = c.get("total_spent")
            try:
                spent_val = float(spent) if spent is not None else 0.0
            except Exception:
                spent_val = 0.0
            out.append(
                {
                    "id": c.get("id"),
                    "customer_name": name,
                    "note": c.get("note") or "",
                    "email_subscription_status": email_sub_status(c),
                    "location": fmt_location(c),
                    "orders": int(c.get("orders_count") or 0),
                    "amount_spent": {"value": round(spent_val, 2), "currency": currency},
                    # for campaigns / internal tooling (not shown in table)
                    "email": c.get("email") or "",
                    "phone": c.get("phone") or "",
                    "updated_at": c.get("updated_at"),
                }
            )

        return {
            "store": (store.strip().upper() if store else None),
            "total_count": total_count,
            "customers": out,
            "next_page_info": next_pi,
            "prev_page_info": prev_pi,
        }

@router.get("/shopify-orders")
async def shopify_orders(
    customer_id: str,
    limit: int = 50,
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """Return recent orders for a Shopify customer (admin-simplified list)."""
    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    params = {
        "customer_id": customer_id,
        "status": "any",
        "order": "created_at desc",
        "limit": max(1, min(int(limit), 250)),
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{base}/orders.json", params=params, timeout=15, **extra_args)
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                detail = {"error": "rate_limited", "message": "Shopify rate limit reached", "retry_after": retry_after}
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=429, content=detail)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response is not None and exc.response.status_code == 429:
                retry_after = exc.response.headers.get("Retry-After")
                detail = {"error": "rate_limited", "message": "Shopify rate limit reached", "retry_after": retry_after}
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=429, content=detail)
            raise

        orders = resp.json().get("orders", [])
        domain = base.replace("https://", "").replace("http://", "").split("/admin/api", 1)[0]
        simplified = []
        for o in orders:
            # Shopify REST Admin API returns order.tags as a comma-separated string; expose as an array
            tags_str = o.get("tags") or ""
            tags_arr = [t.strip() for t in str(tags_str).split(",") if t and t.strip()]
            simplified.append({
                "id": o.get("id"),
                "order_number": o.get("name"),
                "created_at": o.get("created_at"),
                "financial_status": o.get("financial_status"),
                "fulfillment_status": o.get("fulfillment_status"),
                "total_price": o.get("total_price"),
                "currency": o.get("currency"),
                "admin_url": f"https://{domain}/admin/orders/{o.get('id')}",
                "tags": tags_arr,
                "note": o.get("note") or "",
            })
        return simplified

@router.post("/shopify-orders/{order_id}/tags")
async def add_order_tag(
    order_id: str,
    body: dict = Body(...),
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """Add a tag to a Shopify order. Requires write_orders scope.

    Body: { "tag": "..." }
    Returns: { ok: true, order_id, tags: [..] }
    """
    tag = (body or {}).get("tag")
    tag = (tag or "").strip()
    if not tag:
        raise HTTPException(status_code=400, detail="Missing tag")

    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    async with httpx.AsyncClient() as client:
        # Fetch current tags first to avoid overwriting
        get_resp = await client.get(f"{base}/orders/{order_id}.json", timeout=15, **extra_args)
        if get_resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Order not found")
        if get_resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks read_orders scope or app not installed.")
        get_resp.raise_for_status()
        order_obj = (get_resp.json() or {}).get("order") or {}
        current_tags_str = order_obj.get("tags") or ""
        current_tags = [t.strip() for t in str(current_tags_str).split(",") if t and t.strip()]
        if tag not in current_tags:
            current_tags.append(tag)

        update_payload = {"order": {"id": int(str(order_id)), "tags": ", ".join(current_tags)}}
        put_resp = await client.put(f"{base}/orders/{order_id}.json", json=update_payload, timeout=15, **extra_args)
        if put_resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks write_orders scope or app not installed.")
        put_resp.raise_for_status()
        updated_order = (put_resp.json() or {}).get("order") or {}
        tags_str = updated_order.get("tags") or ", ".join(current_tags)
        tags_arr = [t.strip() for t in str(tags_str).split(",") if t and t.strip()]
        return {"ok": True, "order_id": updated_order.get("id") or order_id, "tags": tags_arr}

@router.delete("/shopify-orders/{order_id}/tags")
async def remove_order_tag(
    order_id: str,
    body: dict = Body(...),
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """Remove a tag from a Shopify order. Requires write_orders scope.

    Body: { "tag": "..." }
    Returns: { ok: true, order_id, tags: [..] }
    """
    tag = (body or {}).get("tag")
    tag = (tag or "").strip()
    if not tag:
        raise HTTPException(status_code=400, detail="Missing tag")

    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    async with httpx.AsyncClient() as client:
        get_resp = await client.get(f"{base}/orders/{order_id}.json", timeout=15, **extra_args)
        if get_resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Order not found")
        if get_resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks read_orders scope or app not installed.")
        get_resp.raise_for_status()
        order_obj = (get_resp.json() or {}).get("order") or {}
        current_tags_str = order_obj.get("tags") or ""
        current_tags = [t.strip() for t in str(current_tags_str).split(",") if t and t.strip()]
        next_tags = [t for t in current_tags if t.lower() != tag.lower()]

        update_payload = {"order": {"id": int(str(order_id)), "tags": ", ".join(next_tags)}}
        put_resp = await client.put(f"{base}/orders/{order_id}.json", json=update_payload, timeout=15, **extra_args)
        if put_resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks write_orders scope or app not installed.")
        put_resp.raise_for_status()
        updated_order = (put_resp.json() or {}).get("order") or {}
        tags_str = updated_order.get("tags") or ", ".join(next_tags)
        tags_arr = [t.strip() for t in str(tags_str).split(",") if t and t.strip()]
        return {"ok": True, "order_id": updated_order.get("id") or order_id, "tags": tags_arr}

@router.post("/shopify-orders/{order_id}/note")
async def add_order_note(
    order_id: str,
    body: dict = Body(...),
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """Append a note to a Shopify order. Requires write_orders scope.

    Body: { "note": "..." }
    Appends to existing note with a newline.
    Returns: { ok: true, order_id, note: "..." }
    """
    new_note_fragment = (body or {}).get("note")
    new_note_fragment = (new_note_fragment or "").strip()
    if not new_note_fragment:
        raise HTTPException(status_code=400, detail="Missing note")

    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    async with httpx.AsyncClient() as client:
        # Fetch current order to read existing note
        get_resp = await client.get(f"{base}/orders/{order_id}.json", timeout=15, **extra_args)
        if get_resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Order not found")
        if get_resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks read_orders scope or app not installed.")
        get_resp.raise_for_status()
        order_obj = (get_resp.json() or {}).get("order") or {}
        current_note = (order_obj.get("note") or "").strip()
        combined_note = new_note_fragment if not current_note else f"{current_note}\n{new_note_fragment}"

        update_payload = {"order": {"id": int(str(order_id)), "note": combined_note}}
        put_resp = await client.put(f"{base}/orders/{order_id}.json", json=update_payload, timeout=15, **extra_args)
        if put_resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks write_orders scope or app not installed.")
        put_resp.raise_for_status()
        updated_order = (put_resp.json() or {}).get("order") or {}
        final_note = (updated_order.get("note") or combined_note)
        return {"ok": True, "order_id": updated_order.get("id") or order_id, "note": final_note}

@router.delete("/shopify-orders/{order_id}/note")
async def delete_order_note(
    order_id: str,
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    """Clear the note on a Shopify order (set to empty). Requires write_orders scope.

    Returns: { ok: true, order_id, note: "" }
    """
    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    async with httpx.AsyncClient() as client:
        update_payload = {"order": {"id": int(str(order_id)), "note": ""}}
        put_resp = await client.put(f"{base}/orders/{order_id}.json", json=update_payload, timeout=15, **extra_args)
        if put_resp.status_code == 403:
            raise HTTPException(status_code=403, detail="Shopify token lacks write_orders scope or app not installed.")
        if put_resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Order not found")
        put_resp.raise_for_status()
        updated_order = (put_resp.json() or {}).get("order") or {}
        return {"ok": True, "order_id": updated_order.get("id") or order_id, "note": ""}

@router.get("/shopify-shipping-options")
async def get_shipping_options(
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    base, extra_args, _store_used, store = await _shopify_http_context(store, x_workspace)
    endpoint = f"{base}/shipping_zones.json"
    async with httpx.AsyncClient() as client:
        resp = await client.get(endpoint, **extra_args)
        resp.raise_for_status()
        data = resp.json()
        shipping_methods = []
        for zone in data.get("shipping_zones", []):
            # Price-based rates
            for rate in zone.get("price_based_shipping_rates", []):
                shipping_methods.append({
                    "id": rate.get("id"),
                    "name": rate.get("name"),
                    "price": float(rate.get("price", 0)),
                    "zone": zone.get("name"),
                    "type": "price_based"
                })
            # Weight-based rates
            for rate in zone.get("weight_based_shipping_rates", []):
                shipping_methods.append({
                    "id": rate.get("id"),
                    "name": rate.get("name"),
                    "price": float(rate.get("price", 0)),
                    "zone": zone.get("name"),
                    "type": "weight_based"
                })
            # Carrier shipping rates (for completeness)
            for rate in zone.get("carrier_shipping_rate_providers", []):
                shipping_methods.append({
                    "id": rate.get("id"),
                    "name": rate.get("name"),
                    "zone": zone.get("name"),
                    "type": "carrier"
                })
        print("EXTRACTED RATES:", shipping_methods)  # <--- Will now not be empty!
        return shipping_methods

@router.post("/create-shopify-order")
async def create_shopify_order(
    data: dict = Body(...),
    store: str | None = Query(None, description="Optional Shopify store prefix (e.g. IRRAKIDS)"),
    x_workspace: str | None = Header(None, alias="X-Workspace"),
):
    ws = _normalize_ws_id(x_workspace)
    oauth = await _get_shopify_oauth_record(ws)
    oauth_shop = str((oauth or {}).get("shop") or "").strip().lower()
    oauth_token = str((oauth or {}).get("access_token") or "").strip()

    store = _resolve_store_from_workspace(store, x_workspace)

    # Prefer per-workspace OAuth store connection when present, so each workspace uses its own Shopify store.
    if oauth_shop and oauth_token:
        store_used = f"OAUTH:{oauth_shop}"
        base = _oauth_admin_api_base(oauth_shop)
        extra_args = {"headers": {"X-Shopify-Access-Token": oauth_token}}
    else:
        store_used = store or "DEFAULT"
        base = admin_api_base(store)
        extra_args = _client_args(store=store)
    warnings: list[str] = []
    shipping_title = data.get("delivery", "Home Delivery")
    shipping_lines = [{
        "title": shipping_title,
        "price": 0.00,
        "code": "STANDARD"
    }]
    # Optional order note and image URL (stored as note and note_attributes)
    order_note = (data.get("order_note") or data.get("note") or "").strip()
    order_image_url = (data.get("order_image_url") or data.get("image_url") or "").strip()
    note_attributes: list[dict] = []
    if order_image_url:
        note_attributes.append({"name": "image_url", "value": order_image_url})
    if order_note:
        note_attributes.append({"name": "note_text", "value": order_note})
    # Attach customer to draft order. Shopify expects `customer` object (with id),
    # not `customer_id` at the root of draft_order. Optionally create the customer first.
    order_block = {}
    customer_id = data.get("customer_id")
    # Customer IDs are store-specific. The UI can sometimes send a customer_id created in a different
    # workspace/store; Shopify draft order creation may then fail with 422 "Record is invalid".
    try:
        cid_str = str(customer_id).strip() if customer_id is not None else ""
    except Exception:
        cid_str = ""
    if cid_str:
        if not cid_str.isdigit():
            warnings.append("Ignoring non-numeric customer_id (Shopify ids are numeric).")
            customer_id = None
        else:
            try:
                async with httpx.AsyncClient() as client:
                    chk = await client.get(f"{base}/customers/{cid_str}.json", timeout=10, **extra_args)
                    if chk.status_code == 404:
                        warnings.append("customer_id not found in this store; will resolve by phone/email instead.")
                        customer_id = None
                    elif chk.status_code == 403:
                        warnings.append("Shopify token lacks read_customers scope; cannot validate customer_id, using inline customer fields.")
                        customer_id = None
                    elif chk.status_code >= 400:
                        warnings.append("Could not validate customer_id in this store; using inline customer fields.")
                        customer_id = None
            except Exception:
                # Best-effort: if validation fails due to network issues, keep existing behavior.
                pass
    # If no explicit id provided, try to resolve by phone best-effort
    if not customer_id:
        try:
            phone_q = normalize_phone(data.get("phone", ""))
            if phone_q:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"{base}/customers/search.json",
                        params={"query": f"phone:{phone_q}"},
                        timeout=10,
                        **extra_args,
                    )
                    if resp.status_code == 200:
                        items = (resp.json() or {}).get("customers") or []
                        if items:
                            customer_id = items[0].get("id")
        except Exception:
            customer_id = None

    # If still not found, try to resolve by email (Shopify supports email search)
    if not customer_id and (data.get("email") or "").strip():
        try:
            email_q = (data.get("email") or "").strip()
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{base}/customers/search.json",
                    params={"query": f"email:{email_q}"},
                    timeout=10,
                    **extra_args,
                )
                if resp.status_code == 200:
                    items = (resp.json() or {}).get("customers") or []
                    if items:
                        customer_id = items[0].get("id")
        except Exception:
            pass

    # Optionally create a new Shopify customer if missing
    create_if_missing = bool(data.get("create_customer_if_missing", True))
    if not customer_id and create_if_missing:
        try:
            fn, ln = _split_name(data.get("name", ""))
            customer_payload = {
                "customer": {
                    "first_name": fn or "",
                    "last_name": ln or "",
                    "email": data.get("email") or "",
                    "phone": normalize_phone(data.get("phone", "")),
                    "addresses": [
                        {
                            "first_name": fn or "",
                            "last_name": ln or "",
                            "address1": data.get("address", ""),
                            "city": data.get("city", ""),
                            "province": data.get("province", ""),
                            "zip": data.get("zip", ""),
                            "country": "Morocco",
                            "country_code": "MA",
                            "phone": normalize_phone(data.get("phone", "")),
                            "name": data.get("name", ""),
                        }
                    ],
                }
            }
            CUSTOMERS_ENDPOINT = f"{base}/customers.json"
            async with httpx.AsyncClient() as client:
                c_resp = await client.post(CUSTOMERS_ENDPOINT, json=customer_payload, timeout=20, **extra_args)
                if c_resp.status_code in (201, 200):
                    c_json = c_resp.json() or {}
                    created = (c_json.get("customer") or {})
                    if created.get("id"):
                        customer_id = created["id"]
                elif c_resp.status_code == 403:
                    warnings.append("Shopify token lacks write_customers scope; could not create/link customer.")
                elif c_resp.status_code >= 400:
                    try:
                        err_txt = (c_resp.text or "").strip()
                    except Exception:
                        err_txt = ""
                    if err_txt:
                        warnings.append(f"Customer creation failed: {err_txt[:200]}")
        except Exception as e:
            logger.warning("Failed to auto-create customer: %s", e)

    if customer_id:
        order_block["customer"] = {"id": customer_id}
    else:
        fn, ln = _split_name(data.get("name", ""))
        order_block["customer"] = {
            "first_name": fn,
            "last_name": ln,
            "email": data.get("email", ""),
            "phone": normalize_phone(data.get("phone", ""))
        }

    fn_sa, ln_sa = _split_name(data.get("name", ""))
    shipping_address = {
        "first_name": fn_sa or "",
        "last_name": ln_sa or "",
        "address1": data.get("address", ""),
        "city": data.get("city", ""),
        "province": data.get("province", ""),
        "zip": data.get("zip", ""),
        "country": "Morocco",
        "country_code": "MA",
        "name": data.get("name", ""),
        "phone": normalize_phone(data.get("phone", "")),
    }

    # If we couldn't attach a customer, also persist customer fields in draft note for visibility
    if not customer_id:
        if data.get("name"):
            note_attributes.append({"name": "customer_name", "value": str(data.get("name"))})
        if data.get("phone"):
            note_attributes.append({"name": "customer_phone", "value": normalize_phone(data.get("phone", ""))})
        if data.get("email"):
            note_attributes.append({"name": "customer_email", "value": str(data.get("email"))})
    # Helper to ensure 2-decimal string for amounts
    def _money2(value: float | int | str) -> str:
        try:
            return f"{float(value):.2f}"
        except Exception:
            return "0.00"

    draft_order_payload = {
        "draft_order": {
            "line_items": [
                {
                    "variant_id": item["variant_id"],
                    "quantity": int(item["quantity"]),
                    **(
                        {
                            "applied_discount": {
                                # Shopify accepts amount (fixed) or percentage. Use fixed amount rounded to 2dp.
                                "value": _money2(item.get("discount", 0)),
                                "value_type": "fixed_amount",
                                "amount": _money2(item.get("discount", 0)),
                                "title": "Item discount",
                            }
                        } if float(item.get("discount", 0)) > 0 else {}
                    )
                }
                for item in data.get("items", [])
            ],
            "shipping_address": shipping_address,
            "billing_address": shipping_address,
            "shipping_lines": shipping_lines,
            "email": data.get("email", ""),
            "phone": normalize_phone(data.get("phone", "")),
            **({"note": order_note} if order_note else {}),
            **({"note_attributes": note_attributes} if note_attributes else {}),
            **order_block
        }
    }
    DRAFT_ORDERS_ENDPOINT = f"{base}/draft_orders.json"
    def _shopify_err_detail(resp: httpx.Response) -> str:
        # Shopify commonly returns: {"errors": "..."} (string or dict) or {error, errors, message}.
        req_id = ""
        try:
            req_id = str(resp.headers.get("x-request-id") or resp.headers.get("X-Request-Id") or "").strip()
        except Exception:
            req_id = ""
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                if payload.get("errors") is not None:
                    try:
                        err_obj = payload.get("errors")
                        if isinstance(err_obj, (dict, list)):
                            msg = json.dumps(err_obj, ensure_ascii=False)
                        else:
                            msg = str(err_obj)
                    except Exception:
                        msg = f"{payload.get('errors')}"
                    return f"(shopify_request_id={req_id}) {msg}".strip() if req_id else msg
                if payload.get("error") is not None:
                    msg = f"{payload.get('error')}"
                    return f"(shopify_request_id={req_id}) {msg}".strip() if req_id else msg
                if payload.get("message") is not None:
                    msg = f"{payload.get('message')}"
                    return f"(shopify_request_id={req_id}) {msg}".strip() if req_id else msg
                # Fallback: stringify the full response payload
                try:
                    msg = json.dumps(payload, ensure_ascii=False)
                except Exception:
                    msg = str(payload)
                return f"(shopify_request_id={req_id}) {msg}".strip() if req_id else msg
        except Exception:
            pass
        try:
            msg = (resp.text or "").strip()
            return f"(shopify_request_id={req_id}) {msg}".strip() if req_id else msg
        except Exception:
            return ""

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                DRAFT_ORDERS_ENDPOINT,
                json=draft_order_payload,
                timeout=20,
                **extra_args,
            )
            resp.raise_for_status()
            draft_data = resp.json()
            draft_id = draft_data["draft_order"]["id"]
        except httpx.HTTPStatusError as exc:
            r = exc.response
            detail = _shopify_err_detail(r) if r is not None else str(exc)
            # Preserve Shopify status codes (401/403/404/422) so the UI can show a real cause.
            raise HTTPException(
                status_code=int(getattr(r, "status_code", 502) or 502),
                detail=f"[store={store_used}] {detail}"[:2000],
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"[store={store_used}] Failed to reach Shopify: {str(exc)[:500]}")

        # Draft admin URL
        domain = base.replace("https://", "").replace("http://", "").split("/admin/api", 1)[0]
        draft_admin_url = f"https://{domain}/admin/draft_orders/{draft_id}"

        # If not asked to complete now, return draft info
        if not bool(data.get("complete_now")):
            return {
                "ok": True,
                "draft_order_id": draft_id,
                "shopify_admin_link": draft_admin_url,
                "completed": False,
                "store": store_used,
                "message": (
                    "Draft order created. Open the link in Shopify admin, and click 'Create order' with 'Payment due later' when customer pays."
                ),
                **({"warnings": warnings} if warnings else {})
            }

        # Complete the draft order (payment pending)
        COMPLETE_ENDPOINT = f"{base}/draft_orders/{draft_id}/complete.json"
        try:
            comp_resp = await client.post(
                COMPLETE_ENDPOINT,
                params={"payment_pending": "true"},
                timeout=20,
                **extra_args,
            )
            comp_resp.raise_for_status()
            comp_json = comp_resp.json() or {}
        except httpx.HTTPStatusError as exc:
            r = exc.response
            detail = _shopify_err_detail(r) if r is not None else str(exc)
            raise HTTPException(
                status_code=int(getattr(r, "status_code", 502) or 502),
                detail=f"[store={store_used}] {detail}"[:2000],
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"[store={store_used}] Failed to reach Shopify: {str(exc)[:500]}")
        order_id = (
            (comp_json.get("draft_order") or {}).get("order_id")
            or (comp_json.get("order") or {}).get("id")
        )

        order_admin_link = None
        if order_id:
            order_admin_link = f"https://{domain}/admin/orders/{order_id}"

            # Write metafields if provided
            metafields_endpoint = f"{base}/orders/{order_id}/metafields.json"
            metafields_payloads = []
            if order_image_url:
                metafields_payloads.append({
                    "metafield": {
                        "namespace": "custom",
                        "key": "image_url",
                        "type": "url",
                        "value": order_image_url,
                    }
                })
            if order_note:
                metafields_payloads.append({
                    "metafield": {
                        "namespace": "custom",
                        "key": "note_text",
                        "type": "single_line_text_field",
                        "value": order_note,
                    }
                })
            for payload in metafields_payloads:
                try:
                    mf_resp = await client.post(metafields_endpoint, json=payload, timeout=15, **extra_args)
                    # Do not raise if forbidden; continue best-effort
                    if mf_resp.status_code >= 400:
                        logger.warning("Metafield write failed: %s", mf_resp.text)
                except Exception as e:
                    logger.warning("Metafield write exception: %s", e)

        return {
            "ok": True,
            "completed": True,
            "draft_order_id": draft_id,
            **({"order_id": order_id} if order_id else {}),
            "shopify_admin_link": draft_admin_url,
            **({"order_admin_link": order_admin_link} if order_admin_link else {}),
            "store": store_used,
            "message": "Draft order completed with payment pending." if order_id else "Draft order created, but completion response did not include order id.",
            **({"warnings": warnings} if warnings else {})
        }
