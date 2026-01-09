import asyncio
import json
import uuid
import hashlib
import hmac
import base64
import secrets
import logging
from datetime import datetime, timezone, timedelta
import struct
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict
import time
import os
import re
import aiosqlite
import aiofiles
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from contextvars import ContextVar
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Request, Response, UploadFile, File, Form, HTTPException, Body, Depends
from starlette.requests import Request as _LimiterRequest
from starlette.responses import Response as _LimiterResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import httpx
import redis.asyncio as redis
from fastapi.responses import PlainTextResponse
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
import subprocess
import asyncpg
import mimetypes
from jose import jwt, JWTError
from passlib.context import CryptContext
from .google_cloud_storage import upload_file_to_gcs, download_file_from_gcs, maybe_signed_url_for, _parse_gcs_url, _get_client
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from .observability.context import (
    get_request_id as _get_request_id,
    set_request_id as _set_request_id,
    reset_request_id as _reset_request_id,
    get_agent_username as _get_agent_username,
    set_agent_username as _set_agent_username,
    reset_agent_username as _reset_agent_username,
)
from .observability.logging import configure_logging as _configure_logging
from .webhook import WebhookRuntime, WebhookState, create_webhook_router, start_webhook_workers

from fastapi.staticfiles import StaticFiles
from base64 import b64encode
try:
    import orjson  # type: ignore
    from fastapi.responses import ORJSONResponse  # type: ignore
    _ORJSON_AVAILABLE = True
except Exception:
    _ORJSON_AVAILABLE = False
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from fastapi.responses import StreamingResponse
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse
from PIL import Image, ImageOps  # type: ignore
import io

# Absolute paths
ROOT_DIR = Path(__file__).resolve().parent.parent
MEDIA_DIR = ROOT_DIR / "media"
MEDIA_DIR.mkdir(exist_ok=True)

# (static mount will be added later, after route declarations)

# Load environment variables early so defaults below can be overridden by a local `.env`.
# In managed platforms (Cloud Run/Render), environment variables are injected directly and this is a no-op.
load_dotenv()

# ── Cloud‑Run helpers ────────────────────────────────────────────
PORT = int(os.getenv("PORT", "8080"))
BASE_URL = os.getenv("BASE_URL", f"http://localhost:{PORT}")
REDIS_URL = os.getenv("REDIS_URL", "")
DB_PATH = os.getenv("DB_PATH") or str(ROOT_DIR / "data" / "whatsapp_messages.db")
DATABASE_URL = os.getenv("DATABASE_URL")  # optional PostgreSQL URL
DATABASE_URL_NOVA = os.getenv("DATABASE_URL_NOVA") or os.getenv("DATABASE_URL_IRRANOVA") or ""
PG_POOL_MIN = int(os.getenv("PG_POOL_MIN", "1"))
# Cloud Run can run with high request concurrency; a pool of 4 can easily bottleneck and cause
# cascading timeouts (503/504). Keep this modest by default; override via env for your DB tier.
PG_POOL_MAX = int(os.getenv("PG_POOL_MAX", "10"))
REQUIRE_POSTGRES = int(os.getenv("REQUIRE_POSTGRES", "1"))  # when 1 and DATABASE_URL is set, never fallback to SQLite
# SQLite lock/backoff tuning (ms). Keep small so endpoints don't hang for a long time under contention.
SQLITE_BUSY_TIMEOUT_MS = int(os.getenv("SQLITE_BUSY_TIMEOUT_MS", "3000"))
# Query timeouts to avoid Cloud Run 504s under load (seconds)
CONVERSATIONS_DB_TIMEOUT_SECONDS = float(os.getenv("CONVERSATIONS_DB_TIMEOUT_SECONDS", "10"))
MESSAGES_DB_TIMEOUT_SECONDS = float(os.getenv("MESSAGES_DB_TIMEOUT_SECONDS", "12"))
NOTES_DB_TIMEOUT_SECONDS = float(os.getenv("NOTES_DB_TIMEOUT_SECONDS", "8"))
MARK_READ_DB_TIMEOUT_SECONDS = float(os.getenv("MARK_READ_DB_TIMEOUT_SECONDS", "6"))
WEBHOOK_ENQUEUE_TIMEOUT_SECONDS = float(os.getenv("WEBHOOK_ENQUEUE_TIMEOUT_SECONDS", "1.5"))
TRACK_DB_TIMEOUT_SECONDS = float(os.getenv("TRACK_DB_TIMEOUT_SECONDS", "1.0"))
# WhatsApp Cloud API timeouts (seconds) - prevents mark-read from hanging and producing 504s.
WHATSAPP_HTTP_TIMEOUT_SECONDS = float(os.getenv("WHATSAPP_HTTP_TIMEOUT_SECONDS", "12"))
WHATSAPP_HTTP_CONNECT_TIMEOUT_SECONDS = float(os.getenv("WHATSAPP_HTTP_CONNECT_TIMEOUT_SECONDS", "5"))
# Auth DB operation timeout (seconds). Prevents Cloud Run from returning an upstream 504 on slow DB calls.
# NOTE: 8s was too tight for cold pool creation / transient DB slowness and caused intermittent /auth/login 503s.
AUTH_DB_TIMEOUT_SECONDS = float(os.getenv("AUTH_DB_TIMEOUT_SECONDS", "15"))
# Health DB check timeout (seconds)
HEALTH_DB_TIMEOUT_SECONDS = float(os.getenv("HEALTH_DB_TIMEOUT_SECONDS", "2"))
# Postgres connection/pool behavior.
# Important: pool creation must be faster than AUTH_DB_TIMEOUT_SECONDS, otherwise auth endpoints will 503 on cold start.
PG_CONNECT_TIMEOUT_SECONDS = float(
    os.getenv("PG_CONNECT_TIMEOUT_SECONDS", str(min(10.0, max(2.0, AUTH_DB_TIMEOUT_SECONDS - 0.5))))
)
PG_POOL_RETRY_BACKOFF_SECONDS = float(os.getenv("PG_POOL_RETRY_BACKOFF_SECONDS", "15"))
# Startup gating:
# If enabled, a DB init failure will fail the process startup (Cloud Run won't route traffic to a broken revision).
# NOTE: This can also cause deployment failures if the DB is temporarily unreachable during rollout.
_BLOCK_STARTUP_ON_DB_FAILURE_ENV = (os.getenv("BLOCK_STARTUP_ON_DB_FAILURE", "") or "").strip()
BLOCK_STARTUP_ON_DB_FAILURE = (
    (_BLOCK_STARTUP_ON_DB_FAILURE_ENV == "1")
    if _BLOCK_STARTUP_ON_DB_FAILURE_ENV
    else False
)
# Webhook ingress queue to ensure we ACK Meta quickly and process in background.
WEBHOOK_QUEUE_MAXSIZE = int(os.getenv("WEBHOOK_QUEUE_MAXSIZE", "1000"))
WEBHOOK_WORKERS = int(os.getenv("WEBHOOK_WORKERS", "2"))
# Safety timeout for processing a single webhook event (seconds). If exceeded, we log and drop that event.
WEBHOOK_PROCESSING_TIMEOUT_SECONDS = float(os.getenv("WEBHOOK_PROCESSING_TIMEOUT_SECONDS", "300"))
# Durable webhook queue (recommended): Redis Streams.
# When enabled and Redis is connected, /webhook will XADD events and ACK immediately.
WEBHOOK_USE_REDIS_STREAM = os.getenv("WEBHOOK_USE_REDIS_STREAM", "1") == "1"
WEBHOOK_STREAM_KEY = os.getenv("WEBHOOK_STREAM_KEY", "wa:webhooks")
WEBHOOK_STREAM_GROUP = os.getenv("WEBHOOK_STREAM_GROUP", "webhook-workers")
WEBHOOK_STREAM_DLQ_KEY = os.getenv("WEBHOOK_STREAM_DLQ_KEY", "wa:webhooks:dlq")
WEBHOOK_MAX_ATTEMPTS = int(os.getenv("WEBHOOK_MAX_ATTEMPTS", "20"))
WEBHOOK_CLAIM_MIN_IDLE_MS = int(os.getenv("WEBHOOK_CLAIM_MIN_IDLE_MS", "60000"))  # 60s

# Durable webhook queue (no Redis): Postgres-backed queue table.
# When enabled and DATABASE_URL is set, /webhook will INSERT payload into webhook_events and ACK immediately.
WEBHOOK_USE_DB_QUEUE = os.getenv("WEBHOOK_USE_DB_QUEUE", "1") == "1"
WEBHOOK_DB_BATCH_SIZE = int(os.getenv("WEBHOOK_DB_BATCH_SIZE", "25"))
WEBHOOK_DB_POLL_INTERVAL_SEC = float(os.getenv("WEBHOOK_DB_POLL_INTERVAL_SEC", "1.0"))
# Runtime readiness flag for the Postgres webhook queue table.
# We only start DB workers / enqueue into DB when this is True.
WEBHOOK_DB_READY: bool = False
# Anything that **must not** be baked in the image (tokens, IDs …) is
# already picked up with os.getenv() further below. Keep it that way.

# Configure logging level (handlers/format wired up after workspace helpers exist).
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Configuration is sourced from environment variables below. Removed duplicate static Config.
CATALOG_CACHE_FILE = "catalog_cache.json"
UPLOADS_DIR = "uploads"
WHATSAPP_API_VERSION = "v19.0"
MAX_CATALOG_ITEMS = 30
RATE_LIMIT_DELAY = 0
CATALOG_CACHE_TTL_SEC = 15 * 60

def _safe_cache_token(value: str) -> str:
    """Safe, short token for filenames/keys (avoid path traversal / weird chars)."""
    try:
        s = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value or "").strip())
        s = s.strip("_")
        return (s[:64] or "default")
    except Exception:
        return "default"

def _catalog_cache_file_for(workspace: str, catalog_id: str | None = None) -> str:
    """Return a per-workspace (and per-catalog) cache filename."""
    ws = _safe_cache_token(workspace)
    cid = _safe_cache_token(catalog_id or "")
    # Keep the legacy name for default workspace with no catalog_id override
    if ws == _safe_cache_token(DEFAULT_WORKSPACE) and not cid:
        return CATALOG_CACHE_FILE
    return f"catalog_cache_{ws}{'_' + cid if cid else ''}.json"

def _ws_setting_key(base_key: str, workspace: str | None = None) -> str:
    """Namespace a settings key by workspace so a shared DB can still isolate settings."""
    ws = _coerce_workspace(workspace or get_current_workspace())
    return f"{str(base_key or '').strip()}::{ws}"

async def _get_effective_catalog_id(workspace: str | None = None) -> str:
    """Resolve catalog_id for a workspace (DB override -> env per-workspace -> global env)."""
    ws = _coerce_workspace(workspace or get_current_workspace())
    try:
        cfg = await message_processor._get_inbox_env(ws)  # uses short TTL cache
        cid = str((cfg or {}).get("catalog_id") or "").strip()
        if cid:
            return cid
    except Exception:
        pass
    try:
        suf = re.sub(r"[^A-Z0-9]+", "_", str(ws or "").strip().upper())
        cid2 = str(os.getenv(f"CATALOG_ID_{suf}", "") or "").strip()
        return cid2 or str(CATALOG_ID or "").strip()
    except Exception:
        return str(CATALOG_ID or "").strip()

async def _sync_whatsapp_runtime_for_workspace(workspace: str) -> None:
    """Load DB-configured WhatsApp creds for a workspace into runtime router + phone map (best-effort)."""
    ws = _coerce_workspace(workspace)
    if not ws:
        return
    try:
        cfg = await message_processor._get_inbox_env(ws)
    except Exception:
        cfg = {}
    phone_id = str((cfg or {}).get("phone_number_id") or "").strip()
    token = str((cfg or {}).get("access_token") or "").strip()
    # Remove stale phone_id → workspace mappings for this workspace.
    # Otherwise, changing a workspace phone_number_id can leave the old phone_id routed to this workspace,
    # causing webhook mis-routing and intermittent "phone_number_id mismatch" skips.
    try:
        for pid, w in list((RUNTIME_PHONE_ID_TO_WORKSPACE or {}).items()):
            if str(w or "").strip().lower() == ws and str(pid or "").strip() != str(phone_id or "").strip():
                try:
                    del RUNTIME_PHONE_ID_TO_WORKSPACE[pid]
                except Exception:
                    pass
    except Exception:
        pass
    # Only update if meaningful; keep env fallback otherwise.
    try:
        if phone_id and not _is_placeholder_phone(phone_id):
            RUNTIME_PHONE_ID_TO_WORKSPACE[phone_id] = ws
    except Exception:
        pass
    try:
        prev = RUNTIME_WHATSAPP_CONFIG_BY_WORKSPACE.get(ws) or {}
        new_token = token if (token and not _is_placeholder_token(token)) else str(prev.get("access_token") or "")
        new_phone = phone_id if (phone_id and not _is_placeholder_phone(phone_id)) else str(prev.get("phone_number_id") or "")
        RUNTIME_WHATSAPP_CONFIG_BY_WORKSPACE[ws] = {"access_token": new_token, "phone_number_id": new_phone}
    except Exception:
        pass
    # Update active router client immediately
    try:
        if hasattr(message_processor, "whatsapp_messenger") and hasattr(message_processor.whatsapp_messenger, "update_workspace_config"):
            message_processor.whatsapp_messenger.update_workspace_config(ws, access_token=token or None, phone_number_id=phone_id or None)  # type: ignore[attr-defined]
    except Exception:
        pass

# Backwards-compatibility shim for tests and existing imports expecting `main.config`
try:
    from types import SimpleNamespace
    config = SimpleNamespace(
        WHATSAPP_API_VERSION=WHATSAPP_API_VERSION,
        MAX_CATALOG_ITEMS=MAX_CATALOG_ITEMS,
        CATALOG_ID=None,  # set below after env load
        CATALOG_CACHE_FILE=CATALOG_CACHE_FILE,
        RATE_LIMIT_DELAY=RATE_LIMIT_DELAY,
        UPLOADS_DIR=UPLOADS_DIR,
    )
except Exception:
    config = None  # type: ignore
# Verbose logging flag (minimize noisy logs when off)
LOG_VERBOSE = os.getenv("LOG_VERBOSE", "0") == "1"
DISABLE_AUTH = os.getenv("DISABLE_AUTH", "0") == "1"

# Backpressure and rate limiting configuration
WA_MAX_CONCURRENCY = int(os.getenv("WA_MAX_CONCURRENCY", "4"))
SEND_TEXT_PER_MIN = int(os.getenv("SEND_TEXT_PER_MIN", "30"))
SEND_MEDIA_PER_MIN = int(os.getenv("SEND_MEDIA_PER_MIN", "5"))
BURST_WINDOW_SEC = int(os.getenv("BURST_WINDOW_SEC", "10"))
ENABLE_WS_PUBSUB = os.getenv("ENABLE_WS_PUBSUB", "1") == "1"
TRACK_CLICKS_PER_MIN = int(os.getenv("TRACK_CLICKS_PER_MIN", "240"))
# NOTE: TRACK_IP_SALT is finalized after AGENT_AUTH_SECRET is loaded (defined later).
TRACK_IP_SALT = (os.getenv("TRACK_IP_SALT", "") or "").strip()
TRACK_ALLOWED_ORIGINS_ENV = (os.getenv("TRACK_ALLOWED_ORIGINS", "") or "").strip()
TRACK_ALLOWED_ORIGINS = [o.strip().lower() for o in TRACK_ALLOWED_ORIGINS_ENV.split(",") if o.strip()]

# Safety: don't leak internal filesystem paths in /health unless explicitly enabled.
HEALTH_EXPOSE_INTERNALS = (os.getenv("HEALTH_EXPOSE_INTERNALS", "0") or "0").strip() == "1"

def _safe_db_url_summary(url: str | None) -> dict:
    """Return non-sensitive DB routing info (no passwords)."""
    try:
        if not url:
            return {"configured": False}
        p = urlparse(str(url))
        return {
            "configured": True,
            "scheme": (p.scheme or "").lower(),
            "host": p.hostname or None,
            "port": p.port or None,
            "dbname": (p.path or "").lstrip("/") or None,
            "user": p.username or None,
        }
    except Exception:
        return {"configured": bool(url), "unparseable": True}

# ── Multi-workspace (two WhatsApp numbers) ────────────────────────
# Goal: keep customers/messages/orders/analytics isolated per workspace (store),
# while allowing the same agents/auth across workspaces.
ENABLE_MULTI_WORKSPACE = (os.getenv("ENABLE_MULTI_WORKSPACE", "0") or "0").strip() == "1"
DEFAULT_WORKSPACE = (os.getenv("DEFAULT_WORKSPACE", "irranova") or "irranova").strip().lower()
WORKSPACES = [w.strip().lower() for w in (os.getenv("WORKSPACES", "irranova,irrakids") or "").split(",") if w.strip()]
if DEFAULT_WORKSPACE not in WORKSPACES:
    WORKSPACES = [DEFAULT_WORKSPACE] + [w for w in WORKSPACES if w != DEFAULT_WORKSPACE]

_CURRENT_WORKSPACE: ContextVar[str] = ContextVar("current_workspace", default=DEFAULT_WORKSPACE)

# Extra workspaces added at runtime (admin settings). These are stored in the shared auth/settings DB
# and loaded on startup (best-effort). They allow adding workspaces without redeploying.
DYNAMIC_WORKSPACES: set[str] = set()
_AUTOMATION_RULES_V2_INIT_DONE: bool = False
_AUTOMATION_RULES_V2_INIT_LOCK: asyncio.Lock = asyncio.Lock()

def _all_workspaces_set() -> set[str]:
    try:
        base = set((WORKSPACES or []) + [DEFAULT_WORKSPACE])
    except Exception:
        base = {DEFAULT_WORKSPACE}
    try:
        base |= set(DYNAMIC_WORKSPACES or set())
    except Exception:
        pass
    # never return empty
    return base or {DEFAULT_WORKSPACE}

def _normalize_workspace_id(raw: str) -> str:
    try:
        s = str(raw or "").strip().lower()
        s = re.sub(r"[^a-z0-9_-]+", "", s)
        return s
    except Exception:
        return ""

def get_current_workspace() -> str:
    try:
        w = str(_CURRENT_WORKSPACE.get() or DEFAULT_WORKSPACE).strip().lower()
        return w if w in _all_workspaces_set() else DEFAULT_WORKSPACE
    except Exception:
        return DEFAULT_WORKSPACE


# Configure logging once the workspace helper exists (inject request/workspace/agent into log records).
try:
    _configure_logging(
        level=LOG_LEVEL,
        workspace_getter=get_current_workspace,
        request_id_getter=_get_request_id,
        agent_getter=_get_agent_username,
    )
except Exception:
    # Fallback to minimal logging if something goes wrong during import.
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

def _coerce_workspace(value: str | None) -> str:
    v = str(value or "").strip().lower()
    return v if v in _all_workspaces_set() else DEFAULT_WORKSPACE

def _workspace_from_request(request: Request) -> str:
    # Header preferred, query param fallback
    try:
        hdr = (request.headers.get("x-workspace") or request.headers.get("X-Workspace") or "").strip()
    except Exception:
        hdr = ""
    if hdr:
        return _coerce_workspace(hdr)
    try:
        qp = (request.query_params.get("workspace") or "").strip()  # type: ignore[attr-defined]
    except Exception:
        qp = ""
    return _coerce_workspace(qp)

def _derive_tenant_db_path(base_path: str, workspace: str) -> str:
    """Derive per-workspace SQLite DB paths from a base DB_PATH when not explicitly configured."""
    try:
        p = Path(str(base_path))
        if p.suffix.lower() == ".db":
            return str(p.with_name(f"{p.stem}_{workspace}{p.suffix}"))
    except Exception:
        pass
    # fallback to standard location
    return str(ROOT_DIR / "data" / f"whatsapp_messages_{workspace}.db")

TENANT_DB_PATHS: Dict[str, str] = {}
try:
    TENANT_DB_PATHS = {
        "irranova": os.getenv("DB_PATH_IRRANOVA") or _derive_tenant_db_path(DB_PATH, "irranova"),
        "irrakids": os.getenv("DB_PATH_IRRAKIDS") or _derive_tenant_db_path(DB_PATH, "irrakids"),
    }
    # allow custom WORKSPACES without explicit vars (derive from DB_PATH)
    for w in WORKSPACES:
        if w not in TENANT_DB_PATHS:
            TENANT_DB_PATHS[w] = os.getenv(f"DB_PATH_{w.upper()}") or _derive_tenant_db_path(DB_PATH, w)
except Exception:
    TENANT_DB_PATHS = {}

# Auth/settings DB (shared across workspaces). Defaults to the legacy DB_PATH unless multi-workspace is enabled.
AUTH_DB_PATH = os.getenv("AUTH_DB_PATH") or (str(ROOT_DIR / "data" / "whatsapp_auth.db") if ENABLE_MULTI_WORKSPACE else DB_PATH)

# Tenant DB URLs (Postgres/Supabase): default DATABASE_URL is irrakids, DATABASE_URL_NOVA is irranova.
# This matches the requested env setup: keep existing DATABASE_URL as-is, only add DATABASE_URL_NOVA.
TENANT_DB_URLS: Dict[str, str] = {}
try:
    TENANT_DB_URLS = {
        "irrakids": (DATABASE_URL or "").strip(),
        "irranova": (DATABASE_URL_NOVA or "").strip() or (DATABASE_URL or "").strip(),
    }
    for w in WORKSPACES:
        if w in TENANT_DB_URLS and TENANT_DB_URLS[w]:
            continue
        # Generic override: DATABASE_URL_<WORKSPACE>
        TENANT_DB_URLS[w] = (os.getenv(f"DATABASE_URL_{w.upper()}", "") or "").strip() or (DATABASE_URL or "").strip()
except Exception:
    TENANT_DB_URLS = {}

# Global semaphore to cap concurrent WhatsApp Graph API calls per instance
wa_semaphore = asyncio.Semaphore(WA_MAX_CONCURRENCY)

def _vlog(*args, **kwargs):
    if LOG_VERBOSE:
        print(*args, **kwargs)

# Suppress noisy prints in production while preserving error-like messages
try:
    import builtins as _builtins  # type: ignore
    _original_print = _builtins.print

    def _smart_print(*args, **kwargs):
        text = " ".join(str(a) for a in args)
        lower = text.lower()
        if ("error" in lower) or ("failed" in lower) or ("\u274c" in text) or ("\u2757" in text):
            logging.error(text)
        elif LOG_VERBOSE:
            logging.info(text)
        # else: drop message to keep logs quiet

    if not LOG_VERBOSE:
        _builtins.print = _smart_print  # type: ignore
except Exception:
    # If anything goes wrong, keep default print behavior
    pass

# ── Authentication helpers (modern) ────────────────────────────────
#
# Password hashing:
# - New passwords use Argon2 (passlib).
# - Existing deployments may still have legacy `salt$hexhash` PBKDF2 hashes; we verify those too.
#
# Tokens:
# - Access tokens are JWT (HS256) with short TTL.
# - Refresh tokens are random secrets stored hashed in DB and sent as HttpOnly cookies.
#
AGENT_AUTH_SECRET = os.getenv("AGENT_AUTH_SECRET", "") or os.getenv("SECRET_KEY", "")
if not TRACK_IP_SALT:
    # Best-effort: re-use auth secret as salt (keeps deterministic hashing across instances),
    # otherwise fall back to a dev-only salt.
    TRACK_IP_SALT = (AGENT_AUTH_SECRET or "dev-unsafe-salt").strip()

# Default to 24h to avoid frequent logouts in production.
# We also enforce a minimum of 24h to prevent accidental short TTLs in Cloud Run env.
# - 86400  = 24 hours
# - 172800 = 48 hours
ACCESS_TOKEN_TTL_SECONDS = max(
    int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", str(24 * 3600))),
    24 * 3600,
)
REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", str(30 * 24 * 3600)))  # 30 days
# Auto-logout / online presence (activity-based)
INACTIVITY_TIMEOUT_SECONDS = int(os.getenv("INACTIVITY_TIMEOUT_SECONDS", str(30 * 60)))  # 30 minutes
# Keep last_seen cached long enough that we can still enforce inactivity even after long idle periods.
AGENT_ACTIVITY_CACHE_TTL_SECONDS = int(os.getenv("AGENT_ACTIVITY_CACHE_TTL_SECONDS", str(7 * 24 * 3600)))  # 7 days
AUTH_COOKIE_DOMAIN = (os.getenv("AUTH_COOKIE_DOMAIN", "") or "").strip() or None
AUTH_COOKIE_SECURE = os.getenv("AUTH_COOKIE_SECURE", "").strip()  # "", "0", "1" (auto if empty)
AUTH_COOKIE_SAMESITE = (os.getenv("AUTH_COOKIE_SAMESITE", "") or "").strip().lower() or "none"  # none|lax|strict
ACCESS_COOKIE_NAME = "agent_access"
REFRESH_COOKIE_NAME = "agent_refresh"
JWT_ISSUER = os.getenv("JWT_ISSUER", "whatsapp-inbox")
EXPOSE_REFRESH_TOKEN_FALLBACK = os.getenv("EXPOSE_REFRESH_TOKEN_FALLBACK", "1") == "1"
REFRESH_ROTATE_ON_REFRESH = os.getenv("REFRESH_ROTATE_ON_REFRESH", "0") == "1"
# Agent auth cache (in-memory). Helps avoid intermittent DB timeouts on /auth/login.
# Keep TTL short to limit exposure if an admin changes a password.
AGENT_AUTH_CACHE_TTL_SECONDS = int(os.getenv("AGENT_AUTH_CACHE_TTL_SECONDS", "60"))
# Agent auth cache in Redis (shared across instances). This is the robust path for Cloud Run:
# even if Postgres is slow/unreachable during cold starts, agents can still login.
AGENT_AUTH_REDIS_TTL_SECONDS = int(os.getenv("AGENT_AUTH_REDIS_TTL_SECONDS", str(7 * 24 * 3600)))  # 7 days
# For login, use a shorter DB timeout and fall back to Redis cache. Prevents 15s hangs.
AUTH_LOGIN_DB_TIMEOUT_SECONDS = float(os.getenv("AUTH_LOGIN_DB_TIMEOUT_SECONDS", "6"))

pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    default="argon2",
    deprecated="auto",
)

def _legacy_pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        if not salt or not h:
            return False
        # legacy format: "<hexsalt>$<hexhash>"
        if not re.fullmatch(r"[0-9a-fA-F]{16,}", salt):
            return False
        if not re.fullmatch(r"[0-9a-fA-F]{32,}", h):
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000)
        return h.lower() == dk.hex().lower()
    except Exception:
        return False

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, stored: str) -> bool:
    try:
        if not stored:
            return False
        # passlib formats (argon2/bcrypt)
        if stored.startswith("$"):
            return pwd_context.verify(password, stored)
        # legacy pbkdf2
        return _legacy_pbkdf2_verify(password, stored)
    except Exception:
        return False

def _jwt_secret() -> str:
    # Keep a hard requirement in production, but don't crash tests/dev when DISABLE_AUTH is on.
    if not AGENT_AUTH_SECRET and not DISABLE_AUTH:
        # Still allow the app to boot, but login won't work safely without a secret.
        logging.getLogger(__name__).warning("AGENT_AUTH_SECRET is empty; set it for secure authentication.")
    return AGENT_AUTH_SECRET or "dev-unsafe-secret"

def issue_access_token(username: str, is_admin: bool) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "is_admin": bool(is_admin),
        "iss": JWT_ISSUER,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS)).timestamp()),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")

def parse_access_token(token: str) -> Optional[dict]:
    try:
        if not token:
            return None
        payload = jwt.decode(
            token,
            _jwt_secret(),
            algorithms=["HS256"],
            options={"require_sub": True, "require_exp": True},
            issuer=JWT_ISSUER,
        )
        username = str(payload.get("sub") or "").strip()
        if not username:
            return None
        return {"username": username, "is_admin": bool(payload.get("is_admin"))}
    except JWTError:
        return None
    except Exception:
        return None

def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _cookie_secure_flag(request: Request) -> bool:
    # If AUTH_COOKIE_SECURE is set explicitly, honor it.
    if AUTH_COOKIE_SECURE in ("0", "false", "False"):
        return False
    if AUTH_COOKIE_SECURE in ("1", "true", "True"):
        return True
    try:
        return (request.url.scheme or "").lower() == "https"
    except Exception:
        return False

def _cookie_domain_for_request(request: Request) -> str | None:
    """Return AUTH_COOKIE_DOMAIN only if it matches the current host (prevents invalid Domain attrs)."""
    if not AUTH_COOKIE_DOMAIN:
        return None
    try:
        host = (request.url.hostname or "").lower()
        dom = str(AUTH_COOKIE_DOMAIN).lstrip(".").lower()
        if host == dom or host.endswith("." + dom):
            return AUTH_COOKIE_DOMAIN
    except Exception:
        return None
    return None

def _extract_access_token_from_request(request: Request) -> Optional[str]:
    try:
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
        if auth_header:
            parts = auth_header.split()
            if len(parts) >= 2 and parts[0].lower() == "bearer":
                return parts[1].strip()
    except Exception:
        pass
    try:
        token = request.cookies.get(ACCESS_COOKIE_NAME)
        if token:
            return token
    except Exception:
        pass
    return None

async def get_current_agent(request: Request) -> dict:
    """Return the authenticated agent (username/is_admin) or raise 401."""
    if DISABLE_AUTH:
        return {"username": "admin", "is_admin": True}
    # IMPORTANT: Browsers may carry both an HttpOnly cookie token and a fallback Authorization header token.
    # If the header token is stale/expired but the cookie is fresh (after /auth/refresh), preferring the header
    # causes intermittent 401s (e.g., analytics calls showing "Unauthorized"). So: try header first, then cookie.
    header_token: Optional[str] = None
    cookie_token: Optional[str] = None
    try:
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
        if auth_header:
            parts = auth_header.split()
            if len(parts) >= 2 and parts[0].lower() == "bearer":
                header_token = parts[1].strip()
    except Exception:
        header_token = None
    try:
        cookie_token = request.cookies.get(ACCESS_COOKIE_NAME)  # type: ignore[arg-type]
    except Exception:
        cookie_token = None

    parsed = parse_access_token(header_token or "")
    if not parsed or not parsed.get("username"):
        parsed = parse_access_token(cookie_token or "")
    if not parsed or not parsed.get("username"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"username": parsed["username"], "is_admin": bool(parsed.get("is_admin"))}

async def require_admin(agent: dict = Depends(get_current_agent)) -> dict:
    if not agent.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin required")
    return agent

def _is_public_path(path: str) -> bool:
    # Static + media
    if path.startswith("/static/") or path.startswith("/media/"):
        return True
    # PWA assets served at root by CRA build
    if path in (
        "/sw.js",
        "/manifest.json",
        "/asset-manifest.json",
        "/robots.txt",
        "/logo192.png",
        "/logo512.png",
        "/broken-image.png",
    ):
        return True
    # Frontend entry points
    if path in ("/", "/login", "/favicon.ico"):
        return True
    # Health/version
    if path in ("/health", "/version"):
        return True
    # Auth endpoints (login/refresh/logout are public; /auth/me is protected)
    if path in ("/auth/login", "/auth/refresh", "/auth/logout"):
        return True
    # Webhook endpoints must remain public for Meta
    if path.startswith("/webhook"):
        return True
    # Delivery app outbound status webhooks must be public (called server-to-server).
    if path.startswith("/delivery/webhook"):
        return True
    # Public tracking endpoints (Shopify theme / website)
    if path.startswith("/track/"):
        return True
    # Image proxy must be reachable by <img> tags (no Authorization header).
    # Endpoint itself enforces allowlist/auth to avoid becoming an open proxy.
    if path.startswith("/proxy-image"):
        return True
    return False

def _maybe_get_agent_from_request(request: Request) -> Optional[dict]:
    """Best-effort auth parse for endpoints that are public but still want gating for some hosts."""
    if DISABLE_AUTH:
        return {"username": "admin", "is_admin": True}
    try:
        token = _extract_access_token_from_request(request)
        parsed = parse_access_token(token or "")
        if parsed and parsed.get("username"):
            return {"username": parsed["username"], "is_admin": bool(parsed.get("is_admin"))}
    except Exception:
        pass
    return None
# Get environment variables
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "chafiq")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "your_access_token_here")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "your_phone_number_id")
CATALOG_ID = os.getenv("CATALOG_ID", "CATALOGID")
META_ACCESS_TOKEN = os.getenv("META_ACCESS_TOKEN", ACCESS_TOKEN)
# App credentials for webhook signature verification and token debugging
META_APP_ID = os.getenv("META_APP_ID", "") or os.getenv("FB_APP_ID", "")
META_APP_SECRET = os.getenv("META_APP_SECRET", "") or os.getenv("FB_APP_SECRET", "")

# Workspace-specific WhatsApp credentials (optional, for ENABLE_MULTI_WORKSPACE=1).
# Requirement: keep irrakids envs unchanged (WHATSAPP_ACCESS_TOKEN/WHATSAPP_PHONE_NUMBER_ID),
# and only add NOVA envs for irranova.
# Back-compat: still accept *_IRRANOVA as aliases if already used somewhere.
WHATSAPP_ACCESS_TOKEN_NOVA = (
    os.getenv("WHATSAPP_ACCESS_TOKEN_NOVA", "")
    or os.getenv("WA_ACCESS_TOKEN_NOVA", "")
    or os.getenv("WHATSAPP_ACCESS_TOKEN_IRRANOVA", "")
    or os.getenv("WA_ACCESS_TOKEN_IRRANOVA", "")
)
WHATSAPP_PHONE_NUMBER_ID_NOVA = (
    os.getenv("WHATSAPP_PHONE_NUMBER_ID_NOVA", "")
    or os.getenv("WA_PHONE_NUMBER_ID_NOVA", "")
    or os.getenv("WHATSAPP_PHONE_NUMBER_ID_IRRANOVA", "")
    or os.getenv("WA_PHONE_NUMBER_ID_IRRANOVA", "")
)

WHATSAPP_CONFIG_BY_WORKSPACE: Dict[str, dict] = {
    # Default workspace uses legacy vars unless overridden.
    "irranova": {
        "access_token": (WHATSAPP_ACCESS_TOKEN_NOVA or ACCESS_TOKEN),
        "phone_number_id": (WHATSAPP_PHONE_NUMBER_ID_NOVA or PHONE_NUMBER_ID),
    },
    "irrakids": {
        # Keep irrakids envs unchanged: default to the legacy single vars.
        "access_token": ACCESS_TOKEN,
        "phone_number_id": PHONE_NUMBER_ID,
    },
}
for w in WORKSPACES:
    if w not in WHATSAPP_CONFIG_BY_WORKSPACE:
        # Allow custom workspaces via generic env names WHATSAPP_ACCESS_TOKEN_<WS>, WHATSAPP_PHONE_NUMBER_ID_<WS>
        WHATSAPP_CONFIG_BY_WORKSPACE[w] = {
            "access_token": os.getenv(f"WHATSAPP_ACCESS_TOKEN_{w.upper()}", "") or ACCESS_TOKEN,
            "phone_number_id": os.getenv(f"WHATSAPP_PHONE_NUMBER_ID_{w.upper()}", "") or PHONE_NUMBER_ID,
        }

PHONE_ID_TO_WORKSPACE: Dict[str, str] = {}
try:
    for w, cfg in (WHATSAPP_CONFIG_BY_WORKSPACE or {}).items():
        pid = str((cfg or {}).get("phone_number_id") or "").strip()
        if pid and pid != "your_phone_number_id":
            PHONE_ID_TO_WORKSPACE[pid] = str(w).strip().lower()
except Exception:
    PHONE_ID_TO_WORKSPACE = {}

# Runtime WhatsApp routing state (can be updated from DB settings without redeploy).
# We seed with env values for backwards compatibility, but DB settings can override per workspace.
RUNTIME_WHATSAPP_CONFIG_BY_WORKSPACE: Dict[str, dict] = dict(WHATSAPP_CONFIG_BY_WORKSPACE or {})
RUNTIME_PHONE_ID_TO_WORKSPACE: Dict[str, str] = dict(PHONE_ID_TO_WORKSPACE or {})
RUNTIME_WEBHOOK_VERIFY_TOKENS: set[str] = set([str(VERIFY_TOKEN or "").strip()]) if str(VERIFY_TOKEN or "").strip() else set()

def _is_placeholder_token(tok: str | None) -> bool:
    t = str(tok or "").strip()
    return (not t) or (t == "your_access_token_here")

def _is_placeholder_phone(pid: str | None) -> bool:
    p = str(pid or "").strip()
    return (not p) or (p == "your_phone_number_id")

# When set, only process webhooks for these phone number ids (comma-separated).
# Defaults to the configured phone_number_id(s) when available.
_allowed_raw = (os.getenv("ALLOWED_PHONE_NUMBER_ID", "") or "").strip()
ALLOWED_PHONE_NUMBER_IDS: Set[str] = set([x.strip() for x in _allowed_raw.split(",") if x.strip()])
if not ALLOWED_PHONE_NUMBER_IDS:
    try:
        # Default allow all configured phone ids (multi) or the legacy single one.
        for _w, cfg in (WHATSAPP_CONFIG_BY_WORKSPACE or {}).items():
            pid = str((cfg or {}).get("phone_number_id") or "").strip()
            if pid and pid != "your_phone_number_id":
                ALLOWED_PHONE_NUMBER_IDS.add(pid)
    except Exception:
        pass

# Sync CATALOG_ID into compatibility shim, if present
try:
    if config is not None:
        config.CATALOG_ID = CATALOG_ID  # type: ignore[attr-defined]
except Exception:
    pass

# Feature flags: auto-reply with catalog match
# Default ON so catalog links/IDs auto-respond for all customers
AUTO_REPLY_CATALOG_MATCH = os.getenv("AUTO_REPLY_CATALOG_MATCH", "1") == "1"
try:
    AUTO_REPLY_MIN_SCORE = float(os.getenv("AUTO_REPLY_MIN_SCORE", "0.6"))
except Exception:
    AUTO_REPLY_MIN_SCORE = 0.6

# Optional: restrict auto-replies to a whitelist of phone numbers (WhatsApp IDs)
def _digits_only(value: str) -> str:
    try:
        return "".join([ch for ch in str(value) if ch.isdigit()])
    except Exception:
        return str(value or "")

_TEST_NUMBERS_RAW = os.getenv("AUTO_REPLY_TEST_NUMBERS", "")
AUTO_REPLY_TEST_NUMBERS: Set[str] = set(
    _digits_only(n.strip()) for n in _TEST_NUMBERS_RAW.split(",") if n.strip()
)

# Survey test config (override scheduler for specific numbers)
_SURVEY_TEST_NUMBERS_RAW = os.getenv("SURVEY_TEST_NUMBERS", "")
SURVEY_TEST_NUMBERS: Set[str] = set(
    _digits_only(n.strip()) for n in _SURVEY_TEST_NUMBERS_RAW.split(",") if n.strip()
)
try:
    SURVEY_TEST_DELAY_SEC = int(os.getenv("SURVEY_TEST_DELAY_SEC", "0") or "0")
except Exception:
    SURVEY_TEST_DELAY_SEC = 0
SURVEY_TEST_IGNORE_INVOICE = os.getenv("SURVEY_TEST_IGNORE_INVOICE", "0") == "1"
SURVEY_TEST_BYPASS_COOLDOWN = os.getenv("SURVEY_TEST_BYPASS_COOLDOWN", "0") == "1"
try:
    SURVEY_TEST_COOLDOWN_SEC = int(os.getenv("SURVEY_TEST_COOLDOWN_SEC", "60") or "60")
except Exception:
    SURVEY_TEST_COOLDOWN_SEC = 60

_vlog(f"🔧 Configuration loaded:")
_vlog(f"   VERIFY_TOKEN: {VERIFY_TOKEN}")
_vlog(f"   ACCESS_TOKEN: {ACCESS_TOKEN[:20]}..." if len(ACCESS_TOKEN) > 20 else f"   ACCESS_TOKEN: {ACCESS_TOKEN}")
_vlog(f"   PHONE_NUMBER_ID: {PHONE_NUMBER_ID}")

# Feature flags / tunables
AUDIO_VOICE_ENABLED = (os.getenv("WA_AUDIO_VOICE", "1") or "1").strip() not in ("0", "false", "False")

# Build/version identifiers for frontend refresh banner
APP_BUILD_ID = os.getenv("APP_BUILD_ID") or datetime.utcnow().strftime("%Y%m%d%H%M%S")
APP_STARTED_AT = datetime.utcnow().isoformat()

def chunk_list(items: List[str], size: int):
    """Yield successive chunks from a list."""
    for i in range(0, len(items), size):
        yield items[i:i + size]

async def convert_webm_to_ogg(src_path: Path) -> Path:
    """
    Convert a WebM/unknown audio file to real OGG-Opus so WhatsApp accepts it.
    Returns the new path (same stem, .ogg extension).
    Requires ffmpeg to be installed on the server / Docker image.
    """
    # Always write to a new .ogg file to avoid in-place overwrite
    # Keep human-friendly stem when possible and add a short suffix
    safe_stem = src_path.stem or "audio"
    dst_path = src_path.with_name(f"{safe_stem}_opus48_{uuid.uuid4().hex[:6]}.ogg")
    cmd = [
        "ffmpeg", "-y",
        "-i", str(src_path),
        # Hardened Opus settings per WA Cloud guidance
        "-vn",
        "-ac", "1",
        "-ar", "48000",
        "-c:a", "libopus",
        "-b:a", "32k",
        "-vbr", "on",
        "-compression_level", "10",
        "-application", "voip",
        "-frame_duration", "20",
        str(dst_path),
    ]

    loop = asyncio.get_event_loop()
    proc = await loop.run_in_executor(None, lambda: subprocess.run(cmd, capture_output=True))
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "ignore")
        raise RuntimeError(err or "ffmpeg failed")
    return dst_path

async def compute_audio_waveform(src_path: Path, buckets: int = 56) -> list[int]:
    """Compute a simple peak-based waveform (0..100) using ffmpeg to decode to PCM.

    - Decodes to mono 16-bit PCM at 16 kHz
    - Splits into N buckets and records the peak absolute amplitude per bucket
    - Normalizes to 0..100 for UI
    """
    try:
        # Decode with ffmpeg to raw PCM (s16le), 1 channel, 16 kHz
        cmd = [
            "ffmpeg", "-hide_banner", "-nostdin", "-loglevel", "error",
            "-i", str(src_path),
            "-ac", "1", "-ar", "16000",
            "-f", "s16le",
            "pipe:1",
        ]
        loop = asyncio.get_event_loop()
        proc = await loop.run_in_executor(None, lambda: subprocess.run(cmd, capture_output=True))
        if proc.returncode != 0:
            # If decode fails, return a flat placeholder waveform
            return [30] * max(1, int(buckets))
        pcm = proc.stdout or b""
        if not pcm:
            return [30] * max(1, int(buckets))

        # Interpret bytes as signed 16-bit little-endian samples
        num_samples = len(pcm) // 2
        if num_samples <= 0:
            return [30] * max(1, int(buckets))

        # Avoid extreme memory on edge cases: cap to ~5 minutes at 16 kHz
        max_samples = 5 * 60 * 16000
        if num_samples > max_samples:
            pcm = pcm[: max_samples * 2]
            num_samples = max_samples

        # Unpack in chunks to avoid a giant tuple at once
        # We'll compute peaks per bucket on the fly
        num_buckets = max(8, min(256, int(buckets)))
        bucket_size = max(1, num_samples // num_buckets)
        peaks: list[int] = []
        max_abs = 1
        for i in range(0, num_samples, bucket_size):
            chunk = pcm[i * 2 : (i + bucket_size) * 2]
            if not chunk:
                break
            # iterate 2 bytes at a time
            local_peak = 0
            for j in range(0, len(chunk), 2):
                sample = struct.unpack_from('<h', chunk, j)[0]
                a = abs(sample)
                if a > local_peak:
                    local_peak = a
            peaks.append(local_peak)
            if local_peak > max_abs:
                max_abs = local_peak

        # Normalize to 0..100 and clamp to at least 8 and at most 46 like UI bounds
        norm = []
        for p in peaks[:num_buckets]:
            v = int(round((p / max_abs) * 100)) if max_abs > 0 else 0
            norm.append(max(0, min(100, v)))
        # Ensure fixed length by padding/truncating
        if len(norm) < num_buckets:
            norm += [0] * (num_buckets - len(norm))
        elif len(norm) > num_buckets:
            norm = norm[:num_buckets]
        return norm
    except Exception:
        return [30] * max(1, int(buckets))

async def convert_any_to_m4a(src_path: Path) -> Path:
    """Convert any input audio to M4A/AAC 44.1 kHz mono.

    Used as a last-resort fallback if Graph rejects Opus/OGG upload.
    """
    dst_path = src_path.with_suffix(".m4a")
    cmd = [
        "ffmpeg", "-y",
        "-i", str(src_path),
        "-vn",
        "-ac", "1",
        "-ar", "44100",
        "-c:a", "aac",
        "-b:a", "48k",
        str(dst_path),
    ]
    loop = asyncio.get_event_loop()
    proc = await loop.run_in_executor(None, lambda: subprocess.run(cmd, capture_output=True))
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "ignore")
        raise RuntimeError(err or "ffmpeg failed")
    return dst_path

async def probe_audio_channels(src_path: Path) -> int:
    """Return number of channels for the first audio stream, or 0 if unknown."""
    try:
        cmd = [
            "ffprobe", "-v", "error",
            "-select_streams", "a:0",
            "-show_entries", "stream=channels",
            "-of", "csv=p=0",
            str(src_path),
        ]
        loop = asyncio.get_event_loop()
        proc = await loop.run_in_executor(None, lambda: subprocess.run(cmd, capture_output=True))
        if proc.returncode == 0:
            out = (proc.stdout or b"").decode().strip()
            try:
                return int(out)
            except Exception:
                return 0
        return 0
    except Exception:
        return 0

# Enhanced WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = defaultdict(set)
        self.message_queue: Dict[str, List[dict]] = defaultdict(list)
        self.connection_metadata: Dict[WebSocket, dict] = {}
        # Optional: will be attached after initialization
        self.redis_manager = None
        # Per-agent token buckets for backpressure
        self._ws_buckets: Dict[str, Dict[str, float]] = {}
    
    def _key(self, user_id: str, workspace: str | None = None) -> str:
        ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
        return f"{ws}:{str(user_id)}"

    async def connect(self, websocket: WebSocket, user_id: str, client_info: dict = None, workspace: str | None = None):
        """Connect a new WebSocket for a user"""
        await websocket.accept()
        ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
        key = self._key(user_id, ws)
        self.active_connections[key].add(websocket)
        self.connection_metadata[websocket] = {
            "user_id": user_id,
            "workspace": ws,
            "key": key,
            "connected_at": datetime.utcnow(),
            "client_info": client_info or {}
        }
        
        # Send queued messages to newly connected user
        if key in self.message_queue:
            for message in self.message_queue[key]:
                try:
                    await websocket.send_json(message)
                except:
                    pass
            del self.message_queue[key]
        
        # Avoid print+emoji which gets promoted to ERROR by the smart_print wrapper.
        logging.getLogger(__name__).info(
            "WS connected user_id=%s connections_for_user=%s",
            key,
            len(self.active_connections.get(key) or []),
        )
    
    def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket"""
        if websocket in self.connection_metadata:
            key = self.connection_metadata[websocket].get("key") or self.connection_metadata[websocket].get("user_id")
            self.active_connections[str(key)].discard(websocket)
            del self.connection_metadata[websocket]
            
            if key in self.active_connections and not self.active_connections[str(key)]:
                del self.active_connections[str(key)]
            
            # Normal disconnects are expected (tab close, network change, idle timeout).
            # Keep this as INFO to reduce log noise/cost.
            logging.getLogger(__name__).info("WS disconnected user_id=%s", key)
    
    async def _send_local(self, user_id: str, message: dict, workspace: str | None = None):
        _vlog(f"📤 Attempting to send to user {user_id}")
        _vlog("📤 Message content:", json.dumps(message, indent=2))
        """Send message to all connections of a specific user"""
        key = self._key(user_id, workspace)
        if key in self.active_connections:
            disconnected = set()
            for websocket in self.active_connections[key].copy():
                try:
                    await websocket.send_json(message)
                except:
                    disconnected.add(websocket)
            
            for ws in disconnected:
                self.disconnect(ws)
        else:
            # Queue message for offline user
            self.message_queue[key].append(message)
            if len(self.message_queue[key]) > 100:
                self.message_queue[key] = self.message_queue[key][-50:]

    def _consume_ws_token(self, user_id: str, is_media: bool = False) -> bool:
        try:
            # Simple leaky bucket using monotonic time
            bucket_key = f"{user_id}:{'media' if is_media else 'text'}"
            bucket = self._ws_buckets.get(bucket_key) or {"allowance": float(SEND_MEDIA_PER_MIN if is_media else SEND_TEXT_PER_MIN), "last": time.monotonic()}
            now = time.monotonic()
            rate_per_sec = (SEND_MEDIA_PER_MIN if is_media else SEND_TEXT_PER_MIN) / 60.0
            # Refill based on elapsed time
            bucket["allowance"] = min(float(SEND_MEDIA_PER_MIN if is_media else SEND_TEXT_PER_MIN), bucket["allowance"] + (now - bucket["last"]) * rate_per_sec)
            bucket["last"] = now
            if bucket["allowance"] < 1.0:
                self._ws_buckets[bucket_key] = bucket
                return False
            bucket["allowance"] -= 1.0
            self._ws_buckets[bucket_key] = bucket
            return True
        except Exception:
            return True

    async def send_to_user(self, user_id: str, message: dict, workspace: str | None = None):
        """Send locally and, if enabled, publish to Redis for other instances."""
        await self._send_local(user_id, message, workspace=workspace)
        try:
            if ENABLE_WS_PUBSUB and getattr(self, "redis_manager", None):
                await self.redis_manager.publish_ws_event(user_id, message, workspace=workspace)
        except Exception as exc:
            _vlog(f"WS publish error: {exc}")
    
    async def broadcast_to_admins(self, message: dict, exclude_user: str = None):
        """Broadcast message to inbox listeners.

        Historically this looked up "admin users" from the DB (users.is_admin=1) and sent to those user_ids.
        In production, DB hiccups/timeouts would silently prevent broadcasts and the UI would only update on hard refresh.

        Fix: Always broadcast to the shared inbox channel "admin" (i.e. /ws/admin), regardless of DB health.
        Then best-effort also send to any additional DB-flagged admin user_ids (if present).
        """
        # Always send to the shared inbox channel where all agents connect (/ws/admin).
        try:
            if exclude_user != "admin":
                await self.send_to_user("admin", message)
        except Exception:
            pass

        # Optional legacy path: also broadcast to any DB-flagged admin users.
        try:
            admin_users = await self.get_admin_users()
        except Exception:
            admin_users = []
        for admin_id in admin_users or []:
            if admin_id in (exclude_user, "admin"):
                continue
            try:
                await self.send_to_user(admin_id, message)
            except Exception:
                pass
    
    def get_active_users(self) -> List[str]:
        """Get list of currently active users"""
        return list(self.active_connections.keys())
    
    async def get_admin_users(self) -> List[str]:
        """Get admin user IDs from database"""
        return await db_manager.get_admin_users()

# Redis Manager for caching
class RedisManager:
    def __init__(self, redis_url: str | None = None):
        self.redis_url = redis_url or REDIS_URL
        self.redis_client: Optional[redis.Redis] = None

    # -------- agent presence / activity (online) --------
    def _agent_last_seen_key(self, workspace: str, username: str) -> str:
        ws = _coerce_workspace(workspace or DEFAULT_WORKSPACE)
        u = str(username or "").strip().lower()
        return f"agent_last_seen:{ws}:{u}"

    async def touch_agent_last_seen(self, username: str, workspace: str | None = None) -> None:
        """Update last activity timestamp for an agent (best-effort)."""
        if not self.redis_client:
            return
        u = str(username or "").strip()
        if not u:
            return
        ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
        key = self._agent_last_seen_key(ws, u)
        try:
            now = str(time.time())
            await self.redis_client.setex(key, int(AGENT_ACTIVITY_CACHE_TTL_SECONDS), now)
        except Exception:
            return

    async def get_agent_last_seen(self, username: str, workspace: str | None = None) -> Optional[float]:
        if not self.redis_client:
            return None
        u = str(username or "").strip()
        if not u:
            return None
        ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
        key = self._agent_last_seen_key(ws, u)
        try:
            raw = await self.redis_client.get(key)
            if not raw:
                return None
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", "ignore")
            return float(raw)
        except Exception:
            return None

    async def clear_agent_last_seen(self, username: str, workspace: str | None = None) -> None:
        if not self.redis_client:
            return
        u = str(username or "").strip()
        if not u:
            return
        ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
        key = self._agent_last_seen_key(ws, u)
        try:
            await self.redis_client.delete(key)
        except Exception:
            return
    
    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            print("✅ Redis connected")
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            self.redis_client = None
    
    async def cache_message(self, user_id: str, message: dict, ttl: int = 3600, workspace: str | None = None):
        """Cache message with TTL"""
        if not self.redis_client:
            return
        
        try:
            ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
            key = f"recent_messages:{ws}:{user_id}"
            await self.redis_client.lpush(key, json.dumps(message))
            await self.redis_client.ltrim(key, 0, 49)  # Keep last 50 messages
            await self.redis_client.expire(key, ttl)
        except Exception as e:
            print(f"Redis cache error: {e}")
    
    async def get_recent_messages(self, user_id: str, limit: int = 20, workspace: str | None = None) -> List[dict]:
        """Get recent messages from cache"""
        if not self.redis_client:
            return []
        
        try:
            ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
            key = f"recent_messages:{ws}:{user_id}"
            messages = await self.redis_client.lrange(key, 0, limit - 1)
            return [json.loads(msg) for msg in messages]
        except Exception as e:
            print(f"Redis get error: {e}")
            return []

    async def publish_ws_event(self, user_id: str, message: dict, workspace: str | None = None):
        """Publish a WebSocket event so other instances can deliver it."""
        if not self.redis_client:
            return
        try:
            ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
            payload = json.dumps({"workspace": ws, "user_id": user_id, "message": message})
            await self.redis_client.publish("ws_events", payload)
        except Exception as exc:
            print(f"Redis publish error: {exc}")

    # -------- agent auth cache helpers --------
    def _agent_auth_key(self, username: str) -> str:
        return f"agent_auth:{str(username or '').strip().lower()}"

    async def get_agent_auth_record(self, username: str) -> Optional[dict]:
        """Get cached agent auth record from Redis: {'password_hash': str, 'is_admin': int}."""
        if not self.redis_client:
            return None
        u = str(username or "").strip().lower()
        if not u:
            return None
        try:
            raw = await self.redis_client.get(self._agent_auth_key(u))
            if not raw:
                return None
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", "ignore")
            data = json.loads(raw) if isinstance(raw, str) else None
            if not isinstance(data, dict):
                return None
            ph = data.get("password_hash")
            if not ph:
                return None
            return {"password_hash": str(ph), "is_admin": int(data.get("is_admin") or 0)}
        except Exception:
            return None

    async def set_agent_auth_record(self, username: str, password_hash: str, is_admin: int, ttl_seconds: int | None = None) -> None:
        if not self.redis_client:
            return
        u = str(username or "").strip().lower()
        if not u:
            return
        payload = {"password_hash": str(password_hash or ""), "is_admin": int(is_admin or 0)}
        try:
            ttl = int(ttl_seconds) if ttl_seconds is not None else int(AGENT_AUTH_REDIS_TTL_SECONDS)
            await self.set_json(self._agent_auth_key(u), payload, ttl=ttl if ttl > 0 else None)
        except Exception:
            return

    async def delete_agent_auth_record(self, username: str) -> None:
        if not self.redis_client:
            return
        u = str(username or "").strip().lower()
        if not u:
            return
        try:
            await self.redis_client.delete(self._agent_auth_key(u))
        except Exception:
            return

    # -------- simple feature helpers --------
    async def was_auto_reply_recent(self, user_id: str, window_sec: int = 24 * 60 * 60) -> bool:
        """Return True if an auto-reply marker exists for the user (within TTL)."""
        if not self.redis_client:
            return False
        try:
            key = f"auto_reply_sent:{user_id}"
            exists = await self.redis_client.exists(key)
            return bool(exists)
        except Exception:
            return False

    async def mark_auto_reply_sent(self, user_id: str, window_sec: int = 24 * 60 * 60) -> None:
        """Set a marker that suppresses further auto replies for window_sec seconds."""
        if not self.redis_client:
            return
        try:
            key = f"auto_reply_sent:{user_id}"
            await self.redis_client.setex(key, window_sec, "1")
        except Exception:
            return

    async def subscribe_ws_events(self, connection_manager: "ConnectionManager"):
        """Subscribe to WS events and forward them to local connections only."""
        if not self.redis_client:
            return
        try:
            pubsub = self.redis_client.pubsub(ignore_subscribe_messages=True)
            await pubsub.subscribe("ws_events")
            async for msg in pubsub.listen():
                try:
                    if msg and msg.get("type") == "message":
                        data = json.loads(msg.get("data"))
                        uid = data.get("user_id")
                        ws = data.get("workspace")
                        payload = data.get("message")
                        if uid and payload:
                            await connection_manager._send_local(uid, payload, workspace=ws)
                except Exception as inner_exc:
                    _vlog(f"WS subscribe handler error: {inner_exc}")
        except Exception as exc:
            print(f"Redis subscribe error: {exc}")

    # -------- survey helpers --------
    async def get_json(self, key: str) -> Optional[dict]:
        if not self.redis_client:
            return None
        try:
            raw = await self.redis_client.get(key)
            if not raw:
                return None
            return json.loads(raw)
        except Exception:
            return None

    async def set_json(self, key: str, value: dict, ttl: int | None = None) -> None:
        if not self.redis_client:
            return
        try:
            data = json.dumps(value, ensure_ascii=False)
            if ttl and ttl > 0:
                await self.redis_client.setex(key, ttl, data)
            else:
                await self.redis_client.set(key, data)
        except Exception:
            return

    async def was_survey_invited_recent(self, user_id: str) -> bool:
        if not self.redis_client:
            return False
        try:
            key = f"survey_invited:{user_id}"
            exists = await self.redis_client.exists(key)
            return bool(exists)
        except Exception:
            return False

    async def mark_survey_invited(self, user_id: str, window_sec: int = 30 * 24 * 60 * 60) -> None:
        if not self.redis_client:
            return
        try:
            key = f"survey_invited:{user_id}"
            await self.redis_client.setex(key, window_sec, "1")
        except Exception:
            return

    async def get_survey_state(self, user_id: str) -> Optional[dict]:
        return await self.get_json(f"survey_state:{user_id}")

    async def set_survey_state(self, user_id: str, state: dict, ttl_sec: int = 3 * 24 * 60 * 60) -> None:
        await self.set_json(f"survey_state:{user_id}", state, ttl=ttl_sec)

    async def clear_survey_state(self, user_id: str) -> None:
        if not self.redis_client:
            return
        try:
            await self.redis_client.delete(f"survey_state:{user_id}")
        except Exception:
            return

# WhatsApp API Client
class WhatsAppMessenger:
    def __init__(self, access_token: str | None = None, phone_number_id: str | None = None):
        # Important: only fall back to env when the param is None.
        # Passing an empty string should NOT silently fall back to env; it should behave as "not configured".
        self.access_token = (str(ACCESS_TOKEN or "") if access_token is None else str(access_token or "")).strip()
        self.phone_number_id = (str(PHONE_NUMBER_ID or "") if phone_number_id is None else str(phone_number_id or "")).strip()
        self._rebuild()

    def _rebuild(self) -> None:
        self.base_url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{self.phone_number_id}"
        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }


class WorkspaceWhatsAppRouter:
    """Routes WhatsApp Graph API calls to the correct phone_number_id/token for the current workspace."""

    def __init__(self, configs: Dict[str, dict]):
        self._configs = configs or {}
        self._clients: Dict[str, WhatsAppMessenger] = {}
        for ws, cfg in (self._configs or {}).items():
            try:
                self._clients[str(ws).strip().lower()] = WhatsAppMessenger(
                    access_token=str((cfg or {}).get("access_token") or ""),
                    phone_number_id=str((cfg or {}).get("phone_number_id") or ""),
                )
            except Exception:
                continue

    def update_workspace_config(self, workspace: str, access_token: str | None = None, phone_number_id: str | None = None) -> None:
        """Update in-memory routing for a workspace (used after DB settings save/startup)."""
        ws = _coerce_workspace(workspace)
        if not ws:
            return
        prev = (self._configs or {}).get(ws) or {}
        next_cfg = {
            "access_token": str(access_token if access_token is not None else prev.get("access_token") or "").strip(),
            "phone_number_id": str(phone_number_id if phone_number_id is not None else prev.get("phone_number_id") or "").strip(),
        }
        try:
            self._configs[ws] = next_cfg
        except Exception:
            pass
        try:
            self._clients[ws] = WhatsAppMessenger(
                access_token=str(next_cfg.get("access_token") or ""),
                phone_number_id=str(next_cfg.get("phone_number_id") or ""),
            )
        except Exception:
            pass

    def _client(self, workspace: str | None = None) -> WhatsAppMessenger:
        ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
        c = self._clients.get(ws)
        if c:
            return c
        # Fallback to default workspace or legacy single client
        c2 = self._clients.get(DEFAULT_WORKSPACE)
        if c2:
            return c2
        # last resort
        return WhatsAppMessenger()

    @property
    def phone_number_id(self) -> str:
        return self._client().phone_number_id

    @property
    def access_token(self) -> str:
        return self._client().access_token

    def __getattr__(self, name: str):
        # Delegate methods/attrs to the active workspace client.
        return getattr(self._client(), name)
    
    async def send_text_message(self, to: str, message: str, context_message_id: str | None = None) -> dict:
        """Send text message via WhatsApp API"""
        url = f"{self.base_url}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "text",
            "text": {"body": message}
        }
        if context_message_id:
            payload["context"] = {"message_id": context_message_id}
        
        print(f"🚀 Sending WhatsApp message to {to}: {message}")
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, headers=self.headers)
            result = response.json()
            print(f"📱 WhatsApp API Response: {result}")
            return result

    async def send_template_message(
        self,
        to: str,
        template_name: str,
        language: str = "en",
        components: list[dict] | None = None,
        context_message_id: str | None = None,
    ) -> dict:
        """Send a WhatsApp template message via Graph API."""
        url = f"{self.base_url}/messages"
        tpl = {
            "name": str(template_name or "").strip(),
            "language": {"code": str(language or "en").strip() or "en"},
        }
        if components:
            tpl["components"] = components
        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "template",
            "template": tpl,
        }
        if context_message_id:
            payload["context"] = {"message_id": context_message_id}
        return await self._make_request("messages", payload)

    async def send_reaction(self, to: str, target_message_id: str, emoji: str, action: str = "react") -> dict:
        """Send a reaction to a specific message via WhatsApp API."""
        data = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "reaction",
            "reaction": {
                "message_id": target_message_id,
                "emoji": emoji,
                "action": action or "react",
            },
        }
        return await self._make_request("messages", data)

    async def _make_request(self, endpoint: str, data: dict) -> dict:
        """Helper to send POST requests to WhatsApp API"""
        url = f"{self.base_url}/{endpoint}"
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, headers=self.headers)
            if response.status_code < 200 or response.status_code >= 300:
                # Log response body for easier debugging
                try:
                    body = response.text
                except Exception:
                    body = "<no body>"
                print(
                    f"❌ WhatsApp API request to {endpoint} failed with status {response.status_code}: {body}"
                )
                raise Exception(
                    f"WhatsApp API request failed with status {response.status_code}"
                )

            return response.json()

    async def send_catalog_products(self, user_id: str, product_ids: List[str], catalog_id: str | None = None) -> List[Dict[str, Any]]:
        """Send multiple catalog products in chunks, with clear bilingual part labels."""
        results = []
        # Pre-split to compute part numbers and item ranges
        chunks: List[List[str]] = list(chunk_list(product_ids, MAX_CATALOG_ITEMS))
        total_parts: int = len(chunks) if chunks else 0
        running_index: int = 1

        for part_index, chunk in enumerate(chunks, start=1):
            start_idx = running_index
            end_idx = running_index + len(chunk) - 1
            running_index += len(chunk)

            # Short bilingual header: "Partie X/Y • الجزء X/Y"
            header_text = f"Partie {part_index}/{total_parts} • الجزء {part_index}/{total_parts}"
            # Bilingual body explaining which range this part covers
            body_text_fr = f"Voici la partie {part_index}/{total_parts} des articles (\u2116 {start_idx}–{end_idx})."
            body_text_ar = f"هذه هي الجزء {part_index}/{total_parts} من العناصر (رقم {start_idx}–{end_idx})."
            body_text = f"{body_text_fr}\n{body_text_ar}"

            # Also reflect the part info in the section title for extra visibility
            section_title = f"Part {part_index}/{total_parts}"

            data = {
                "messaging_product": "whatsapp",
                "to": user_id,
                "type": "interactive",
                "interactive": {
                    "type": "product_list",
                    "header": {"type": "text", "text": header_text},
                    "body": {"text": body_text},
                    "action": {
                        "catalog_id": str(catalog_id or CATALOG_ID),
                        "sections": [
                            {
                                "title": section_title,
                                "product_items": [
                                    {"product_retailer_id": rid} for rid in chunk
                                ],
                            }
                        ],
                    },
                },
            }

            result = await self._make_request("messages", data)
            results.append(result)
        return results

    async def send_single_catalog_item(self, user_id: str, product_retailer_id: str, caption: str = "", catalog_id: str | None = None) -> Dict[str, Any]:
        """Send a single catalog item (interactive) with optional caption."""
        data = {
            "messaging_product": "whatsapp",
            "to": user_id,
            "type": "interactive",
            "interactive": {
                "type": "product",
                "body": {"text": caption or "Découvrez ce produit !\nتفقد هذا المنتج!"},
                "action": {
                    "catalog_id": str(catalog_id or CATALOG_ID),
                    "product_retailer_id": product_retailer_id
                }
            }
        }
        return await self._make_request("messages", data)

    async def send_reply_buttons(self, user_id: str, body_text: str, buttons: List[Dict[str, str]]) -> Dict[str, Any]:
        """Send WhatsApp interactive reply buttons.

        buttons: list of {"id": str, "title": str}
        """
        data = {
            "messaging_product": "whatsapp",
            "to": user_id,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": {"text": body_text},
                "action": {
                    "buttons": [
                        {"type": "reply", "reply": {"id": str(b.get("id")), "title": str(b.get("title"))[:20]}}  # WA title max 20 chars
                        for b in (buttons or []) if b.get("id") and b.get("title")
                    ]
                },
            },
        }
        return await self._make_request("messages", data)

    async def send_list_message(
        self,
        user_id: str,
        body_text: str,
        button_text: str,
        sections: List[Dict[str, Any]],
        header_text: Optional[str] = None,
        footer_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send WhatsApp interactive list message.

        sections: [ { title: str, rows: [ { id: str, title: str, description?: str } ] } ]
        """
        interactive: Dict[str, Any] = {
            "type": "list",
            "body": {"text": body_text},
            "action": {
                "button": button_text[:20] if button_text else "Choose",
                "sections": [],
            },
        }
        if header_text:
            interactive["header"] = {"type": "text", "text": header_text}
        if footer_text:
            interactive["footer"] = {"text": footer_text}

        cleaned_sections: List[Dict[str, Any]] = []
        for sec in sections or []:
            title = str(sec.get("title") or "")
            rows_in = sec.get("rows") or []
            rows: List[Dict[str, str]] = []
            for r in rows_in:
                rid = str(r.get("id") or "").strip()
                rtitle = str(r.get("title") or "").strip()
                if not rid or not rtitle:
                    continue
                row: Dict[str, str] = {"id": rid, "title": rtitle[:24]}
                desc = str(r.get("description") or "").strip()
                if desc:
                    row["description"] = desc[:72]
                rows.append(row)
            if rows:
                cleaned_sections.append({
                    **({"title": title[:24]} if title else {}),
                    "rows": rows,
                })
        interactive["action"]["sections"] = cleaned_sections

        data = {
            "messaging_product": "whatsapp",
            "to": user_id,
            "type": "interactive",
            "interactive": interactive,
        }
        return await self._make_request("messages", data)

    async def send_full_catalog(self, user_id: str, caption: str = "") -> List[Dict[str, Any]]:
        """Send the entire catalog to a user, optionally with a caption."""
        ws = get_current_workspace()
        cid = await _get_effective_catalog_id(ws)
        cache_file = _catalog_cache_file_for(ws, cid)
        products = catalog_manager.get_cached_products(cache_file=cache_file)
        product_ids = [p.get("retailer_id") for p in products if p.get("retailer_id")]

        if caption:
            await self.send_text_message(user_id, caption)

        if not product_ids:
            return []

        return await self.send_catalog_products(user_id, product_ids, catalog_id=cid)

    async def send_full_set(self, user_id: str, set_id: str, caption: str = "") -> List[Dict[str, Any]]:
        """Send all products for a specific set in chunks."""
        ws = get_current_workspace()
        cid = await _get_effective_catalog_id(ws)
        cache_file = _catalog_cache_file_for(ws, cid)
        products = await CatalogManager.get_products_for_set(set_id, limit=60, catalog_id=cid, cache_file=cache_file)
        product_ids = [p.get("retailer_id") for p in products if p.get("retailer_id")]

        if caption:
            await self.send_text_message(user_id, caption)

        if not product_ids:
            return []

        return await self.send_catalog_products(user_id, product_ids, catalog_id=cid)
    
    async def send_media_message(
        self,
        to: str,
        media_type: str,
        media_id_or_url: str,
        caption: str = "",
        context_message_id: str | None = None,
        audio_voice: bool | None = None,
    ) -> dict:
        """Send media message - handles both media_id and URL"""
        url = f"{self.base_url}/messages"
        
        # Check if it's a media_id (no http/https) or URL
        is_link = media_id_or_url.startswith(('http://', 'https://'))
        if is_link:
            media_payload = {"link": media_id_or_url}
        else:
            media_payload = {"id": media_id_or_url}  # Use media_id
        
        # Only attach caption for media types that support it
        if caption and media_type in ("image", "video", "document"):
            media_payload["caption"] = caption
        
        # Apply audio-specific flags for PTT/voice notes when using media_id
        if media_type == "audio" and not is_link:
            # WA Cloud voice note hints improve cross-client reliability
            enable_voice = (audio_voice is None or audio_voice is True) and AUDIO_VOICE_ENABLED
            if enable_voice:
                media_payload["voice"] = True

        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": media_type,
            media_type: media_payload
        }
        if context_message_id:
            payload["context"] = {"message_id": context_message_id}
        
        print(f"🚀 Sending WhatsApp media to {to}: {media_type} - {media_id_or_url}")
        timeout = httpx.Timeout(
            float(WHATSAPP_HTTP_TIMEOUT_SECONDS),
            connect=float(WHATSAPP_HTTP_CONNECT_TIMEOUT_SECONDS),
        )
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=self.headers)
            # Best-effort parse; WhatsApp may return non-JSON on errors.
            try:
                result = response.json()
            except Exception:
                result = {"status_code": response.status_code, "text": response.text}
            print(f"📱 WhatsApp Media API Response: {result}")
            return result

    async def mark_message_as_read(self, message_id: str) -> dict:
        """Send a read receipt to WhatsApp for a given message"""
        url = f"{self.base_url}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "status": "read",
            "message_id": message_id,
        }
        timeout = httpx.Timeout(
            float(WHATSAPP_HTTP_TIMEOUT_SECONDS),
            connect=float(WHATSAPP_HTTP_CONNECT_TIMEOUT_SECONDS),
        )
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=self.headers)
            try:
                return response.json()
            except Exception:
                return {"status_code": response.status_code, "text": response.text}
    
    async def download_media(self, media_id: str) -> tuple[bytes, str]:
        """Download media from WhatsApp.

        Returns a tuple ``(content, mime_type)`` where ``content`` is the raw
        bytes of the file and ``mime_type`` comes from the ``Content-Type``
        header of the media response.
        """
        url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{media_id}"

        timeout = httpx.Timeout(
            float(WHATSAPP_HTTP_TIMEOUT_SECONDS),
            connect=float(WHATSAPP_HTTP_CONNECT_TIMEOUT_SECONDS),
        )
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=self.headers)
            if response.status_code != 200:
                raise Exception(f"Failed to get media info: {response.text}")

            media_info = response.json()
            media_url = media_info.get("url")

            if not media_url:
                raise Exception("No media URL in response")

            media_response = await client.get(media_url, headers=self.headers)
            if media_response.status_code != 200:
                raise Exception(f"Failed to download media: {media_response.text}")

            mime_type = media_response.headers.get("Content-Type", "")
            return media_response.content, mime_type

# ────────────────────────────────────────────────────────────
# Async, single-source Database helper – WhatsApp-Web logic
# ────────────────────────────────────────────────────────────
import aiosqlite
from contextlib import asynccontextmanager

_STATUS_RANK = {"sending": 0, "sent": 1, "delivered": 2, "read": 3, "failed": 99}

# Order status flags used by the payout/archive workflow
ORDER_STATUS_PAYOUT = "payout"
ORDER_STATUS_ARCHIVED = "archived"

class DatabaseManager:
    """Database helper supporting SQLite and optional PostgreSQL."""

    def __init__(self, db_path: str | None = None, db_url: str | None = None, *, force_single_sqlite: bool = False):
        # Normalize DB URL. Some platforms/tools provide SQLAlchemy-style URLs like
        # "postgresql+asyncpg://..." which asyncpg does NOT accept.
        raw_url = (db_url or DATABASE_URL or "").strip() or None
        if raw_url:
            if raw_url.startswith("postgresql+asyncpg://"):
                raw_url = raw_url.replace("postgresql+asyncpg://", "postgresql://", 1)
            if raw_url.startswith("postgres+asyncpg://"):
                raw_url = raw_url.replace("postgres+asyncpg://", "postgresql://", 1)
            if raw_url.startswith("postgresql+psycopg://"):
                raw_url = raw_url.replace("postgresql+psycopg://", "postgresql://", 1)
            if raw_url.startswith("postgresql+psycopg2://"):
                raw_url = raw_url.replace("postgresql+psycopg2://", "postgresql://", 1)
            # Only treat as Postgres when scheme matches what asyncpg expects
            try:
                from urllib.parse import urlparse as _urlparse
                scheme = (_urlparse(raw_url).scheme or "").lower()
            except Exception:
                scheme = ""
            if scheme not in ("postgresql", "postgres"):
                raw_url = None

        self.db_url = raw_url
        self.db_path = db_path or DB_PATH
        self.use_postgres = bool(self.db_url)
        # When True, never route SQLite connections via workspace mapping (used for shared auth DB).
        self.force_single_sqlite = bool(force_single_sqlite)
        if not self.use_postgres:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._pool: Optional[asyncpg.pool.Pool] = None
        # Pool creation can be slow/fail on cold start. Protect with a lock and add backoff
        # so every request doesn't stampede the DB.
        self._pool_lock = asyncio.Lock()
        self._pool_failed_until: float = 0.0
        self._pool_last_error: Optional[BaseException] = None
        # In-memory cache for agent auth records (password_hash + is_admin). Speeds up login and
        # reduces impact of transient DB slowness. TTL is controlled by AGENT_AUTH_CACHE_TTL_SECONDS.
        self._agent_auth_cache: Dict[str, dict] = {}
        # Columns allowed in the messages table (except auto-increment id)
        self.message_columns = {
            # workspace scoping (required for shared Postgres DB isolation)
            "workspace",
            "wa_message_id",
            "temp_id",
            "user_id",
            "message",
            "type",
            "from_me",
            "status",
            "price",
            "caption",
            "media_path",
            "timestamp",
            "server_ts",
            "url",  # store public URL for media
            # reply / reactions metadata
            "reply_to",            # wa_message_id of the quoted/original message
            "quoted_text",         # optional cached snippet of the quoted message
            "reaction_to",         # wa_message_id of the message this reaction targets
            "reaction_emoji",      # emoji character (e.g. "👍")
            "reaction_action",     # add/remove per WhatsApp payload
            "waveform",            # optional JSON array of peaks for audio
            # product identifiers (ensure catalog items render after reload)
            "product_retailer_id",
            "retailer_id",
            "product_id",
            # agent attribution
            "agent_username",
        }
        # Columns allowed in the conversation_notes table (except auto-increment id)
        self.note_columns = {
            "user_id",
            "agent_username",
            "type",
            "text",
            "url",
            "created_at",
        }

    async def _add_column_if_missing(self, db, table: str, column: str, col_def: str):
        """Add a column to a table if it doesn't already exist."""
        if self.use_postgres:
            # Postgres: use the native IF NOT EXISTS so this remains robust across schemas/search_path.
            # This avoids false positives (e.g., a column existing in a different schema) and fixes
            # cases where information_schema checks can be misleading.
            await db.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_def}")
            return
        else:
            exists = False
            cur = await db.execute(f"PRAGMA table_info({table})")
            cols = [r[1] for r in await cur.fetchall()]
            exists = column in cols
        if not exists:
            await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
            if not self.use_postgres:
                await db.commit()

    async def _get_pool(self):
        if self._pool:
            return self._pool
        if not self.db_url:
            return None

        # Fast-fail during backoff windows to avoid repeated slow connection attempts.
        now = time.time()
        if self._pool_failed_until and now < self._pool_failed_until:
            remaining = max(0.0, self._pool_failed_until - now)
            last = type(self._pool_last_error).__name__ if self._pool_last_error else "unknown"
            raise RuntimeError(f"Postgres pool unavailable (retry in ~{remaining:.0f}s; last_error={last})")

        async with self._pool_lock:
            if self._pool:
                return self._pool
            now = time.time()
            if self._pool_failed_until and now < self._pool_failed_until:
                remaining = max(0.0, self._pool_failed_until - now)
                last = type(self._pool_last_error).__name__ if self._pool_last_error else "unknown"
                raise RuntimeError(f"Postgres pool unavailable (retry in ~{remaining:.0f}s; last_error={last})")

            def _db_url_summary(url: str) -> str:
                # Avoid leaking credentials in logs. Only log basic routing info.
                try:
                    p = urlparse(url)
                    dbname = (p.path or "").lstrip("/") or None
                    user = p.username or None
                    host = p.hostname or None
                    port = p.port or None
                    has_pw = bool(p.password)
                    return f"{p.scheme}://{user or '?'}@{host or '?'}:{port or '?'}{('/' + dbname) if dbname else ''} (password={'set' if has_pw else 'missing'})"
                except Exception:
                    return "unparseable"

            try:
                # Limit pool sizes to avoid exhausting free-tier Postgres (e.g., Supabase)
                self._pool = await asyncpg.create_pool(
                    self.db_url,
                    min_size=PG_POOL_MIN,
                    max_size=PG_POOL_MAX,
                    timeout=float(PG_CONNECT_TIMEOUT_SECONDS),
                    # PgBouncer (Supabase pooler) + prepared statements don't mix in transaction pooling
                    # Disable statement cache to avoid prepared-statement usage across pooled connections
                    statement_cache_size=0,
                    # Recycle idle connections to keep footprint small on free tiers
                    max_inactive_connection_lifetime=60.0,
                )
                self._pool_last_error = None
                self._pool_failed_until = 0.0
            except Exception as exc:
                self._pool_last_error = exc
                self._pool_failed_until = time.time() + float(PG_POOL_RETRY_BACKOFF_SECONDS)
                logging.getLogger(__name__).error(
                    "Postgres pool creation failed (will back off %ss). db=%s err=%s",
                    float(PG_POOL_RETRY_BACKOFF_SECONDS),
                    _db_url_summary(self.db_url or ""),
                    exc,
                )
                if self.db_url and REQUIRE_POSTGRES:
                    # Explicitly require Postgres: surface error and do not silently fallback
                    raise
                # Fallback to SQLite if not strictly requiring Postgres
                print(f"⚠️ Postgres pool creation failed, falling back to SQLite: {exc}")
                self.use_postgres = False
                self._pool = None

        return self._pool

    def _convert(self, query: str) -> str:
        """Convert SQLite style placeholders to asyncpg numbered ones."""
        if not self.use_postgres:
            return query

        idx = 1

        # Replace positional and named placeholders in the order they appear
        def repl(match):
            nonlocal idx
            rep = f"${idx}"
            idx += 1
            return rep

        # IMPORTANT:
        # - We support SQLite-style positional placeholders "?".
        # - We support named placeholders like ":id" (used by some internal helpers).
        #
        # Do NOT treat time literals like "00:00:00" (":00") as placeholders.
        # The old pattern (:\w+) matched ":00" and would rewrite SQL literals into "$1$2",
        # breaking queries (e.g., analytics bucket formatting).
        query = re.sub(r"\?|:[A-Za-z_]\w*", repl, query)
        return query

    # ── basic connection helper ──
    @asynccontextmanager
    async def _conn(self):
        # Try Postgres first, but robustly fall back to SQLite if no pool
        if self.use_postgres:
            pool = await self._get_pool()
            if pool:
                async with pool.acquire() as conn:
                    yield conn
                return
            # Pool unavailable → switch to SQLite for this session
            if self.db_url and REQUIRE_POSTGRES:
                raise RuntimeError("Postgres required but connection pool is unavailable")
            self.use_postgres = False
        # For SQLite, keep lock waits bounded so requests don't hang indefinitely.
        # `timeout` is in seconds and controls how long SQLite waits to acquire locks.
        timeout_s = max(0.1, float(SQLITE_BUSY_TIMEOUT_MS) / 1000.0)
        # Multi-workspace support (SQLite): route connections to the active workspace DB.
        db_path = self.db_path
        try:
            if ENABLE_MULTI_WORKSPACE and not getattr(self, "force_single_sqlite", False):
                ws = get_current_workspace()
                db_path = (TENANT_DB_PATHS or {}).get(ws) or db_path
        except Exception:
            db_path = self.db_path
        try:
            Path(str(db_path)).parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        async with aiosqlite.connect(db_path, timeout=timeout_s) as db:
            db.row_factory = aiosqlite.Row
            try:
                await db.execute(f"PRAGMA busy_timeout = {int(SQLITE_BUSY_TIMEOUT_MS)}")
            except Exception:
                pass
            yield db
    async def ping(self) -> bool:
        """Lightweight DB connectivity check (used by /health)."""
        try:
            async with self._conn() as db:
                if self.use_postgres:
                    row = await db.fetchrow("SELECT 1 AS ok")
                    return bool(row[0]) if row else False
                cur = await db.execute("SELECT 1")
                row = await cur.fetchone()
                return bool(row[0]) if row else False
        except Exception:
            return False

    # ── schema ──
    async def init_db(self):
        async with self._conn() as db:
            # IMPORTANT: keep schema compatible with both SQLite and Postgres (we transform a few tokens below).
            # We include a workspace column for shared-DB multi-workspace isolation.
            base_script = f"""
                CREATE TABLE IF NOT EXISTS messages (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace      TEXT NOT NULL DEFAULT '{DEFAULT_WORKSPACE}',
                    wa_message_id  TEXT,
                    temp_id        TEXT,
                    user_id        TEXT NOT NULL,
                    message        TEXT,
                    type           TEXT DEFAULT 'text',
                    from_me        INTEGER DEFAULT 0,             -- bool 0/1
                    status         TEXT  DEFAULT 'sending',
                    price          TEXT,
                    caption        TEXT,
                    url            TEXT,
                    media_path     TEXT,
                    -- replies & reactions
                    reply_to       TEXT,
                    quoted_text    TEXT,
                    reaction_to    TEXT,
                    reaction_emoji TEXT,
                    reaction_action TEXT,
                    waveform       TEXT,
                    timestamp      TEXT  DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS users (
                    user_id    TEXT PRIMARY KEY,
                    name       TEXT,
                    phone      TEXT,
                    is_admin   INTEGER DEFAULT 0,
                    last_seen  TEXT,
                    created_at TEXT  DEFAULT CURRENT_TIMESTAMP
                );

                -- Agents who handle the shared inbox
                CREATE TABLE IF NOT EXISTS agents (
                    username      TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_admin      INTEGER DEFAULT 0,
                    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Refresh tokens for agents (hashed token stored server-side)
                CREATE TABLE IF NOT EXISTS agent_refresh_tokens (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash    TEXT UNIQUE NOT NULL,
                    agent_username TEXT NOT NULL REFERENCES agents(username),
                    expires_at    TEXT NOT NULL,
                    revoked_at    TEXT,
                    created_at    TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_refresh_agent_time
                    ON agent_refresh_tokens (agent_username, datetime(created_at));

                -- Durable analytics events (append-only, idempotent via UNIQUE indexes)
                -- event_type:
                --   inbound_message | outbound_message | inbound_replied | order_created
                CREATE TABLE IF NOT EXISTS agent_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type      TEXT NOT NULL,
                    user_id         TEXT,
                    agent_username  TEXT,
                    assigned_agent  TEXT,  -- snapshot for inbound messages at receive time
                    wa_message_id   TEXT,
                    inbound_wa_message_id TEXT,
                    outbound_wa_message_id TEXT,
                    order_id        TEXT,
                    ts              TEXT NOT NULL,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_agent_events_type_ts
                    ON agent_events (event_type, datetime(ts));
                CREATE INDEX IF NOT EXISTS idx_agent_events_agent_ts
                    ON agent_events (agent_username, datetime(ts));
                CREATE INDEX IF NOT EXISTS idx_agent_events_assigned_ts
                    ON agent_events (assigned_agent, datetime(ts));
                CREATE UNIQUE INDEX IF NOT EXISTS uniq_agent_events_inbound
                    ON agent_events (event_type, user_id, wa_message_id);
                CREATE UNIQUE INDEX IF NOT EXISTS uniq_agent_events_outbound
                    ON agent_events (event_type, user_id, wa_message_id);
                CREATE UNIQUE INDEX IF NOT EXISTS uniq_agent_events_order
                    ON agent_events (event_type, order_id);

                -- Link an inbound customer message to the first agent reply (counts "messages replied to" accurately)
                CREATE TABLE IF NOT EXISTS inbound_replies (
                    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id                TEXT NOT NULL,
                    inbound_wa_message_id  TEXT NOT NULL,
                    inbound_ts             TEXT NOT NULL,
                    replied_by_agent       TEXT NOT NULL,
                    first_reply_wa_message_id TEXT NOT NULL,
                    first_reply_ts         TEXT NOT NULL,
                    created_at             TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uniq_inbound_replies_inbound
                    ON inbound_replies (user_id, inbound_wa_message_id);
                CREATE INDEX IF NOT EXISTS idx_inbound_replies_agent_ts
                    ON inbound_replies (replied_by_agent, datetime(first_reply_ts));

                -- Optional metadata per customer conversation
                CREATE TABLE IF NOT EXISTS conversation_meta (
                    user_id        TEXT PRIMARY KEY,
                    assigned_agent TEXT REFERENCES agents(username),
                    tags           TEXT, -- JSON array of strings
                    avatar_url     TEXT,
                    -- attribution fields (e.g. website WhatsApp icon)
                    source         TEXT,
                    click_id       TEXT,
                    source_first_inbound_ts TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_conv_source_ts
                    ON conversation_meta (source, source_first_inbound_ts);
                CREATE INDEX IF NOT EXISTS idx_conv_click_id
                    ON conversation_meta (click_id);

                -- Internal, agent-only notes attached to a conversation
                CREATE TABLE IF NOT EXISTS conversation_notes (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id         TEXT NOT NULL,
                    agent_username  TEXT,
                    type            TEXT DEFAULT 'text', -- 'text' | 'audio'
                    text            TEXT,
                    url             TEXT,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_msg_wa_id
                    ON messages (wa_message_id);

                CREATE INDEX IF NOT EXISTS idx_msg_user_time
                    ON messages (user_id, datetime(timestamp));

                -- Additional index to optimize TEXT-based timestamp ordering in SQLite
                CREATE INDEX IF NOT EXISTS idx_msg_user_ts_text
                    ON messages (user_id, timestamp);

                CREATE INDEX IF NOT EXISTS idx_notes_user_time
                    ON conversation_notes (user_id, datetime(created_at));

                -- Idempotency: ensure per-chat uniqueness for wa_message_id and temp_id
                CREATE UNIQUE INDEX IF NOT EXISTS uniq_msg_user_wa
                    ON messages (workspace, user_id, wa_message_id);

                -- Orders table used to track payout status
                CREATE TABLE IF NOT EXISTS orders (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_id   TEXT UNIQUE,
                    status     TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                -- Orders created attribution (per agent)
                CREATE TABLE IF NOT EXISTS orders_created (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_id        TEXT,
                    user_id         TEXT,
                    agent_username  TEXT,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_orders_created_agent_time
                    ON orders_created (agent_username, created_at);
                CREATE UNIQUE INDEX IF NOT EXISTS uniq_orders_created_order
                    ON orders_created (order_id);

                -- Key/value settings store (JSON-encoded values)
                CREATE TABLE IF NOT EXISTS settings (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                );

                -- Automation rule stats (durable counters; avoids reliance on Redis)
                CREATE TABLE IF NOT EXISTS automation_rule_stats (
                    rule_id         TEXT PRIMARY KEY,
                    triggers        INTEGER NOT NULL DEFAULT 0,
                    messages_sent   INTEGER NOT NULL DEFAULT 0,
                    tags_added      INTEGER NOT NULL DEFAULT 0,
                    last_trigger_ts TEXT
                );

                -- Website (Shopify) WhatsApp click tracking (public, append-only)
                CREATE TABLE IF NOT EXISTS whatsapp_clicks (
                    click_id    TEXT PRIMARY KEY,
                    ts          TEXT NOT NULL,
                    page_url    TEXT,
                    product_id  TEXT,
                    shop_domain TEXT,
                    ua          TEXT,
                    ip_hash     TEXT,
                    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_whatsapp_clicks_ts
                    ON whatsapp_clicks (ts);

                -- Durable webhook queue (SQLite fallback; Postgres has a dedicated JSONB schema below)
                CREATE TABLE IF NOT EXISTS webhook_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    status          TEXT NOT NULL DEFAULT 'pending', -- pending|processing|retry|done|dead
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    payload         TEXT NOT NULL,
                    last_error      TEXT,
                    next_attempt_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    locked_at       TEXT,
                    lock_owner      TEXT,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at      TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_webhook_events_due
                    ON webhook_events (status, datetime(next_attempt_at), id);
                """
            if self.use_postgres:
                script = base_script.replace(
                    "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY"
                )
                # PostgreSQL doesn't support the SQLite datetime() function in
                # index definitions, so index the raw timestamp column instead.
                script = script.replace("datetime(timestamp)", "timestamp")
                script = script.replace("datetime(created_at)", "created_at")
                script = script.replace("datetime(ts)", "ts")
                script = script.replace("datetime(first_reply_ts)", "first_reply_ts")
                script = script.replace("datetime(next_attempt_at)", "next_attempt_at")

                def _strip_pg_dash_comments(sql: str) -> str:
                    """Remove SQL line comments (`-- ...`) including inline parts.

                    Important: our schema string contains semicolons inside comments (e.g. "... fallback; Postgres ...").
                    If we split on ';' first, we may end up executing a chunk that starts with "Postgres ...",
                    causing `syntax error at or near "Postgres"` and preventing DB initialization.
                    """
                    try:
                        out_lines: list[str] = []
                        for line in (sql or "").splitlines():
                            # Remove inline comment portion as well.
                            if "--" in line:
                                line = line.split("--", 1)[0]
                            if line.strip():
                                out_lines.append(line)
                        return "\n".join(out_lines).strip()
                    except Exception:
                        return (sql or "").strip()

                script_no_comments = _strip_pg_dash_comments(script)
                statements = [s.strip() for s in script_no_comments.split(";") if s and s.strip()]
                for stmt in statements:
                    await db.execute(stmt)
                # Ensure the additional composite index exists in Postgres as well
                await db.execute("CREATE INDEX IF NOT EXISTS idx_msg_user_ts_text ON messages (user_id, timestamp)")
                # Durable webhook queue schema for Postgres (JSONB + timestamptz + SKIP LOCKED friendly index)
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS webhook_events (
                        id BIGSERIAL PRIMARY KEY,
                        status TEXT NOT NULL DEFAULT 'pending',
                        attempts INTEGER NOT NULL DEFAULT 0,
                        payload JSONB NOT NULL,
                        last_error TEXT,
                        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        locked_at TIMESTAMPTZ,
                        lock_owner TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                await db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_webhook_events_due ON webhook_events (status, next_attempt_at, id)"
                )
            else:
                await db.executescript(base_script)
                await db.commit()

            # Ensure newer columns exist for deployments created before they were added
            # Workspace isolation
            await self._add_column_if_missing(db, "messages", "workspace", f"TEXT DEFAULT '{DEFAULT_WORKSPACE}'")
            try:
                # Backfill any existing rows missing workspace to DEFAULT_WORKSPACE
                q = self._convert("UPDATE messages SET workspace = ? WHERE workspace IS NULL OR workspace = ''")
                if self.use_postgres:
                    await db.execute(q, DEFAULT_WORKSPACE)
                else:
                    await db.execute(q, (DEFAULT_WORKSPACE,))
                    await db.commit()
            except Exception:
                pass

            await self._add_column_if_missing(db, "messages", "temp_id", "TEXT")
            await self._add_column_if_missing(db, "messages", "url", "TEXT")
            # reply/reactions columns (idempotent)
            await self._add_column_if_missing(db, "messages", "reply_to", "TEXT")
            await self._add_column_if_missing(db, "messages", "quoted_text", "TEXT")
            await self._add_column_if_missing(db, "messages", "reaction_to", "TEXT")
            await self._add_column_if_missing(db, "messages", "reaction_emoji", "TEXT")
            await self._add_column_if_missing(db, "messages", "reaction_action", "TEXT")
            await self._add_column_if_missing(db, "messages", "waveform", "TEXT")
            # Ensure product identifiers columns exist for catalog items
            await self._add_column_if_missing(db, "messages", "product_retailer_id", "TEXT")
            await self._add_column_if_missing(db, "messages", "retailer_id", "TEXT")
            await self._add_column_if_missing(db, "messages", "product_id", "TEXT")
            # Ensure server-side timestamp column exists
            await self._add_column_if_missing(db, "messages", "server_ts", "TEXT")
            # Ensure agent attribution column exists
            await self._add_column_if_missing(db, "messages", "agent_username", "TEXT")

            # Ensure conversation attribution columns exist
            await self._add_column_if_missing(db, "conversation_meta", "source", "TEXT")
            await self._add_column_if_missing(db, "conversation_meta", "click_id", "TEXT")
            await self._add_column_if_missing(db, "conversation_meta", "source_first_inbound_ts", "TEXT")
            try:
                # Indexes (idempotent)
                if self.use_postgres:
                    await db.execute("CREATE INDEX IF NOT EXISTS idx_conv_source_ts ON conversation_meta (source, source_first_inbound_ts)")
                    await db.execute("CREATE INDEX IF NOT EXISTS idx_conv_click_id ON conversation_meta (click_id)")
                    await db.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_clicks_ts ON whatsapp_clicks (ts)")
                else:
                    await db.execute("CREATE INDEX IF NOT EXISTS idx_conv_source_ts ON conversation_meta (source, source_first_inbound_ts)")
                    await db.execute("CREATE INDEX IF NOT EXISTS idx_conv_click_id ON conversation_meta (click_id)")
                    await db.execute("CREATE INDEX IF NOT EXISTS idx_whatsapp_clicks_ts ON whatsapp_clicks (ts)")
                    await db.commit()
            except Exception:
                # Non-fatal: indexes are best-effort
                pass
            # Add index on server_ts for ordering by receive time
            if self.use_postgres:
                await db.execute("CREATE INDEX IF NOT EXISTS idx_msg_user_server_ts ON messages (user_id, server_ts)")
                # Speed up inbox queries on large Postgres datasets (used by /conversations).
                # Expression/partial indexes are safe and idempotent.
                try:
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_msg_user_ts_coalesce ON messages (user_id, (COALESCE(server_ts, timestamp)) DESC)"
                    )
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_msg_unread_user ON messages (user_id) WHERE from_me = 0 AND status <> 'read'"
                    )
                except Exception:
                    # Best-effort: do not fail init if index creation is not permitted.
                    pass
            else:
                await db.execute("CREATE INDEX IF NOT EXISTS idx_msg_user_server_ts ON messages (user_id, server_ts)")
                await db.commit()

            # Create index on temp_id now that the column is guaranteed to exist
            if self.use_postgres:
                await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_temp_id ON messages (temp_id)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_msg_user_ts_text ON messages (user_id, timestamp)")
            else:
                await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_temp_id ON messages (temp_id)")
                await db.commit()

            # Ensure uniqueness is workspace-scoped (older deployments had uniq_msg_user_wa on (user_id, wa_message_id)).
            try:
                if self.use_postgres:
                    await db.execute("DROP INDEX IF EXISTS uniq_msg_user_wa_old")
                else:
                    await db.execute("DROP INDEX IF EXISTS uniq_msg_user_wa_old")
                    await db.commit()
            except Exception:
                pass
            try:
                # Drop and recreate the canonical index name to include workspace.
                if self.use_postgres:
                    await db.execute("DROP INDEX IF EXISTS uniq_msg_user_wa")
                    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uniq_msg_user_wa ON messages (workspace, user_id, wa_message_id)")
                else:
                    await db.execute("DROP INDEX IF EXISTS uniq_msg_user_wa")
                    await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS uniq_msg_user_wa ON messages (workspace, user_id, wa_message_id)")
                    await db.commit()
            except Exception:
                pass

    # ── Agents management ──────────────────────────────────────────
    async def create_agent(self, username: str, name: str, password_hash: str, is_admin: int = 0):
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT INTO agents (username, name, password_hash, is_admin)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    name=EXCLUDED.name,
                    password_hash=EXCLUDED.password_hash,
                    is_admin=EXCLUDED.is_admin
                """
            )
            params = (username, name, password_hash, int(is_admin))
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()
        try:
            # Populate cache immediately (helps first login after agent creation).
            self._agent_auth_cache_set(username, password_hash, int(is_admin or 0))
        except Exception:
            pass

    async def list_agents(self) -> List[dict]:
        async with self._conn() as db:
            if self.use_postgres:
                query = self._convert("SELECT username, name, is_admin, created_at FROM agents ORDER BY created_at DESC")
                rows = await db.fetch(query)
                return [dict(r) for r in rows]
            else:
                query = self._convert("SELECT username, name, is_admin, created_at FROM agents ORDER BY datetime(created_at) DESC")
                cur = await db.execute(query)
                rows = await cur.fetchall()
                return [dict(r) for r in rows]

    async def list_agent_auth_records(self) -> List[dict]:
        """Return username/password_hash/is_admin for all agents (used to warm Redis cache)."""
        async with self._conn() as db:
            query = self._convert("SELECT username, password_hash, is_admin FROM agents")
            if self.use_postgres:
                rows = await db.fetch(query)
                return [{"username": r[0], "password_hash": r[1], "is_admin": int(r[2] or 0)} for r in rows]
            cur = await db.execute(query)
            rows = await cur.fetchall()
            return [{"username": r[0], "password_hash": r[1], "is_admin": int((r[2] if len(r) > 2 else 0) or 0)} for r in rows]

    async def delete_agent(self, username: str):
        async with self._conn() as db:
            query = self._convert("DELETE FROM agents WHERE username = ?")
            params = (username,)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()
        try:
            self._agent_auth_cache.pop(str(username or ""), None)
        except Exception:
            pass

    def _agent_auth_cache_get(self, username: str) -> Optional[dict]:
        try:
            ttl = int(AGENT_AUTH_CACHE_TTL_SECONDS)
            if ttl <= 0:
                return None
            u = str(username or "").strip()
            if not u:
                return None
            entry = self._agent_auth_cache.get(u)
            if not entry:
                return None
            ts = float(entry.get("ts") or 0.0)
            if (time.time() - ts) > ttl:
                self._agent_auth_cache.pop(u, None)
                return None
            return entry
        except Exception:
            return None

    def _agent_auth_cache_set(self, username: str, password_hash: str, is_admin: int) -> None:
        try:
            ttl = int(AGENT_AUTH_CACHE_TTL_SECONDS)
            if ttl <= 0:
                return
            u = str(username or "").strip()
            if not u:
                return
            self._agent_auth_cache[u] = {
                "password_hash": str(password_hash or ""),
                "is_admin": int(is_admin or 0),
                "ts": time.time(),
            }
        except Exception:
            return

    async def get_agent_auth_record(self, username: str) -> Optional[dict]:
        """Return {'password_hash': str, 'is_admin': int} for an agent, or None.

        Uses a small in-memory cache to reduce DB calls on /auth/login.
        """
        cached = self._agent_auth_cache_get(username)
        if cached:
            return {"password_hash": cached.get("password_hash") or "", "is_admin": int(cached.get("is_admin") or 0)}

        async with self._conn() as db:
            query = self._convert("SELECT password_hash, is_admin FROM agents WHERE username = ?")
            params = (username,)
            if self.use_postgres:
                row = await db.fetchrow(query, *params)
                if not row:
                    return None
                password_hash = row[0]
                is_admin = row[1]
            else:
                cur = await db.execute(query, params)
                row = await cur.fetchone()
                if not row:
                    return None
                password_hash = row[0]
                is_admin = row[1] if len(row) > 1 else 0
            out = {"password_hash": password_hash, "is_admin": int(is_admin or 0)}
            try:
                self._agent_auth_cache_set(username, str(password_hash or ""), int(is_admin or 0))
            except Exception:
                pass
            return out

    async def get_agent_password_hash(self, username: str) -> Optional[str]:
        rec = await self.get_agent_auth_record(username)
        return (rec or {}).get("password_hash") or None

    async def set_agent_password_hash(self, username: str, password_hash: str):
        async with self._conn() as db:
            query = self._convert("UPDATE agents SET password_hash = ? WHERE username = ?")
            params = (password_hash, username)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()
        try:
            # Invalidate cache so the next login re-reads both password_hash and is_admin from DB.
            self._agent_auth_cache.pop(str(username or ""), None)
        except Exception:
            pass

    async def get_agent_is_admin(self, username: str) -> int:
        """Return 1 if agent is admin, else 0."""
        rec = await self.get_agent_auth_record(username)
        return int((rec or {}).get("is_admin") or 0)

    # ── Refresh token storage ──────────────────────────────────────
    async def store_refresh_token(self, token_hash: str, agent_username: str, expires_at_iso: str):
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT INTO agent_refresh_tokens (token_hash, agent_username, expires_at, revoked_at)
                VALUES (?, ?, ?, NULL)
                """
            )
            params = (token_hash, agent_username, expires_at_iso)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def get_refresh_token(self, token_hash: str) -> Optional[dict]:
        async with self._conn() as db:
            query = self._convert(
                "SELECT token_hash, agent_username, expires_at, revoked_at, created_at FROM agent_refresh_tokens WHERE token_hash = ?"
            )
            params = (token_hash,)
            if self.use_postgres:
                row = await db.fetchrow(query, *params)
                return dict(row) if row else None
            cur = await db.execute(query, params)
            row = await cur.fetchone()
            return dict(row) if row else None

    async def revoke_refresh_token(self, token_hash: str):
        async with self._conn() as db:
            query = self._convert(
                "UPDATE agent_refresh_tokens SET revoked_at = COALESCE(?, CURRENT_TIMESTAMP) WHERE token_hash = ?"
            )
            params = (datetime.utcnow().isoformat(), token_hash)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def revoke_all_refresh_tokens_for_agent(self, agent_username: str):
        async with self._conn() as db:
            query = self._convert(
                "UPDATE agent_refresh_tokens SET revoked_at = COALESCE(?, CURRENT_TIMESTAMP) WHERE agent_username = ? AND revoked_at IS NULL"
            )
            params = (datetime.utcnow().isoformat(), agent_username)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    # ── Durable analytics events (append-only) ─────────────────────
    async def log_agent_event(
        self,
        *,
        event_type: str,
        ts: str,
        user_id: Optional[str] = None,
        agent_username: Optional[str] = None,
        assigned_agent: Optional[str] = None,
        wa_message_id: Optional[str] = None,
        inbound_wa_message_id: Optional[str] = None,
        outbound_wa_message_id: Optional[str] = None,
        order_id: Optional[str] = None,
    ) -> None:
        """Insert an analytics event idempotently (UNIQUE indexes prevent duplicates)."""
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT OR IGNORE INTO agent_events
                  (event_type, user_id, agent_username, assigned_agent, wa_message_id, inbound_wa_message_id, outbound_wa_message_id, order_id, ts)
                VALUES
                  (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            # Postgres: emulate OR IGNORE using ON CONFLICT DO NOTHING
            if self.use_postgres:
                query = self._convert(
                    """
                    INSERT INTO agent_events
                      (event_type, user_id, agent_username, assigned_agent, wa_message_id, inbound_wa_message_id, outbound_wa_message_id, order_id, ts)
                    VALUES
                      (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """
                )
            params = (
                event_type,
                user_id,
                agent_username,
                assigned_agent,
                wa_message_id,
                inbound_wa_message_id,
                outbound_wa_message_id,
                order_id,
                ts,
            )
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def mark_latest_inbound_replied(
        self,
        *,
        user_id: str,
        replied_by_agent: str,
        outbound_wa_message_id: str,
        first_reply_ts: str,
    ) -> Optional[dict]:
        """Find the latest inbound customer message not yet counted as replied, and link it to this reply."""
        async with self._conn() as db:
            # Find the latest inbound message with wa_message_id, not yet present in inbound_replies
            q = self._convert(
                """
                SELECT wa_message_id, COALESCE(server_ts, timestamp) AS ts
                FROM messages
                WHERE user_id = ?
                  AND from_me = 0
                  AND wa_message_id IS NOT NULL
                  AND wa_message_id != ''
                  AND COALESCE(server_ts, timestamp) <= ?
                  AND wa_message_id NOT IN (
                    SELECT inbound_wa_message_id FROM inbound_replies WHERE user_id = ?
                  )
                ORDER BY COALESCE(server_ts, timestamp) DESC
                LIMIT 1
                """
            )
            params = (user_id, first_reply_ts, user_id)
            if self.use_postgres:
                row = await db.fetchrow(q, *params)
                inbound_wa = (row["wa_message_id"] if row else None)
                inbound_ts = (row["ts"] if row else None)
            else:
                cur = await db.execute(q, params)
                row = await cur.fetchone()
                inbound_wa = (row["wa_message_id"] if row else None) if row else None
                inbound_ts = (row["ts"] if row else None) if row else None
            if not inbound_wa or not inbound_ts:
                return None

            ins = self._convert(
                """
                INSERT OR IGNORE INTO inbound_replies
                  (user_id, inbound_wa_message_id, inbound_ts, replied_by_agent, first_reply_wa_message_id, first_reply_ts)
                VALUES
                  (?, ?, ?, ?, ?, ?)
                """
            )
            if self.use_postgres:
                ins = self._convert(
                    """
                    INSERT INTO inbound_replies
                      (user_id, inbound_wa_message_id, inbound_ts, replied_by_agent, first_reply_wa_message_id, first_reply_ts)
                    VALUES
                      (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (user_id, inbound_wa_message_id) DO NOTHING
                    """
                )
            iparams = (user_id, inbound_wa, inbound_ts, replied_by_agent, outbound_wa_message_id, first_reply_ts)
            if self.use_postgres:
                await db.execute(ins, *iparams)
            else:
                await db.execute(ins, iparams)
                await db.commit()

            # Also log an event for fast reporting
            try:
                await self.log_agent_event(
                    event_type="inbound_replied",
                    ts=first_reply_ts,
                    user_id=user_id,
                    agent_username=replied_by_agent,
                    inbound_wa_message_id=inbound_wa,
                    outbound_wa_message_id=outbound_wa_message_id,
                )
            except Exception:
                pass
            return {"user_id": user_id, "inbound_wa_message_id": inbound_wa, "inbound_ts": inbound_ts}

    # ── Conversation metadata (assignment, tags, avatar) ───────────
    async def get_conversation_meta(self, user_id: str) -> dict:
        async with self._conn() as db:
            query = self._convert(
                "SELECT assigned_agent, tags, avatar_url, source, click_id, source_first_inbound_ts "
                "FROM conversation_meta WHERE user_id = ?"
            )
            params = (user_id,)
            if self.use_postgres:
                row = await db.fetchrow(query, *params)
            else:
                cur = await db.execute(query, params)
                row = await cur.fetchone()
            if not row:
                return {}
            d = dict(row)
            try:
                if isinstance(d.get("tags"), str):
                    d["tags"] = json.loads(d["tags"]) if d["tags"] else []
            except Exception:
                d["tags"] = []
            return d

    async def log_whatsapp_click(
        self,
        click_id: str,
        ts: str,
        page_url: Optional[str] = None,
        product_id: Optional[str] = None,
        shop_domain: Optional[str] = None,
        ua: Optional[str] = None,
        ip_hash: Optional[str] = None,
    ) -> None:
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT INTO whatsapp_clicks (click_id, ts, page_url, product_id, shop_domain, ua, ip_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(click_id) DO NOTHING
                """
            )
            params = (click_id, ts, page_url, product_id, shop_domain, ua, ip_hash)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def try_set_conversation_attribution_from_click(
        self,
        user_id: str,
        click_id: str,
        first_inbound_ts: str,
        source: str = "shopify_wa_icon",
    ) -> bool:
        """Set attribution only if not already attributed. Returns True if updated."""
        if not user_id or not click_id:
            return False
        try:
            meta = await self.get_conversation_meta(user_id)
            if (meta.get("source") or meta.get("click_id")):
                return False
        except Exception:
            meta = {}
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT INTO conversation_meta (user_id, source, click_id, source_first_inbound_ts)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    source=EXCLUDED.source,
                    click_id=EXCLUDED.click_id,
                    source_first_inbound_ts=COALESCE(conversation_meta.source_first_inbound_ts, EXCLUDED.source_first_inbound_ts)
                """
            )
            params = (user_id, source, click_id, first_inbound_ts)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()
        return True

    async def get_shopify_inbox_analytics(self, start: Optional[str] = None, end: Optional[str] = None, bucket: str = "day") -> dict:
        """Analytics for website WhatsApp icon funnel (clicks -> initiated chats -> inbound msgs -> orders)."""
        end_iso = end or datetime.utcnow().isoformat()
        start_iso = start or (datetime.utcnow() - timedelta(days=30)).isoformat()
        bucket = (bucket or "day").lower().strip()
        if bucket not in ("hour", "day"):
            bucket = "day"

        # Normalize incoming ISO timestamps so Postgres CAST(... AS TIMESTAMP) won't choke on timezone suffixes like "Z".
        # We compare all timestamps after truncating to the first 19 chars ("YYYY-MM-DDTHH:MM:SS"), so do the same here.
        def _iso19(s: str) -> str:
            try:
                dt = _parse_dt_any(s)
                if not dt:
                    raise ValueError("invalid datetime")
                dt = dt.astimezone(timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%S")
            except Exception:
                # Best-effort fallback: strip to 19 chars, replace space with T, drop trailing Z
                ss = str(s or "").replace("Z", "").replace("z", "")
                ss = ss.replace(" ", "T")
                return ss[:19]

        start_iso19 = _iso19(start_iso)
        end_iso19 = _iso19(end_iso)

        def _bucket_expr_sqlite(col: str) -> str:
            # Normalize to "YYYY-MM-DDTHH:00:00" or "YYYY-MM-DDT00:00:00" text
            if bucket == "hour":
                return f"strftime('%Y-%m-%dT%H:00:00', SUBSTR(REPLACE({col}, ' ', 'T'), 1, 19))"
            return f"strftime('%Y-%m-%dT00:00:00', SUBSTR(REPLACE({col}, ' ', 'T'), 1, 19))"

        def _bucket_expr_pg(col: str) -> str:
            # Cast text timestamps to timestamp, then date_trunc and format back to ISO-ish text
            if bucket == "hour":
                return f"to_char(date_trunc('hour', CAST(SUBSTRING(REPLACE({col}, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP)), 'YYYY-MM-DD\"T\"HH24:00:00')"
            return f"to_char(date_trunc('day', CAST(SUBSTRING(REPLACE({col}, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP)), 'YYYY-MM-DD\"T\"00:00:00')"

        async with self._conn() as db:
            src = "shopify_wa_icon"

            # Clicks
            if self.use_postgres:
                b_click = _bucket_expr_pg("ts")
                q_clicks = self._convert(
                    f"""
                    SELECT {b_click} AS bucket, COUNT(*) AS c
                    FROM whatsapp_clicks
                    WHERE CAST(SUBSTRING(REPLACE(ts, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) >= CAST(? AS TIMESTAMP)
                      AND CAST(SUBSTRING(REPLACE(ts, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) <= CAST(? AS TIMESTAMP)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                rows = await db.fetch(q_clicks, start_iso19, end_iso19)
                clicks = {str(r["bucket"]): int(r["c"] or 0) for r in rows}
            else:
                b_click = _bucket_expr_sqlite("ts")
                q_clicks = self._convert(
                    f"""
                    SELECT {b_click} AS bucket, COUNT(*) AS c
                    FROM whatsapp_clicks
                    WHERE SUBSTR(REPLACE(ts, ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                      AND SUBSTR(REPLACE(ts, ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                cur = await db.execute(q_clicks, (start_iso19, end_iso19))
                rows = await cur.fetchall()
                clicks = {str(r["bucket"]): int(r["c"] or 0) for r in rows}

            # Conversations initiated (first inbound stamped)
            if self.use_postgres:
                b_init = _bucket_expr_pg("source_first_inbound_ts")
                q_init = self._convert(
                    f"""
                    SELECT {b_init} AS bucket, COUNT(*) AS c
                    FROM conversation_meta
                    WHERE source = ?
                      AND source_first_inbound_ts IS NOT NULL
                      AND CAST(SUBSTRING(REPLACE(source_first_inbound_ts, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) >= CAST(? AS TIMESTAMP)
                      AND CAST(SUBSTRING(REPLACE(source_first_inbound_ts, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) <= CAST(? AS TIMESTAMP)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                rows = await db.fetch(q_init, src, start_iso19, end_iso19)
                initiated = {str(r["bucket"]): int(r["c"] or 0) for r in rows}
            else:
                b_init = _bucket_expr_sqlite("source_first_inbound_ts")
                q_init = self._convert(
                    f"""
                    SELECT {b_init} AS bucket, COUNT(*) AS c
                    FROM conversation_meta
                    WHERE source = ?
                      AND source_first_inbound_ts IS NOT NULL
                      AND SUBSTR(REPLACE(source_first_inbound_ts, ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                      AND SUBSTR(REPLACE(source_first_inbound_ts, ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                cur = await db.execute(q_init, (src, start_iso19, end_iso19))
                rows = await cur.fetchall()
                initiated = {str(r["bucket"]): int(r["c"] or 0) for r in rows}

            # Inbound messages for attributed conversations
            if self.use_postgres:
                b_msg = _bucket_expr_pg("COALESCE(server_ts, timestamp)")
                q_msgs = self._convert(
                    f"""
                    SELECT {b_msg} AS bucket, COUNT(*) AS c
                    FROM messages m
                    WHERE m.from_me = 0
                      AND m.user_id IN (SELECT user_id FROM conversation_meta WHERE source = ?)
                      AND CAST(SUBSTRING(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) >= CAST(? AS TIMESTAMP)
                      AND CAST(SUBSTRING(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) <= CAST(? AS TIMESTAMP)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                rows = await db.fetch(q_msgs, src, start_iso19, end_iso19)
                inbound_msgs = {str(r["bucket"]): int(r["c"] or 0) for r in rows}
            else:
                b_msg = _bucket_expr_sqlite("COALESCE(server_ts, timestamp)")
                q_msgs = self._convert(
                    f"""
                    SELECT {b_msg} AS bucket, COUNT(*) AS c
                    FROM messages m
                    WHERE m.from_me = 0
                      AND m.user_id IN (SELECT user_id FROM conversation_meta WHERE source = ?)
                      AND SUBSTR(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                      AND SUBSTR(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                cur = await db.execute(q_msgs, (src, start_iso19, end_iso19))
                rows = await cur.fetchall()
                inbound_msgs = {str(r["bucket"]): int(r["c"] or 0) for r in rows}

            # Orders created for attributed conversations
            if self.use_postgres:
                b_ord = _bucket_expr_pg("oc.created_at")
                q_ord = self._convert(
                    f"""
                    SELECT {b_ord} AS bucket, COUNT(*) AS c
                    FROM orders_created oc
                    JOIN conversation_meta cm ON cm.user_id = oc.user_id
                    WHERE cm.source = ?
                      AND CAST(SUBSTRING(REPLACE(oc.created_at, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) >= CAST(? AS TIMESTAMP)
                      AND CAST(SUBSTRING(REPLACE(oc.created_at, ' ', 'T') FROM 1 FOR 19) AS TIMESTAMP) <= CAST(? AS TIMESTAMP)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                rows = await db.fetch(q_ord, src, start_iso19, end_iso19)
                orders = {str(r["bucket"]): int(r["c"] or 0) for r in rows}
            else:
                b_ord = _bucket_expr_sqlite("oc.created_at")
                q_ord = self._convert(
                    f"""
                    SELECT {b_ord} AS bucket, COUNT(*) AS c
                    FROM orders_created oc
                    JOIN conversation_meta cm ON cm.user_id = oc.user_id
                    WHERE cm.source = ?
                      AND SUBSTR(REPLACE(oc.created_at, ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                      AND SUBSTR(REPLACE(oc.created_at, ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                    GROUP BY bucket
                    ORDER BY bucket
                    """
                )
                cur = await db.execute(q_ord, (src, start_iso19, end_iso19))
                rows = await cur.fetchall()
                orders = {str(r["bucket"]): int(r["c"] or 0) for r in rows}

        # Merge into a single aligned series
        all_keys = sorted(set(clicks.keys()) | set(initiated.keys()) | set(inbound_msgs.keys()) | set(orders.keys()))
        series = []
        total_clicks = 0
        total_initiated = 0
        total_inbound = 0
        total_orders = 0
        for k in all_keys:
            c = int(clicks.get(k, 0) or 0)
            i = int(initiated.get(k, 0) or 0)
            m = int(inbound_msgs.get(k, 0) or 0)
            o = int(orders.get(k, 0) or 0)
            total_clicks += c
            total_initiated += i
            total_inbound += m
            total_orders += o
            series.append({"bucket": k, "clicks": c, "initiated": i, "inbound_messages": m, "orders_created": o})

        return {
            "start": start_iso,
            "end": end_iso,
            "bucket": bucket,
            "totals": {
                "clicks": total_clicks,
                "initiated_conversations": total_initiated,
                "inbound_messages": total_inbound,
                "orders_created": total_orders,
                "orders_per_initiated": (float(total_orders) / float(total_initiated)) if total_initiated else 0.0,
            },
            "series": series,
        }

    async def upsert_conversation_meta(self, user_id: str, assigned_agent: Optional[str] = None, tags: Optional[List[str]] = None, avatar_url: Optional[str] = None):
        async with self._conn() as db:
            existing = await self.get_conversation_meta(user_id)
            new_tags = tags if tags is not None else existing.get("tags")
            new_assignee = assigned_agent if assigned_agent is not None else existing.get("assigned_agent")
            new_avatar = avatar_url if avatar_url is not None else existing.get("avatar_url")

            query = self._convert(
                """
                INSERT INTO conversation_meta (user_id, assigned_agent, tags, avatar_url)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    assigned_agent=EXCLUDED.assigned_agent,
                    tags=EXCLUDED.tags,
                    avatar_url=EXCLUDED.avatar_url
                """
            )
            params = (user_id, new_assignee, json.dumps(new_tags) if isinstance(new_tags, list) else new_tags, new_avatar)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def set_conversation_assignment(self, user_id: str, agent_username: Optional[str]):
        await self.upsert_conversation_meta(user_id, assigned_agent=agent_username)

    async def set_conversation_tags(self, user_id: str, tags: List[str]):
        await self.upsert_conversation_meta(user_id, tags=tags)

    # ── UPSERT with status-precedence ──
    async def upsert_message(self, data: dict):
        """
        Insert a new row or update an existing one (found by wa_message_id OR temp_id).
        The status is *only* upgraded – you can't go from 'delivered' ➜ 'sent', etc.
        """
        # Ensure workspace is always set for isolation (shared Postgres DB).
        try:
            data = dict(data or {})
            if not data.get("workspace"):
                data["workspace"] = get_current_workspace()
        except Exception:
            pass

        # Drop any keys not present in the messages table to avoid SQL errors
        data = {k: v for k, v in data.items() if k in self.message_columns}

        async with self._conn() as db:
            row = None
            if data.get("wa_message_id") and data.get("user_id"):
                query = self._convert("SELECT * FROM messages WHERE workspace = ? AND user_id = ? AND wa_message_id = ?")
                params = [data.get("workspace") or get_current_workspace(), data["user_id"], data["wa_message_id"]]
                if self.use_postgres:
                    row = await db.fetchrow(query, *params)
                else:
                    cur = await db.execute(query, tuple(params))
                    row = await cur.fetchone()

            if not row and data.get("temp_id") and data.get("user_id"):
                query = self._convert("SELECT * FROM messages WHERE workspace = ? AND user_id = ? AND temp_id = ?")
                params = [data.get("workspace") or get_current_workspace(), data["user_id"], data["temp_id"]]
                if self.use_postgres:
                    row = await db.fetchrow(query, *params)
                else:
                    cur = await db.execute(query, tuple(params))
                    row = await cur.fetchone()

            # 2) decide insert vs update
            if row:
                current_status = row["status"]
                new_status     = data.get("status", current_status)

                # only overwrite if status is an upgrade
                if _STATUS_RANK.get(new_status, 0) < _STATUS_RANK.get(current_status, 0):
                    return  # ignore downgrade

                merged = {**dict(row), **data}
                cols = [k for k in merged.keys() if k != "id"]
                sets = ", ".join(f"{c}=:{c}" for c in cols)
                merged["id"] = row["id"]
                query = self._convert(f"UPDATE messages SET {sets} WHERE id = :id")
                if self.use_postgres:
                    await db.execute(query, *[merged[c] for c in cols + ["id"]])
                else:
                    await db.execute(query, merged)
            else:
                # Avoid inserting placeholder rows without a user_id (would violate NOT NULL)
                if not data.get("user_id"):
                    return
                cols = ", ".join(data.keys())
                qs   = ", ".join("?" for _ in data)
                query = self._convert(f"INSERT INTO messages ({cols}) VALUES ({qs})")
                try:
                    if self.use_postgres:
                        await db.execute(query, *data.values())
                    else:
                        await db.execute(query, tuple(data.values()))
                except Exception as exc:
                    # If a concurrent insert violated unique (user_id, temp_id|wa_message_id), fall back to update
                    try:
                        if data.get("wa_message_id"):
                            sel = self._convert("SELECT * FROM messages WHERE workspace = ? AND user_id = ? AND wa_message_id = ?")
                            params = [data.get("workspace") or get_current_workspace(), data["user_id"], data["wa_message_id"]]
                        else:
                            sel = self._convert("SELECT * FROM messages WHERE workspace = ? AND user_id = ? AND temp_id = ?")
                            params = [data.get("workspace") or get_current_workspace(), data["user_id"], data.get("temp_id")]
                        if self.use_postgres:
                            row = await db.fetchrow(sel, *params)
                        else:
                            cur = await db.execute(sel, tuple(params))
                            row = await cur.fetchone()
                        if row:
                            current_status = row["status"]
                            new_status = data.get("status", current_status)
                            if _STATUS_RANK.get(new_status, 0) < _STATUS_RANK.get(current_status, 0):
                                return
                            merged = {**dict(row), **data}
                            cols2 = [k for k in merged.keys() if k != "id"]
                            sets2 = ", ".join(f"{c}=:{c}" for c in cols2)
                            merged["id"] = row["id"]
                            upd = self._convert(f"UPDATE messages SET {sets2} WHERE id = :id")
                            if self.use_postgres:
                                await db.execute(upd, *[merged[c] for c in cols2 + ["id"]])
                            else:
                                await db.execute(upd, merged)
                    except Exception:
                        raise exc
            if not self.use_postgres:
                await db.commit()

    # ── wrapper helpers re-used elsewhere ──
    async def get_messages(self, user_id: str, offset=0, limit=50) -> list[dict]:
        """Return the last N messages for a conversation, in chronological order (oldest→newest).

        Pagination is based on newest-first windows on the DB side (DESC with OFFSET),
        then reversed in-memory to chronological order for the UI.
        """
        async with self._conn() as db:
            ws = get_current_workspace()
            if self.use_postgres:
                # Order by server receive time when available, falling back to original timestamp
                query = self._convert(
                    "SELECT * FROM messages WHERE workspace = ? AND user_id = ? ORDER BY COALESCE(server_ts, timestamp) DESC LIMIT ? OFFSET ?"
                )
            else:
                # SQLite: ISO-8601 strings sort correctly lexicographically
                query = self._convert(
                    "SELECT * FROM messages WHERE workspace = ? AND user_id = ? ORDER BY COALESCE(server_ts, timestamp) DESC LIMIT ? OFFSET ?"
                )
            params = [ws, user_id, limit, offset]
            if self.use_postgres:
                rows = await db.fetch(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                rows = await cur.fetchall()
            # Reverse to chronological order for display
            ordered = [dict(r) for r in rows][::-1]
            return ordered

    async def get_messages_since(self, user_id: str, since_timestamp: str, limit: int = 500) -> list[dict]:
        """Return messages newer than the given ISO-8601 timestamp, ascending order.

        Relies on ISO-8601 lexicographic ordering for TEXT timestamps.
        """
        async with self._conn() as db:
            query = self._convert(
                "SELECT * FROM messages WHERE workspace = ? AND user_id = ? AND COALESCE(server_ts, timestamp) > ? ORDER BY COALESCE(server_ts, timestamp) ASC LIMIT ?"
            )
            params = [get_current_workspace(), user_id, since_timestamp, limit]
            if self.use_postgres:
                rows = await db.fetch(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_messages_before(self, user_id: str, before_timestamp: str, limit: int = 50) -> list[dict]:
        """Return messages older than the given ISO-8601 timestamp, ascending order.

        On the DB side we fetch newest-first (DESC) window older than the pivot,
        then reverse to chronological order for display.
        """
        async with self._conn() as db:
            query = self._convert(
                "SELECT * FROM messages WHERE workspace = ? AND user_id = ? AND COALESCE(server_ts, timestamp) < ? ORDER BY COALESCE(server_ts, timestamp) DESC LIMIT ?"
            )
            params = [get_current_workspace(), user_id, before_timestamp, limit]
            if self.use_postgres:
                rows = await db.fetch(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                rows = await cur.fetchall()
            return [dict(r) for r in rows][::-1]

    # ── Conversation notes helpers ─────────────────────────────────
    async def add_note(self, note: dict) -> dict:
        """Insert a new conversation note and return the stored row."""
        data = {k: v for k, v in (note or {}).items() if k in self.note_columns}
        if not data.get("user_id"):
            raise HTTPException(status_code=400, detail="user_id is required")
        async with self._conn() as db:
            cols = ", ".join(data.keys())
            qs = ", ".join("?" for _ in data)
            query = self._convert(f"INSERT INTO conversation_notes ({cols}) VALUES ({qs})")
            if self.use_postgres:
                await db.execute(query, *data.values())
                rowq = self._convert(
                    "SELECT * FROM conversation_notes WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
                )
                rows = await db.fetch(rowq, data["user_id"], 1)
                return dict(rows[0]) if rows else data
            else:
                await db.execute(query, tuple(data.values()))
                await db.commit()
                cur = await db.execute(
                    "SELECT * FROM conversation_notes WHERE user_id = ? ORDER BY datetime(created_at) DESC LIMIT 1",
                    (data["user_id"],),
                )
                row = await cur.fetchone()
                return dict(row) if row else data

    async def list_notes(self, user_id: str) -> list[dict]:
        if not user_id:
            return []
        async with self._conn() as db:
            if self.use_postgres:
                q = self._convert(
                    "SELECT * FROM conversation_notes WHERE user_id = ? ORDER BY created_at ASC"
                )
                rows = await db.fetch(q, user_id)
                return [dict(r) for r in rows]
            else:
                cur = await db.execute(
                    "SELECT * FROM conversation_notes WHERE user_id = ? ORDER BY datetime(created_at) ASC",
                    (user_id,),
                )
                rows = await cur.fetchall()
                return [dict(r) for r in rows]

    async def delete_note(self, note_id: int):
        async with self._conn() as db:
            if self.use_postgres:
                await db.execute("DELETE FROM conversation_notes WHERE id = $1", note_id)
            else:
                await db.execute("DELETE FROM conversation_notes WHERE id = ?", (note_id,))
                await db.commit()

    async def update_message_status(self, wa_message_id: str, status: str):
        """Persist a status update for a message identified by wa_message_id.

        Returns the temp_id if available so the UI can reconcile optimistic bubbles.
        """
        # Look up the owning user and temp_id so we can perform a precise upsert
        user_id: Optional[str] = None
        temp_id: Optional[str] = None
        async with self._conn() as db:
            try:
                ws = get_current_workspace()
                query = self._convert("SELECT user_id, temp_id, status FROM messages WHERE workspace = ? AND wa_message_id = ?")
                params = [ws, wa_message_id]
                if self.use_postgres:
                    row = await db.fetchrow(query, *params)
                else:
                    cur = await db.execute(query, tuple(params))
                    row = await cur.fetchone()
                if row:
                    user_id = row["user_id"]
                    temp_id = row["temp_id"]
                    # Guard against downgrades at DB boundary as well (belt and braces)
                    current_status = row["status"]
                    if _STATUS_RANK.get(status, 0) < _STATUS_RANK.get(current_status, 0):
                        return temp_id
            except Exception:
                # If lookup fails, fall back to best-effort upsert without temp_id
                pass

        if user_id:
            await self.upsert_message({"user_id": user_id, "wa_message_id": wa_message_id, "status": status})
        # If we couldn't resolve user_id, do nothing to avoid inserting orphan rows
        return temp_id

    async def get_user_for_message(self, wa_message_id: str) -> str | None:
        async with self._conn() as db:
            ws = get_current_workspace()
            query = self._convert("SELECT user_id FROM messages WHERE workspace = ? AND wa_message_id = ?")
            params = [ws, wa_message_id]
            if self.use_postgres:
                row = await db.fetchrow(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                row = await cur.fetchone()
            return row["user_id"] if row else None

    async def get_last_agent_message_time(self, user_id: str) -> Optional[str]:
        """Return ISO timestamp of the last outbound (from_me=1) message for a user."""
        async with self._conn() as db:
            query = self._convert(
                "SELECT MAX(COALESCE(server_ts, timestamp)) as t FROM messages WHERE workspace = ? AND user_id = ? AND from_me = 1"
            )
            params = [get_current_workspace(), user_id]
            if self.use_postgres:
                row = await db.fetchrow(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                row = await cur.fetchone()
            return (row and (row["t"] or None)) if row else None

    async def has_invoice_message(self, user_id: str) -> bool:
        """Detect whether an automated invoice image was sent in this chat.

        Heuristic: any outbound image message with an Arabic caption containing 'فاتورتك'.
        """
        async with self._conn() as db:
            # Use LIKE on caption; fall back to 0 when caption is NULL
            query = self._convert(
                "SELECT COUNT(*) AS c FROM messages WHERE workspace = ? AND user_id = ? AND from_me = 1 AND type = 'image' AND COALESCE(caption, '') LIKE ?"
            )
            params = [get_current_workspace(), user_id, "%فاتورتك%"]
            if self.use_postgres:
                row = await db.fetchrow(query, *params)
                count = int(row[0]) if row else 0
            else:
                cur = await db.execute(query, tuple(params))
                row = await cur.fetchone()
                count = int(row[0]) if row else 0
            return count > 0

    async def upsert_user(self, user_id: str, name=None, phone=None, is_admin: int | None = None):
        async with self._conn() as db:
            if is_admin is None:
                query = self._convert(
                    """
                    INSERT INTO users (user_id, name, phone, last_seen)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(user_id) DO UPDATE SET
                        name=COALESCE(EXCLUDED.name, users.name),
                        phone=COALESCE(EXCLUDED.phone, users.phone),
                        last_seen=CURRENT_TIMESTAMP
                    """
                )
                params = (user_id, name, phone)
            else:
                query = self._convert(
                    """
                    INSERT INTO users (user_id, name, phone, is_admin, last_seen)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(user_id) DO UPDATE SET
                        name=COALESCE(EXCLUDED.name, users.name),
                        phone=COALESCE(EXCLUDED.phone, users.phone),
                        is_admin=EXCLUDED.is_admin,
                        last_seen=CURRENT_TIMESTAMP
                    """
                )
                params = (user_id, name, phone, int(is_admin))

            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def save_message(self, message: dict, wa_message_id: str, status: str):
        """Persist a sent message using the final WhatsApp ID."""
        data = {
            "wa_message_id": wa_message_id,
            "temp_id": message.get("temp_id") or message.get("id"),
            "user_id": message.get("user_id"),
            "message": message.get("message"),
            "type": message.get("type", "text"),
            "from_me": 1,
            "status": status,
            "price": message.get("price"),
            "caption": message.get("caption"),
            "url": message.get("url"),
            "media_path": message.get("media_path"),
            "timestamp": message.get("timestamp"),
            "waveform": message.get("waveform"),
            # persist product identifiers so frontend can restore rich bubble
            "product_retailer_id": (
                message.get("product_retailer_id")
                or message.get("retailer_id")
                or message.get("product_id")
            ),
            "retailer_id": message.get("retailer_id"),
            "product_id": message.get("product_id"),
        }
        # Remove None values so SQL doesn't fail on NOT NULL columns
        clean = {k: v for k, v in data.items() if v is not None}
        await self.upsert_message(clean)

        # Durable analytics: log outbound + mark reply-to-inbound when we have final WA id
        try:
            agent_username = (message.get("agent_username") or message.get("agent") or "").strip() or None
            if agent_username:
                ts = str(message.get("server_ts") or message.get("timestamp") or datetime.utcnow().isoformat())
                await self.log_agent_event(
                    event_type="outbound_message",
                    ts=ts,
                    user_id=str(message.get("user_id") or ""),
                    agent_username=agent_username,
                    wa_message_id=str(wa_message_id),
                )
                # Count this as replying to the latest unreplied inbound message (1-to-1)
                await self.mark_latest_inbound_replied(
                    user_id=str(message.get("user_id") or ""),
                    replied_by_agent=agent_username,
                    outbound_wa_message_id=str(wa_message_id),
                    first_reply_ts=ts,
                )
        except Exception:
            pass

    async def mark_messages_as_read(self, user_id: str, message_ids: List[str] | None = None):
        """Mark one or all messages in a conversation as read."""
        async with self._conn() as db:
            ws = get_current_workspace()
            if message_ids:
                placeholders = ",".join("?" * len(message_ids))
                query = self._convert(
                    f"UPDATE messages SET status='read' WHERE workspace = ? AND user_id = ? AND wa_message_id IN ({placeholders})"
                )
                params = [ws, user_id, *message_ids]
            else:
                query = self._convert(
                    "UPDATE messages SET status='read' WHERE workspace = ? AND user_id = ? AND from_me = 0 AND status != 'read'"
                )
                params = [ws, user_id]
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, tuple(params))
                await db.commit()

    async def get_admin_users(self) -> List[str]:
        """Return list of user_ids flagged as admins."""
        async with self._conn() as db:
            query = self._convert("SELECT user_id FROM users WHERE is_admin = 1")
            if self.use_postgres:
                rows = await db.fetch(query)
            else:
                cur = await db.execute(query)
                rows = await cur.fetchall()
            return [r["user_id"] for r in rows]

    async def get_conversations_with_stats(
        self,
        q: Optional[str] = None,
        unread_only: bool = False,
        assigned: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 1000,
        offset: int = 0,
        viewer_agent: Optional[str] = None,
    ) -> List[dict]:
        """Return conversation summaries for chat list with optional filters.

        Optimized single-query plan for Postgres; SQLite uses existing per-user aggregation.
        """
        async with self._conn() as db:
            ws = get_current_workspace()
            # Postgres optimized path
            if self.use_postgres:
                # Important: keep this fast on large datasets.
                # We compute the "page" of conversations first (last message per user),
                # then compute unread/unresponded stats ONLY for those users.
                base = self._convert(
                    """
                    WITH last_msg AS (
                      SELECT DISTINCT ON (user_id)
                        user_id,
                        message,
                        type,
                        from_me,
                        status,
                        COALESCE(server_ts, timestamp) AS ts
                      FROM messages
                      WHERE workspace = ?
                      ORDER BY user_id, COALESCE(server_ts, timestamp) DESC
                    ),
                    page AS (
                      SELECT *
                      FROM last_msg
                      ORDER BY ts DESC NULLS LAST
                      LIMIT ? OFFSET ?
                    ),
                    counts AS (
                      SELECT
                        user_id,
                        COUNT(*) FILTER (WHERE from_me = 0 AND status <> 'read') AS unread_count,
                        MAX(COALESCE(server_ts, timestamp)) FILTER (WHERE from_me = 1) AS last_agent_ts
                      FROM messages
                      WHERE workspace = ? AND user_id IN (SELECT user_id FROM page)
                      GROUP BY user_id
                    ),
                    unresponded AS (
                      SELECT
                        m.user_id,
                        COUNT(*) FILTER (
                          WHERE m.from_me = 0
                            AND m.status = 'read'
                            AND COALESCE(m.server_ts, m.timestamp) > COALESCE(c.last_agent_ts, '1970-01-01')
                        ) AS unresponded_count
                      FROM messages m
                      JOIN counts c ON c.user_id = m.user_id
                      WHERE m.workspace = ? AND m.user_id IN (SELECT user_id FROM page)
                      GROUP BY m.user_id, c.last_agent_ts
                    )
                    SELECT
                      p.user_id,
                      u.name,
                      u.phone,
                      p.message AS last_message,
                      p.type AS last_message_type,
                      p.from_me AS last_message_from_me,
                      p.status AS last_message_status,
                      p.ts AS last_message_time,
                      COALESCE(c.unread_count, 0) AS unread_count,
                      COALESCE(ur.unresponded_count, 0) AS unresponded_count,
                      cm.assigned_agent,
                      cm.tags,
                      cm.avatar_url AS avatar
                    FROM page p
                    LEFT JOIN users u ON u.user_id = p.user_id
                    LEFT JOIN counts c ON c.user_id = p.user_id
                    LEFT JOIN unresponded ur ON ur.user_id = p.user_id
                    LEFT JOIN conversation_meta cm ON cm.user_id = p.user_id
                    ORDER BY p.ts DESC NULLS LAST
                    """
                )
                rows = await db.fetch(base, ws, limit, offset, ws, ws)
                conversations: List[dict] = []
                for r in rows:
                    # Normalize tags JSON to list
                    tags_raw = r["tags"] if "tags" in r else None
                    try:
                        tags_list = json.loads(tags_raw) if isinstance(tags_raw, str) and tags_raw else []
                    except Exception:
                        tags_list = []
                    conv = {
                        "user_id": r["user_id"],
                        "name": r["name"],
                        "phone": r["phone"],
                        "last_message": r["last_message"],
                        "last_message_time": r["last_message_time"],
                        "last_message_type": r["last_message_type"],
                        "last_message_from_me": bool(r["last_message_from_me"]) if r["last_message_from_me"] is not None else None,
                        "last_message_status": r["last_message_status"],
                        "unread_count": r["unread_count"] or 0,
                        "unresponded_count": r["unresponded_count"] or 0,
                        "avatar": (r["avatar"] if "avatar" in r else None),
                        "assigned_agent": r["assigned_agent"],
                        "tags": tags_list,
                    }
                    # Apply light in-memory filters
                    if q:
                        t = (conv.get("name") or conv.get("user_id") or "").lower()
                        if q.lower() not in t:
                            continue
                    if unread_only and not (conv.get("unread_count") or 0) > 0:
                        continue
                    if assigned is not None:
                        if assigned == "mine":
                            if viewer_agent and (conv.get("assigned_agent") not in (None, viewer_agent)):
                                continue
                        elif assigned == "unassigned" and conv.get("assigned_agent"):
                            continue
                        elif assigned not in (None, "unassigned") and conv.get("assigned_agent") != assigned:
                            continue
                    if tags:
                        conv_tags = set(conv.get("tags") or [])
                        if not set(tags).issubset(conv_tags):
                            continue
                    conversations.append(conv)
                return conversations

            # SQLite fallback path (existing logic)
            cur = await db.execute(self._convert("SELECT DISTINCT user_id FROM messages WHERE workspace = ?"), (ws,))
            user_rows = await cur.fetchall()
            user_ids = [r["user_id"] for r in user_rows]

            conversations = []
            for uid in user_ids:
                cur = await db.execute(self._convert("SELECT name, phone FROM users WHERE user_id = ?"), (uid,))
                user = await cur.fetchone()

                cur = await db.execute(
                    self._convert(
                        "SELECT message, type, from_me, status, COALESCE(server_ts, timestamp) AS ts FROM messages WHERE workspace = ? AND user_id = ? ORDER BY COALESCE(server_ts, timestamp) DESC LIMIT 1"
                    ),
                    (ws, uid)
                )
                last = await cur.fetchone()
                last_msg = last["message"] if last else None
                last_time = last["ts"] if last else None
                last_type = last["type"] if last else None
                last_from_me = bool(last["from_me"]) if last and ("from_me" in last) else None
                last_status = last["status"] if last else None

                cur = await db.execute(
                    self._convert("SELECT COUNT(*) AS c FROM messages WHERE workspace = ? AND user_id = ? AND from_me = 0 AND status != 'read'"),
                    (ws, uid)
                )
                unread_row = await cur.fetchone()
                unread = unread_row["c"]

                cur = await db.execute(
                    self._convert(
                        "SELECT MAX(COALESCE(server_ts, timestamp)) as t FROM messages WHERE workspace = ? AND user_id = ? AND from_me = 1"
                    ),
                    (ws, uid)
                )
                last_agent_row = await cur.fetchone()
                last_agent = (last_agent_row["t"] or "1970-01-01") if last_agent_row else "1970-01-01"

                cur = await db.execute(
                    self._convert(
                        "SELECT COUNT(*) AS c FROM messages WHERE workspace = ? AND user_id = ? AND from_me = 0 AND status = 'read' AND COALESCE(server_ts, timestamp) > ?"
                    ),
                    (ws, uid, last_agent),
                )
                unr_row = await cur.fetchone()
                unresponded = unr_row["c"]

                meta = await self.get_conversation_meta(uid)
                conv = {
                    "user_id": uid,
                    "name": user["name"] if user else None,
                    "phone": user["phone"] if user else None,
                    "last_message": last_msg,
                    "last_message_time": last_time,
                    "last_message_type": last_type,
                    "last_message_from_me": last_from_me,
                    "last_message_status": last_status,
                    "unread_count": unread,
                    "unresponded_count": unresponded,
                    "avatar": meta.get("avatar_url"),
                    "assigned_agent": meta.get("assigned_agent"),
                    "tags": meta.get("tags", []),
                }
                # Apply filters in-memory
                if q:
                    t = (conv.get("name") or conv.get("user_id") or "").lower()
                    if q.lower() not in t:
                        continue
                if unread_only and not (conv.get("unread_count") or 0) > 0:
                    continue
                if assigned is not None:
                    if assigned == "mine":
                        if viewer_agent and (conv.get("assigned_agent") not in (None, viewer_agent)):
                            continue
                    elif assigned == "unassigned" and conv.get("assigned_agent"):
                        continue
                    elif assigned not in (None, "unassigned") and conv.get("assigned_agent") != assigned:
                        continue
                if tags:
                    conv_tags = set(conv.get("tags") or [])
                    if not set(tags).issubset(conv_tags):
                        continue
                conversations.append(conv)

            conversations.sort(key=lambda x: x["last_message_time"] or "", reverse=True)
            # Apply pagination for SQLite path
            return conversations[offset: offset + limit]

    # ── Settings (key/value JSON) ──────────────────────────────────
    async def get_setting(self, key: str) -> Optional[str]:
        async with self._conn() as db:
            query = self._convert("SELECT value FROM settings WHERE key = ?")
            params = (key,)
            if self.use_postgres:
                row = await db.fetchrow(query, *params)
                return row[0] if row else None
            else:
                cur = await db.execute(query, params)
                row = await cur.fetchone()
                return row[0] if row else None

    async def set_setting(self, key: str, value: Any):
        # value is JSON-serializable
        data = json.dumps(value)
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT INTO settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value
                """
            )
            params = (key, data)
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def delete_setting(self, key: str) -> None:
        """Delete a settings key (best-effort)."""
        if not key:
            return
        async with self._conn() as db:
            query = self._convert("DELETE FROM settings WHERE key = ?")
            params = (key,)
            try:
                if self.use_postgres:
                    await db.execute(query, *params)
                else:
                    await db.execute(query, params)
                    await db.commit()
            except Exception:
                return

    # ── Automation stats (durable) ────────────────────────────────
    async def _ensure_automation_stats_table(self) -> None:
        """Ensure automation_rule_stats table exists (best-effort)."""
        async with self._conn() as db:
            stmt = self._convert(
                """
                CREATE TABLE IF NOT EXISTS automation_rule_stats (
                    rule_id         TEXT PRIMARY KEY,
                    triggers        INTEGER NOT NULL DEFAULT 0,
                    messages_sent   INTEGER NOT NULL DEFAULT 0,
                    tags_added      INTEGER NOT NULL DEFAULT 0,
                    last_trigger_ts TEXT
                )
                """
            )
            try:
                if self.use_postgres:
                    await db.execute(stmt)
                else:
                    await db.execute(stmt)
                    await db.commit()
            except Exception:
                return

    async def inc_automation_rule_stat(self, rule_id: str, field: str, inc: int = 1, *, last_trigger_ts: str | None = None) -> None:
        rid = str(rule_id or "").strip()
        if not rid:
            return
        col = str(field or "").strip().lower()
        if col not in ("triggers", "messages_sent", "tags_added"):
            return
        inc_n = int(inc or 0)
        if inc_n == 0:
            return
        try:
            await self._ensure_automation_stats_table()
        except Exception:
            pass
        async with self._conn() as db:
            # Upsert and increment the desired column; update last_trigger_ts when provided.
            if self.use_postgres:
                stmt = f"""
                INSERT INTO automation_rule_stats (rule_id, {col}, last_trigger_ts)
                VALUES ($1, $2, $3)
                ON CONFLICT (rule_id) DO UPDATE
                  SET {col} = automation_rule_stats.{col} + EXCLUDED.{col},
                      last_trigger_ts = COALESCE(EXCLUDED.last_trigger_ts, automation_rule_stats.last_trigger_ts)
                """
                await db.execute(stmt, rid, inc_n, last_trigger_ts)
            else:
                stmt = f"""
                INSERT INTO automation_rule_stats (rule_id, {col}, last_trigger_ts)
                VALUES (?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                  {col} = {col} + excluded.{col},
                  last_trigger_ts = COALESCE(excluded.last_trigger_ts, last_trigger_ts)
                """
                await db.execute(self._convert(stmt), (rid, inc_n, last_trigger_ts))
                await db.commit()

    async def get_automation_rule_stats(self, rule_ids: list[str]) -> dict[str, dict]:
        ids = [str(x or "").strip() for x in (rule_ids or []) if str(x or "").strip()]
        if not ids:
            return {}
        try:
            await self._ensure_automation_stats_table()
        except Exception:
            pass
        async with self._conn() as db:
            if self.use_postgres:
                # Use ANY($1) for array membership
                rows = await db.fetch(
                    "SELECT rule_id, triggers, messages_sent, tags_added, last_trigger_ts FROM automation_rule_stats WHERE rule_id = ANY($1)",
                    ids,
                )
            else:
                qmarks = ",".join(["?"] * len(ids))
                cur = await db.execute(
                    self._convert(
                        f"SELECT rule_id, triggers, messages_sent, tags_added, last_trigger_ts FROM automation_rule_stats WHERE rule_id IN ({qmarks})"
                    ),
                    tuple(ids),
                )
                rows = await cur.fetchall()
            out: dict[str, dict] = {}
            for r in rows or []:
                try:
                    d = dict(r) if not self.use_postgres else {
                        "rule_id": r["rule_id"],
                        "triggers": r["triggers"],
                        "messages_sent": r["messages_sent"],
                        "tags_added": r["tags_added"],
                        "last_trigger_ts": r["last_trigger_ts"],
                    }
                except Exception:
                    try:
                        d = dict(r)
                    except Exception:
                        continue
                rid = str(d.get("rule_id") or "").strip()
                if rid:
                    out[rid] = {
                        "triggers": int(d.get("triggers") or 0),
                        "messages_sent": int(d.get("messages_sent") or 0),
                        "tags_added": int(d.get("tags_added") or 0),
                        "last_trigger_ts": d.get("last_trigger_ts") or None,
                    }
            return out

    async def get_tag_options(self) -> List[dict]:
        raw = await self.get_setting("tag_options")
        try:
            options = json.loads(raw) if raw else []
            # ensure list of dicts with label and icon
            cleaned = []
            for opt in options or []:
                if isinstance(opt, dict) and opt.get("label"):
                    cleaned.append({"label": opt["label"], "icon": opt.get("icon", "")})
                elif isinstance(opt, str):
                    cleaned.append({"label": opt, "icon": ""})
            return cleaned
        except Exception:
            return []

    async def set_tag_options(self, options: List[dict]):
        # Persist as provided
        await self.set_setting("tag_options", options)

    # ----- Order payout helpers -----
    async def add_delivered_order(self, order_id: str):
        """Add an order to the payouts list."""
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT INTO orders (order_id, status)
                VALUES (?, ?)
                ON CONFLICT(order_id) DO UPDATE SET status=?
                """
            )
            params = [order_id, ORDER_STATUS_PAYOUT, ORDER_STATUS_PAYOUT]
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, tuple(params))
                await db.commit()

    async def mark_payout_paid(self, order_id: str):
        """Archive an order once its payout has been processed."""
        async with self._conn() as db:
            query = self._convert("UPDATE orders SET status=? WHERE order_id = ?")
            params = [ORDER_STATUS_ARCHIVED, order_id]
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, tuple(params))
                await db.commit()

    async def get_payouts(self) -> List[dict]:
        """Return orders currently awaiting payout."""
        async with self._conn() as db:
            if self.use_postgres:
                query = self._convert(
                    "SELECT * FROM orders WHERE status=? ORDER BY created_at DESC"
                )
            else:
                query = self._convert(
                    "SELECT * FROM orders WHERE status=? ORDER BY datetime(created_at) DESC"
                )
            params = [ORDER_STATUS_PAYOUT]
            if self.use_postgres:
                rows = await db.fetch(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_archived_orders(self) -> List[dict]:
        """Return archived (paid) orders."""
        async with self._conn() as db:
            if self.use_postgres:
                query = self._convert(
                    "SELECT * FROM orders WHERE status=? ORDER BY created_at DESC"
                )
            else:
                query = self._convert(
                    "SELECT * FROM orders WHERE status=? ORDER BY datetime(created_at) DESC"
                )
            params = [ORDER_STATUS_ARCHIVED]
            if self.use_postgres:
                rows = await db.fetch(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                rows = await cur.fetchall()
            return [dict(r) for r in rows]

    # ----- Agent analytics helpers -----
    async def log_order_created(self, order_id: str, user_id: Optional[str], agent_username: Optional[str]):
        async with self._conn() as db:
            query = self._convert(
                """
                INSERT INTO orders_created (order_id, user_id, agent_username, created_at)
                VALUES (?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
                """
            )
            # created_at left None for default
            params = [order_id, user_id, agent_username, None]
            if self.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, tuple(params))
                await db.commit()

    async def get_agent_analytics(self, agent_username: str, start: Optional[str] = None, end: Optional[str] = None) -> dict:
        # Default window: last 30 days
        end_iso = end or datetime.utcnow().isoformat()
        start_iso = start or (datetime.utcnow() - timedelta(days=30)).isoformat()
        async with self._conn() as db:
            params = [start_iso, end_iso, agent_username]

            # Durable analytics:
            # - received: inbound messages assigned to this agent at receive-time
            # - replied_to: number of inbound messages that this agent replied to (distinct inbound)
            # - sent: number of outbound messages successfully sent by this agent
            # - orders: number of orders created by this agent

            # inbound received (snapshot assignment)
            q_recv = self._convert(
                """
                SELECT COUNT(*) AS c
                FROM agent_events
                WHERE event_type = 'inbound_message'
                  AND assigned_agent = ?
                  AND SUBSTR(REPLACE(ts, ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                  AND SUBSTR(REPLACE(ts, ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                """
            )
            rparams = [agent_username, start_iso, end_iso]
            if self.use_postgres:
                row = await db.fetchrow(q_recv, *rparams)
                messages_received = int((row[0] if row else 0) or 0)
            else:
                cur = await db.execute(q_recv, tuple(rparams))
                row = await cur.fetchone()
                messages_received = int((row[0] if row else 0) or 0)

            # inbound replied-to (distinct inbound)
            q_replied = self._convert(
                """
                SELECT COUNT(*) AS c
                FROM inbound_replies
                WHERE replied_by_agent = ?
                  AND SUBSTR(REPLACE(first_reply_ts, ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                  AND SUBSTR(REPLACE(first_reply_ts, ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                """
            )
            if self.use_postgres:
                row = await db.fetchrow(q_replied, *rparams)
                messages_replied_to = int((row[0] if row else 0) or 0)
            else:
                cur = await db.execute(q_replied, tuple(rparams))
                row = await cur.fetchone()
                messages_replied_to = int((row[0] if row else 0) or 0)

            # outbound sent (final WA id saved)
            q_sent = self._convert(
                """
                SELECT COUNT(*) AS c
                FROM agent_events
                WHERE event_type = 'outbound_message'
                  AND agent_username = ?
                  AND SUBSTR(REPLACE(ts, ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                  AND SUBSTR(REPLACE(ts, ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                """
            )
            if self.use_postgres:
                row = await db.fetchrow(q_sent, *rparams)
                messages_sent = int((row[0] if row else 0) or 0)
            else:
                cur = await db.execute(q_sent, tuple(rparams))
                row = await cur.fetchone()
                messages_sent = int((row[0] if row else 0) or 0)

            # orders created
            q_order = self._convert(
                """
                SELECT COUNT(*) AS c
                FROM orders_created
                WHERE agent_username = ?
                  AND SUBSTR(REPLACE(created_at, ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                  AND SUBSTR(REPLACE(created_at, ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                """
            )
            if self.use_postgres:
                row = await db.fetchrow(q_order, *rparams)
                orders_created = int((row[0] if row else 0) or 0)
            else:
                cur = await db.execute(q_order, tuple(rparams))
                row = await cur.fetchone()
                orders_created = int((row[0] if row else 0) or 0)

            # average response time in seconds (to previous inbound)
            if self.use_postgres:
                q_avg = self._convert(
                    """
                    SELECT AVG(
                        EXTRACT(EPOCH FROM CAST(COALESCE(m.server_ts, m.timestamp) AS TIMESTAMP)) -
                        EXTRACT(EPOCH FROM CAST((
                            SELECT COALESCE(mi.server_ts, mi.timestamp)
                            FROM messages mi
                            WHERE mi.user_id = m.user_id AND mi.from_me = 0
                                  AND COALESCE(mi.server_ts, mi.timestamp) <= COALESCE(m.server_ts, m.timestamp)
                            ORDER BY COALESCE(mi.server_ts, mi.timestamp) DESC
                            LIMIT 1
                        ) AS TIMESTAMP))
                    ) AS avg_sec
                    FROM messages m
                    WHERE m.from_me = 1 AND m.agent_username = ?
                      AND SUBSTR(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                      AND SUBSTR(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                    """
                )
            else:
                q_avg = self._convert(
                    """
                    SELECT AVG(
                        strftime('%s', COALESCE(m.server_ts, m.timestamp)) -
                        strftime('%s', (
                            SELECT COALESCE(mi.server_ts, mi.timestamp)
                            FROM messages mi
                            WHERE mi.user_id = m.user_id AND mi.from_me = 0
                                  AND COALESCE(mi.server_ts, mi.timestamp) <= COALESCE(m.server_ts, m.timestamp)
                            ORDER BY COALESCE(mi.server_ts, mi.timestamp) DESC
                            LIMIT 1
                        ))
                    ) AS avg_sec
                    FROM messages m
                    WHERE m.from_me = 1 AND m.agent_username = ?
                      AND SUBSTR(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T'), 1, 19) >= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                      AND SUBSTR(REPLACE(COALESCE(m.server_ts, m.timestamp), ' ', 'T'), 1, 19) <= SUBSTR(REPLACE(?, ' ', 'T'), 1, 19)
                    """
                )
            if self.use_postgres:
                row = await db.fetchrow(q_avg, *params)
                avg_response_seconds = float(row[0]) if row and row[0] is not None else None
            else:
                cur = await db.execute(q_avg, tuple(params))
                row = await cur.fetchone()
                avg_response_seconds = float(row[0]) if row and row[0] is not None else None

            return {
                "agent": agent_username,
                "start": start_iso,
                "end": end_iso,
                # Backwards compatible field name, but now counts *successful outbound sends* from durable events
                "messages_sent": int(messages_sent),
                # New, more precise breakdown
                "messages_received": int(messages_received),
                "messages_replied_to": int(messages_replied_to),
                "orders_created": int(orders_created),
                **({"avg_response_seconds": avg_response_seconds} if avg_response_seconds is not None else {}),
            }

    async def get_all_agents_analytics(self, start: Optional[str] = None, end: Optional[str] = None) -> List[dict]:
        agents = await self.list_agents()
        results: List[dict] = []
        for a in agents:
            username = a.get("username")
            if not username:
                continue
            stats = await self.get_agent_analytics(username, start, end)
            # add agent name if present
            if a.get("name"):
                stats["name"] = a.get("name")
            results.append(stats)
        return results


class WorkspaceDatabaseRouter:
    """Route DB operations to the correct DatabaseManager based on current workspace.

    This is a thin delegator: all real methods live on DatabaseManager.
    """

    def __init__(self, managers: Dict[str, DatabaseManager]):
        self._managers = managers or {}

    def _mgr(self, workspace: str | None = None) -> DatabaseManager:
        ws = _coerce_workspace(workspace) if workspace else get_current_workspace()
        m = self._managers.get(ws)
        if m:
            return m
        # If an admin added a new workspace at runtime, lazily create its DB manager
        # so data stays isolated even without a restart.
        try:
            # NOTE: We intentionally allow lazy tenant creation even when ENABLE_MULTI_WORKSPACE=0.
            # In that mode, the default workspace continues to use the legacy DB_PATH,
            # but additional workspaces get their own derived tenant DB so inbox data/settings never leak.
            if ws and ws != DEFAULT_WORKSPACE:
                db_url = (TENANT_DB_URLS or {}).get(ws) or (TENANT_DB_URLS or {}).get(DEFAULT_WORKSPACE) or DATABASE_URL
                db_path = (TENANT_DB_PATHS or {}).get(ws) or _derive_tenant_db_path(DB_PATH, ws)
                try:
                    TENANT_DB_PATHS[ws] = db_path
                except Exception:
                    pass
                try:
                    # Keep a string entry; DatabaseManager will normalize/ignore invalid URLs.
                    TENANT_DB_URLS[ws] = str(db_url or "")
                except Exception:
                    pass
                m = DatabaseManager(db_path=db_path, db_url=db_url)
                self._managers[ws] = m
                return m
        except Exception:
            pass
        m2 = self._managers.get(DEFAULT_WORKSPACE)
        if m2:
            return m2
        # last resort: any manager
        return next(iter(self._managers.values()))

    @property
    def use_postgres(self) -> bool:
        return bool(getattr(self._mgr(), "use_postgres", False))

    @property
    def db_path(self) -> str:
        return str(getattr(self._mgr(), "db_path", DB_PATH))

    @property
    def db_url(self) -> str | None:
        return getattr(self._mgr(), "db_url", None)

    @asynccontextmanager
    async def _conn(self):
        async with self._mgr()._conn() as db:
            yield db

    def __getattr__(self, name: str):
        return getattr(self._mgr(), name)

# Message Processor with Complete Optimistic UI
class MessageProcessor:
    def __init__(self, connection_manager: ConnectionManager, redis_manager: RedisManager, db_manager: DatabaseManager):
        self.connection_manager = connection_manager
        self.redis_manager = redis_manager
        self.db_manager = db_manager
        # Seed routing from env for backwards compat; runtime can be updated from DB settings without redeploy.
        self.whatsapp_messenger = WorkspaceWhatsAppRouter(RUNTIME_WHATSAPP_CONFIG_BY_WORKSPACE)
        self.media_dir = MEDIA_DIR
        self.media_dir.mkdir(exist_ok=True)
        # Best-effort in-memory cache for automation rules (workspace-scoped)
        self._automation_rules_cache: dict[str, tuple[float, list[dict]]] = {}
        # Best-effort in-memory cache for inbox environment overrides (workspace-scoped)
        self._inbox_env_cache: dict[str, tuple[float, dict]] = {}

    async def _ensure_automation_rules_v2(self) -> list[dict]:
        """Ensure the global automation rules store exists in the shared auth/settings DB.

        - New canonical key: auth_db_manager setting "automation_rules_v2"
        - Backwards compatibility: migrate existing per-workspace "automation_rules" into v2
          (each migrated rule becomes scoped to the workspace it came from).
        """
        global _AUTOMATION_RULES_V2_INIT_DONE
        async with _AUTOMATION_RULES_V2_INIT_LOCK:
            if _AUTOMATION_RULES_V2_INIT_DONE:
                try:
                    raw = await auth_db_manager.get_setting("automation_rules_v2")
                    data = json.loads(raw) if raw else []
                    return data if isinstance(data, list) else []
                except Exception:
                    return []

            # 1) Try load existing v2
            try:
                raw = await auth_db_manager.get_setting("automation_rules_v2")
                data = json.loads(raw) if raw else []
                if isinstance(data, list) and len(data) > 0:
                    _AUTOMATION_RULES_V2_INIT_DONE = True
                    return data
            except Exception:
                pass

            # 2) Migrate from per-workspace v1 store: tenant DB setting "automation_rules"
            merged: dict[str, dict] = {}
            for ws in sorted(list(_all_workspaces_set())):
                w = _normalize_workspace_id(ws)
                if not w:
                    continue
                tok = None
                try:
                    tok = _CURRENT_WORKSPACE.set(_coerce_workspace(w))
                    raw = await db_manager.get_setting("automation_rules")
                    rules = json.loads(raw) if raw else []
                    if not isinstance(rules, list):
                        rules = []
                except Exception:
                    rules = []
                finally:
                    if tok is not None:
                        try:
                            _CURRENT_WORKSPACE.reset(tok)
                        except Exception:
                            pass
                for r in rules or []:
                    if not isinstance(r, dict):
                        continue
                    rid = str(r.get("id") or "").strip()
                    if not rid:
                        continue
                    existing = merged.get(rid)
                    if not existing:
                        rr = dict(r)
                        rr.setdefault("workspaces", [w])
                        merged[rid] = rr
                    else:
                        # Merge workspace scopes
                        try:
                            s = set([_normalize_workspace_id(x) for x in (existing.get("workspaces") or []) if _normalize_workspace_id(x)])
                            s.add(w)
                            existing["workspaces"] = sorted(list(s))
                        except Exception:
                            existing["workspaces"] = [w]

            out = list(merged.values())
            try:
                # Persist migration for future calls
                await auth_db_manager.set_setting("automation_rules_v2", out)
            except Exception:
                pass
            _AUTOMATION_RULES_V2_INIT_DONE = True
            return out

    async def _get_inbox_env(self, workspace: str | None = None) -> dict:
        """Return effective inbox environment settings (DB overrides layered on top of env defaults).

        Stored in DB under settings key "inbox_env" (per-workspace) as JSON:
          {
            "allowed_phone_number_ids": ["..."],
            "survey_test_numbers": ["2126..."],  (digits only)
            "auto_reply_test_numbers": ["2126..."], (digits only)
            "waba_id": "1234567890",
            "catalog_id": "1234567890",
            "phone_number_id": "1234567890",
            "meta_app_id": "1234567890"
            ,"webhook_verify_token": "..."
          }
        """
        ws = _coerce_workspace(workspace or get_current_workspace())
        now = time.time()
        try:
            cached = self._inbox_env_cache.get(ws)
            if cached and (now - float(cached[0])) < 3.0:
                return cached[1] or {}
        except Exception:
            pass

        # Defaults from env
        allowed_default: set[str] = set(ALLOWED_PHONE_NUMBER_IDS or set())
        survey_default: set[str] = set(SURVEY_TEST_NUMBERS or set())
        auto_reply_default: set[str] = set(AUTO_REPLY_TEST_NUMBERS or set())
        # Defaults for new fields
        catalog_default: str = ""
        phone_default: str = ""
        token_default: str = ""
        meta_app_id_default: str = ""
        try:
            # Allow per-workspace env override: CATALOG_ID_<WS>
            suf = re.sub(r"[^A-Z0-9]+", "_", str(ws or "").strip().upper())
            catalog_default = str(os.getenv(f"CATALOG_ID_{suf}", "") or "").strip() or str(CATALOG_ID or "").strip()
        except Exception:
            catalog_default = str(CATALOG_ID or "").strip()
        try:
            phone_default = str((WHATSAPP_CONFIG_BY_WORKSPACE or {}).get(ws, {}).get("phone_number_id") or "").strip() or str(PHONE_NUMBER_ID or "").strip()
        except Exception:
            phone_default = str(PHONE_NUMBER_ID or "").strip()
        try:
            token_default = str((WHATSAPP_CONFIG_BY_WORKSPACE or {}).get(ws, {}).get("access_token") or "").strip() or str(ACCESS_TOKEN or "").strip()
        except Exception:
            token_default = str(ACCESS_TOKEN or "").strip()
        try:
            meta_app_id_default = str(META_APP_ID or "").strip()
        except Exception:
            meta_app_id_default = ""

        # Overrides from DB (optional)
        overrides: dict = {}
        try:
            raw = await self.db_manager.get_setting(_ws_setting_key("inbox_env", ws))
            if (not raw) and ws == _coerce_workspace(DEFAULT_WORKSPACE):
                # Back-compat: older deployments stored default workspace under the plain key.
                raw = await self.db_manager.get_setting("inbox_env")
            overrides = json.loads(raw) if raw else {}
        except Exception:
            overrides = {}
        if not isinstance(overrides, dict):
            overrides = {}

        def _as_list(v):
            if isinstance(v, list):
                return v
            if isinstance(v, str):
                # allow comma/newline separated strings
                parts = []
                for chunk in v.replace("\r", "\n").split("\n"):
                    parts.extend([x.strip() for x in chunk.split(",") if x.strip()])
                return parts
            return []

        allowed_override_raw = _as_list(overrides.get("allowed_phone_number_ids"))
        survey_override_raw = _as_list(overrides.get("survey_test_numbers"))
        auto_reply_override_raw = _as_list(overrides.get("auto_reply_test_numbers"))

        allowed_effective = set([str(x).strip() for x in allowed_override_raw if str(x).strip()]) if allowed_override_raw else allowed_default
        survey_effective = set([_digits_only(str(x).strip()) for x in survey_override_raw if str(x).strip()]) if survey_override_raw else survey_default
        auto_reply_effective = set([_digits_only(str(x).strip()) for x in auto_reply_override_raw if str(x).strip()]) if auto_reply_override_raw else auto_reply_default
        catalog_effective = str((overrides or {}).get("catalog_id") or "").strip() or catalog_default or None
        phone_effective = str((overrides or {}).get("phone_number_id") or "").strip() or phone_default or None
        token_effective = str((overrides or {}).get("access_token") or "").strip() or token_default or None
        meta_app_id_effective = str((overrides or {}).get("meta_app_id") or "").strip() or meta_app_id_default or None
        webhook_verify_token_effective = str((overrides or {}).get("webhook_verify_token") or "").strip() or (str(VERIFY_TOKEN or "").strip() or None)

        out = {
            "workspace": ws,
            "allowed_phone_number_ids": allowed_effective,
            "survey_test_numbers": survey_effective,
            "auto_reply_test_numbers": auto_reply_effective,
            "waba_id": str((overrides or {}).get("waba_id") or "").strip() or None,
            "catalog_id": catalog_effective,
            "phone_number_id": phone_effective,
            "access_token": token_effective,
            "meta_app_id": meta_app_id_effective,
            "webhook_verify_token": webhook_verify_token_effective,
            "overrides": overrides,
        }
        try:
            self._inbox_env_cache[ws] = (now, out)
        except Exception:
            pass
        return out
    
    # Fix the method that was duplicated at the bottom of the file
    async def process_outgoing_message(self, message_data: dict) -> dict:
        """Process outgoing message with instant UI update"""
        user_id = message_data["user_id"]
        await self.db_manager.upsert_user(user_id)
        message_text = str(message_data.get("message", ""))
        message_type = message_data.get("type", "text")
        
        # Generate temporary message ID for instant UI
        # Re-use the temp_id that the React app already put in the payload
        # so the optimistic bubble can be updated instead of duplicated
        temp_id = (
            message_data.get("temp_id")          # ChatWindow / CatalogPanel
            or message_data.get("id")            # safety-net (sometimes they send id only)
            or f"temp_{uuid.uuid4().hex}"        # fall-back if neither exists
        )
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Create optimistic message object
        optimistic_message = {
            "id": temp_id,
            "user_id": user_id,
            "message": message_text,
            "type": message_type,
            "from_me": True,
            "status": "sending",  # Optimistic status
            "timestamp": timestamp,
            "server_ts": timestamp,
            "temp_id": temp_id,
            "price": message_data.get("price", ""),
            "caption": message_data.get("caption", ""),
            "media_path": message_data.get("media_path"),  # Add this field
            # Pass-through identifiers for catalog items so background sender can use them
            "product_retailer_id": (
                message_data.get("product_retailer_id")
                or message_data.get("retailer_id")
                or message_data.get("product_id")
            ),
            # Preserve raw fields as well for debugging/DB if present
            "retailer_id": message_data.get("retailer_id"),
            "product_id": message_data.get("product_id"),
            # carry flags
            "needs_bilingual_prompt": bool(message_data.get("needs_bilingual_prompt")),
            # reply/reactions passthrough
            "reply_to": message_data.get("reply_to"),
            # buttons passthrough for interactive messages
            "buttons": message_data.get("buttons"),
            # template passthrough (for WhatsApp template sends)
            "template_name": message_data.get("template_name"),
            "template_language": message_data.get("template_language"),
            "template_components": message_data.get("template_components"),
        }
        # Attach agent attribution if present
        agent_username = message_data.get("agent_username")
        if agent_username:
            optimistic_message["agent_username"] = agent_username
            # Also include a generic 'agent' alias for UI compatibility
            optimistic_message["agent"] = agent_username
        
        # For media messages, add URL field
        if message_type in ["image", "audio", "video"]:
            if message_data.get("url"):
                optimistic_message["url"] = message_data["url"]
            elif message_text and not message_text.startswith("http"):
                filename = Path(message_text).name
                optimistic_message["url"] = f"{BASE_URL}/media/{filename}"
            else:
                optimistic_message["url"] = message_text
            # pass-through waveform if present
            if message_type == "audio" and isinstance(message_data.get("waveform"), list):
                optimistic_message["waveform"] = message_data.get("waveform")
        
        # 1. INSTANT: Send to UI immediately (optimistic update)
        await self.connection_manager.send_to_user(user_id, {
            "type": "message_sent",
            "data": optimistic_message
        })

        # Also notify inbox listeners so conversation previews update across agents/tabs.
        # The admin UI listens for "message_received" events on /ws/admin and uses them as live previews.
        try:
            await self.connection_manager.broadcast_to_admins(
                {"type": "message_received", "data": optimistic_message}
            )
        except Exception:
            pass
        
        # 2. Cache for quick retrieval
        await self.redis_manager.cache_message(user_id, optimistic_message)
        
        # 3. BACKGROUND: Send to WhatsApp API
        asyncio.create_task(self._send_to_whatsapp_bg(optimistic_message))
        
        return optimistic_message

    # -------------------- Shopify helpers --------------------
    async def _fetch_shopify_variant(self, variant_id: str) -> Optional[dict]:
        try:
            import httpx  # type: ignore
            from .shopify_integration import admin_api_base, _client_args  # type: ignore
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(f"{admin_api_base()}/variants/{variant_id}.json", **_client_args())
                if resp.status_code == 200:
                    return (resp.json() or {}).get("variant") or None
        except Exception:
            return None
        return None

    async def _resolve_shopify_variant(self, numeric_id: str) -> tuple[Optional[str], Optional[dict]]:
        """Return a valid Shopify variant id and variant dict.

        If the provided id is a product id, attempt to fetch its first variant.
        """
        # 1) Try as variant id directly
        v = await self._fetch_shopify_variant(numeric_id)
        if v and v.get("id"):
            return str(v.get("id")), v
        # 2) Try as product id -> first variant
        try:
            import httpx  # type: ignore
            from .shopify_integration import admin_api_base, _client_args  # type: ignore
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(f"{admin_api_base()}/products/{numeric_id}.json", **_client_args())
                if resp.status_code == 200:
                    prod = (resp.json() or {}).get("product") or {}
                    variants = prod.get("variants") or []
                    if variants:
                        v0 = variants[0]
                        # Enrich minimal fields similar to /shopify-variant
                        v0["product_title"] = prod.get("title")
                        images = prod.get("images") or []
                        image_src = (prod.get("image") or {}).get("src") or (images[0].get("src") if images else None)
                        if image_src:
                            v0["image_src"] = image_src
                        return str(v0.get("id")), v0
        except Exception:
            pass
        return None, None

    async def _handle_order_status_request(self, user_id: str) -> None:
        """Fetch recent orders (last 4 days) for this phone and send details."""
        try:
            import httpx  # type: ignore
            from .shopify_integration import fetch_customer_by_phone, admin_api_base, _client_args  # type: ignore
            cust = await fetch_customer_by_phone(user_id)
            if not cust or not isinstance(cust, dict) or not cust.get("customer_id"):
                await self.process_outgoing_message({
                    "user_id": user_id,
                    "type": "text",
                    "from_me": True,
                    "message": (
                        "Aucune commande trouvée pour votre numéro.\n"
                        "لم يتم العثور على أي طلب مرتبط برقم هاتفك."
                    ),
                    "timestamp": datetime.utcnow().isoformat(),
                })
                return
            customer_id = cust["customer_id"]
            now = datetime.utcnow()
            since = (now - timedelta(days=4)).isoformat() + "Z"
            params = {
                "customer_id": str(customer_id),
                "status": "any",
                "order": "created_at desc",
                "limit": 10,
                "created_at_min": since,
            }
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{admin_api_base()}/orders.json", params=params, **_client_args())
                if resp.status_code >= 400:
                    raise Exception(f"Shopify orders error {resp.status_code}")
                orders = (resp.json() or {}).get("orders", [])
            if not orders:
                await self.process_outgoing_message({
                    "user_id": user_id,
                    "type": "text",
                    "from_me": True,
                    "message": (
                        "Aucune commande des 4 derniers jours.\n"
                        "لا توجد طلبات خلال آخر 4 أيام."
                    ),
                    "timestamp": datetime.utcnow().isoformat(),
                })
                return
            # Compose bilingual summary
            lines_fr: list[str] = ["Voici vos commandes (4 derniers jours):"]
            lines_ar: list[str] = ["هذه طلباتك خلال آخر 4 أيام:"]
            # Also collect up to 2 images to send
            images: list[tuple[str, str]] = []  # (url, caption)
            for o in orders[:3]:
                name = o.get("name") or f"#{o.get('id')}"
                created_at = o.get("created_at", "")
                status = o.get("fulfillment_status") or "unfulfilled"
                status_fr = "expédiée" if status == "fulfilled" else "non expédiée"
                status_ar = "مكتملة" if status == "fulfilled" else "غير مكتملة"
                lines_fr.append(f"- {name} — {created_at[:10]} — Statut: {status_fr}")
                lines_ar.append(f"- {name} — {created_at[:10]} — الحالة: {status_ar}")
                for li in (o.get("line_items") or [])[:2]:
                    t = li.get("title") or ""
                    vt = li.get("variant_title") or ""
                    q = li.get("quantity") or 1
                    lines_fr.append(f"  • {t} — {vt} ×{q}")
                    lines_ar.append(f"  • {t} — {vt} ×{q}")
                    # Try to resolve variant image
                    try:
                        vid = li.get("variant_id")
                        if vid and len(images) < 2:
                            v_id_str, v_obj = await self._resolve_shopify_variant(str(vid))
                            img = (v_obj or {}).get("image_src")
                            if img:
                                cap = f"{t} — {vt}"
                                images.append((img, cap))
                    except Exception:
                        pass
            summary = "\n".join(lines_fr + [""] + lines_ar)
            await self.process_outgoing_message({
                "user_id": user_id,
                "type": "text",
                "from_me": True,
                "message": summary,
                "timestamp": datetime.utcnow().isoformat(),
            })
            for url, cap in images:
                await self.process_outgoing_message({
                    "user_id": user_id,
                    "type": "image",
                    "from_me": True,
                    "message": url,
                    "url": url,
                    "caption": cap,
                    "timestamp": datetime.utcnow().isoformat(),
                })
        except Exception as exc:
            print(f"order status fetch error: {exc}")
            await self.process_outgoing_message({
                "user_id": user_id,
                "type": "text",
                "from_me": True,
                "message": (
                    "Une erreur est survenue lors de la récupération de vos commandes.\n"
                    "حدث خطأ أثناء جلب طلباتك."
                ),
                "timestamp": datetime.utcnow().isoformat(),
            })

    async def _send_buy_gender_list(self, user_id: str) -> None:
        body = (
            "Veuillez choisir: Fille ou Garçon\n"
            "يرجى الاختيار: بنت أم ولد"
        )
        sections = [{
            "title": "Genre | النوع",
            "rows": [
                {"id": "gender_girls", "title": "Fille | بنت"},
                {"id": "gender_boys", "title": "Garçon | ولد"},
            ],
        }]
        await self.process_outgoing_message({
            "user_id": user_id,
            "type": "list",
            "from_me": True,
            "message": body,
            "button_text": "Choisir | اختر",
            "sections": sections,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _send_gender_prompt(self, user_id: str, reply_id: str) -> None:
        if reply_id == "gender_girls":
            msg = (
                "Filles: indiquez l'âge (0 mois à 7 ans) et la pointure (16 à 38).\n"
                "البنات: يرجى تزويدنا بالعمر (من 0 شهر إلى 7 سنوات) ومقاس الحذاء (من 16 إلى 38)."
            )
        else:
            msg = (
                "Garçons: indiquez l'âge (0 mois à 10 ans) et la pointure (16 à 38).\n"
                "الأولاد: يرجى تزويدنا بالعمر (من 0 شهر إلى 10 سنوات) ومقاس الحذاء (من 16 إلى 38)."
            )
        await self.process_outgoing_message({
            "user_id": user_id,
            "type": "text",
            "from_me": True,
            "message": msg,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _send_to_whatsapp_bg(self, message: dict):
        """Background task to send message to WhatsApp and update status"""
        temp_id = message["temp_id"]
        user_id = message["user_id"]
        # Internal channels: user_id starting with "team:", "agent:", or "dm:" are NOT sent to WhatsApp
        if isinstance(user_id, str) and (
            user_id.startswith("team:") or user_id.startswith("agent:") or user_id.startswith("dm:")
        ):
            try:
                # Mark as sent immediately for internal channels
                await self.connection_manager.send_to_user(
                    user_id,
                    {"type": "message_status_update", "data": {"temp_id": temp_id, "status": "sent"}},
                )
                final_record = {**message, "status": "sent"}
                await self.db_manager.upsert_message(final_record)
                await self.redis_manager.cache_message(user_id, final_record)
                # Let admin dashboards update their lists
                try:
                    await self.connection_manager.broadcast_to_admins(
                        {"type": "message_received", "data": final_record}
                    )
                except Exception:
                    pass
            except Exception as exc:
                print(f"Internal channel processing error: {exc}")
            return
        
        try:
            # Send to WhatsApp API with concurrency guard
            async with wa_semaphore:
                if message["type"] == "text":
                    # If template metadata is present, send a template message instead of plain text.
                    tname = str(message.get("template_name") or "").strip()
                    if tname:
                        lang = str(message.get("template_language") or "en").strip() or "en"
                        comps = message.get("template_components") or []
                        if not isinstance(comps, list):
                            comps = []
                        wa_response = await self.whatsapp_messenger.send_template_message(
                            user_id,
                            tname,
                            language=lang,
                            components=comps,
                            context_message_id=message.get("reply_to"),
                        )
                    else:
                        wa_response = await self.whatsapp_messenger.send_text_message(
                            user_id, message["message"], context_message_id=message.get("reply_to")
                        )
                elif message["type"] in ("catalog_item", "interactive_product"):
                    # Interactive single product via catalog
                    retailer_id = (
                        message.get("retailer_id")
                        or message.get("product_retailer_id")
                        or message.get("product_id")
                    )
                    caption = message.get("caption") or message.get("message") or ""
                    if not retailer_id:
                        raise Exception("Missing product_retailer_id for catalog_item")
                    try:
                        cid = None
                        try:
                            env_cfg = await self._get_inbox_env(get_current_workspace())
                            cid = (env_cfg or {}).get("catalog_id") or None
                        except Exception:
                            cid = None
                        wa_response = await self.whatsapp_messenger.send_single_catalog_item(
                            user_id, str(retailer_id), caption, catalog_id=cid
                        )
                        # After interactive is delivered, optionally send bilingual prompt as a reply
                        if message.get("needs_bilingual_prompt"):
                            wa_msg_id = None
                            try:
                                wa_msg_id = (((wa_response or {}).get("messages") or [{}])[0] or {}).get("id")
                            except Exception:
                                wa_msg_id = None
                            prompt = (
                                "*Bienvenue chez IRRAKIDS* 👋\n"
                                "*Merci de nous indiquer :*\n"
                                "• Taille souhaitée 📏\n"
                                "• Âge de l'enfant 🎂\n"
                                "• Garçon ou fille 👦👧\n"
                                "*Nous vérifierons la disponibilité et vous proposerons d'autres articles adaptés à votre enfant.*\n"
                                "*مرحبًا بك في IRRAKIDS* 👋\n"
                                "*يرجى تزويدنا بـ:*\n"
                                "• المقاس المطلوب 📏\n"
                                "• عمر الطفل 🎂\n"
                                "• هل هو ولد أم بنت 👦👧\n"
                                "*سنتاكد من تواجد القياس ونرسل لك المنتجات المناسبة لقياس طفلك*"
                            )
                            await self.process_outgoing_message({
                                "user_id": user_id,
                                "type": "text",
                                "from_me": True,
                                "message": prompt,
                                **({"reply_to": wa_msg_id} if wa_msg_id else {}),
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                    except Exception as _exc:
                        # Fallback: try to send first image from cached catalog for visibility
                        try:
                            ws = get_current_workspace()
                            cid = await _get_effective_catalog_id(ws)
                            products = catalog_manager.get_cached_products(cache_file=_catalog_cache_file_for(ws, cid))
                        except Exception:
                            products = []
                        img_url = None
                        price = ""
                        if products:
                            try:
                                p = next((p for p in products if str(p.get("retailer_id")) == str(retailer_id)), None)
                                if p:
                                    images = p.get("images") or []
                                    if images:
                                        img_url = images[0].get("url")
                                    price = p.get("price") or ""
                            except Exception:
                                pass
                        # If not found in Meta catalog, try Shopify variant image using the UI variant id
                        if not img_url:
                            try:
                                ui_variant_id = (
                                    message.get("product_retailer_id")
                                    or message.get("product_id")
                                    or ""
                                )
                                if ui_variant_id:
                                    v = await self._fetch_shopify_variant(str(ui_variant_id))
                                    if v and v.get("image_src"):
                                        img_url = v.get("image_src")
                                        price = v.get("price") or price
                                        # If caption is empty, use variant title
                                        if not caption:
                                            caption = v.get("title") or ""
                            except Exception:
                                pass
                        if img_url:
                            # Send as image with caption if interactive fails
                            wa_response = await self.whatsapp_messenger.send_media_message(
                                user_id, "image", img_url, caption or (price and f"{price} MAD" or "")
                            )
                            if message.get("needs_bilingual_prompt"):
                                wa_msg_id = None
                                try:
                                    wa_msg_id = (((wa_response or {}).get("messages") or [{}])[0] or {}).get("id")
                                except Exception:
                                    wa_msg_id = None
                                prompt = (
                                    "*Bienvenue chez IRRAKIDS* 👋\n"
                                    "*Merci de nous indiquer :*\n"
                                    "• Taille souhaitée 📏\n"
                                    "• Âge de l'enfant 🎂\n"
                                    "• Garçon ou fille 👦👧\n"
                                    "*Nous vérifierons la disponibilité et vous proposerons d'autres articles adaptés à votre enfant.*\n"
                                    "*مرحبًا بك في IRRAKIDS* 👋\n"
                                    "*يرجى تزويدنا بـ:*\n"
                                    "• المقاس المطلوب 📏\n"
                                    "• عمر الطفل 🎂\n"
                                    "• هل هو ولد أم بنت 👦👧\n"
                                    "*سنتاكد من تواجد القياس ونرسل لك المنتجات المناسبة لقياس طفلك*"
                                )
                                await self.process_outgoing_message({
                                    "user_id": user_id,
                                    "type": "text",
                                    "from_me": True,
                                    "message": prompt,
                                    **({"reply_to": wa_msg_id} if wa_msg_id else {}),
                                    "timestamp": datetime.utcnow().isoformat(),
                                })
                        else:
                            # Final fallback to text
                            wa_response = await self.whatsapp_messenger.send_text_message(
                                user_id, caption or str(retailer_id)
                            )
                            if message.get("needs_bilingual_prompt"):
                                wa_msg_id = None
                                try:
                                    wa_msg_id = (((wa_response or {}).get("messages") or [{}])[0] or {}).get("id")
                                except Exception:
                                    wa_msg_id = None
                                prompt = (
                                    "*Bienvenue chez IRRAKIDS* 👋\n"
                                    "*Merci de nous indiquer :*\n"
                                    "• Taille souhaitée 📏\n"
                                    "• Âge de l'enfant 🎂\n"
                                    "• Garçon ou fille 👦👧\n"
                                    "*Nous vérifierons la disponibilité et vous proposerons d'autres articles adaptés à votre enfant.*\n"
                                    "*مرحبًا بك في IRRAKIDS* 👋\n"
                                    "*يرجى تزويدنا بـ:*\n"
                                    "• المقاس المطلوب 📏\n"
                                    "• عمر الطفل 🎂\n"
                                    "• هل هو ولد أم بنت 👦👧\n"
                                    "*سنتاكد من تواجد القياس ونرسل لك المنتجات المناسبة لقياس طفلك*"
                                )
                                await self.process_outgoing_message({
                                    "user_id": user_id,
                                    "type": "text",
                                    "from_me": True,
                                    "message": prompt,
                                    **({"reply_to": wa_msg_id} if wa_msg_id else {}),
                                    "timestamp": datetime.utcnow().isoformat(),
                                })
                elif message["type"] in ("buttons", "interactive_buttons"):
                    body_text = message.get("message") or ""
                    buttons = message.get("buttons") or []
                    if not isinstance(buttons, list) or not buttons:
                        # Fallback to text to avoid hard failure
                        wa_response = await self.whatsapp_messenger.send_text_message(
                            user_id, body_text or ""
                        )
                    else:
                        wa_response = await self.whatsapp_messenger.send_reply_buttons(
                            user_id, body_text, buttons
                        )
                elif message["type"] in ("list", "interactive_list"):
                    body_text = message.get("message") or ""
                    sections = message.get("sections") or []
                    button_text = message.get("button_text") or "Choose"
                    header_text = message.get("header_text") or None
                    footer_text = message.get("footer_text") or None
                    if not isinstance(sections, list) or not sections:
                        wa_response = await self.whatsapp_messenger.send_text_message(
                            user_id, body_text or ""
                        )
                    else:
                        wa_response = await self.whatsapp_messenger.send_list_message(
                            user_id,
                            body_text,
                            button_text,
                            sections,
                            header_text=header_text,
                            footer_text=footer_text,
                        )
                elif message["type"] == "order":
                    # For now send order payload as text to ensure delivery speed
                    payload = message.get("message")
                    wa_response = await self.whatsapp_messenger.send_text_message(
                        user_id, payload if isinstance(payload, str) else json.dumps(payload or {})
                    )
                else:
                    # For media messages: support either local path upload or direct link
                    media_path = message.get("media_path")
                    media_url = message.get("url")
                    # If we have a local path, optionally normalize audio, then upload both to WA and GCS
                    if media_path and Path(media_path).exists():
                        # Background upload to GCS to produce public URL for UI; don't block WA send
                        gcs_url: Optional[str] = None
                        try:
                            # Always normalize audio to OGG/Opus 48k mono
                            if message["type"] == "audio":
                                try:
                                    ogg_path = await convert_webm_to_ogg(Path(media_path))
                                    try:
                                        Path(media_path).unlink(missing_ok=True)
                                    except Exception:
                                        pass
                                    media_path = str(ogg_path)
                                except Exception as _exc:
                                    print(f"Audio normalization failed/skipped: {_exc}")
                            gcs_url = await upload_file_to_gcs(str(media_path))
                            if gcs_url:
                                # Mutate in-memory message so final DB save includes correct URL
                                try:
                                    message["url"] = gcs_url
                                    if message.get("type") in ("audio", "video", "image"):
                                        message["message"] = gcs_url
                                except Exception:
                                    pass
                                # Notify UI and persist URL when ready
                                try:
                                    await self.connection_manager.send_to_user(user_id, {
                                        "type": "message_status_update",
                                        "data": {"temp_id": temp_id, "url": gcs_url}
                                    })
                                except Exception:
                                    pass
                                try:
                                    await self.db_manager.upsert_message({
                                        "user_id": user_id,
                                        "temp_id": temp_id,
                                        "url": gcs_url,
                                        "message": gcs_url if message.get("type") in ("audio", "video", "image") else None,
                                    })
                                except Exception:
                                    pass
                        except Exception as _exc:
                            print(f"GCS upload failed (non-fatal): {_exc}")

                        print(f"📤 Uploading media to WhatsApp: {media_path}")
                        media_info = await self._upload_media_to_whatsapp(media_path, message["type"])
                        # Backward-compatible: allow helper to return either dict({"id": ...}) or raw media id string
                        media_id = media_info.get("id") if isinstance(media_info, dict) else media_info
                        mime_type = (media_info.get("mime_type") if isinstance(media_info, dict) else "") or ""
                        if message["type"] == "audio":
                            # Small settle delay after upload to avoid iOS fetching race
                            await asyncio.sleep(0.5)
                        if message.get("reply_to"):
                            wa_response = await self.whatsapp_messenger.send_media_message(
                                user_id,
                                message["type"],
                                media_id,
                                message.get("caption", ""),
                                context_message_id=message.get("reply_to"),
                            )
                        else:
                            wa_response = await self.whatsapp_messenger.send_media_message(
                                user_id,
                                message["type"],
                                media_id,
                                message.get("caption", ""),
                            )
                    elif media_url and isinstance(media_url, str) and media_url.startswith(("http://", "https://")):
                        # Prefer reliability: fetch the remote URL, upload to WhatsApp, then send by media_id
                        local_tmp_path: Optional[Path] = None
                        try:
                            async with httpx.AsyncClient(timeout=30.0) as client:
                                resp = await client.get(media_url)
                                if resp.status_code >= 400 or not resp.content:
                                    raise Exception(f"download status {resp.status_code}")
                                # Determine extension from content-type or URL
                                ctype = resp.headers.get("Content-Type", "")
                                ext = None
                                if "audio/ogg" in ctype or "opus" in ctype:
                                    ext = ".ogg"
                                elif message["type"] == "audio" and ("webm" in ctype or media_url.lower().endswith((".webm", ".weba"))):
                                    ext = ".webm"
                                elif message["type"] == "image" and ("jpeg" in ctype or media_url.lower().endswith((".jpg", ".jpeg"))):
                                    ext = ".jpg"
                                elif message["type"] == "image" and ("png" in ctype or media_url.lower().endswith(".png")):
                                    ext = ".png"
                                elif message["type"] == "video" and ("mp4" in ctype or media_url.lower().endswith(".mp4")):
                                    ext = ".mp4"
                                elif message["type"] == "document":
                                    # try to preserve original extension if any
                                    parsed = urlparse(media_url)
                                    name = os.path.basename(parsed.path or "")
                                    ext = os.path.splitext(name)[1] or ".bin"
                                else:
                                    ext = ".bin"

                                ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                                local_tmp_path = self.media_dir / f"{message['type']}_{ts}_{uuid.uuid4().hex[:8]}{ext}"
                                async with aiofiles.open(local_tmp_path, "wb") as f:
                                    await f.write(resp.content)

                            # Always normalize audio → OGG/Opus 48k mono
                            if message["type"] == "audio":
                                try:
                                    ogg_path = await convert_webm_to_ogg(local_tmp_path)
                                    try:
                                        local_tmp_path.unlink(missing_ok=True)
                                    except Exception:
                                        pass
                                    local_tmp_path = ogg_path
                                except Exception as _exc:
                                    print(f"Audio normalization from URL failed/skipped: {_exc}")

                            media_info = await self._upload_media_to_whatsapp(str(local_tmp_path), message["type"])
                            media_id = media_info.get("id") if isinstance(media_info, dict) else media_info
                            mime_type = (media_info.get("mime_type") if isinstance(media_info, dict) else "") or ""
                            if message["type"] == "audio":
                                await asyncio.sleep(0.5)
                            if message.get("reply_to"):
                                wa_response = await self.whatsapp_messenger.send_media_message(
                                    user_id,
                                    message["type"],
                                    media_id,
                                    message.get("caption", ""),
                                    context_message_id=message.get("reply_to"),
                                )
                            else:
                                wa_response = await self.whatsapp_messenger.send_media_message(
                                    user_id,
                                    message["type"],
                                    media_id,
                                    message.get("caption", ""),
                                )

                            # Store media_path for cleanup in finally and to align with DB/UI state
                            try:
                                message["media_path"] = str(local_tmp_path)
                            except Exception:
                                pass
                        except Exception as _exc:
                            # For audio, never fall back to sending by link – raise to surface failure
                            if message.get("type") == "audio":
                                print(f"URL fetch→upload failed for audio, not sending by link: {_exc}")
                                raise
                            # For other media, last resort: send public link
                            print(f"URL fetch→upload fallback failed, sending link: {_exc}")
                            if message.get("reply_to"):
                                wa_response = await self.whatsapp_messenger.send_media_message(
                                    user_id, message["type"], media_url, message.get("caption", ""), context_message_id=message.get("reply_to")
                                )
                            else:
                                wa_response = await self.whatsapp_messenger.send_media_message(
                                    user_id, message["type"], media_url, message.get("caption", "")
                                )
                    else:
                        raise Exception("No media found: require url http(s) or valid media_path")
            
            # Extract WhatsApp message ID
            wa_message_id = None
            if "messages" in wa_response and wa_response["messages"]:
                wa_message_id = wa_response["messages"][0].get("id")
            
            if not wa_message_id:
                raise Exception(f"No message ID in WhatsApp response: {wa_response}")
            
            # Update message status to 'sent'
            status_update = {
                "type": "message_status_update",
                "data": {
                    "temp_id": temp_id,
                    "wa_message_id": wa_message_id,
                    "status": "sent"
                }
            }
            
            # Send status update to UI
            await self.connection_manager.send_to_user(user_id, status_update)
            
            # Save to database with real WhatsApp ID
            await self.db_manager.save_message(message, wa_message_id, "sent")
            
            # If this is an invoice image (Arabic caption contains 'فاتورتك'), send the warning message as a reply
            try:
                if (message.get("type") == "image"):
                    cap = str(message.get("caption") or "")
                    if "فاتورتك" in cap:
                        warning_msg = (
                            "تنبيه مهم ⚠️\n"
                            "عند استلام طلبك، يرجى فحص المنتج وتجربته قبل دفع المبلغ للموزع. 📦✅\n"
                            "إذا كان المقاس غير مناسب أو وُجدت أي مشكلة في المنتج، يُرجى إرجاع الطلب فورًا مع الموزع، وسنتكفل بإرسال بديل دون أي رسوم إضافية. 🙏⭐\n"
                            "رضاكم أولويتنا دائمًا مع IRRAKIDS. شكرًا لثقتكم بنا ❤️"
                        )
                        await self.process_outgoing_message({
                            "user_id": user_id,
                            "type": "text",
                            "from_me": True,
                            "message": warning_msg,
                            "reply_to": wa_message_id,
                            "timestamp": datetime.utcnow().isoformat(),
                        })
            except Exception as _exc:
                print(f"invoice warning follow-up failed: {_exc}")
            
            _vlog(f"✅ Message sent successfully: {wa_message_id}")
            
        except Exception as e:
            print(f"❌ WhatsApp send failed: {e}")
            # Update UI with error status
            error_update = {
                "type": "message_status_update", 
                "data": {
                    "temp_id": temp_id,
                    "status": "failed",
                    "error": str(e)
                }
            }
            await self.connection_manager.send_to_user(user_id, error_update)
        finally:
            media_path = message.get("media_path")
            if media_path and Path(media_path).exists():
                try:
                    Path(media_path).unlink(missing_ok=True)
                except Exception as e:
                    print(f"⚠️ Cleanup failed for {media_path}: {e}")

    async def _verify_graph_media(self, media_id: str) -> dict:
        """Fetch media metadata from Graph and return JSON."""
        url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{media_id}"
        headers = {"Authorization": f"Bearer {self.whatsapp_messenger.access_token}"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"Media verify failed: {resp.status_code} {resp.text}")
            return resp.json()

    async def _upload_media_to_whatsapp(self, file_path: str, media_type: str) -> dict:
        """Upload media file to WhatsApp and return {id, mime_type, filename}.

        Implements backoff and, for audio, verifies Graph media and may fallback to AAC/M4A.
        """
        src = Path(file_path)
        if not src.exists():
            raise Exception(f"Media file not found: {file_path}")

        upload_url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{self.whatsapp_messenger.phone_number_id}/media"

        async def choose_mime(path: Path, mtype: str) -> str:
            suffix = path.suffix.lower()
            if mtype == "audio":
                if suffix == ".ogg":
                    return "audio/ogg"
                if suffix in (".m4a", ".mp4", ".aac"):
                    return "audio/mp4"
            if mtype == "image":
                if suffix in (".jpg", ".jpeg"):
                    return "image/jpeg"
                if suffix == ".png":
                    return "image/png"
            if mtype == "video":
                return "video/mp4"
            if mtype == "document":
                if suffix == ".pdf":
                    return "application/pdf"
            return f"{mtype}/*"

        async def attempt_upload(path: Path, mtype: str) -> dict:
            # Read file content
            async with aiofiles.open(path, 'rb') as f:
                file_content = await f.read()

            mime_type = await choose_mime(path, mtype)
            files = {
                'file': (path.name, file_content, mime_type),
                'messaging_product': (None, 'whatsapp'),
                # Graph expects concrete MIME here (e.g., audio/ogg), not generic 'audio'
                'type': (None, mime_type),
            }
            headers = {"Authorization": f"Bearer {self.whatsapp_messenger.access_token}"}

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(upload_url, files=files, headers=headers)
                _vlog(f"📤 WhatsApp upload response: {response.status_code}")
                _vlog(f"📤 Response body: {response.text}")
                if response.status_code != 200:
                    raise Exception(f"WhatsApp media upload failed: {response.text}")
                result = response.json()
                media_id = result.get("id")
                if not media_id:
                    raise Exception(f"No media_id in WhatsApp response: {result}")
                return {"id": media_id, "upload_mime": mime_type, "filename": path.name}

        # Backoff attempts
        delays = [0.25, 0.5, 1.0, 2.0, 4.0]
        last_err: Optional[Exception] = None
        for i, delay in enumerate(delays, start=1):
            try:
                info = await attempt_upload(src, media_type)
                # Verify for audio
                if media_type == "audio":
                    meta = await self._verify_graph_media(info["id"])
                    # Expect strict fields
                    mime = (meta.get("mime_type") or "").lower()
                    sha256 = meta.get("sha256")
                    size = meta.get("file_size")
                    if not sha256 or not size:
                        raise Exception("Graph media missing sha256/file_size")
                    # Prefer explicit Opus-in-Ogg when source was .ogg
                    if src.suffix.lower() == ".ogg" and "audio/ogg" not in mime:
                        raise Exception(f"Unexpected audio MIME from Graph: {mime}")
                    info["mime_type"] = mime
                else:
                    meta = await self._verify_graph_media(info["id"])  # sanity
                    info["mime_type"] = (meta.get("mime_type") or info.get("upload_mime") or "").lower()
                _vlog(f"✅ Media uploaded & verified. ID: {info['id']} MIME: {info.get('mime_type')}")
                return info
            except Exception as e:
                last_err = e
                _vlog(f"⏳ Upload attempt {i} failed: {e}")
                await asyncio.sleep(delay)

        # Final fallback for audio: convert to M4A and re-upload (still by media_id, never link)
        if media_type == "audio":
            try:
                m4a_path = await convert_any_to_m4a(src)
                info = await attempt_upload(m4a_path, media_type)
                meta = await self._verify_graph_media(info["id"])
                info["mime_type"] = (meta.get("mime_type") or info.get("upload_mime") or "").lower()
                _vlog(f"✅ Fallback M4A uploaded & verified. ID: {info['id']} MIME: {info.get('mime_type')}")
                return info
            except Exception as e:
                raise Exception(f"Failed after retries and m4a fallback: {e}")

        # Non-audio: give up
        raise Exception(f"Failed to upload media to WhatsApp after retries: {last_err}")
    
    async def process_incoming_message(self, webhook_data: dict):
        _vlog("🚨 process_incoming_message CALLED")
        _vlog(json.dumps(webhook_data, indent=2))
        """Process incoming WhatsApp message"""
        ws_token = None
        try:
            value = webhook_data['entry'][0]['changes'][0]['value']

            # Derive workspace from payload metadata (preferred) or from an attached hint by /webhook ingress.
            incoming_phone_id = ""
            try:
                meta = value.get("metadata") or {}
                incoming_phone_id = str(meta.get("phone_number_id") or "")
            except Exception:
                incoming_phone_id = ""

            hinted_ws = None
            try:
                hinted_ws = webhook_data.get("_workspace")
            except Exception:
                hinted_ws = None

            def _ws_from_config(pid: str) -> str:
                """Best-effort: map incoming phone_number_id to workspace by scanning runtime/env configs."""
                try:
                    p = str(pid or "").strip()
                    if not p:
                        return ""
                    for _w, _cfg in (RUNTIME_WHATSAPP_CONFIG_BY_WORKSPACE or {}).items():
                        try:
                            if str((_cfg or {}).get("phone_number_id") or "").strip() == p:
                                return _coerce_workspace(_w)
                        except Exception:
                            continue
                    for _w, _cfg in (WHATSAPP_CONFIG_BY_WORKSPACE or {}).items():
                        try:
                            if str((_cfg or {}).get("phone_number_id") or "").strip() == p:
                                return _coerce_workspace(_w)
                        except Exception:
                            continue
                    return ""
                except Exception:
                    return ""

            # Prefer runtime mapping (can be updated from DB settings). Fallback to env-derived mapping.
            ws_from_phone = (RUNTIME_PHONE_ID_TO_WORKSPACE.get(incoming_phone_id) or PHONE_ID_TO_WORKSPACE.get(incoming_phone_id))
            # Workspace hint is best-effort; the authoritative routing key is metadata.phone_number_id.
            ws_from_phone_norm = _coerce_workspace(ws_from_phone) if ws_from_phone else ""
            hinted_ws_norm = _coerce_workspace(str(hinted_ws or "")) if hinted_ws else ""
            derived_ws = _ws_from_config(incoming_phone_id) or ws_from_phone_norm or hinted_ws_norm or ""
            if hinted_ws_norm and ws_from_phone_norm and hinted_ws_norm != ws_from_phone_norm:
                _vlog(
                    f"⚠️ Webhook workspace hint mismatch: hinted={hinted_ws_norm} phone_map={ws_from_phone_norm} phone_number_id={incoming_phone_id} (using phone_map)"
                )
            if not derived_ws:
                # Unknown phone_number_id → do not process into any workspace (prevents leakage).
                _vlog(f"⏭️ Skipping webhook: unknown phone_number_id={incoming_phone_id}")
                return
            ws_token = _CURRENT_WORKSPACE.set(_coerce_workspace(derived_ws))

            # Strict enforcement: only process if the workspace's configured phone_number_id matches the incoming one.
            try:
                env_cfg = await self._get_inbox_env(get_current_workspace())
                expected_pid = str((env_cfg or {}).get("phone_number_id") or "").strip()
                if expected_pid and incoming_phone_id and (str(incoming_phone_id).strip() != expected_pid):
                    async def _ws_for_pid(pid: str) -> str:
                        try:
                            p = str(pid or "").strip()
                            if not p:
                                return ""
                            # Prefer shared Redis mapping (multi-instance stable)
                            try:
                                r = getattr(self.redis_manager, "redis_client", None)
                                if r:
                                    raw = await r.hget("wa:phone_id_to_workspace", p)
                                    if raw is not None:
                                        if isinstance(raw, (bytes, bytearray)):
                                            raw = raw.decode("utf-8", "ignore")
                                        ws2 = _coerce_workspace(str(raw or "").strip())
                                        if ws2:
                                            return ws2
                            except Exception:
                                pass
                            # Next: scan per-workspace inbox_env (DB + env defaults) for a matching phone_number_id.
                            # This avoids relying on a stale _workspace hint or per-instance memory maps.
                            try:
                                candidates = sorted(list(_all_workspaces_set()))
                            except Exception:
                                candidates = sorted(list(set((WORKSPACES or [DEFAULT_WORKSPACE]))))
                            for w in candidates:
                                ww = _coerce_workspace(w)
                                if not ww:
                                    continue
                                try:
                                    cfg = await self._get_inbox_env(ww)
                                    pid2 = str((cfg or {}).get("phone_number_id") or "").strip()
                                    if pid2 and pid2 == p:
                                        return ww
                                except Exception:
                                    continue
                            # Prefer scanning runtime configs (avoids stale phone_id map entries).
                            for _w, _cfg in (RUNTIME_WHATSAPP_CONFIG_BY_WORKSPACE or {}).items():
                                try:
                                    if str((_cfg or {}).get("phone_number_id") or "").strip() == p:
                                        return _coerce_workspace(_w)
                                except Exception:
                                    continue
                            for _w, _cfg in (WHATSAPP_CONFIG_BY_WORKSPACE or {}).items():
                                try:
                                    if str((_cfg or {}).get("phone_number_id") or "").strip() == p:
                                        return _coerce_workspace(_w)
                                except Exception:
                                    continue
                            # Fallback to maps
                            return _coerce_workspace(
                                (RUNTIME_PHONE_ID_TO_WORKSPACE.get(p) or PHONE_ID_TO_WORKSPACE.get(p) or "")
                            )
                        except Exception:
                            return ""

                    target_ws = await _ws_for_pid(incoming_phone_id)
                    if target_ws and target_ws != get_current_workspace():
                        _vlog(
                            f"🔁 Rerouting webhook by phone_number_id: incoming={incoming_phone_id} from={get_current_workspace()} to={target_ws}"
                        )
                        # Switch workspace context (avoid dropping the webhook due to a bad hint/stale map)
                        try:
                            if ws_token is not None:
                                _CURRENT_WORKSPACE.reset(ws_token)
                        except Exception:
                            pass
                        ws_token = _CURRENT_WORKSPACE.set(_coerce_workspace(target_ws))
                        try:
                            env_cfg = await self._get_inbox_env(get_current_workspace())
                            expected_pid = str((env_cfg or {}).get("phone_number_id") or "").strip()
                        except Exception:
                            expected_pid = ""
                        if expected_pid and incoming_phone_id and (str(incoming_phone_id).strip() != expected_pid):
                            _vlog(
                                f"⏭️ Skipping webhook after reroute: phone_number_id mismatch workspace={get_current_workspace()} incoming={incoming_phone_id} expected={expected_pid}"
                            )
                            return
                    else:
                        # Treat as a processing failure so the webhook worker can retry and/or DLQ.
                        raise RuntimeError(
                            f"phone_number_id mismatch (unroutable): workspace={get_current_workspace()} incoming={incoming_phone_id} expected={expected_pid}"
                        )
            except RuntimeError:
                # Important: do NOT swallow routing failures; the webhook worker must retry and/or DLQ.
                raise
            except Exception:
                pass

            # Optional: Filter by phone_number_id allowlist (supports multiple IDs)
            try:
                env_cfg = await self._get_inbox_env(get_current_workspace())
                allowed_ids = set((env_cfg or {}).get("allowed_phone_number_ids") or set())
                expected_pid2 = str((env_cfg or {}).get("phone_number_id") or "").strip()
                if allowed_ids and incoming_phone_id and (incoming_phone_id not in allowed_ids):
                    # Safety: if allowlist is misconfigured but the incoming phone_number_id matches this workspace's
                    # configured phone_number_id, do NOT drop inbound messages (warn and continue).
                    if expected_pid2 and str(incoming_phone_id).strip() == expected_pid2:
                        _vlog(
                            f"⚠️ allowlist mismatch: incoming phone_number_id={incoming_phone_id} matches workspace={get_current_workspace()} phone_number_id "
                            f"but is not in allowed_phone_number_ids={sorted(list(allowed_ids))[:10]} (allowing message)"
                        )
                    else:
                        _vlog(
                            f"⏭️ Skipping webhook for phone_number_id {incoming_phone_id} (allowed {sorted(list(allowed_ids))[:10]})"
                        )
                        return
            except Exception:
                pass

            # Handle status updates
            if "statuses" in value:
                await self._handle_status_updates(value["statuses"])

            # Handle incoming messages
            if "messages" in value:
                # Extract contacts info if available
                contacts_info = value.get("contacts", [])

                for i, message in enumerate(value["messages"]):
                    # Add contact info to message if available
                    if i < len(contacts_info):
                        message["contact_info"] = contacts_info[i]
                    await self._handle_incoming_message(message)

        except Exception as e:
            # Critical: re-raise so the durable queue (Redis Streams / Postgres webhook_events)
            # can retry and eventually DLQ instead of silently dropping the webhook.
            print(f"Webhook processing error: {e}")
            raise
        finally:
            if ws_token is not None:
                try:
                    _CURRENT_WORKSPACE.reset(ws_token)
                except Exception:
                    pass


    async def _handle_status_updates(self, statuses: list):
        """Process status notifications from WhatsApp"""
        for item in statuses:
            wa_id = item.get("id")
            status = item.get("status")
            if not wa_id or not status:
                continue

            # Update DB and fetch temp_id/user_id (skip if user_id unknown)
            temp_id = await self.db_manager.update_message_status(wa_id, status)
            user_id = await self.db_manager.get_user_for_message(wa_id)
            if not user_id:
                continue

            timestamp = datetime.utcfromtimestamp(
                int(item.get("timestamp", 0))
            ).isoformat()

            await self.connection_manager.send_to_user(user_id, {
                "type": "message_status_update",
                "data": {
                    "temp_id": temp_id,
                    "wa_message_id": wa_id,
                    "status": status,
                    "timestamp": timestamp,
                }
            })


    async def _handle_incoming_message(self, message: dict):
        print("📨 _handle_incoming_message CALLED")
        print(json.dumps(message, indent=2))
        
        sender = message.get("from") or (message.get("contact_info") or {}).get("wa_id")
        if not sender:
            raise RuntimeError("incoming message missing sender id")
        msg_type = message["type"]
        wa_message_id = message.get("id")
        timestamp = datetime.utcfromtimestamp(int(message.get("timestamp", 0))).isoformat()
        server_now = datetime.now(timezone.utc).isoformat()
        
        # Extract contact name from contacts array if available
        contact_name = None
        # Note: contacts info is typically in the webhook's 'contacts' field, not message
        
        await self.db_manager.upsert_user(sender, contact_name, sender)
        # Auto-unarchive: if conversation is marked as Done, remove the tag on any new incoming message
        try:
            meta = await self.db_manager.get_conversation_meta(sender)
            tags = list(meta.get("tags") or []) if isinstance(meta, dict) else []
            if any(str(t).lower() == 'done' for t in tags):
                new_tags = [t for t in tags if str(t).lower() != 'done']
                await self.db_manager.set_conversation_tags(sender, new_tags)
        except Exception as _e:
            # Non-fatal: do not block message processing
            pass
        
        # Special case: reactions are not normal bubbles – broadcast an update instead
        if msg_type == "reaction":
            reaction = message.get("reaction", {})
            target_id = reaction.get("message_id")
            emoji = reaction.get("emoji")
            action = reaction.get("action", "react")
            reaction_event = {
                "type": "reaction_update",
                "data": {
                    "user_id": sender,
                    "target_wa_message_id": target_id,
                    "emoji": emoji,
                    "action": action,
                    "from_me": False,
                    "wa_message_id": wa_message_id,
                    "timestamp": timestamp,
                },
            }
            try:
                # Persist a lightweight record for auditing/history
                await self.db_manager.upsert_message({
                    "wa_message_id": wa_message_id,
                    "user_id": sender,
                    "type": "reaction",
                    "from_me": 0,
                    "status": "received",
                    "timestamp": timestamp,
                    "reaction_to": target_id,
                    "reaction_emoji": emoji,
                    "reaction_action": action,
                })
            except Exception:
                pass
            # Notify UI
            await self.connection_manager.send_to_user(sender, reaction_event)
            await self.connection_manager.broadcast_to_admins(reaction_event, exclude_user=sender)
            return

        # Create message object with proper URL field
        message_obj = {
            "id": wa_message_id,
            "user_id": sender,
            "type": msg_type,
            "from_me": False,
            "status": "received",
            "timestamp": timestamp,
            "server_ts": server_now,
            "wa_message_id": wa_message_id
        }
        
        # Extract message content and generate proper URLs
        if msg_type == "text":
            body = message["text"]["body"]
            click_id = None
            try:
                # Shopify theme tracking marker (we strip it from the visible chat)
                m = re.search(r"(?:^|\n)\s*WA_CLICK_ID\s*[:=]\s*([a-f0-9]{16,64})\s*(?:\n|$)", body or "", re.IGNORECASE)
                if m:
                    click_id = (m.group(1) or "").strip().lower()
                    # Remove the marker line from the message shown to agents
                    body = re.sub(
                        r"(?:^|\n)\s*WA_CLICK_ID\s*[:=]\s*[a-f0-9]{16,64}\s*(?=\n|$)",
                        "",
                        body or "",
                        flags=re.IGNORECASE,
                    ).strip()
            except Exception:
                click_id = None
            message_obj["message"] = body
            if click_id:
                try:
                    await self.db_manager.try_set_conversation_attribution_from_click(
                        user_id=sender,
                        click_id=click_id,
                        first_inbound_ts=str(server_now or timestamp or datetime.utcnow().isoformat()),
                        source="shopify_wa_icon",
                    )
                except Exception:
                    pass
        elif msg_type == "interactive":
            try:
                inter = message.get("interactive", {}) or {}
                btn = inter.get("button_reply") or {}
                lst = inter.get("list_reply") or {}
                title = (btn.get("title") or lst.get("title") or "").strip()
                # Capture id for workflow routing
                reply_id = (btn.get("id") or lst.get("id") or "").strip()
                message_obj["type"] = "text"
                message_obj["message"] = title or "[interactive_reply]"
                # Route survey interactions before generic acknowledgment
                if reply_id.startswith("survey_"):
                    # Persist the textual reply bubble first
                    await self.connection_manager.send_to_user(sender, {
                        "type": "message_received",
                        "data": message_obj
                    })
                    await self.connection_manager.broadcast_to_admins(
                        {"type": "message_received", "data": message_obj}, exclude_user=sender
                    )
                    db_data = {k: v for k, v in message_obj.items() if k != "id"}
                    await self.redis_manager.cache_message(sender, db_data)
                    await self.db_manager.upsert_message(db_data)
                    # Handle the survey reply and return (skip default ack)
                    try:
                        await self._handle_survey_interaction(sender, reply_id, title)
                    except Exception as _exc:
                        print(f"Survey interaction error: {_exc}")
                    return
                # Order status flow
                if reply_id == "order_status":
                    # Persist UI bubble then handle
                    await self.connection_manager.send_to_user(sender, {
                        "type": "message_received",
                        "data": message_obj
                    })
                    await self.connection_manager.broadcast_to_admins(
                        {"type": "message_received", "data": message_obj}, exclude_user=sender
                    )
                    db_data = {k: v for k, v in message_obj.items() if k != "id"}
                    await self.redis_manager.cache_message(sender, db_data)
                    await self.db_manager.upsert_message(db_data)
                    try:
                        await self._handle_order_status_request(sender)
                    except Exception as _exc:
                        print(f"order_status flow error: {_exc}")
                    return
                # Buy flow start → show gender list
                if reply_id == "buy_item":
                    await self.connection_manager.send_to_user(sender, {
                        "type": "message_received",
                        "data": message_obj
                    })
                    await self.connection_manager.broadcast_to_admins(
                        {"type": "message_received", "data": message_obj}, exclude_user=sender
                    )
                    db_data = {k: v for k, v in message_obj.items() if k != "id"}
                    await self.redis_manager.cache_message(sender, db_data)
                    await self.db_manager.upsert_message(db_data)
                    try:
                        await self._send_buy_gender_list(sender)
                    except Exception as _exc:
                        print(f"buy flow start error: {_exc}")
                    return
                # Gender selection → send size/age prompt
                if reply_id in ("gender_girls", "gender_boys"):
                    await self.connection_manager.send_to_user(sender, {
                        "type": "message_received",
                        "data": message_obj
                    })
                    await self.connection_manager.broadcast_to_admins(
                        {"type": "message_received", "data": message_obj}, exclude_user=sender
                    )
                    db_data = {k: v for k, v in message_obj.items() if k != "id"}
                    await self.redis_manager.cache_message(sender, db_data)
                    await self.db_manager.upsert_message(db_data)
                    try:
                        await self._send_gender_prompt(sender, reply_id)
                    except Exception as _exc:
                        print(f"gender prompt error: {_exc}")
                    return
            except Exception:
                message_obj["type"] = "text"
                message_obj["message"] = "[interactive_reply]"
        elif msg_type == "image":
            image_path, drive_url = await self._download_media(message["image"]["id"], "image")
            message_obj["message"] = image_path
            message_obj["url"] = drive_url
            message_obj["caption"] = message["image"].get("caption", "")
        elif msg_type == "sticker":
            # Treat stickers as images for display purposes
            try:
                sticker_path, drive_url = await self._download_media(message["sticker"]["id"], "image")
                message_obj["type"] = "image"
                message_obj["message"] = sticker_path
                message_obj["url"] = drive_url
                message_obj["caption"] = ""
            except Exception:
                # Fallback to a text label if download fails
                message_obj["type"] = "text"
                message_obj["message"] = "[sticker]"
        elif msg_type == "audio":
            audio_path, drive_url = await self._download_media(message["audio"]["id"], "audio")
            message_obj["message"] = audio_path
            message_obj["url"] = drive_url
            message_obj["transcription"] = ""
        elif msg_type == "video":
            video_path, drive_url = await self._download_media(message["video"]["id"], "video")
            message_obj["message"] = video_path
            message_obj["url"] = drive_url
            message_obj["caption"] = message["video"].get("caption", "")
        elif msg_type == "order":
            message_obj["message"] = json.dumps(message.get("order", {}))

        # Replies: capture quoted message id if present
        try:
            ctx = message.get("context") or {}
            if isinstance(ctx, dict) and ctx.get("id"):
                message_obj["reply_to"] = ctx.get("id")
        except Exception:
            pass
        
        # Persist first, then broadcast to ensure durability even if clients are offline
        # Remove "id" so SQLite doesn't try to insert the text wa_message_id into INTEGER PK
        db_data = {k: v for k, v in message_obj.items() if k != "id"}
        await self.db_manager.upsert_message(db_data)
        await self.redis_manager.cache_message(sender, db_data)

        # Durable analytics: inbound message received (assigned snapshot at receive time)
        try:
            assigned_snapshot = None
            try:
                meta = await self.db_manager.get_conversation_meta(sender)
                assigned_snapshot = (meta.get("assigned_agent") if isinstance(meta, dict) else None)
            except Exception:
                assigned_snapshot = None
            await self.db_manager.log_agent_event(
                event_type="inbound_message",
                ts=str(db_data.get("server_ts") or db_data.get("timestamp") or datetime.utcnow().isoformat()),
                user_id=str(sender),
                assigned_agent=(str(assigned_snapshot).strip() if assigned_snapshot else None),
                wa_message_id=str(db_data.get("wa_message_id") or ""),
            )
        except Exception:
            pass

        # Now deliver to UI and admin dashboards
        await self.connection_manager.send_to_user(sender, {
            "type": "message_received",
            "data": message_obj
        })
        await self.connection_manager.broadcast_to_admins(
            {"type": "message_received", "data": message_obj},
            exclude_user=sender
        )
        
        # Auto-responses
        try:
            if msg_type == "text":
                await self._maybe_auto_reply_with_catalog(sender, message_obj.get("message", ""))
            elif msg_type == "interactive":
                # Default acknowledgement when no special handler above
                await self.process_outgoing_message({
                    "user_id": sender,
                    "type": "text",
                    "from_me": True,
                    "message": "Message reçu. Merci !\nتم استلام ردك، شكرًا لك!",
                    "timestamp": datetime.utcnow().isoformat(),
                })
        except Exception as _exc:
            # Never break incoming flow due to auto-reply errors
            print(f"Auto-reply failed: {_exc}")

        # Workspace-scoped "simple automations" (admin-configured rules).
        # Run async so webhook ingest latency stays low.
        try:
            if msg_type == "text":
                txt = str(message_obj.get("message") or "")
            else:
                txt = ""
            # IMPORTANT: this runs after webhook processing may reset the workspace contextvar,
            # so bind the current workspace explicitly for the task.
            ws = get_current_workspace()
            asyncio.create_task(self._run_simple_automations(sender, incoming_text=txt, message_obj=message_obj, workspace=ws))
        except Exception:
            pass

    async def _load_automation_rules(self, workspace: str) -> list[dict]:
        """Load automation rules (global store, filtered by workspace) with a small in-memory cache."""
        ws = _coerce_workspace(workspace or DEFAULT_WORKSPACE)
        now = time.time()
        try:
            cached = self._automation_rules_cache.get(ws)
            if cached and (now - float(cached[0])) < 3.0:
                return cached[1] or []
        except Exception:
            pass
        try:
            rules_all = await self._ensure_automation_rules_v2()
            if not isinstance(rules_all, list):
                rules_all = []
        except Exception:
            rules_all = []
        # normalize to list[dict]
        cleaned: list[dict] = []
        for r in rules_all or []:
            if not isinstance(r, dict):
                continue
            rid = str(r.get("id") or "").strip()
            if not rid:
                continue
            # Workspace scope: if missing, treat as current workspace only (backwards compat)
            scopes = r.get("workspaces")
            applies = False
            try:
                if scopes is None:
                    applies = True  # legacy rules are stored per-workspace; migration should add scope, but keep safe
                elif isinstance(scopes, list):
                    s = set([_normalize_workspace_id(x) for x in scopes if _normalize_workspace_id(x)])
                    applies = ("*" in s) or (ws in s)
                else:
                    applies = True
            except Exception:
                applies = True
            if not applies:
                continue
            cleaned.append(r)
        try:
            self._automation_rules_cache[ws] = (now, cleaned)
        except Exception:
            pass
        return cleaned

    def _render_template(self, s: str, ctx: dict) -> str:
        """Template helper supporting dotted paths: {{ customer.phone }}."""
        def _resolve(path: str):
            p = str(path or "").strip()
            if not p:
                return ""
            cur = ctx
            # support dot + [idx]
            for part in p.split("."):
                part = part.strip()
                if not part:
                    continue
                m = re.fullmatch(r"([A-Za-z0-9_]+)\[(\d+)\]", part)
                key = part
                idx = None
                if m:
                    key = m.group(1)
                    idx = int(m.group(2))
                if isinstance(cur, dict):
                    cur = cur.get(key)
                else:
                    return ""
                if idx is not None:
                    if isinstance(cur, list) and 0 <= idx < len(cur):
                        cur = cur[idx]
                    else:
                        return ""
            if cur is None:
                return ""
            return str(cur)

        try:
            if not s:
                return ""
            text = str(s)
            # Replace all {{ ... }} occurrences
            def _repl(m):
                return _resolve(m.group(1))
            return re.sub(r"\{\{\s*([^}]+?)\s*\}\}", _repl, text)
        except Exception:
            return str(s or "")

    async def _run_simple_automations(self, user_id: str, incoming_text: str, message_obj: dict | None = None, workspace: str | None = None) -> None:
        """Execute enabled simple automation rules for an inbound WhatsApp text message."""
        ws_token = None
        try:
            if workspace:
                try:
                    ws_token = _CURRENT_WORKSPACE.set(_coerce_workspace(workspace))
                except Exception:
                    ws_token = None

            # Only run for real WhatsApp customers, not internal channels
            if not isinstance(user_id, str):
                return
            if user_id.startswith(("dm:", "team:", "agent:")):
                return
            # Only inbound messages
            if message_obj and bool(message_obj.get("from_me")):
                return

            ws = get_current_workspace()
            rules = await self._load_automation_rules(ws)
            if not rules:
                return

            text = str(incoming_text or "")
            text_lc = text.lower()
            ctx = {
                "phone": user_id,
                "user_id": user_id,
                "text": text,
            }

            for rule in rules:
                try:
                    if not isinstance(rule, dict):
                        continue
                    if not bool(rule.get("enabled", False)):
                        continue
                    trigger = rule.get("trigger") or {}
                    if not isinstance(trigger, dict):
                        trigger = {}
                    if str(trigger.get("source") or "whatsapp").lower() != "whatsapp":
                        continue
                    if str(trigger.get("event") or "incoming_message").lower() not in ("incoming_message", "message"):
                        continue

                    # Condition
                    cond = rule.get("condition") or {}
                    if not isinstance(cond, dict):
                        cond = {}
                    mode = str(cond.get("match") or "contains").lower()
                    needle = str(cond.get("value") or "").strip()
                    keywords = cond.get("keywords")
                    if isinstance(keywords, list):
                        kws = [str(x or "").strip() for x in keywords if str(x or "").strip()]
                    else:
                        kws = []

                    matched = False
                    if mode == "any":
                        matched = True
                    elif kws:
                        matched = any((k.lower() in text_lc) for k in kws)
                    elif not needle:
                        matched = True
                    elif mode == "contains":
                        matched = needle.lower() in text_lc
                    elif mode == "starts_with":
                        matched = text_lc.startswith(needle.lower())
                    elif mode == "regex":
                        try:
                            matched = bool(re.search(needle, text, flags=re.IGNORECASE))
                        except Exception:
                            matched = False
                    else:
                        matched = False

                    if not matched:
                        continue

                    # Simple per-rule stats (best-effort, Redis if available)
                    try:
                        rds = getattr(self.redis_manager, "redis_client", None)
                        if rds:
                            stats_key = f"automation:stats:{_coerce_workspace(ws)}:{rule.get('id')}"
                            await rds.hincrby(stats_key, "triggers", 1)
                            await rds.hset(stats_key, mapping={"last_trigger_ts": str(datetime.utcnow().isoformat())})
                    except Exception:
                        pass
                    try:
                        await self.db_manager.inc_automation_rule_stat(
                            str(rule.get("id") or ""),
                            "triggers",
                            1,
                            last_trigger_ts=str(datetime.utcnow().isoformat()),
                        )
                    except Exception:
                        pass

                    # Cooldown (best-effort)
                    cooldown = int(rule.get("cooldown_seconds") or 0)
                    if cooldown > 0 and getattr(self.redis_manager, "redis_client", None):
                        try:
                            cd_key = f"automation:cooldown:{_coerce_workspace(ws)}:{rule.get('id')}:{user_id}"
                            ok = await self.redis_manager.redis_client.set(cd_key, "1", ex=cooldown, nx=True)
                            if not ok:
                                continue
                        except Exception:
                            pass

                    # Actions
                    actions = rule.get("actions") or []
                    if isinstance(actions, dict):
                        actions = [actions]
                    if not isinstance(actions, list):
                        actions = []
                    for act in actions:
                        if not isinstance(act, dict):
                            continue
                        at = str(act.get("type") or "").strip().lower()
                        if at in ("send_text", "send_whatsapp_text"):
                            msg = self._render_template(str(act.get("text") or ""), ctx).strip()
                            if not msg:
                                continue
                            await self.process_outgoing_message({
                                "user_id": self._render_template(str(act.get("to") or "{{ phone }}"), ctx).strip() or user_id,
                                "type": "text",
                                "from_me": True,
                                "message": msg,
                                "timestamp": datetime.utcnow().isoformat(),
                                # mark as system/automation for downstream filtering (best-effort)
                                "agent_username": "automation",
                            })
                            try:
                                rds = getattr(self.redis_manager, "redis_client", None)
                                if rds:
                                    stats_key = f"automation:stats:{_coerce_workspace(ws)}:{rule.get('id')}"
                                    await rds.hincrby(stats_key, "messages_sent", 1)
                            except Exception:
                                pass
                            try:
                                await self.db_manager.inc_automation_rule_stat(str(rule.get("id") or ""), "messages_sent", 1)
                            except Exception:
                                pass
                        elif at in ("send_template", "send_whatsapp_template"):
                            to_id = self._render_template(str(act.get("to") or "{{ phone }}"), ctx).strip() or user_id
                            tname = self._render_template(str(act.get("template_name") or ""), ctx).strip()
                            lang = str(act.get("language") or "en").strip() or "en"
                            comps = act.get("components") or []
                            if not tname:
                                continue
                            # Provide a visible bubble to the inbox (message preview) while sending the template.
                            preview = str(act.get("preview") or f"[template] {tname}")
                            await self.process_outgoing_message({
                                "user_id": to_id,
                                "type": "text",
                                "from_me": True,
                                "message": preview,
                                "timestamp": datetime.utcnow().isoformat(),
                                "agent_username": "automation",
                                # Template send metadata (handled by background sender)
                                "template_name": tname,
                                "template_language": lang,
                                "template_components": comps,
                            })
                        elif at in ("add_tag", "tag"):
                            tag = str(act.get("tag") or "").strip()
                            if not tag:
                                continue
                            try:
                                meta = await self.db_manager.get_conversation_meta(user_id)
                                tags = list((meta or {}).get("tags") or []) if isinstance(meta, dict) else []
                            except Exception:
                                tags = []
                            if tag not in tags:
                                tags.append(tag)
                                try:
                                    await self.db_manager.set_conversation_tags(user_id, tags)
                                    # Notify UI best-effort via admin ws: ChatList merges tags from conversation fetch,
                                    # but this gives faster visual feedback.
                                    await self.connection_manager.broadcast_to_admins({
                                        "type": "conversation_tags_updated",
                                        "data": {"user_id": user_id, "tags": tags},
                                    })
                                    try:
                                        rds = getattr(self.redis_manager, "redis_client", None)
                                        if rds:
                                            stats_key = f"automation:stats:{_coerce_workspace(ws)}:{rule.get('id')}"
                                            await rds.hincrby(stats_key, "tags_added", 1)
                                    except Exception:
                                        pass
                                    try:
                                        await self.db_manager.inc_automation_rule_stat(str(rule.get("id") or ""), "tags_added", 1)
                                    except Exception:
                                        pass
                                except Exception:
                                    pass
                except Exception as exc:
                    print(f"automation rule failed: {exc}")
                    continue
        except Exception:
            return
        finally:
            if ws_token is not None:
                try:
                    _CURRENT_WORKSPACE.reset(ws_token)
                except Exception:
                    pass

    async def _run_shopify_automations(self, topic: str, payload: dict, workspace: str | None = None) -> None:
        """Execute automations for a Shopify webhook event.

        Rules must have trigger.source == "shopify" and trigger.event == <topic>, e.g. "orders/paid".
        """
        ws_token = None
        try:
            if workspace:
                try:
                    ws_token = _CURRENT_WORKSPACE.set(_coerce_workspace(workspace))
                except Exception:
                    ws_token = None

            ws = get_current_workspace()
            rules = await self._load_automation_rules(ws)
            if not rules:
                return

            topic_norm = str(topic or "").strip()
            if not topic_norm:
                return

            data = payload if isinstance(payload, dict) else {}

            def _first(*vals):
                for v in vals:
                    if v is None:
                        continue
                    s = str(v).strip()
                    if s:
                        return s
                return ""

            # Extract phone from common Shopify fields (digits-only for our inbox ids)
            phone_raw = _first(
                (data.get("customer") or {}).get("phone") if isinstance(data.get("customer"), dict) else None,
                data.get("phone"),
                (data.get("destination") or {}).get("phone") if isinstance(data.get("destination"), dict) else None,  # fulfillments/create
                (data.get("shipping_address") or {}).get("phone") if isinstance(data.get("shipping_address"), dict) else None,
                (data.get("billing_address") or {}).get("phone") if isinstance(data.get("billing_address"), dict) else None,
            )
            phone_digits = _digits_only(phone_raw)

            # Fulfillment webhooks often don't include customer phone. If we have an order_id, enrich from Shopify.
            if not phone_digits:
                try:
                    order_id = (
                        data.get("order_id")
                        or (data.get("order") or {}).get("id") if isinstance(data.get("order"), dict) else None
                        or (data.get("fulfillment") or {}).get("order_id") if isinstance(data.get("fulfillment"), dict) else None
                    )
                    order_id_s = str(order_id).strip() if order_id is not None else ""
                    if order_id_s and order_id_s.isdigit():
                        from .shopify_integration import admin_api_base, _client_args  # type: ignore

                        async with httpx.AsyncClient(timeout=15.0) as client:
                            resp = await client.get(f"{admin_api_base()}/orders/{order_id_s}.json", **_client_args())
                            if resp.status_code == 200:
                                order_obj = (resp.json() or {}).get("order") or {}
                                if isinstance(order_obj, dict):
                                    phone_raw2 = _first(
                                        (order_obj.get("customer") or {}).get("phone") if isinstance(order_obj.get("customer"), dict) else None,
                                        order_obj.get("phone"),
                                        (order_obj.get("shipping_address") or {}).get("phone") if isinstance(order_obj.get("shipping_address"), dict) else None,
                                        (order_obj.get("billing_address") or {}).get("phone") if isinstance(order_obj.get("billing_address"), dict) else None,
                                    )
                                    phone_digits = _digits_only(phone_raw2) or phone_digits
                                    # Keep context richer for templating/rules
                                    data = dict(data)
                                    data["_order"] = order_obj
                except Exception:
                    pass

            # Context for templating
            ctx = {
                "topic": topic_norm,
                "phone": phone_digits,
                "customer": (data.get("customer") if isinstance(data.get("customer"), dict) else {}),
                "order_number": data.get("name") or data.get("order_number") or "",
                "total_price": data.get("total_price") or "",
                "payload": data,
            }

            # Best-effort raw text for keyword matching
            try:
                hay = json.dumps(data, ensure_ascii=False).lower()
            except Exception:
                hay = ""

            for rule in rules:
                try:
                    if not isinstance(rule, dict) or not bool(rule.get("enabled", False)):
                        continue
                    trigger = rule.get("trigger") or {}
                    if not isinstance(trigger, dict):
                        trigger = {}
                    if str(trigger.get("source") or "").lower() != "shopify":
                        continue
                    # Allow exact topic match; Shopify sends topics like "orders/paid", "orders/updated", etc.
                    if str(trigger.get("event") or "").strip() != topic_norm:
                        continue

                    # Optional testing guard: if configured, only fire when the order/draft-order phone matches.
                    # Accept either list or newline/comma separated string.
                    try:
                        test_phones = rule.get("test_phone_numbers") or rule.get("test_numbers") or []
                        if isinstance(test_phones, str):
                            test_phones = [x.strip() for x in re.split(r"[,\n\r]+", test_phones) if x and x.strip()]
                        if isinstance(test_phones, list):
                            test_set = {_digits_only(str(x or "")) for x in test_phones}
                            test_set = {x for x in test_set if x}
                        else:
                            test_set = set()
                        if test_set:
                            # Allow testing even if the webhook payload doesn't include a phone number
                            # (e.g. fulfillments/create). If exactly one test number is configured, route to it.
                            if not phone_digits:
                                if len(test_set) == 1:
                                    phone_digits = next(iter(test_set))
                                    ctx["phone"] = phone_digits
                                else:
                                    continue
                            if phone_digits not in test_set:
                                continue
                    except Exception:
                        pass

                    # Optional simple condition:
                    # - match=contains + keywords: search within payload JSON
                    # - match=tag_contains + value: match order.tags contains value (Shopify tags string)
                    cond = rule.get("condition") or {}
                    if not isinstance(cond, dict):
                        cond = {}
                    match_mode = str(cond.get("match") or "").strip().lower()
                    if match_mode in ("tag_contains", "tagged_with"):
                        needle = str(cond.get("value") or cond.get("tag") or "").strip().lower()
                        if needle:
                            tags_str = str(data.get("tags") or "")
                            tags = [t.strip().lower() for t in tags_str.split(",") if t and t.strip()]
                            if needle not in tags:
                                continue
                    else:
                        keywords = cond.get("keywords")
                        kws = [str(x or "").strip().lower() for x in keywords] if isinstance(keywords, list) else []
                        if kws and hay:
                            if not any(k and (k in hay) for k in kws):
                                continue

                    # Stats trigger
                    try:
                        await self.db_manager.inc_automation_rule_stat(
                            str(rule.get("id") or ""),
                            "triggers",
                            1,
                            last_trigger_ts=str(datetime.utcnow().isoformat()),
                        )
                    except Exception:
                        pass

                    actions = rule.get("actions") or []
                    if isinstance(actions, dict):
                        actions = [actions]
                    if not isinstance(actions, list):
                        actions = []

                    for act in actions:
                        if not isinstance(act, dict):
                            continue
                        at = str(act.get("type") or "").strip().lower()
                        if at in ("send_text", "send_whatsapp_text"):
                            to_id = self._render_template(str(act.get("to") or "{{ phone }}"), ctx).strip() or phone_digits
                            msg = self._render_template(str(act.get("text") or ""), ctx).strip()
                            if not (to_id and msg):
                                continue
                            await self.process_outgoing_message({
                                "user_id": to_id,
                                "type": "text",
                                "from_me": True,
                                "message": msg,
                                "timestamp": datetime.utcnow().isoformat(),
                                "agent_username": "automation",
                            })
                            try:
                                await self.db_manager.inc_automation_rule_stat(str(rule.get("id") or ""), "messages_sent", 1)
                            except Exception:
                                pass
                        elif at in ("send_template", "send_whatsapp_template"):
                            to_id = self._render_template(str(act.get("to") or "{{ phone }}"), ctx).strip() or phone_digits
                            tname = self._render_template(str(act.get("template_name") or ""), ctx).strip()
                            lang = str(act.get("language") or "en").strip() or "en"
                            comps = act.get("components") or []
                            if not isinstance(comps, list):
                                comps = []
                            if not (to_id and tname):
                                continue
                            preview = str(act.get("preview") or f"[template] {tname}")
                            await self.process_outgoing_message({
                                "user_id": to_id,
                                "type": "text",
                                "from_me": True,
                                "message": preview,
                                "timestamp": datetime.utcnow().isoformat(),
                                "agent_username": "automation",
                                "template_name": tname,
                                "template_language": lang,
                                "template_components": comps,
                            })
                            try:
                                await self.db_manager.inc_automation_rule_stat(str(rule.get("id") or ""), "messages_sent", 1)
                            except Exception:
                                pass
                except Exception as exc:
                    print(f"shopify automation failed: {exc}")
                    continue
        finally:
            if ws_token is not None:
                try:
                    _CURRENT_WORKSPACE.reset(ws_token)
                except Exception:
                    pass

    async def _run_delivery_automations(self, event: str, payload: dict, workspace: str | None = None) -> None:
        """Execute automations for a Delivery App webhook event (e.g. order status changed).

        Rules must have:
          trigger.source == "delivery"
          trigger.event == <event>, e.g. "order_status_changed"
        """
        ws_token = None
        try:
            if workspace:
                try:
                    ws_token = _CURRENT_WORKSPACE.set(_coerce_workspace(workspace))
                except Exception:
                    ws_token = None

            ws = get_current_workspace()
            rules = await self._load_automation_rules(ws)
            if not rules:
                return

            event_norm = str(event or "").strip() or "order_status_changed"
            data = payload if isinstance(payload, dict) else {}

            # Accept either flat payload or { order: {...} }
            order_obj = data.get("order") if isinstance(data.get("order"), dict) else {}
            if not isinstance(order_obj, dict):
                order_obj = {}

            def _first(*vals):
                for v in vals:
                    if v is None:
                        continue
                    s = str(v).strip()
                    if s:
                        return s
                return ""

            phone_raw = _first(
                data.get("customer_phone"),
                data.get("phone"),
                order_obj.get("customer_phone"),
                order_obj.get("phone"),
            )
            phone_digits = _digits_only(phone_raw)

            status_val = _first(
                data.get("status"),
                data.get("new_status"),
                order_obj.get("status"),
                order_obj.get("delivery_status"),
                order_obj.get("new_status"),
            )
            status_norm = str(status_val or "").strip()

            ctx = {
                "event": event_norm,
                "phone": phone_digits,
                "status": status_norm,
                "order": order_obj,
                # Common aliases for convenience in templates
                "order_id": order_obj.get("id") or data.get("order_id") or "",
                "order_name": order_obj.get("order_name") or data.get("order_name") or "",
                "city": order_obj.get("city") or data.get("city") or "",
                "cash_amount": order_obj.get("cash_amount") or data.get("cash_amount") or "",
                "payload": data,
            }

            # Best-effort raw text for fallback keyword matching
            try:
                hay = json.dumps(data, ensure_ascii=False).lower()
            except Exception:
                hay = ""

            for rule in rules:
                try:
                    if not isinstance(rule, dict) or not bool(rule.get("enabled", False)):
                        continue
                    trigger = rule.get("trigger") or {}
                    if not isinstance(trigger, dict):
                        trigger = {}
                    if str(trigger.get("source") or "").lower() != "delivery":
                        continue
                    if str(trigger.get("event") or "").strip() != event_norm:
                        continue

                    # Optional testing guard: only fire for specific phone numbers.
                    try:
                        test_phones = rule.get("test_phone_numbers") or rule.get("test_numbers") or []
                        if isinstance(test_phones, str):
                            test_phones = [x.strip() for x in re.split(r"[,\n\r]+", test_phones) if x and x.strip()]
                        if isinstance(test_phones, list):
                            test_set = {_digits_only(str(x or "")) for x in test_phones}
                            test_set = {x for x in test_set if x}
                        else:
                            test_set = set()
                        if test_set:
                            if not phone_digits:
                                continue
                            if phone_digits not in test_set:
                                continue
                    except Exception:
                        pass

                    cond = rule.get("condition") or {}
                    if not isinstance(cond, dict):
                        cond = {}
                    mode = str(cond.get("match") or "any").strip().lower()

                    matched = False
                    if mode in ("any", "*"):
                        matched = True
                    elif mode in ("status_in", "delivery_status_in"):
                        raw = cond.get("statuses")
                        if isinstance(raw, str):
                            statuses = [x.strip() for x in re.split(r"[,\n\r]+", raw) if x and x.strip()]
                        elif isinstance(raw, list):
                            statuses = [str(x or "").strip() for x in raw if str(x or "").strip()]
                        else:
                            statuses = []
                        sset = {s.lower() for s in statuses if s}
                        matched = bool(status_norm) and (status_norm.lower() in sset) if sset else True
                    elif mode in ("status_equals", "delivery_status_equals"):
                        needle = str(cond.get("value") or "").strip().lower()
                        matched = bool(needle) and bool(status_norm) and (status_norm.lower() == needle)
                    else:
                        # Fallback: contains keywords in payload json
                        keywords = cond.get("keywords")
                        kws = [str(x or "").strip().lower() for x in keywords] if isinstance(keywords, list) else []
                        if kws and hay:
                            matched = any(k and (k in hay) for k in kws)
                        else:
                            matched = True

                    if not matched:
                        continue

                    try:
                        await self.db_manager.inc_automation_rule_stat(
                            str(rule.get("id") or ""),
                            "triggers",
                            1,
                            last_trigger_ts=str(datetime.utcnow().isoformat()),
                        )
                    except Exception:
                        pass

                    actions = rule.get("actions") or []
                    if isinstance(actions, dict):
                        actions = [actions]
                    if not isinstance(actions, list):
                        actions = []

                    for act in actions:
                        if not isinstance(act, dict):
                            continue
                        at = str(act.get("type") or "").strip().lower()
                        if at in ("send_text", "send_whatsapp_text"):
                            to_id = self._render_template(str(act.get("to") or "{{ phone }}"), ctx).strip() or phone_digits
                            msg = self._render_template(str(act.get("text") or ""), ctx).strip()
                            if not (to_id and msg):
                                continue
                            await self.process_outgoing_message({
                                "user_id": to_id,
                                "type": "text",
                                "from_me": True,
                                "message": msg,
                                "timestamp": datetime.utcnow().isoformat(),
                                "agent_username": "automation",
                            })
                            try:
                                await self.db_manager.inc_automation_rule_stat(str(rule.get("id") or ""), "messages_sent", 1)
                            except Exception:
                                pass
                        elif at in ("send_template", "send_whatsapp_template"):
                            to_id = self._render_template(str(act.get("to") or "{{ phone }}"), ctx).strip() or phone_digits
                            tname = self._render_template(str(act.get("template_name") or ""), ctx).strip()
                            lang = str(act.get("language") or "en").strip() or "en"
                            comps = act.get("components") or []
                            if not isinstance(comps, list):
                                comps = []
                            if not (to_id and tname):
                                continue
                            preview = str(act.get("preview") or f"[template] {tname}")
                            await self.process_outgoing_message({
                                "user_id": to_id,
                                "type": "text",
                                "from_me": True,
                                "message": preview,
                                "timestamp": datetime.utcnow().isoformat(),
                                "agent_username": "automation",
                                "template_name": tname,
                                "template_language": lang,
                                "template_components": comps,
                            })
                            try:
                                await self.db_manager.inc_automation_rule_stat(str(rule.get("id") or ""), "messages_sent", 1)
                            except Exception:
                                pass
                except Exception as exc:
                    print(f"delivery automation failed: {exc}")
                    continue
        finally:
            if ws_token is not None:
                try:
                    _CURRENT_WORKSPACE.reset(ws_token)
                except Exception:
                    pass

    # -------- survey flow --------
    async def send_survey_invite(self, user_id: str) -> None:
        body = (
            "Aidez-nous à nous améliorer et obtenez 15% de réduction sur votre commande.\n"
            "ساعدنا على التحسن واحصل على خصم 15% على طلبك."
        )
        await self.process_outgoing_message({
            "user_id": user_id,
            "type": "buttons",
            "from_me": True,
            "message": body,
            "buttons": [
                {"id": "survey_start_ok", "title": "موافق | OK"},
                {"id": "survey_decline", "title": "غير مهتم | Pas int."},
            ],
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def _handle_survey_interaction(self, user_id: str, reply_id: str, title: str) -> None:
        state = await self.redis_manager.get_survey_state(user_id) or {}
        stage = state.get("stage") or "start"
        uid_digits = _digits_only(user_id)
        try:
            env_cfg = await self._get_inbox_env()
            survey_tests = set((env_cfg or {}).get("survey_test_numbers") or set())
            is_test = uid_digits in survey_tests
        except Exception:
            is_test = uid_digits in SURVEY_TEST_NUMBERS

        # Start → ask rating
        if reply_id == "survey_start_ok":
            state = {"stage": "rating", "started_at": datetime.utcnow().isoformat()}
            await self.redis_manager.set_survey_state(user_id, state)
            body = (
                "Comment évaluez-vous la performance de notre agent ?\n"
                "كيف تقيم أداء وكيل المحادثة؟"
            )
            sections = [{
                "title": "Rating | التقييم",
                "rows": [
                    {"id": "survey_rate_1", "title": "⭐ 1"},
                    {"id": "survey_rate_2", "title": "⭐⭐ 2"},
                    {"id": "survey_rate_3", "title": "⭐⭐⭐ 3"},
                    {"id": "survey_rate_4", "title": "⭐⭐⭐⭐ 4"},
                    {"id": "survey_rate_5", "title": "⭐⭐⭐⭐⭐ 5"},
                ],
            }]
            await self.process_outgoing_message({
                "user_id": user_id,
                "type": "list",
                "from_me": True,
                "message": body,
                "button_text": "Choisir | اختر",
                "sections": sections,
                "timestamp": datetime.utcnow().isoformat(),
            })
            return

        # Decline → thank you
        if reply_id == "survey_decline":
            await self.redis_manager.clear_survey_state(user_id)
            if not (is_test and SURVEY_TEST_BYPASS_COOLDOWN):
                if is_test and SURVEY_TEST_COOLDOWN_SEC > 0:
                    await self.redis_manager.mark_survey_invited(user_id, window_sec=SURVEY_TEST_COOLDOWN_SEC)
                else:
                    await self.redis_manager.mark_survey_invited(user_id)
            await self.process_outgoing_message({
                "user_id": user_id,
                "type": "text",
                "from_me": True,
                "message": (
                    "Merci pour votre temps. Si vous changez d'avis, écrivez-nous.\n"
                    "شكرًا لوقتك. إذا غيرت رأيك، راسلنا في أي وقت."
                ),
                "timestamp": datetime.utcnow().isoformat(),
            })
            return

        # Rating selected → store and ask improvement
        if reply_id.startswith("survey_rate_"):
            try:
                rating = int(reply_id.split("_")[-1])
            except Exception:
                rating = None
            if not rating:
                return
            state["rating"] = max(1, min(5, rating))
            state["stage"] = "improvement"
            await self.redis_manager.set_survey_state(user_id, state)

            body = (
                "Quel aspect souhaitez-vous que nous améliorions le plus ?\n"
                "ما هو أكثر شيء تريد منا تحسينه؟"
            )
            sections = [{
                "title": "Improve | تحسين",
                "rows": [
                    {"id": "survey_improve_products", "title": "المزيد من المنتجات", "description": "Plus de produits"},
                    {"id": "survey_improve_service", "title": "تحسينات الخدمة", "description": "Améliorations du service"},
                    {"id": "survey_improve_prices", "title": "أسعار ملائمة", "description": "Des prix plus abordables"},
                    {"id": "survey_improve_quality", "title": "جودة أعلى", "description": "Produits de meilleure qualité"},
                ],
            }]
            await self.process_outgoing_message({
                "user_id": user_id,
                "type": "list",
                "from_me": True,
                "message": body,
                "button_text": "Choisir | اختر",
                "sections": sections,
                "timestamp": datetime.utcnow().isoformat(),
            })
            return

        # Improvement selected → thank and summarize
        if reply_id.startswith("survey_improve_"):
            map_ar = {
                "survey_improve_products": "المزيد من المنتجات",
                "survey_improve_service": "تحسينات الخدمة",
                "survey_improve_prices": "أسعار أكثر ملاءمة",
                "survey_improve_quality": "منتجات ذات جودة أعلى",
            }
            map_fr = {
                "survey_improve_products": "Plus de produits",
                "survey_improve_service": "Améliorations du service",
                "survey_improve_prices": "Des prix plus abordables",
                "survey_improve_quality": "Produits de meilleure qualité",
            }
            improvement_ar = map_ar.get(reply_id, title or "")
            improvement_fr = map_fr.get(reply_id, title or "")
            rating = int(state.get("rating") or 0)
            stars = "⭐" * max(1, min(5, rating)) if rating else "—"
            state["improvement"] = reply_id
            state["stage"] = "done"
            await self.redis_manager.set_survey_state(user_id, state, ttl_sec=7 * 24 * 60 * 60)
            if not (is_test and SURVEY_TEST_BYPASS_COOLDOWN):
                if is_test and SURVEY_TEST_COOLDOWN_SEC > 0:
                    await self.redis_manager.mark_survey_invited(user_id, window_sec=SURVEY_TEST_COOLDOWN_SEC)
                else:
                    await self.redis_manager.mark_survey_invited(user_id)

            summary = (
                f"Merci pour votre aide ! Cela nous aidera à nous améliorer.\n"
                f"Évaluation: {stars} ({rating}/5)\n"
                f"Amélioration prioritaire: {improvement_fr}\n\n"
                f"شكرًا لمساعدتك! هذا سيساعدنا على التحسن.\n"
                f"التقييم: {stars} ({rating}/5)\n"
                f"الأولوية في التحسين: {improvement_ar}\n\n"
                f"لقد حصلت على خصم 15% — يرجى إرسال صور المنتجات التي تريدها في طلبك.\n"
                f"Vous bénéficiez de 15% de réduction — envoyez-nous les images des articles souhaités."
            )
            await self.process_outgoing_message({
                "user_id": user_id,
                "type": "text",
                "from_me": True,
                "message": summary,
                "timestamp": datetime.utcnow().isoformat(),
            })
            return

    # ------------------------- auto-reply helpers -------------------------
    def _extract_product_retailer_id(self, text: str) -> Optional[str]:
        """Extract a product/variant id only when explicitly referenced.

        Accepted sources:
        - Explicit pattern like "ID: 123456" (6+ digits)
        - From URLs: variant query, generic id query, or /variants/{id} in path
        """
        try:
            if not text:
                return None
            # 1) Explicit label "ID: <digits>"
            m = re.search(r"\bID\s*[:：]\s*(\d{6,})\b", text, re.IGNORECASE)
            if m:
                return m.group(1)
            # 1.5) Extract from any URL in the text
            try:
                urls = re.findall(r"https?://\S+", text)
            except Exception:
                urls = []
            for u in urls:
                try:
                    parsed = urlparse(u)
                    qs = parse_qs(parsed.query or "")
                    # Shopify-style variant param
                    if "variant" in qs and qs["variant"]:
                        v = qs["variant"][-1]
                        if re.fullmatch(r"\d{6,}", v or ""):
                            return v
                    # Generic id param
                    if "id" in qs and qs["id"]:
                        v = qs["id"][-1]
                        if re.fullmatch(r"\d{6,}", v or ""):
                            return v
                    # Path pattern /variants/{id}
                    m2 = re.search(r"/variants/(\d{6,})(?:/|\b)", parsed.path or "")
                    if m2:
                        return m2.group(1)
                except Exception:
                    continue
            # NOTE: Do not treat bare digit sequences as valid IDs to avoid
            # false positives from casual numbers in normal text. Only explicit
            # "ID:" labels or URLs are accepted.
        except Exception:
            pass
        return None
    def _normalize_for_match(self, text: str) -> list[str]:
        text_lc = (text or "").lower()
        # Replace non-alphanumerics with space and split
        tokens = re.split(r"[^a-z0-9]+", text_lc)
        return [t for t in tokens if len(t) >= 2]

    def _score_product_name_match(self, text_tokens: list[str], product_name: Optional[str]) -> float:
        if not product_name:
            return 0.0
        name_tokens = self._normalize_for_match(product_name)
        if not name_tokens:
            return 0.0
        name_token_set = set(name_tokens)
        text_token_set = set(text_tokens)
        common = name_token_set.intersection(text_token_set)
        # Base score: token overlap ratio relative to product name tokens
        score = len(common) / max(1, len(name_token_set))
        # Bonus if full normalized name appears as substring of text
        text_joined = " ".join(text_tokens)
        name_joined = " ".join(name_tokens)
        if name_joined and name_joined in text_joined:
            score += 0.2
        return min(score, 1.0)

    async def _best_catalog_match(self, text: str) -> Optional[dict]:
        try:
            ws = get_current_workspace()
            cid = await _get_effective_catalog_id(ws)
            products = catalog_manager.get_cached_products(cache_file=_catalog_cache_file_for(ws, cid))
        except Exception:
            products = []
        if not products:
            return None
        text_tokens = self._normalize_for_match(text)
        if not text_tokens:
            return None
        best: tuple[float, dict] | None = None
        for product in products:
            score = self._score_product_name_match(text_tokens, product.get("name"))
            if score <= 0:
                continue
            # Require at least one image to reply
            images = product.get("images") or []
            if not images:
                continue
            if not best or score > best[0]:
                best = (score, product)
        if not best:
            return None
        if best[0] < AUTO_REPLY_MIN_SCORE:
            return None
        return best[1]

    async def _maybe_auto_reply_with_catalog(self, user_id: str, text: str) -> None:
        if not AUTO_REPLY_CATALOG_MATCH:
            return
        # Only the QUICK-REPLY BUTTONS are gated by test numbers; catalog matches are for all
        try:
            env_cfg = await self._get_inbox_env()
            test_numbers = set((env_cfg or {}).get("auto_reply_test_numbers") or set())
            is_test_number = _digits_only(user_id) in test_numbers
        except Exception:
            is_test_number = False
        # 24h cooldown per user (bypass when an explicit product ID/URL is present)
        try:
            if await self.redis_manager.was_auto_reply_recent(user_id):
                try:
                    has_explicit_id = bool(self._extract_product_retailer_id(text))
                except Exception:
                    has_explicit_id = False
                if not has_explicit_id:
                    return
        except Exception:
            pass
        # 0) If the message has no URL and contains no digits, offer quick-reply buttons
        try:
            has_url = bool(re.search(r"https?://", text or ""))
            has_digit = bool(re.search(r"\d", text or ""))
        except Exception:
            has_url = False
            has_digit = False
        if (not has_url) and (not has_digit) and is_test_number:
            await self.process_outgoing_message({
                "user_id": user_id,
                "type": "buttons",
                "from_me": True,
                "message": (
                    "Veuillez choisir une option :\nJe veux acheter un article\nJe veux vérifier le statut de ma commande\n\n"
                    "اختر خيارًا:\nأريد شراء منتج\nأريد التحقق من حالة طلبي"
                ),
                "buttons": [
                    {"id": "buy_item", "title": "Acheter | شراء"},
                    {"id": "order_status", "title": "Statut | حالة"},
                ],
                "timestamp": datetime.utcnow().isoformat(),
            })
            try:
                await self.redis_manager.mark_auto_reply_sent(user_id)
            except Exception:
                pass
            return
        # 1) Try explicit retailer_id extraction from text
        retailer_id_raw = self._extract_product_retailer_id(text)
        if retailer_id_raw:
            # Resolve to a valid Shopify variant id if needed
            resolved_variant_id: Optional[str] = None
            resolved_variant: Optional[dict] = None
            try:
                resolved_variant_id, resolved_variant = await self._resolve_shopify_variant(str(retailer_id_raw))
            except Exception:
                resolved_variant_id, resolved_variant = None, None
            try:
                ws = get_current_workspace()
                cid = await _get_effective_catalog_id(ws)
                products = catalog_manager.get_cached_products(cache_file=_catalog_cache_file_for(ws, cid))
            except Exception:
                products = []
            if products:
                matched = next((p for p in products if str(p.get("retailer_id")) == str(retailer_id_raw)), None)
            else:
                matched = None

            if matched:
                # Send interactive catalog item; mark to append bilingual prompt after delivery
                await self.process_outgoing_message({
                    "user_id": user_id,
                    "type": "catalog_item",
                    "from_me": True,
                    # UI should carry Shopify variant id for Add to Order if we resolved it
                    "product_retailer_id": str(resolved_variant_id or retailer_id_raw),
                    # Use meta retailer_id for WA interactive send
                    "retailer_id": str(matched.get("retailer_id")),
                    "caption": (resolved_variant or {}).get("title") or matched.get("name") or "",
                    "timestamp": datetime.utcnow().isoformat(),
                    "needs_bilingual_prompt": True,
                })
                try:
                    await self.redis_manager.mark_auto_reply_sent(user_id)
                except Exception:
                    pass
                return
            else:
                # No local catalog match, still try to send interactive product by retailer_id
                # Build caption from Shopify variant if available
                cap = ""
                if resolved_variant:
                    t = resolved_variant.get("title") or ""
                    pr = resolved_variant.get("price") or ""
                    cap = (f"{t} - {pr} MAD").strip(" -")
                await self.process_outgoing_message({
                    "user_id": user_id,
                    "type": "catalog_item",
                    "from_me": True,
                    # UI variant id for Add to Order
                    "product_retailer_id": str(resolved_variant_id or retailer_id_raw),
                    "caption": cap,
                    "timestamp": datetime.utcnow().isoformat(),
                    "needs_bilingual_prompt": True,
                })
                try:
                    await self.redis_manager.mark_auto_reply_sent(user_id)
                except Exception:
                    pass
                return

        # 2) Fallback to name-based best match using score threshold
        product = await self._best_catalog_match(text)
        if not product:
            return
        images = product.get("images") or []
        if not images:
            return
        image_url = images[0].get("url")
        if not image_url:
            return
        caption_parts = [p for p in [product.get("name"), product.get("price")] if p]
        caption = " - ".join(caption_parts)
        # Removed automatic image auto-reply on name-based match
        return

    async def _download_media(self, media_id: str, media_type: str) -> tuple[str, str]:
        """Download media from WhatsApp and upload it to Google Cloud Storage.

        Returns a tuple ``(local_path, drive_url)`` where ``drive_url`` is the
        public link to the uploaded file. Raises an exception if the upload
        fails so callers don't fall back to local paths.
        """
        try:
            media_content, mime_type = await self.whatsapp_messenger.download_media(media_id)
            mime_type = mime_type.split(';', 1)[0].strip()

            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            file_extension = mimetypes.guess_extension(mime_type) or ""
            if not file_extension and mime_type.startswith("audio/"):
                file_extension = ".ogg"
            filename = f"{media_type}_{timestamp}_{media_id[:8]}{file_extension}"
            file_path = self.media_dir / filename

            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(media_content)

            drive_url = await upload_file_to_gcs(
                str(file_path), mime_type
            )
            if not drive_url:
                raise RuntimeError("GCS upload failed")

            # Return a relative path for clients and the public GCS URL
            return f"/media/{filename}", drive_url

        except Exception as e:
            print(f"Error downloading media {media_id}: {e}")
            raise

# ------------------------- helpers -------------------------

async def lookup_phone(user_id: str) -> Optional[str]:
    """Return the stored phone number for a user, if available."""
    try:
        async with db_manager._conn() as conn:
            cur = await conn.execute(
                "SELECT phone FROM users WHERE user_id = ?",
                (user_id,),
            )
            row = await cur.fetchone()
            if row:
                phone = row["phone"]
                if phone:
                    return str(phone)
    except Exception as exc:
        print(f"lookup_phone error: {exc}")
    return None

# Initialize managers
_tenant_managers: Dict[str, DatabaseManager] = {}
if ENABLE_MULTI_WORKSPACE:
    for _ws in (WORKSPACES or [DEFAULT_WORKSPACE]):
        _w = _coerce_workspace(_ws)
        # Prefer workspace Postgres URL (Supabase). Fallback to SQLite per-tenant path.
        _url = (TENANT_DB_URLS or {}).get(_w) or None
        _path = (TENANT_DB_PATHS or {}).get(_w) or DB_PATH
        _tenant_managers[_w] = DatabaseManager(db_path=_path, db_url=_url)
else:
    # Keep legacy behavior for the default workspace (existing data stays in DB_PATH / DATABASE_URL),
    # but still route by workspace using lazy tenant DB managers for other workspaces.
    _tenant_managers[_coerce_workspace(DEFAULT_WORKSPACE)] = DatabaseManager(
        db_path=DB_PATH,
        db_url=(DATABASE_URL or None),
    )
db_manager = WorkspaceDatabaseRouter(_tenant_managers)

# Shared auth/settings DB (agents, refresh tokens, tag options) lives on the default DATABASE_URL (irrakids)
# as requested. Fallback to AUTH_DB_PATH/SQLite when DATABASE_URL is not configured.
auth_db_manager = DatabaseManager(db_url=(DATABASE_URL or None), db_path=AUTH_DB_PATH, force_single_sqlite=True)
connection_manager = ConnectionManager()
redis_manager = RedisManager()
message_processor = MessageProcessor(connection_manager, redis_manager, db_manager)

# ────────────────────────────────────────────────────────────
# Webhook ingress: ACK fast, process async
# ────────────────────────────────────────────────────────────
WEBHOOK_QUEUE: "asyncio.Queue[dict]" = asyncio.Queue(maxsize=max(1, int(WEBHOOK_QUEUE_MAXSIZE)))
WEBHOOK_STATE = WebhookState(db_ready=False)
webhook_runtime = WebhookRuntime(
    db_manager=db_manager,
    redis_manager=redis_manager,
    message_processor=message_processor,
    webhook_queue=WEBHOOK_QUEUE,
    coerce_workspace=_coerce_workspace,
    vlog=_vlog,
    verify_token=VERIFY_TOKEN,
    verify_tokens=RUNTIME_WEBHOOK_VERIFY_TOKENS,
    meta_app_secret=META_APP_SECRET,
    # Do NOT block ingress by a static env allowlist; routing is enforced later per-workspace.
    allowed_phone_number_ids=set(),
    # Use runtime mapping (DB-driven) so new workspace phone ids work without redeploy.
    phone_id_to_workspace=RUNTIME_PHONE_ID_TO_WORKSPACE,
    default_workspace=DEFAULT_WORKSPACE,
    use_redis_stream=bool(WEBHOOK_USE_REDIS_STREAM),
    stream_key=WEBHOOK_STREAM_KEY,
    stream_group=WEBHOOK_STREAM_GROUP,
    stream_dlq_key=WEBHOOK_STREAM_DLQ_KEY,
    max_attempts=int(WEBHOOK_MAX_ATTEMPTS),
    claim_min_idle_ms=int(WEBHOOK_CLAIM_MIN_IDLE_MS),
    use_db_queue=bool(WEBHOOK_USE_DB_QUEUE),
    db_batch_size=int(WEBHOOK_DB_BATCH_SIZE),
    db_poll_interval_sec=float(WEBHOOK_DB_POLL_INTERVAL_SEC),
    enqueue_timeout_seconds=float(WEBHOOK_ENQUEUE_TIMEOUT_SECONDS),
    workers=int(WEBHOOK_WORKERS),
    processing_timeout_seconds=float(WEBHOOK_PROCESSING_TIMEOUT_SECONDS),
    state=WEBHOOK_STATE,
)
messenger = message_processor.whatsapp_messenger

# FastAPI app
app = FastAPI(default_response_class=(ORJSONResponse if _ORJSON_AVAILABLE else JSONResponse))
app.include_router(create_webhook_router(webhook_runtime))

# ── Request context: request_id (for tracing) ──────────────────────
@app.middleware("http")
async def request_id_middleware(request: StarletteRequest, call_next):
    incoming = (request.headers.get("x-request-id") or request.headers.get("X-Request-Id") or "").strip()
    rid, tok = _set_request_id(incoming or None)
    try:
        resp: StarletteResponse = await call_next(request)
        try:
            resp.headers["X-Request-Id"] = rid
        except Exception:
            pass
        return resp
    finally:
        try:
            _reset_request_id(tok)
        except Exception:
            pass

# ── Auth middleware: protect API routes by default ─────────────────
@app.middleware("http")
async def _auth_middleware(request: StarletteRequest, call_next):
    try:
        if DISABLE_AUTH:
            return await call_next(request)
        if request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if _is_public_path(path):
            return await call_next(request)
        # Enforce authentication
        try:
            agent = await get_current_agent(request)  # type: ignore[arg-type]
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

        # Enforce inactivity auto-logout (best-effort, Redis-backed).
        # If agent hasn't been active in > INACTIVITY_TIMEOUT_SECONDS, force re-login.
        try:
            ws = get_current_workspace()
            uname = str((agent or {}).get("username") or "")
            if uname and getattr(redis_manager, "redis_client", None):
                last = await redis_manager.get_agent_last_seen(uname, workspace=ws)
                if last is not None and (time.time() - float(last)) > float(INACTIVITY_TIMEOUT_SECONDS):
                    try:
                        await auth_db_manager.revoke_all_refresh_tokens_for_agent(uname)
                    except Exception:
                        pass
                    try:
                        # Clear presence for all configured workspaces (so admin view updates immediately)
                        for _w in (WORKSPACES or [DEFAULT_WORKSPACE]):
                            try:
                                await redis_manager.clear_agent_last_seen(uname, workspace=_w)
                            except Exception:
                                continue
                    except Exception:
                        pass
                    return JSONResponse(status_code=401, content={"detail": "Session expired due to inactivity"})
                # Touch activity on every authenticated request
                await redis_manager.touch_agent_last_seen(uname, workspace=ws)
        except Exception:
            pass

        request.state.agent = agent  # type: ignore[attr-defined]
        tok = None
        try:
            tok = _set_agent_username(str(agent.get("username") or "") if isinstance(agent, dict) else None)
        except Exception:
            tok = None
        try:
            return await call_next(request)
        finally:
            if tok is not None:
                try:
                    _reset_agent_username(tok)
                except Exception:
                    pass
    except Exception:
        # Do not mask unexpected server bugs as "Unauthorized" — it makes debugging impossible.
        logging.getLogger(__name__).exception("Unhandled error in auth middleware")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# Expose Prometheus metrics
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# Enable Shopify integration only if it can be imported/configured.
SHOPIFY_ROUTES_ENABLED: bool = False
SHOPIFY_ROUTES_ERROR: str | None = None
try:
    from .shopify_integration import router as shopify_router  # type: ignore
    app.include_router(shopify_router)
    print("✅ Shopify integration routes enabled")
    SHOPIFY_ROUTES_ENABLED = True
except Exception as exc:
    print(f"⚠️ Shopify integration disabled: {exc}")
    SHOPIFY_ROUTES_ENABLED = False
    SHOPIFY_ROUTES_ERROR = str(exc)

def _has_route(path: str, method: str) -> bool:
    try:
        m = str(method or "").upper()
        for r in getattr(app, "routes", []) or []:
            try:
                if getattr(r, "path", None) != path:
                    continue
                methods = getattr(r, "methods", None) or set()
                if m in methods:
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False

# Ensure these endpoints exist even if the Shopify router fails to mount (prevents 404s in the UI).
if not _has_route("/search-customer", "GET"):
    @app.get("/search-customer")
    async def search_customer_endpoint(phone_number: str):
        try:
            from .shopify_integration import fetch_customer_by_phone  # type: ignore
            data = await fetch_customer_by_phone(phone_number)
            if not data:
                raise HTTPException(status_code=404, detail="Customer not found")
            if isinstance(data, dict) and data.get("status") == 403:
                raise HTTPException(status_code=403, detail=data.get("detail") or "Forbidden")
            if isinstance(data, dict) and data.get("error"):
                raise HTTPException(status_code=int(data.get("status", 500)), detail=data.get("detail") or data.get("error"))
            return data
        except HTTPException:
            raise
        except Exception as exc:
            # Config/import errors show as 503 (not 404) so the frontend can handle it.
            raise HTTPException(status_code=503, detail=f"Shopify integration disabled: {SHOPIFY_ROUTES_ERROR or str(exc) or 'not configured'}")

if not _has_route("/search-customers-all", "GET"):
    @app.get("/search-customers-all")
    async def search_customers_all_endpoint(phone_number: str):
        try:
            # Reuse the existing implementation inside the integration module if available.
            from . import shopify_integration as si  # type: ignore
            fn = getattr(si, "search_customers_all", None)
            if callable(fn):
                return await fn(phone_number=phone_number)
            raise RuntimeError("search_customers_all not available")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Shopify integration disabled: {SHOPIFY_ROUTES_ERROR or str(exc) or 'not configured'}")

@app.get("/debug/shopify")
async def debug_shopify(_: dict = Depends(require_admin)):
    """Admin-only: confirm whether Shopify routes were mounted + basic config state."""
    info: dict = {"enabled": bool(SHOPIFY_ROUTES_ENABLED), "error": SHOPIFY_ROUTES_ERROR}
    try:
        # Import lazily; this should not raise in our integration module, but keep it defensive.
        from . import shopify_integration as si  # type: ignore
        # Avoid leaking secrets; only report whether config appears present.
        info["configured"] = bool(getattr(si, "STORE_URL", None)) and bool(getattr(si, "API_KEY", None))
        info["store_url"] = str(getattr(si, "STORE_URL", "") or "")
    except Exception as exc:
        info["configured"] = False
        info["import_error"] = str(exc)
    return info


# Mount the media directory to serve uploaded files
app.mount("/media", StaticFiles(directory=str(MEDIA_DIR)), name="media")

# Configure CORS via environment (comma-separated list). Default to '*'.
_allowed_origins = os.getenv("ALLOWED_ORIGINS", "*")
allowed_origins = [o.strip() for o in _allowed_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compression for faster responses
app.add_middleware(GZipMiddleware, minimum_size=500)

# Trusted hosts (optional but recommended in production)
_allowed_hosts_env = os.getenv("ALLOWED_HOSTS", "*")
allowed_hosts = [h.strip() for h in _allowed_hosts_env.split(",") if h.strip()]
if allowed_hosts and allowed_hosts != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

# Workspace context middleware (must run for all tenant-scoped endpoints).
# Frontend sends `X-Workspace: irranova|irrakids` on every request.
@app.middleware("http")
async def workspace_context_middleware(request: StarletteRequest, call_next):
    ws = _workspace_from_request(request)  # type: ignore[arg-type]
    token = _CURRENT_WORKSPACE.set(ws)
    try:
        resp: StarletteResponse = await call_next(request)
        try:
            resp.headers["X-Workspace"] = ws
        except Exception:
            pass
        return resp
    finally:
        try:
            _CURRENT_WORKSPACE.reset(token)
        except Exception:
            pass

# Smart caching: no-cache HTML shell, long cache for static assets
@app.middleware("http")
async def no_cache_html(request: StarletteRequest, call_next):
    response: StarletteResponse = await call_next(request)
    path = request.url.path or "/"
    # Service worker script must never be long-cached, otherwise clients get stuck on old SW
    if path == "/sw.js" or path.endswith("/sw.js"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response
    if path == "/" or path.endswith(".html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    # Always serve freshest app code to avoid hard refresh requirements
    if path.endswith((".js", ".css", ".map")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    # Allow long-lived cache for static media assets only (not JS/CSS)
    elif (
        path.startswith("/static/")
        or path.endswith((
            ".png",
            ".jpg",
            ".jpeg",
            ".svg",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
        ))
    ) and not path.endswith(".html"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response

@app.on_event("startup")
async def startup():
    logging.getLogger("httpx").setLevel(logging.WARNING)
    # DB init strategy:
    # - If Postgres is configured+required, we fail startup so Cloud Run won't route traffic to a broken revision.
    # - Otherwise (SQLite/dev), we allow startup to continue in "degraded" mode and endpoints will surface 503s as needed.
    try:
        # 1) Shared auth/settings DB
        await asyncio.wait_for(auth_db_manager.init_db(), timeout=30.0)

        # Best-effort: load dynamic workspace registry (admin-managed) from shared settings DB.
        # This allows /app-config + request routing to recognize newly added workspaces without redeploy.
        try:
            raw = await auth_db_manager.get_setting("workspace_registry")
            data = json.loads(raw) if raw else []
            if isinstance(data, list):
                for item in data:
                    try:
                        ws = str((item or {}).get("id") or "").strip().lower()
                        if ws:
                            DYNAMIC_WORKSPACES.add(ws)
                    except Exception:
                        continue
        except Exception:
            pass

        # Best-effort: load WhatsApp routing config from DB per workspace so UI-created workspaces work without env.
        try:
            for w in sorted(list(_all_workspaces_set())):
                try:
                    await _sync_whatsapp_runtime_for_workspace(w)
                except Exception:
                    continue
        except Exception:
            pass

        # Best-effort: load persisted phone_number_id -> workspace mapping from shared auth/settings DB.
        # This makes webhook routing deterministic across Cloud Run instances/restarts even without Redis.
        try:
            raw_map = await auth_db_manager.get_setting("phone_id_to_workspace")
            m = json.loads(raw_map) if raw_map else {}
            if isinstance(m, dict):
                for pid, ws in list(m.items()):
                    p = str(pid or "").strip()
                    w = _coerce_workspace(str(ws or "").strip())
                    if p and w:
                        RUNTIME_PHONE_ID_TO_WORKSPACE[p] = w
        except Exception:
            pass
        # Best-effort: accept DB-provided webhook verify tokens (Meta still uses only one token per URL).
        try:
            for w in sorted(list(_all_workspaces_set())):
                try:
                    cfg = await message_processor._get_inbox_env(w)
                    vt = str((cfg.get("overrides") or {}).get("webhook_verify_token") or "").strip()
                    if vt:
                        RUNTIME_WEBHOOK_VERIFY_TOKENS.add(vt)
                except Exception:
                    continue
        except Exception:
            pass

        # 2) Tenant DB(s) (log per-workspace failures explicitly so we can spot misconfigured NOVA DBs)
        tenant_errors: list[tuple[str, str]] = []
        if ENABLE_MULTI_WORKSPACE:
            for ws in (WORKSPACES or [DEFAULT_WORKSPACE]):
                w = _coerce_workspace(ws)
                tok = _CURRENT_WORKSPACE.set(w)
                try:
                    await asyncio.wait_for(db_manager.init_db(), timeout=30.0)
                except Exception as exc:
                    tenant_errors.append((w, str(exc)))
                    logging.getLogger(__name__).exception(
                        "Tenant DB init failed workspace=%s db=%s err=%s",
                        w,
                        _safe_db_url_summary((TENANT_DB_URLS or {}).get(w)),
                        exc,
                    )
                finally:
                    try:
                        _CURRENT_WORKSPACE.reset(tok)
                    except Exception:
                        pass
        else:
            await asyncio.wait_for(db_manager.init_db(), timeout=30.0)

        if tenant_errors and BLOCK_STARTUP_ON_DB_FAILURE:
            raise RuntimeError(f"Tenant DB init failures: {tenant_errors}")
    except Exception as exc:
        logging.getLogger(__name__).exception(
            "DB init failed during startup (%s): %s",
            "failing startup" if BLOCK_STARTUP_ON_DB_FAILURE else "continuing degraded",
            exc,
        )
        if BLOCK_STARTUP_ON_DB_FAILURE:
            raise
    # Optional: bootstrap an initial admin agent for fresh deployments.
    # This avoids a chicken-and-egg situation where /admin/agents requires an admin,
    # but there are no agents yet.
    try:
        bootstrap_user = (os.getenv("BOOTSTRAP_ADMIN_USERNAME", "") or "").strip()
        bootstrap_pass = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "") or ""
        bootstrap_name = (os.getenv("BOOTSTRAP_ADMIN_NAME", "") or "").strip() or bootstrap_user or "Admin"
        if bootstrap_user and bootstrap_pass:
            agent_count = 0
            async with auth_db_manager._conn() as db:
                if auth_db_manager.use_postgres:
                    row = await db.fetchrow("SELECT COUNT(*) AS c FROM agents")
                    agent_count = int(row[0]) if row else 0
                else:
                    cur = await db.execute("SELECT COUNT(*) FROM agents")
                    row = await cur.fetchone()
                    agent_count = int(row[0]) if row else 0
            if agent_count == 0:
                await auth_db_manager.create_agent(
                    username=bootstrap_user,
                    name=bootstrap_name,
                    password_hash=hash_password(bootstrap_pass),
                    is_admin=1,
                )
                print(f"✅ Bootstrapped initial admin agent: {bootstrap_user}")
    except Exception as exc:
        print(f"Bootstrap admin skipped/failed: {exc}")
    try:
        # Safe startup hint about DB backend and pool settings
        from urllib.parse import urlparse
        parsed = urlparse(DATABASE_URL) if DATABASE_URL else None
        port_info = parsed.port if parsed else None
        backend = "postgres" if db_manager.use_postgres else "sqlite"
        print(f"DB init: backend={backend}, db_port={port_info}, pool_min={PG_POOL_MIN}, pool_max={PG_POOL_MAX}")
    except Exception:
        pass
    # Optional: validate access token against Graph if app credentials provided
    try:
        if ACCESS_TOKEN and META_APP_ID and META_APP_SECRET:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Use debug_token to verify token status
                resp = await client.get(
                    "https://graph.facebook.com/debug_token",
                    params={
                        "input_token": ACCESS_TOKEN,
                        "access_token": f"{META_APP_ID}|{META_APP_SECRET}",
                    },
                )
                if resp.status_code == 200:
                    data = resp.json() or {}
                    d = (data.get("data") or {})
                    if not d.get("is_valid", False):
                        print(f"⚠️ Meta access token appears invalid: {d}")
                else:
                    print(f"⚠️ Token debug request failed: {resp.status_code} {await resp.aread()}\n")
    except Exception as exc:
        print(f"⚠️ Token debug error: {exc}")
    # Connect to Redis only if configured
    if REDIS_URL:
        await redis_manager.connect()
    # Attach Redis manager to connection manager for WS pub/sub
    connection_manager.redis_manager = redis_manager
    if ENABLE_WS_PUBSUB and redis_manager.redis_client:
        asyncio.create_task(redis_manager.subscribe_ws_events(connection_manager))
    # Initialize rate limiter
    if redis_manager.redis_client:
        try:
            await FastAPILimiter.init(redis_manager.redis_client)
        except Exception as exc:
            print(f"Rate limiter init failed: {exc}")
    # Ensure conversation_notes table exists for legacy deployments
    try:
        async with db_manager._conn() as db:
            if db_manager.use_postgres:
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS conversation_notes ("
                    "id SERIAL PRIMARY KEY, user_id TEXT NOT NULL, agent_username TEXT, type TEXT DEFAULT 'text', text TEXT, url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
                )
                await db.execute("CREATE INDEX IF NOT EXISTS idx_notes_user_time ON conversation_notes (user_id, created_at)")
            else:
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS conversation_notes ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, agent_username TEXT, type TEXT DEFAULT 'text', text TEXT, url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
                )
                await db.execute("CREATE INDEX IF NOT EXISTS idx_notes_user_time ON conversation_notes (user_id, datetime(created_at))")
                await db.commit()
    except Exception as exc:
        print(f"conversation_notes ensure failed: {exc}")

    # Start webhook background workers so /webhook can ACK quickly.
    try:
        await start_webhook_workers(webhook_runtime)
        # Mirror runtime flag into legacy global for any old helper callers.
        try:
            globals()["WEBHOOK_DB_READY"] = bool(webhook_runtime.state.db_ready)
        except Exception:
            pass
    except Exception as exc:
        print(f"Webhook worker startup failed: {exc}")
    # Catalog cache: avoid blocking startup in production
    try:
        # Use the default workspace's catalog id on startup; other workspaces refresh on demand.
        ws0 = _coerce_workspace(DEFAULT_WORKSPACE)
        cid0 = await _get_effective_catalog_id(ws0)
        cache_file0 = _catalog_cache_file_for(ws0, cid0)
        # Try hydrate from GCS quickly if missing
        if not os.path.exists(cache_file0):
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    download_file_from_gcs,
                    cache_file0,
                    cache_file0,
                )
            except Exception:
                pass

        # In tests, refresh synchronously so assertions can observe the file
        if os.getenv("PYTEST_CURRENT_TEST"):
            try:
                count = await catalog_manager.refresh_catalog_cache(cid0, cache_file0)
                print(f"Catalog cache created with {count} items (sync in tests)")
            except Exception as exc:
                print(f"Catalog cache refresh failed (tests): {exc}")
        else:
            # In prod, refresh in background to avoid startup timeouts
            async def _refresh_cache_bg():
                try:
                    count = await catalog_manager.refresh_catalog_cache(cid0, cache_file0)
                    print(f"Catalog cache created with {count} items")
                except Exception as exc:
                    print(f"Catalog cache refresh failed: {exc}")

            asyncio.create_task(_refresh_cache_bg())
    except Exception as exc:
        print(f"Catalog cache init error: {exc}")

    # Start survey scheduler background loop (requires Redis)
    try:
        if redis_manager.redis_client:
            asyncio.create_task(run_survey_scheduler())
    except Exception as exc:
        print(f"Failed to start survey scheduler: {exc}")

def _parse_iso_ts(ts: str) -> Optional[datetime]:
    try:
        s = str(ts or "").strip()
        if not s:
            return None
        if s.isdigit():
            # seconds epoch
            sec = int(s)
            if len(s) > 10:
                # already ms
                return datetime.fromtimestamp(sec / 1000, tz=timezone.utc)
            return datetime.fromtimestamp(sec, tz=timezone.utc)
        # Normalize Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None

async def _survey_sweep_once() -> None:
    try:
        conversations = await db_manager.get_conversations_with_stats()
    except Exception as exc:
        print(f"survey sweep: failed to list conversations: {exc}")
        return
    now = datetime.utcnow().replace(tzinfo=None)
    try:
        env_cfg = await message_processor._get_inbox_env(get_current_workspace())
        survey_tests = set((env_cfg or {}).get("survey_test_numbers") or set())
    except Exception:
        survey_tests = set(SURVEY_TEST_NUMBERS or set())
    for conv in conversations:
        try:
            user_id = conv.get("user_id")
            if not user_id or not isinstance(user_id, str):
                continue
            # Skip internal channels
            if user_id.startswith("team:") or user_id.startswith("agent:") or user_id.startswith("dm:"):
                continue
            uid_digits = _digits_only(user_id)
            is_test = uid_digits in survey_tests
            # Only if customer hasn't replied since last agent msg
            unresponded = int(conv.get("unresponded_count") or 0)
            if unresponded != 0:
                continue
            last_agent_ts = await db_manager.get_last_agent_message_time(user_id)
            if not last_agent_ts:
                continue
            dt = _parse_iso_ts(last_agent_ts)
            if not dt:
                continue
            # Make naive for comparison with now
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            threshold = (
                timedelta(seconds=SURVEY_TEST_DELAY_SEC)
                if (is_test and SURVEY_TEST_DELAY_SEC > 0)
                else timedelta(hours=4)
            )
            if (now - dt) < threshold:
                continue
            # Do not re-invite within cooldown window
            if not (is_test and SURVEY_TEST_BYPASS_COOLDOWN) and await redis_manager.was_survey_invited_recent(user_id):
                continue
            # Skip if an invoice was sent in this chat (order exists for this number)
            try:
                if (not (is_test and SURVEY_TEST_IGNORE_INVOICE)) and await db_manager.has_invoice_message(user_id):
                    continue
            except Exception:
                # On error, be safe and skip
                continue
            # Send invite and mark
            try:
                await message_processor.send_survey_invite(user_id)
                if is_test and SURVEY_TEST_BYPASS_COOLDOWN:
                    # no-op; allow rapid retests
                    pass
                elif is_test and SURVEY_TEST_COOLDOWN_SEC > 0:
                    await redis_manager.mark_survey_invited(user_id, window_sec=SURVEY_TEST_COOLDOWN_SEC)
                else:
                    await redis_manager.mark_survey_invited(user_id)
            except Exception as exc:
                print(f"survey invite failed for {user_id}: {exc}")
        except Exception:
            continue

async def run_survey_scheduler() -> None:
    # Sweep every 5 minutes
    while True:
        try:
            await _survey_sweep_once()
        except Exception as exc:
            print(f"survey scheduler loop error: {exc}")
        await asyncio.sleep(300)

# Optional rate limit dependencies that no-op when limiter is not initialized
async def _optional_rate_limit_text(request: _LimiterRequest, response: _LimiterResponse):
    try:
        if FastAPILimiter.redis:
            limiter = RateLimiter(times=SEND_TEXT_PER_MIN, seconds=60)
            return await limiter(request, response)
    except Exception:
        return

async def _optional_rate_limit_media(request: _LimiterRequest, response: _LimiterResponse):
    try:
        if FastAPILimiter.redis:
            limiter = RateLimiter(times=SEND_MEDIA_PER_MIN, seconds=60)
            return await limiter(request, response)
    except Exception:
        return

async def _optional_rate_limit_track(request: _LimiterRequest, response: _LimiterResponse):
    try:
        if FastAPILimiter.redis:
            limiter = RateLimiter(times=TRACK_CLICKS_PER_MIN, seconds=60)
            return await limiter(request, response)
    except Exception:
        return

    

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    """WebSocket endpoint for real-time communication"""
    # Workspace selection (query param). Frontend connects with ?workspace=irranova|irrakids
    try:
        ws_q = websocket.query_params.get("workspace")  # type: ignore[attr-defined]
    except Exception:
        ws_q = None
    ws = _coerce_workspace(str(ws_q or DEFAULT_WORKSPACE))
    ws_token = _CURRENT_WORKSPACE.set(ws)

    # Authenticate agent for WS. Browser sends cookies automatically for same-origin.
    ws_agent: Optional[dict] = None
    if DISABLE_AUTH:
        ws_agent = {"username": "admin", "is_admin": True}
    else:
        try:
            token = websocket.cookies.get(ACCESS_COOKIE_NAME)  # type: ignore[attr-defined]
        except Exception:
            token = None
        ws_agent = parse_access_token(token or "")
        # Fallback: allow token via query string when cookies are blocked.
        if not ws_agent:
            try:
                qs_token = websocket.query_params.get("token")  # type: ignore[attr-defined]
            except Exception:
                qs_token = None
            if qs_token:
                ws_agent = parse_access_token(str(qs_token))
        if not ws_agent:
            # Helpful log for diagnosing cookie issues in production
            try:
                has_cookie_hdr = bool(websocket.headers.get("cookie"))  # type: ignore[attr-defined]
            except Exception:
                has_cookie_hdr = False
            logging.getLogger(__name__).warning(
                "WS auth failed: missing/invalid cookie and no valid token query (cookie_name=%s has_cookie_header=%s) path=/ws/%s",
                ACCESS_COOKIE_NAME,
                has_cookie_hdr,
                user_id,
            )
            try:
                # Avoid "need to call accept first" errors in some ASGI servers.
                try:
                    await websocket.accept()
                except Exception:
                    pass
                await websocket.close(code=4401)
            except Exception:
                pass
            try:
                _CURRENT_WORKSPACE.reset(ws_token)
            except Exception:
                pass
            return

    agent_username = str(ws_agent.get("username") or "")
    is_admin = bool(ws_agent.get("is_admin"))

    # NOTE: By request, all authenticated agents can access the shared inbox
    # and thus can connect to /ws/admin and any /ws/{user_id}.

    # Connect after auth so we can attach reliable agent identity
    await connection_manager.connect(websocket, user_id, client_info={"agent": agent_username}, workspace=ws)
    # Mark activity on WS connect (presence should work even if the agent only has WS open).
    try:
        if agent_username:
            await redis_manager.touch_agent_last_seen(agent_username, workspace=ws)
    except Exception:
        pass
    if user_id == "admin":
        # Best-effort: mark the shared inbox channel in DB for legacy admin-user discovery.
        # Do not let DB issues kill the WS connection (agents still need realtime).
        try:
            await db_manager.upsert_user(user_id, is_admin=1)
        except Exception:
            pass
    
    try:
        # Send recent messages on connection
        recent_messages = await redis_manager.get_recent_messages(user_id)
        if not recent_messages:
            recent_messages = await db_manager.get_messages(user_id, limit=20)
        if recent_messages:
            # Ensure chronological order for the client by server receive time when available
            try:
                def to_ms(t):
                    if not t: return 0
                    s = str(t)
                    if s.isdigit():
                        return int(s) * (1000 if len(s) <= 10 else 1)
                    from datetime import datetime as _dt
                    try:
                        return int(_dt.fromisoformat(s).timestamp() * 1000)
                    except Exception:
                        return 0
                recent_messages = sorted(recent_messages, key=lambda m: to_ms(m.get("server_ts") or m.get("timestamp")))
            except Exception:
                pass
            await websocket.send_json({
                "type": "recent_messages",
                "data": recent_messages
            })
        
        # Listen for incoming WebSocket messages
        while True:
            data = await websocket.receive_json()
            await handle_websocket_message(websocket, user_id, data)
            
    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        connection_manager.disconnect(websocket)
    finally:
        try:
            _CURRENT_WORKSPACE.reset(ws_token)
        except Exception:
            pass

async def handle_websocket_message(websocket: WebSocket, user_id: str, data: dict):
    """Handle incoming WebSocket messages from client"""
    message_type = data.get("type")

    # Any WS message counts as activity for the connected agent (best-effort).
    try:
        meta0 = connection_manager.connection_metadata.get(websocket) or {}
        ws0 = meta0.get("workspace") or get_current_workspace()
        agent0 = ((meta0.get("client_info") or {}) or {}).get("agent")
        agent0 = str(agent0 or "").strip()
        if agent0:
            await redis_manager.touch_agent_last_seen(agent0, workspace=str(ws0))
    except Exception:
        pass
    
    if message_type == "send_message":
        message_data = data.get("data", {})
        message_data["user_id"] = user_id
        # Attach agent username from connection metadata (authoritative)
        try:
            meta = connection_manager.connection_metadata.get(websocket) or {}
            agent_username = ((meta.get("client_info") or {}) or {}).get("agent")
            if agent_username:
                message_data["agent_username"] = agent_username
        except Exception:
            pass
        # Enforce WS backpressure: token bucket per agent
        is_media = str(message_data.get("type", "text")) in ("image", "audio", "video", "document")
        # Ensure rate limits are per-workspace+conversation key
        key = connection_manager._key(user_id)
        if not connection_manager._consume_ws_token(key, is_media=is_media):
            try:
                await websocket.send_json({
                    "type": "error",
                    "data": {
                        "code": "rate_limited",
                        "message": f"Rate limit exceeded for {'media' if is_media else 'text'} messages. Please slow down.",
                    }
                })
            except Exception:
                pass
            return
        # FIXED: Call the method on message_processor instance
        await message_processor.process_outgoing_message(message_data)

    elif message_type == "mark_as_read":
        message_ids = data.get("message_ids", [])
        if message_ids:
            message_ids = list(set(message_ids))
        print(f"Marking messages as read: {message_ids}")
        await db_manager.mark_messages_as_read(user_id, message_ids or None)
        for mid in message_ids:
            try:
                await messenger.mark_message_as_read(mid)
            except Exception as e:
                print(f"Failed to send read receipt for {mid}: {e}")
        await connection_manager.send_to_user(user_id, {
            "type": "messages_marked_read",
            "data": {"user_id": user_id, "message_ids": message_ids}
        })
        
    elif message_type == "typing":
        is_typing = data.get("is_typing", False)
        typing_event = {
            "type": "typing",
            "data": {"user_id": user_id, "is_typing": is_typing},
        }

        # Send to other connections of the same user (excluding sender)
        key = connection_manager._key(user_id)
        # Back-compat: some callers/tests may still store connections under the raw user_id.
        conns = (
            connection_manager.active_connections.get(key)
            or connection_manager.active_connections.get(user_id)
            or set()
        )
        for ws in conns.copy():
            if ws is not websocket:
                try:
                    await ws.send_json(typing_event)
                except Exception:
                    connection_manager.disconnect(ws)

        # Notify admin dashboards
        await connection_manager.broadcast_to_admins(
            typing_event, exclude_user=user_id
        )
        
    elif message_type == "react":
        # Send a reaction to a specific message
        target_id = data.get("target_wa_message_id") or data.get("message_id")
        emoji = data.get("emoji")
        action = data.get("action") or "react"
        if not (target_id and emoji):
            return
        try:
            await messenger.send_reaction(user_id, target_id, emoji, action)
        except Exception as e:
            print(f"Failed to send reaction: {e}")
            return
        event = {
            "type": "reaction_update",
            "data": {
                "user_id": user_id,
                "target_wa_message_id": target_id,
                "emoji": emoji,
                "action": action,
                "from_me": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }
        await connection_manager.send_to_user(user_id, event)
        await connection_manager.broadcast_to_admins(event, exclude_user=user_id)
        try:
            await db_manager.upsert_message({
                "user_id": user_id,
                "type": "reaction",
                "from_me": 1,
                "status": "sent",
                "timestamp": event["data"]["timestamp"],
                "reaction_to": target_id,
                "reaction_emoji": emoji,
                "reaction_action": action,
            })
        except Exception:
            pass

    elif message_type == "get_conversation_history":
        offset = data.get("offset", 0)
        limit = data.get("limit", 50)
        messages = await db_manager.get_messages(user_id, offset, limit)
        await websocket.send_json({
            "type": "conversation_history",
            "data": messages
        })
    elif message_type == "resume_since":
        since = data.get("since")
        limit = int(data.get("limit", 500))
        if since:
            try:
                messages = await db_manager.get_messages_since(user_id, since, limit=limit)
                if messages:
                    await websocket.send_json({"type": "conversation_history", "data": messages})
            except Exception as e:
                print(f"resume_since failed: {e}")
    elif message_type == "ping":
        try:
            await websocket.send_json({"type": "pong", "ts": data.get("ts")})
        except Exception:
            pass

@app.post("/test-media-upload")
async def test_media_upload(file: UploadFile = File(...)):
    """Test endpoint to debug media upload issues"""
    try:
        _vlog(f"📁 Received file: {file.filename}")
        _vlog(f"📁 Content type: {file.content_type}")
        _vlog(f"📁 File size: {file.size if hasattr(file, 'size') else 'Unknown'}")
        
        # Read file content
        content = await file.read()
        _vlog(f"📁 Read {len(content)} bytes")
        
        # Reset file pointer for actual processing
        await file.seek(0)
        
        return {
            "status": "success",
            "filename": file.filename,
            "content_type": file.content_type,
            "size": len(content)
        }
        
    except Exception as e:
        print(f"❌ Test upload error: {e}")
        return {"error": str(e), "status": "failed"}


# ───────────────────────── Internal Notes Upload (no WhatsApp send) ─────────────────────────
@app.post("/notes/upload")
async def upload_note_file(
    file: UploadFile = File(...),
):
    """Upload a note attachment (e.g., audio) and return a public URL, without sending to WhatsApp."""
    try:
        # Ensure media folder exists
        MEDIA_DIR.mkdir(exist_ok=True)

        # Persist upload locally first
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        suffix = Path(file.filename or "note").suffix or ".bin"
        filename = f"note_{timestamp}_{uuid.uuid4().hex[:8]}{suffix}"
        file_path = MEDIA_DIR / filename

        content = await file.read()
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(content)

        # Upload to Cloud Storage and return the public URL
        try:
            media_url = await upload_file_to_gcs(str(file_path))
        except Exception as exc:
            print(f"GCS upload failed for notes upload (returning local path): {exc}")
            media_url = None

        if media_url:
            return {"url": media_url, "file_path": str(file_path)}
        else:
            # Fallback to serving via local /media mount
            return {"url": f"/media/{filename}", "file_path": str(file_path)}
    except HTTPException:
        raise
    except Exception as exc:
        print(f"❌ Error in /notes/upload: {exc}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")

@app.post("/send-message")
async def send_message_endpoint(
    request: dict,
    _: None = Depends(_optional_rate_limit_text),
    actor: dict = Depends(get_current_agent),
):
    """Send text message - Frontend uses this endpoint"""
    try:
        # Extract data from request
        user_id = request.get("user_id")
        message_text = request.get("message")
        message_type = request.get("type", "text")
        from_me = True
        
        if not user_id or not message_text:
            return {"error": "Missing user_id or message"}
        
        # Create message object
        message_data = {
            "user_id": user_id,
            "message": message_text,
            "type": message_type,
            "from_me": from_me,
            "timestamp": datetime.utcnow().isoformat()
        }
        # Authoritative agent attribution
        agent_username = actor.get("username")
        if agent_username:
            message_data["agent_username"] = agent_username

        # Process the message
        result = await message_processor.process_outgoing_message(message_data)
        return {"status": "success", "message": result}
        
    except Exception as e:
        print(f"Error sending message: {e}")
        return {"error": str(e)}

@app.get("/conversations/{user_id}/messages")
async def get_conversation_messages(user_id: str, offset: int = 0, limit: int = 50, actor: dict = Depends(get_current_agent)):
    """Get conversation messages with pagination"""
    if offset == 0:
        cached_messages = await redis_manager.get_recent_messages(user_id, limit)
        if cached_messages:
            return {"messages": cached_messages, "source": "cache"}
    
    messages = await db_manager.get_messages(user_id, offset, limit)
    return {"messages": messages, "source": "database"}

@app.get("/messages/{user_id}/since")
async def get_messages_since_endpoint(user_id: str, since: str, limit: int = 500, actor: dict = Depends(get_current_agent)):
    """Get messages newer than the given ISO-8601 timestamp."""
    try:
        messages = await db_manager.get_messages_since(user_id, since, limit)
        return messages
    except Exception as e:
        print(f"Error fetching messages since: {e}")
        return []

@app.get("/messages/{user_id}/before")
async def get_messages_before_endpoint(user_id: str, before: str, limit: int = 50, actor: dict = Depends(get_current_agent)):
    """Get messages older than the given ISO-8601 timestamp."""
    try:
        messages = await db_manager.get_messages_before(user_id, before, limit)
        return messages
    except Exception as e:
        print(f"Error fetching messages before: {e}")
        return []

@app.get("/users/online")
async def get_online_users():
    """Get list of currently online users"""
    return {"online_users": connection_manager.get_active_users()}

@app.post("/conversations/{user_id}/mark-read")
async def mark_conversation_read(user_id: str, message_ids: List[str] = Body(None)):
    """Mark messages as read"""
    try:
        ids: List[str] | None = None
        if message_ids:
            try:
                # Dedupe but keep stable order
                seen = set()
                ids = []
                for mid in message_ids:
                    mid = str(mid)
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    ids.append(mid)
            except Exception:
                ids = list(set([str(x) for x in message_ids if x]))

        # Safety cap: mark-read should be cheap; client can retry if needed.
        if ids and len(ids) > 500:
            ids = ids[:500]

        print(f"Marking messages as read: {ids}")

        # DB write must not hang long enough to produce Cloud Run 504.
        await asyncio.wait_for(
            db_manager.mark_messages_as_read(user_id, ids),
            timeout=max(0.2, float(MARK_READ_DB_TIMEOUT_SECONDS)),
        )

        # Fire-and-forget WhatsApp read receipts; never block the HTTP response on them.
        if ids:
            async def _send_receipts(_ids: list[str]):
                # Small concurrency limit to avoid stampeding the WhatsApp API.
                sem = asyncio.Semaphore(int(os.getenv("MARK_READ_WA_MAX_CONCURRENCY", "5")))

                async def _one(mid: str):
                    async with sem:
                        try:
                            await messenger.mark_message_as_read(mid)
                        except Exception as exc:
                            print(f"Failed to send read receipt for {mid}: {exc}")

                try:
                    await asyncio.gather(*[_one(mid) for mid in _ids])
                except Exception:
                    pass

            try:
                asyncio.create_task(_send_receipts(ids))
            except Exception:
                pass

        # Best-effort notify active chat UI (if connected).
        try:
            await connection_manager.send_to_user(user_id, {
                "type": "messages_marked_read",
                "data": {"user_id": user_id, "message_ids": ids}
            })
        except Exception:
            pass

        return {"status": "success"}
    except Exception as e:
        print(f"Error marking messages as read: {e}")
        return {"error": str(e)}

@app.get("/active-users")
async def get_active_users(_: dict = Depends(require_admin)):
    """Get currently active users"""
    return {"active_users": connection_manager.get_active_users()}

# In-process fallback cache for /conversations (only used when Redis is unavailable and DB is temporarily slow).
_CONVERSATIONS_FALLBACK_CACHE: dict[str, tuple[float, list]] = {}
_CONVERSATIONS_FALLBACK_TTL_SECONDS = 60.0
# Prevent stampedes: only allow a small number of expensive inbox queries concurrently per instance.
_CONVERSATIONS_INFLIGHT_SEM = asyncio.Semaphore(int(os.getenv("CONVERSATIONS_MAX_INFLIGHT", "2")))

@app.get("/conversations")
async def get_conversations(
    q: Optional[str] = None,
    unread_only: bool = False,
    assigned: Optional[str] = None,
    tags: Optional[str] = None,
    unresponded_only: bool = False,
    limit: int = 200,
    offset: int = 0,
    agent: dict = Depends(get_current_agent),
):
    """Get conversations with optional filters: q, unread_only, assigned, tags (csv), unresponded_only."""
    try:
        tag_list = [t.strip() for t in tags.split(",")] if tags else None
        # Short-lived cache to prevent expensive fan-out queries from timing out (Cloud Run 504s).
        # Safe because the result is workspace-scoped and not personalized per-agent (viewer_agent=None).
        try:
            ws = get_current_workspace()
            cache_payload = {
                "q": q or "",
                "unread_only": bool(unread_only),
                "assigned": assigned or "",
                "tags": tag_list or [],
                "unresponded_only": bool(unresponded_only),
                "limit": int(max(1, min(limit, 500))),
                "offset": int(max(0, offset)),
            }
            cache_key = "conversations:%s:%s" % (
                ws,
                hashlib.sha1(json.dumps(cache_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            )
            cached = await redis_manager.get_json(cache_key)
            if isinstance(cached, list):
                return cached
        except Exception:
            cache_key = None

        async def _fetch():
            async with _CONVERSATIONS_INFLIGHT_SEM:
                return await db_manager.get_conversations_with_stats(
                    q=q,
                    unread_only=unread_only,
                    assigned=assigned,
                    tags=tag_list,
                    limit=max(1, min(limit, 500)),
                    offset=max(0, offset),
                    viewer_agent=None,
                )

        # Hard timeout so Cloud Run doesn't return 504 under load.
        conversations = await asyncio.wait_for(_fetch(), timeout=max(1.0, float(CONVERSATIONS_DB_TIMEOUT_SECONDS)))
        if unresponded_only:
            conversations = [c for c in conversations if (c.get("unresponded_count") or 0) > 0]

        # Cache result briefly (best-effort).
        try:
            if cache_key and isinstance(conversations, list):
                await redis_manager.set_json(cache_key, conversations, ttl=5)
                # Also keep a slightly longer in-process copy as a fallback for transient DB/Redis issues.
                _CONVERSATIONS_FALLBACK_CACHE[cache_key] = (time.time(), conversations)
        except Exception:
            pass
        return conversations
    except asyncio.TimeoutError:
        # Best-effort: serve stale cache if present, otherwise degrade gracefully.
        try:
            if cache_key:
                cached = await redis_manager.get_json(cache_key)
                if isinstance(cached, list):
                    return cached
        except Exception:
            pass
        # Fallback: in-process stale cache (covers Redis outage + transient DB slowness).
        try:
            if cache_key and cache_key in _CONVERSATIONS_FALLBACK_CACHE:
                ts0, data = _CONVERSATIONS_FALLBACK_CACHE.get(cache_key) or (0.0, [])
                if isinstance(data, list) and (time.time() - float(ts0)) <= float(_CONVERSATIONS_FALLBACK_TTL_SECONDS):
                    return data
        except Exception:
            pass
        raise HTTPException(status_code=503, detail="Inbox temporarily busy, please retry")
    except Exception as e:
        # If the DB is flaky, prefer returning a stale list instead of hard-failing the UI.
        try:
            if cache_key:
                cached = await redis_manager.get_json(cache_key)
                if isinstance(cached, list):
                    return cached
        except Exception:
            pass
        try:
            if cache_key and cache_key in _CONVERSATIONS_FALLBACK_CACHE:
                ts0, data = _CONVERSATIONS_FALLBACK_CACHE.get(cache_key) or (0.0, [])
                if isinstance(data, list) and (time.time() - float(ts0)) <= float(_CONVERSATIONS_FALLBACK_TTL_SECONDS):
                    return data
        except Exception:
            pass
        print(f"Error fetching conversations: {e}")
        return []

# Public-for-agents: list available agents (for assignment dropdowns)
@app.get("/agents")
async def list_agents_public(_: dict = Depends(get_current_agent)):
    agents = await auth_db_manager.list_agents()
    # Do not expose password hash; list_agents() already omits it. Also omit created_at/is_admin for non-admin UI.
    return [{"username": a.get("username"), "name": a.get("name")} for a in (agents or [])]


@app.get("/agents/online")
async def list_online_agents(_: dict = Depends(get_current_agent)):
    """Return agents that are currently online (active within the last INACTIVITY_TIMEOUT_SECONDS).

    We treat "online" as "recent activity", not "has a refresh token". This prevents agents from
    appearing online forever if they forget to logout.
    """
    ws = get_current_workspace()
    now = time.time()
    online_usernames: set[str] = set()

    # Attach friendly names (best-effort).
    name_by_username: dict[str, str] = {}
    try:
        agents = await auth_db_manager.list_agents()
        for a in agents or []:
            u = str((a or {}).get("username") or "").strip()
            if not u:
                continue
            n = str((a or {}).get("name") or "").strip()
            if n:
                name_by_username[u] = n

            # Preferred: Redis-backed last_seen
            try:
                if getattr(redis_manager, "redis_client", None):
                    last = await redis_manager.get_agent_last_seen(u, workspace=ws)
                    if last is not None and (now - float(last)) <= float(INACTIVITY_TIMEOUT_SECONDS):
                        online_usernames.add(u)
            except Exception:
                pass

        # Fallback: if Redis is not connected, use active WebSocket connections as a best-effort online signal.
        if not getattr(redis_manager, "redis_client", None):
            try:
                for meta in (connection_manager.connection_metadata or {}).values():
                    try:
                        if (meta.get("workspace") or "") != ws:
                            continue
                        agent_username = ((meta.get("client_info") or {}) or {}).get("agent")
                        agent_username = str(agent_username or "").strip()
                        if agent_username:
                            online_usernames.add(agent_username)
                    except Exception:
                        continue
            except Exception:
                pass
    except Exception:
        pass

    out: list[dict] = []
    for u in sorted(list(online_usernames), key=lambda x: x.lower()):
        out.append({"username": u, "name": name_by_username.get(u) or u, "online": True})
    return out

# ----- Agents & assignments management -----

@app.get("/admin/agents")
async def list_agents_endpoint(_: dict = Depends(require_admin)):
    return await auth_db_manager.list_agents()

# ---- Tags options management ----
@app.get("/admin/tag-options")
async def get_tag_options_endpoint(_: dict = Depends(get_current_agent)):
    return await auth_db_manager.get_tag_options()

@app.get("/tag-options")
async def get_tag_options_public(_: dict = Depends(get_current_agent)):
    return await auth_db_manager.get_tag_options()

@app.post("/admin/tag-options")
async def set_tag_options_endpoint(payload: dict = Body(...), _: dict = Depends(require_admin)):
    options = payload.get("options") or []
    if not isinstance(options, list):
        raise HTTPException(status_code=400, detail="options must be a list")
    # normalize items: require label, optional icon
    norm = []
    for item in options:
        if isinstance(item, dict) and item.get("label"):
            norm.append({"label": str(item["label"]), "icon": str(item.get("icon", ""))})
        elif isinstance(item, str):
            norm.append({"label": item, "icon": ""})
    await auth_db_manager.set_tag_options(norm)
    return {"ok": True, "count": len(norm)}


# ---- Automation rules (global store, scoped per rule) ----
@app.get("/automation/rules")
async def get_automation_rules_endpoint(request: Request, _: dict = Depends(require_admin)):
    """Return automation rules for the current workspace by default.

    Query params:
      - all=1 : return all rules (admin/debug)
    """
    ws = _coerce_workspace(get_current_workspace())
    all_q = ""
    try:
        all_q = str(request.query_params.get("all") or "").strip().lower()
    except Exception:
        all_q = ""
    want_all = all_q in ("1", "true", "yes")

    try:
        rules_all = await message_processor._ensure_automation_rules_v2()
        if not isinstance(rules_all, list):
            rules_all = []
    except Exception:
        rules_all = []

    if want_all:
        return rules_all

    # Filter to rules that apply to this workspace
    out: list[dict] = []
    for r in rules_all or []:
        try:
            if not isinstance(r, dict):
                continue
            scopes = r.get("workspaces")
            # Missing scopes: treat as current workspace (legacy/migrated safety)
            if scopes is None:
                out.append(r)
                continue
            if isinstance(scopes, list):
                s = set([_normalize_workspace_id(x) for x in scopes if _normalize_workspace_id(x)])
                if ("*" in s) or (ws in s):
                    out.append(r)
                continue
            # Unknown shape -> include (better to show than hide)
            out.append(r)
        except Exception:
            continue
    return out


@app.post("/automation/rules")
async def set_automation_rules_endpoint(request: Request, payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Save automation rules for the current workspace (merge into global store).

    Default behavior restores the "old method":
    - The UI edits the workspace's list.
    - Saving should not overwrite other workspaces' rules.
    - If a rule is removed from this workspace list, we remove this workspace from its scope
      (and delete the rule entirely if it no longer applies anywhere).

    Query params:
      - full=1 : replace the global list entirely (admin/debug)
    """
    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise HTTPException(status_code=400, detail="rules must be a list")

    full_q = ""
    try:
        full_q = str(request.query_params.get("full") or "").strip().lower()
    except Exception:
        full_q = ""
    full_replace = full_q in ("1", "true", "yes")

    ws = _coerce_workspace(get_current_workspace())

    # Load current global store
    try:
        existing_all = await message_processor._ensure_automation_rules_v2()
        if not isinstance(existing_all, list):
            existing_all = []
    except Exception:
        existing_all = []

    cleaned: list[dict] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip()
        if not rid:
            rid = f"r_{uuid.uuid4().hex[:12]}"
        name = str(r.get("name") or "").strip() or rid
        enabled = bool(r.get("enabled", False))
        trigger = r.get("trigger") if isinstance(r.get("trigger"), dict) else {}
        cond = r.get("condition") if isinstance(r.get("condition"), dict) else {}
        actions = r.get("actions") or []
        if isinstance(actions, dict):
            actions = [actions]
        if not isinstance(actions, list):
            actions = []
        # Optional testing guard: list of phone numbers (digits-only comparison is done at runtime)
        test_phones = r.get("test_phone_numbers") or r.get("test_numbers") or []
        if isinstance(test_phones, str):
            test_phones = [x.strip() for x in re.split(r"[,\n\r]+", test_phones) if x and x.strip()]
        if not isinstance(test_phones, list):
            test_phones = []
        # cap sizes for safety
        if len(test_phones) > 200:
            test_phones = test_phones[:200]
        try:
            test_phones = [str(x or "").strip() for x in test_phones if str(x or "").strip()]
        except Exception:
            test_phones = []
        # cap sizes for safety
        if len(actions) > 10:
            actions = actions[:10]
        out_rule = {
            "id": rid,
            "name": name[:120],
            "enabled": enabled,
            "cooldown_seconds": int(r.get("cooldown_seconds") or 0),
            "trigger": {
                "source": str((trigger or {}).get("source") or "whatsapp"),
                "event": str((trigger or {}).get("event") or "incoming_message"),
            },
            "condition": cond,
            "actions": actions,
        }
        # Workspace scope
        ws_scope = r.get("workspaces")
        scopes: list[str] = []
        try:
            if ws_scope is None:
                scopes = [ws]
            elif isinstance(ws_scope, str):
                v = ws_scope.strip().lower()
                if v in ("*", "all", "all_workspaces"):
                    scopes = ["*"]
                else:
                    scopes = [s for s in [_normalize_workspace_id(x) for x in re.split(r"[,\n\r]+", v)] if s]
            elif isinstance(ws_scope, list):
                scopes = [_normalize_workspace_id(x) for x in ws_scope if _normalize_workspace_id(x)]
            else:
                scopes = [ws]
        except Exception:
            scopes = [ws]
        if "*" in scopes:
            scopes = ["*"]
        if not scopes:
            scopes = [ws]
        # Keep only known workspaces unless using "*"
        if scopes != ["*"]:
            allowed = _all_workspaces_set()
            scopes = [s for s in scopes if s in allowed]
            if not scopes:
                scopes = [ws]
            # Ensure the current workspace is included (old UX expectation)
            if ws not in scopes:
                scopes = [ws] + [s for s in scopes if s != ws]
        out_rule["workspaces"] = scopes
        if test_phones:
            out_rule["test_phone_numbers"] = test_phones
        cleaned.append(out_rule)

    if len(cleaned) > 200:
        cleaned = cleaned[:200]

    if full_replace:
        next_all = cleaned
    else:
        # Merge by workspace:
        # - Upsert incoming rules by id
        # - Any existing rule that applies to this workspace but is missing from incoming list
        #   will have this workspace removed from its scope (or be deleted if no scopes remain).
        by_id: dict[str, dict] = {}
        for r in existing_all or []:
            if isinstance(r, dict) and str(r.get("id") or "").strip():
                by_id[str(r.get("id")).strip()] = r

        incoming_ids = set([str(r.get("id") or "").strip() for r in cleaned if str(r.get("id") or "").strip()])

        # Remove this workspace from rules not present anymore
        for rid, rr in list(by_id.items()):
            try:
                scopes = rr.get("workspaces")
                if scopes is None:
                    continue
                if not isinstance(scopes, list):
                    continue
                s = [_normalize_workspace_id(x) for x in scopes if _normalize_workspace_id(x)]
                if "*" in s:
                    continue  # global rule; don't implicitly remove from a single workspace
                if ws in s and rid not in incoming_ids:
                    s2 = [x for x in s if x != ws]
                    if not s2:
                        by_id.pop(rid, None)
                    else:
                        rr2 = dict(rr)
                        rr2["workspaces"] = s2
                        by_id[rid] = rr2
            except Exception:
                continue

        # Upsert incoming rules (these may also target other workspaces)
        for r in cleaned:
            try:
                rid = str(r.get("id") or "").strip()
                if not rid:
                    continue
                by_id[rid] = r
            except Exception:
                continue

        next_all = list(by_id.values())

    await auth_db_manager.set_setting("automation_rules_v2", next_all)
    # Bust caches for immediate effect in webhook-triggered tasks
    try:
        message_processor._automation_rules_cache.clear()
    except Exception:
        pass
    return {"ok": True, "workspace": ws, "count": len(cleaned)}


@app.get("/automation/rules/stats")
async def get_automation_rules_stats_endpoint(_: dict = Depends(require_admin)):
    """Best-effort per-rule counters (Redis-backed when available)."""
    ws = get_current_workspace()
    # Always return something usable by the UI
    try:
        rules = await message_processor._ensure_automation_rules_v2()
        if not isinstance(rules, list):
            rules = []
    except Exception:
        rules = []

    rds = getattr(redis_manager, "redis_client", None)
    # Prefer durable DB stats
    try:
        # Only compute stats for rules that apply to this workspace (or are global).
        ids = []
        for r in (rules or []):
            try:
                rid = str((r or {}).get("id") or "").strip()
                if not rid:
                    continue
                scopes = (r or {}).get("workspaces")
                if scopes is None:
                    ids.append(rid)
                    continue
                if isinstance(scopes, list):
                    s = set([_normalize_workspace_id(x) for x in scopes if _normalize_workspace_id(x)])
                    if ("*" in s) or (_coerce_workspace(ws) in s):
                        ids.append(rid)
                    continue
                # unknown shape -> include
                ids.append(rid)
            except Exception:
                continue
        out = await db_manager.get_automation_rule_stats(ids)
    except Exception:
        out = {}

    # Optionally merge Redis stats (if any) on top (useful for realtime even if DB is slightly behind)
    ids_set = set(ids or [])
    for r in rules or []:
        try:
            rid = str((r or {}).get("id") or "").strip()
            if not rid:
                continue
            if ids_set and rid not in ids_set:
                continue
            stats = out.get(rid) or {"triggers": 0, "messages_sent": 0, "tags_added": 0, "last_trigger_ts": None}
            if rds:
                key = f"automation:stats:{_coerce_workspace(ws)}:{rid}"
                try:
                    data = await rds.hgetall(key)
                except Exception:
                    data = {}
                # redis may return bytes
                def _s(x):
                    if isinstance(x, (bytes, bytearray)):
                        return x.decode("utf-8", "ignore")
                    return str(x)
                if isinstance(data, dict):
                    try:
                        if "triggers" in data or b"triggers" in data:
                            stats["triggers"] = int(_s(data.get("triggers") or data.get(b"triggers") or 0) or 0)
                        if "messages_sent" in data or b"messages_sent" in data:
                            stats["messages_sent"] = int(_s(data.get("messages_sent") or data.get(b"messages_sent") or 0) or 0)
                        if "tags_added" in data or b"tags_added" in data:
                            stats["tags_added"] = int(_s(data.get("tags_added") or data.get(b"tags_added") or 0) or 0)
                        if "last_trigger_ts" in data or b"last_trigger_ts" in data:
                            v = _s(data.get("last_trigger_ts") or data.get(b"last_trigger_ts") or "")
                            stats["last_trigger_ts"] = v or None
                    except Exception:
                        pass
            out[rid] = stats
        except Exception:
            continue
    return {"workspace": ws, "stats": out}


# ---- Inbox environment settings (workspace-scoped, editable from UI) ----
@app.get("/admin/inbox-env")
async def get_inbox_env_endpoint(_: dict = Depends(require_admin)):
    """Return effective inbox env settings (DB overrides layered on env defaults)."""
    cfg = await message_processor._get_inbox_env(get_current_workspace())
    try:
        overrides = cfg.get("overrides") if isinstance(cfg.get("overrides"), dict) else {}
        db_tok = str((overrides or {}).get("access_token") or "").strip()
        eff_tok = str(cfg.get("access_token") or "").strip()

        db_tok_present = bool(db_tok and not _is_placeholder_token(db_tok))
        env_tok_present = (not db_tok_present) and bool(eff_tok and not _is_placeholder_token(eff_tok))
        tok_present = bool(db_tok_present or env_tok_present)
        tok_source = "db" if db_tok_present else ("env" if env_tok_present else "missing")
        tok_hint = (db_tok[-4:] if db_tok_present and len(db_tok) >= 4 else "")
        return {
            "workspace": cfg.get("workspace") or get_current_workspace(),
            "allowed_phone_number_ids": sorted(list(cfg.get("allowed_phone_number_ids") or [])),
            "survey_test_numbers": sorted(list(cfg.get("survey_test_numbers") or [])),
            "auto_reply_test_numbers": sorted(list(cfg.get("auto_reply_test_numbers") or [])),
            "waba_id": cfg.get("waba_id") or "",
            "catalog_id": cfg.get("catalog_id") or "",
            "phone_number_id": cfg.get("phone_number_id") or "",
            "meta_app_id": cfg.get("meta_app_id") or "",
            "webhook_verify_token_present": bool(str((cfg.get("overrides") or {}).get("webhook_verify_token") or "").strip()),
            "access_token_present": tok_present,
            "access_token_source": tok_source,
            "access_token_hint": tok_hint,
            "overrides": cfg.get("overrides") or {},
        }
    except Exception:
        return {
            "workspace": get_current_workspace(),
            "allowed_phone_number_ids": sorted(list(ALLOWED_PHONE_NUMBER_IDS or set())),
            "survey_test_numbers": sorted(list(SURVEY_TEST_NUMBERS or set())),
            "auto_reply_test_numbers": sorted(list(AUTO_REPLY_TEST_NUMBERS or set())),
            "catalog_id": str(CATALOG_ID or "").strip(),
            "phone_number_id": str(PHONE_NUMBER_ID or "").strip(),
            "overrides": {},
        }


@app.post("/admin/inbox-env")
async def set_inbox_env_endpoint(payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Set inbox env overrides for the current workspace.

    Payload accepts lists OR comma/newline-separated strings:
      - allowed_phone_number_ids
      - survey_test_numbers
      - auto_reply_test_numbers
    """
    def _as_list(v):
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            parts = []
            for chunk in v.replace("\r", "\n").split("\n"):
                parts.extend([x.strip() for x in chunk.split(",") if x.strip()])
            return parts
        return []

    allowed = [str(x).strip() for x in _as_list(payload.get("allowed_phone_number_ids")) if str(x).strip()]
    survey = [_digits_only(str(x).strip()) for x in _as_list(payload.get("survey_test_numbers")) if str(x).strip()]
    auto_reply = [_digits_only(str(x).strip()) for x in _as_list(payload.get("auto_reply_test_numbers")) if str(x).strip()]
    waba_id = str((payload or {}).get("waba_id") or "").strip()
    catalog_id = str((payload or {}).get("catalog_id") or "").strip()
    phone_number_id = str((payload or {}).get("phone_number_id") or "").strip()
    meta_app_id = str((payload or {}).get("meta_app_id") or "").strip()
    webhook_verify_token = str((payload or {}).get("webhook_verify_token") or "").strip()
    access_token_in = str((payload or {}).get("access_token") or "").strip()
    clear_access_token = bool((payload or {}).get("clear_access_token"))

    # Normalize: dedupe while keeping stable order
    def _dedupe(xs: list[str]) -> list[str]:
        out = []
        seen = set()
        for x in xs:
            if not x or x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    # Preserve existing access_token unless explicitly provided or explicitly cleared.
    existing_token = ""
    try:
        raw_prev = await db_manager.get_setting(_ws_setting_key("inbox_env", get_current_workspace()))
        prev_obj = json.loads(raw_prev) if raw_prev else {}
        if isinstance(prev_obj, dict):
            existing_token = str(prev_obj.get("access_token") or "").strip()
    except Exception:
        existing_token = ""

    stored = {
        "allowed_phone_number_ids": _dedupe(allowed),
        "survey_test_numbers": _dedupe(survey),
        "auto_reply_test_numbers": _dedupe(auto_reply),
        "waba_id": waba_id,
        "catalog_id": catalog_id,
        "phone_number_id": phone_number_id,
        "meta_app_id": meta_app_id,
        "webhook_verify_token": webhook_verify_token,
        **(
            {}
            if clear_access_token
            else ({"access_token": access_token_in} if access_token_in else ({"access_token": existing_token} if existing_token else {}))
        ),
    }
    ws_now = get_current_workspace()
    await db_manager.set_setting(_ws_setting_key("inbox_env", ws_now), stored)
    # Bust cache for immediate effect
    try:
        ws = _coerce_workspace(get_current_workspace())
        message_processor._inbox_env_cache.pop(ws, None)
    except Exception:
        pass
    # Persist phone_number_id -> workspace mapping in shared storage (Redis/auth DB) for multi-instance stability.
    try:
        pid = str(phone_number_id or "").strip()
        ws_norm = _coerce_workspace(ws_now)
        if pid and ws_norm:
            # 1) Redis (preferred for fast lookups by /webhook ingress)
            try:
                r = getattr(redis_manager, "redis_client", None)
                if r:
                    await r.hset("wa:phone_id_to_workspace", pid, ws_norm)
            except Exception:
                pass
            # 2) Auth DB (durable fallback; also helps rebuild mappings on cold start)
            try:
                raw_map = await auth_db_manager.get_setting("phone_id_to_workspace")
                m = json.loads(raw_map) if raw_map else {}
                if not isinstance(m, dict):
                    m = {}
                # Remove any other phone IDs pointing to this workspace (avoid duplicates)
                try:
                    for k, v in list(m.items()):
                        if str(v or "").strip().lower() == ws_norm and str(k or "").strip() != pid:
                            m.pop(k, None)
                except Exception:
                    pass
                m[pid] = ws_norm
                await auth_db_manager.set_setting("phone_id_to_workspace", m)
            except Exception:
                pass
    except Exception:
        pass
    # Update runtime WhatsApp routing immediately (no redeploy needed).
    try:
        await _sync_whatsapp_runtime_for_workspace(ws_now)
    except Exception:
        pass
    # Update accepted verify tokens for webhook verification (best-effort).
    try:
        if webhook_verify_token:
            RUNTIME_WEBHOOK_VERIFY_TOKENS.add(webhook_verify_token)
        elif str(VERIFY_TOKEN or "").strip():
            RUNTIME_WEBHOOK_VERIFY_TOKENS.add(str(VERIFY_TOKEN or "").strip())
    except Exception:
        pass
    return {"ok": True, "workspace": get_current_workspace(), "saved": stored}


@app.post("/admin/webhook-dlq/replay")
async def replay_webhook_dlq(payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Replay webhook DLQ entries back into the main webhook stream.

    This is a safety net for periods where processing was failing (e.g., routing mismatch).
    Requires Redis Streams to be enabled/available.
    """
    count = 50
    try:
        count = int((payload or {}).get("count") or 50)
    except Exception:
        count = 50
    count = max(1, min(500, count))

    r = getattr(redis_manager, "redis_client", None)
    if not r or not WEBHOOK_USE_REDIS_STREAM:
        raise HTTPException(status_code=400, detail="DLQ replay requires Redis Streams")

    try:
        items = await r.xrevrange(WEBHOOK_STREAM_DLQ_KEY, max="+", min="-", count=count)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read DLQ: {exc}")

    replayed = 0
    for _id, fields in reversed(items or []):  # replay oldest -> newest
        try:
            raw = None
            if isinstance(fields, dict):
                raw = fields.get("payload")
                if raw is None:
                    raw = fields.get(b"payload")
            if raw is None:
                continue
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", "ignore")
            raw = str(raw or "").strip()
            if not raw:
                continue
            await r.xadd(WEBHOOK_STREAM_KEY, {"payload": raw})
            replayed += 1
        except Exception:
            continue

    return {"ok": True, "replayed": replayed, "count": count}


@app.get("/admin/webhook-events/stats")
async def webhook_events_stats(_: dict = Depends(require_admin), hours: int = 72):
    """Inspect Postgres webhook queue stats (requires DATABASE_URL + WEBHOOK_USE_DB_QUEUE=1)."""
    hours = max(1, min(24 * 30, int(hours or 72)))
    if not getattr(db_manager, "use_postgres", False):
        raise HTTPException(status_code=400, detail="webhook_events stats require Postgres (DATABASE_URL)")
    try:
        async with db_manager._conn() as db:
            rows = await db.fetch(
                """
                SELECT status, COUNT(*) AS c
                FROM webhook_events
                WHERE created_at >= NOW() - ($1 * INTERVAL '1 hour')
                GROUP BY status
                """,
                int(hours),
            )
            dead = await db.fetch(
                """
                SELECT id, attempts, created_at, updated_at, LEFT(COALESCE(last_error,''), 500) AS last_error
                FROM webhook_events
                WHERE status='dead'
                  AND created_at >= NOW() - ($1 * INTERVAL '1 hour')
                ORDER BY id DESC
                LIMIT 50
                """,
                int(hours),
            )
        out = {str(r["status"]): int(r["c"] or 0) for r in (rows or [])}
        return {"ok": True, "hours": hours, "counts": out, "dead_sample": [dict(x) for x in (dead or [])]}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to query webhook_events: {exc}")


@app.post("/admin/webhook-events/replay")
async def webhook_events_replay(payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Replay Postgres webhook events by resetting status back to pending.

    Use this when you had a processing outage (routing mismatch, worker crash, etc).
    """
    if not getattr(db_manager, "use_postgres", False):
        raise HTTPException(status_code=400, detail="webhook_events replay requires Postgres (DATABASE_URL)")
    mode = str((payload or {}).get("mode") or "dead").strip().lower()  # dead | retry | pending | all
    hours = 72
    try:
        hours = int((payload or {}).get("hours") or 72)
    except Exception:
        hours = 72
    hours = max(1, min(24 * 30, hours))
    limit = 500
    try:
        limit = int((payload or {}).get("limit") or 500)
    except Exception:
        limit = 500
    limit = max(1, min(5000, limit))

    statuses = {
        "dead": ["dead"],
        "retry": ["retry"],
        "pending": ["pending"],
        "all": ["dead", "retry", "pending"],
    }.get(mode, ["dead"])

    try:
        async with db_manager._conn() as db:
            ids = await db.fetch(
                """
                SELECT id
                FROM webhook_events
                WHERE status = ANY($1::text[])
                  AND created_at >= NOW() - ($2 * INTERVAL '1 hour')
                ORDER BY id ASC
                LIMIT $3
                """,
                statuses,
                int(hours),
                int(limit),
            )
            id_list = [int(r["id"]) for r in (ids or [])]
            if not id_list:
                return {"ok": True, "replayed": 0, "mode": mode, "hours": hours, "limit": limit}
            await db.execute(
                """
                UPDATE webhook_events
                SET status='pending',
                    next_attempt_at=NOW(),
                    locked_at=NULL,
                    lock_owner=NULL,
                    updated_at=NOW()
                WHERE id = ANY($1::bigint[])
                """,
                id_list,
            )
        return {"ok": True, "replayed": len(id_list), "mode": mode, "hours": hours, "limit": limit}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to replay webhook_events: {exc}")


# ---- Workspace registry + per-workspace UI settings (admin) ----

async def _load_workspace_registry() -> list[dict]:
    """Load admin-managed workspace registry from shared auth/settings DB."""
    try:
        raw = await auth_db_manager.get_setting("workspace_registry")
        data = json.loads(raw) if raw else []
        return data if isinstance(data, list) else []
    except Exception:
        return []

async def _save_workspace_registry(items: list[dict]) -> None:
    try:
        await auth_db_manager.set_setting("workspace_registry", items)
    except Exception:
        return

def _workspace_meta_from_registry(registry: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in registry or []:
        if not isinstance(item, dict):
            continue
        ws = _normalize_workspace_id(item.get("id") or "")
        if not ws:
            continue
        out[ws] = {
            "label": str(item.get("label") or "").strip(),
            "short": str(item.get("short") or "").strip(),
        }
    return out

@app.get("/admin/workspaces")
async def admin_list_workspaces(_: dict = Depends(require_admin)):
    """List workspaces with UI metadata (env + DB registry)."""
    reg = await _load_workspace_registry()
    meta = _workspace_meta_from_registry(reg)
    all_ws = sorted(list(_all_workspaces_set()))
    # Ensure registry workspaces are included even if not loaded yet
    for w in meta.keys():
        if w not in all_ws:
            all_ws.append(w)
    all_ws = sorted(set([_normalize_workspace_id(w) for w in all_ws if _normalize_workspace_id(w)]))
    # Update in-memory dynamic set
    try:
        for w in all_ws:
            if w not in WORKSPACES:
                DYNAMIC_WORKSPACES.add(w)
    except Exception:
        pass
    items = []
    for w in all_ws:
        items.append({
            "id": w,
            "label": meta.get(w, {}).get("label") or w.upper(),
            "short": meta.get(w, {}).get("short") or w.upper()[:4],
            "source": "env" if w in WORKSPACES else "db",
        })
    return {
        "default": DEFAULT_WORKSPACE,
        "workspaces": items,
        "registry": reg,
    }

@app.post("/admin/workspaces")
async def admin_upsert_workspace(payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Add/update a workspace in the DB registry. Optionally copy settings from another workspace."""
    ws_id = _normalize_workspace_id((payload or {}).get("id") or "")
    if not ws_id:
        raise HTTPException(status_code=400, detail="Missing workspace id")
    label = str((payload or {}).get("label") or "").strip()
    short = str((payload or {}).get("short") or "").strip()
    copy_from = _normalize_workspace_id((payload or {}).get("copy_from") or "")

    reg = await _load_workspace_registry()
    # Upsert by id
    next_reg: list[dict] = []
    found = False
    for item in reg or []:
        if not isinstance(item, dict):
            continue
        if _normalize_workspace_id(item.get("id") or "") == ws_id:
            found = True
            next_reg.append({
                "id": ws_id,
                "label": label or str(item.get("label") or "").strip(),
                "short": short or str(item.get("short") or "").strip(),
            })
        else:
            next_reg.append(item)
    if not found:
        next_reg.append({"id": ws_id, "label": label, "short": short})
    await _save_workspace_registry(next_reg)

    # Update in-memory list for request routing
    try:
        if ws_id not in WORKSPACES:
            DYNAMIC_WORKSPACES.add(ws_id)
    except Exception:
        pass

    # Ensure tenant DB manager exists (so settings can be stored per workspace)
    try:
        _ = db_manager._mgr(ws_id)  # type: ignore[attr-defined]
        # Best-effort init schema for the new workspace DB (SQLite)
        try:
            tok = _CURRENT_WORKSPACE.set(_coerce_workspace(ws_id))
            await asyncio.wait_for(db_manager.init_db(), timeout=30.0)
        finally:
            try:
                _CURRENT_WORKSPACE.reset(tok)
            except Exception:
                pass
    except Exception:
        pass

    # Optionally copy per-workspace settings
    copied: dict[str, bool] = {}
    if copy_from and copy_from != ws_id:
        try:
            # Copy inbox_env + catalog_filters from source -> dest
            src_mgr = db_manager._mgr(copy_from)  # type: ignore[attr-defined]
            dst_mgr = db_manager._mgr(ws_id)      # type: ignore[attr-defined]
            try:
                raw_env = await src_mgr.get_setting(_ws_setting_key("inbox_env", copy_from))
                if raw_env:
                    await dst_mgr.set_setting(_ws_setting_key("inbox_env", ws_id), json.loads(raw_env))
                    copied["inbox_env"] = True
            except Exception:
                copied["inbox_env"] = False
            try:
                raw_cf = await src_mgr.get_setting(_ws_setting_key("catalog_filters", copy_from))
                if raw_cf:
                    await dst_mgr.set_setting(_ws_setting_key("catalog_filters", ws_id), json.loads(raw_cf))
                    copied["catalog_filters"] = True
            except Exception:
                copied["catalog_filters"] = False
        except Exception:
            pass

    return {"ok": True, "id": ws_id, "label": label, "short": short, "copied": copied}


@app.delete("/admin/workspaces/{workspace_id}")
async def admin_delete_workspace(workspace_id: str, _: dict = Depends(require_admin)):
    """Delete a workspace from the DB registry and remove its stored settings.

    Notes:
    - We do NOT allow deleting env-defined workspaces (WORKSPACES) or the DEFAULT_WORKSPACE.
    - For SQLite tenant DBs, we attempt to delete the derived DB file for that workspace.
    """
    ws_id = _normalize_workspace_id(workspace_id or "")
    if not ws_id:
        raise HTTPException(status_code=400, detail="Missing workspace id")
    if ws_id == _coerce_workspace(DEFAULT_WORKSPACE):
        raise HTTPException(status_code=400, detail="Cannot delete default workspace")
    if ws_id in (WORKSPACES or []):
        raise HTTPException(status_code=400, detail="Cannot delete env workspace; remove it from WORKSPACES env")

    # Remove from registry
    reg = await _load_workspace_registry()
    next_reg = [x for x in (reg or []) if _normalize_workspace_id((x or {}).get("id") or "") != ws_id]
    await _save_workspace_registry(next_reg)

    # Remove from dynamic set
    try:
        DYNAMIC_WORKSPACES.discard(ws_id)
    except Exception:
        pass

    # Remove workspace-scoped settings keys (best-effort)
    deleted_keys: list[str] = []
    try:
        for base in ("inbox_env", "catalog_filters"):
            k = _ws_setting_key(base, ws_id)
            try:
                await db_manager.delete_setting(k)
                deleted_keys.append(k)
            except Exception:
                continue
    except Exception:
        pass

    # Best-effort delete tenant SQLite DB file if present
    deleted_files: list[str] = []
    try:
        p = (TENANT_DB_PATHS or {}).get(ws_id) or _derive_tenant_db_path(DB_PATH, ws_id)
        if p and str(p).lower().endswith(".db") and os.path.exists(p):
            try:
                os.remove(p)
                deleted_files.append(str(p))
            except Exception:
                pass
    except Exception:
        pass

    return {"ok": True, "deleted": ws_id, "deleted_keys": deleted_keys, "deleted_files": deleted_files}


@app.get("/admin/catalog-filters")
async def get_catalog_filters_admin(_: dict = Depends(require_admin)):
    """Get catalog filter buttons for the current workspace (DB override if present)."""
    ws = get_current_workspace()
    try:
        raw = await db_manager.get_setting(_ws_setting_key("catalog_filters", ws))
        if (not raw) and ws == _coerce_workspace(DEFAULT_WORKSPACE):
            raw = await db_manager.get_setting("catalog_filters")
        data = json.loads(raw) if raw else None
        if isinstance(data, list) and len(data) >= 2:
            return {"workspace": ws, "catalogFilters": data}
    except Exception:
        pass
    # Fallback to the same defaults as /app-config (env + safe defaults)
    try:
        def _env_ws(name: str) -> str:
            suf = re.sub(r"[^A-Z0-9]+", "_", str(ws or "").strip().upper())
            v = os.getenv(f"{name}_{suf}", "")
            if v is not None and str(v).strip() != "":
                return str(v)
            return str(os.getenv(name, "") or "")

        def _read_filter(suffix: str):
            label = _env_ws(f"CATALOG_FILTER_{suffix}_LABEL").strip()
            query = _env_ws(f"CATALOG_FILTER_{suffix}_QUERY").strip()
            match = (_env_ws(f"CATALOG_FILTER_{suffix}_MATCH") or "includes").strip().lower()
            if label and query:
                return {
                    "label": label,
                    "query": query,
                    "match": "startsWith" if match in ("start", "startswith", "starts_with", "startsWith") else "includes",
                }
            return None
        fA = _read_filter("A") or {"label": "Girls", "query": "girls", "match": "includes"}
        fB = _read_filter("B") or {"label": "Boys", "query": "boys", "match": "includes"}
        fall = {"label": (_env_ws("CATALOG_FILTER_ALL_LABEL") or "All").strip() or "All", "type": "all"}
        return {"workspace": ws, "catalogFilters": [fA, fB, fall]}
    except Exception:
        return {"workspace": ws, "catalogFilters": [
            {"label": "Girls", "query": "girls", "match": "includes"},
            {"label": "Boys", "query": "boys", "match": "includes"},
            {"label": "All", "type": "all"},
        ]}


@app.post("/admin/catalog-filters")
async def set_catalog_filters_admin(payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Set catalog filter buttons for the current workspace (stored in DB)."""
    ws = get_current_workspace()
    filters = None
    if isinstance(payload, dict):
        filters = payload.get("catalogFilters") if "catalogFilters" in payload else payload.get("filters")
    if not isinstance(filters, list) or len(filters) < 2:
        raise HTTPException(status_code=400, detail="catalogFilters must be a list (2-3 items)")
    # Store as-is (frontend expects this exact structure)
    await db_manager.set_setting(_ws_setting_key("catalog_filters", ws), filters)
    return {"ok": True, "workspace": ws, "saved": filters}


@app.get("/admin/whatsapp/templates")
async def list_whatsapp_templates_endpoint(_: dict = Depends(require_admin)):
    """List WhatsApp message templates for the current workspace (WABA ID required)."""
    cfg = await message_processor._get_inbox_env(get_current_workspace())
    waba_id = str((cfg or {}).get("waba_id") or "").strip()
    if not waba_id:
        raise HTTPException(status_code=400, detail="Missing waba_id (set it in Automation → Environment)")

    # Use the workspace WhatsApp access token
    try:
        token = message_processor.whatsapp_messenger._client(get_current_workspace()).access_token  # type: ignore[attr-defined]
    except Exception:
        token = ACCESS_TOKEN
    if not token:
        raise HTTPException(status_code=503, detail="WhatsApp access token not configured")

    url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{waba_id}/message_templates"
    params = {
        "limit": 200,
        "fields": "name,language,status,category,components",
    }
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, params=params, headers=headers)
        if resp.status_code >= 400:
            try:
                detail = (resp.text or "")[:500]
            except Exception:
                detail = "Template fetch failed"
            raise HTTPException(status_code=resp.status_code, detail=detail)
        data = resp.json() or {}
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
        # Return compact list
        out = []
        for t in items:
            if not isinstance(t, dict):
                continue
            out.append(
                {
                    "name": t.get("name"),
                    "language": t.get("language"),
                    "status": t.get("status"),
                    "category": t.get("category"),
                    "components": t.get("components") or [],
                }
            )
        return {"workspace": get_current_workspace(), "waba_id": waba_id, "templates": out}


@app.post("/admin/whatsapp/templates")
async def create_whatsapp_template_endpoint(payload: dict = Body(...), _: dict = Depends(require_admin)):
    """Create (submit for review) a WhatsApp message template for the current workspace."""
    ws = get_current_workspace()
    cfg = await message_processor._get_inbox_env(ws)
    waba_id = str((cfg or {}).get("waba_id") or "").strip()
    if not waba_id:
        raise HTTPException(status_code=400, detail="Missing waba_id (set it in Automation → Environment)")

    # Use the workspace WhatsApp access token
    try:
        token = message_processor.whatsapp_messenger._client(ws).access_token  # type: ignore[attr-defined]
    except Exception:
        token = ACCESS_TOKEN
    if not token:
        raise HTTPException(status_code=503, detail="WhatsApp access token not configured")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")

    name = str(payload.get("name") or "").strip()
    language = str(payload.get("language") or "").strip()
    category = str(payload.get("category") or "").strip().upper()
    components = payload.get("components") or []

    # Meta template name rules (best-effort): lowercase letters, numbers, underscores.
    if not name:
        raise HTTPException(status_code=400, detail="Missing template name")
    if len(name) > 512:
        raise HTTPException(status_code=400, detail="Template name too long (max 512)")
    if not re.fullmatch(r"[a-z0-9_]+", name):
        raise HTTPException(status_code=400, detail="Invalid template name (use lowercase letters, numbers, underscores)")

    if not language:
        raise HTTPException(status_code=400, detail="Missing language")
    if category not in ("MARKETING", "UTILITY", "AUTHENTICATION"):
        raise HTTPException(status_code=400, detail="Invalid category (MARKETING | UTILITY | AUTHENTICATION)")

    if not isinstance(components, list) or any(not isinstance(c, dict) for c in components):
        raise HTTPException(status_code=400, detail="components must be a list of objects")

    url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{waba_id}/message_templates"
    headers = {"Authorization": f"Bearer {token}"}
    body = {
        "name": name,
        "language": language,
        "category": category,
        "components": components,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=body, headers=headers)
        if resp.status_code >= 400:
            try:
                j = resp.json() or {}
                # Graph-style error message
                msg = (((j.get("error") or {}) if isinstance(j, dict) else {}).get("message") or "") if isinstance(j, dict) else ""
                if msg:
                    raise HTTPException(status_code=resp.status_code, detail=str(msg)[:800])
            except HTTPException:
                raise
            except Exception:
                pass
            try:
                detail = (resp.text or "")[:800]
            except Exception:
                detail = "Template create failed"
            raise HTTPException(status_code=resp.status_code, detail=detail)

        try:
            data = resp.json()
        except Exception:
            data = {"raw": (resp.text or "")[:1000]}
        return {"ok": True, "workspace": ws, "waba_id": waba_id, "result": data}


@app.post("/admin/whatsapp/templates/header-image-upload")
async def upload_template_header_image_endpoint(
    file: UploadFile = File(...),
    _: dict = Depends(require_admin),
):
    """Upload a WhatsApp template header image to GCS and return a public URL (for Meta template samples)."""
    try:
        ct = (getattr(file, "content_type", None) or "").lower()
        name = str(getattr(file, "filename", "") or "header").strip()
        ext = (Path(name).suffix or "").lower()

        allowed_ext = {".jpg", ".jpeg", ".png", ".webp"}
        allowed_ct = {"image/jpeg", "image/jpg", "image/png", "image/webp"}
        if ext and ext not in allowed_ext:
            raise HTTPException(status_code=400, detail="Unsupported image type. Use JPG, PNG, or WEBP.")
        if ct and ct not in allowed_ct:
            raise HTTPException(status_code=400, detail="Unsupported image content-type. Use image/jpeg, image/png, or image/webp.")

        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Empty file")
        if len(content) > 5 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Image too large (max 5MB)")

        MEDIA_DIR.mkdir(exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_ext = ext if ext in allowed_ext else (".png" if ct.endswith("png") else ".jpg")
        filename = f"tpl_header_{ts}_{uuid.uuid4().hex[:10]}{safe_ext}"
        file_path = MEDIA_DIR / filename
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(content)

        try:
            url = await upload_file_to_gcs(str(file_path), content_type=(ct or None))
        except Exception as exc:
            print(f"GCS upload failed for template header upload (fallback to /media): {exc}")
            url = f"/media/{filename}"

        return {"ok": True, "url": url, "filename": filename}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload failed: {exc}")


@app.post("/shopify/webhook/{workspace}")
async def shopify_webhook_endpoint(workspace: str, request: Request):
    """Shopify webhook endpoint (one URL per workspace).

    Configure in Shopify Admin → Settings → Notifications → Webhooks:
      URL: https://<your-domain>/shopify/webhook/irranova
      URL: https://<your-domain>/shopify/webhook/irrakids

    Notes:
    - Shopify requires the FULL URL (base domain + path). Pasting just "/shopify/webhook/irranova" is not enough.
    - Use one webhook per workspace if you run multiple stores/workspaces in the same app.
    - (Optional but recommended) Configure `SHOPIFY_WEBHOOK_SECRET` or per-workspace
      `SHOPIFY_WEBHOOK_SECRET_<WORKSPACE>` (e.g. `SHOPIFY_WEBHOOK_SECRET_IRRANOVA`) to enable HMAC verification.
    """
    ws = _coerce_workspace(workspace)
    ws_token = _CURRENT_WORKSPACE.set(ws)
    try:
        body = await request.body()

        # Verify HMAC if secret configured
        secret = (
            os.getenv(f"SHOPIFY_WEBHOOK_SECRET_{ws.upper()}", "")
            or os.getenv("SHOPIFY_WEBHOOK_SECRET", "")
        ).strip()
        if secret:
            hmac_header = (request.headers.get("X-Shopify-Hmac-Sha256") or "").strip()
            from .shopify_webhook import verify_shopify_webhook_hmac

            ok, dbg = verify_shopify_webhook_hmac(secret, body, hmac_header)
            if not ok:
                # Log safe debug hints (never log the secret).
                try:
                    logging.getLogger(__name__).warning(
                        "Invalid Shopify webhook HMAC (workspace=%s topic=%s shop=%s api=%s webhook_id=%s body_len=%s header_len=%s header_prefix=%s candidates=%s cand_prefixes=%s secret_len=%s secret_hex=%s)",
                        ws,
                        (request.headers.get("X-Shopify-Topic") or "").strip(),
                        (request.headers.get("X-Shopify-Shop-Domain") or "").strip(),
                        (request.headers.get("X-Shopify-API-Version") or "").strip(),
                        (request.headers.get("X-Shopify-Webhook-Id") or "").strip(),
                        dbg.get("body_len"),
                        dbg.get("header_len"),
                        dbg.get("header_prefix"),
                        dbg.get("candidates"),
                        ",".join(dbg.get("candidate_prefixes") or []),
                        dbg.get("secret_len"),
                        dbg.get("secret_is_hex_64"),
                    )
                except Exception:
                    pass
                raise HTTPException(status_code=401, detail="Invalid Shopify webhook HMAC")

        topic = (request.headers.get("X-Shopify-Topic") or "").strip()
        if not topic:
            # Shopify always sends a topic header, but keep safe
            topic = "unknown"

        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            payload = {}

        # ACK fast; process in background
        try:
            asyncio.create_task(message_processor._run_shopify_automations(topic, payload, workspace=ws))
        except Exception:
            pass

        return {"ok": True, "workspace": ws, "topic": topic}
    finally:
        try:
            _CURRENT_WORKSPACE.reset(ws_token)
        except Exception:
            pass


@app.post("/delivery/webhook/{workspace}")
async def delivery_webhook_endpoint(workspace: str, request: Request):
    """Delivery app webhook endpoint (one URL per workspace).

    Delivery app should POST JSON with fields like:
      { "event": "order_status_changed", "order": { ... }, "status": "Livré", "customer_phone": "+212..." }

    This endpoint is intentionally unauthenticated (public) so the delivery app
    can POST status events without managing secrets/tokens.
    """
    ws = _coerce_workspace(workspace)
    ws_token = _CURRENT_WORKSPACE.set(ws)
    try:
        body = await request.body()

        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            payload = {}

        event = "order_status_changed"
        if isinstance(payload, dict):
            event = str(payload.get("event") or payload.get("type") or event).strip() or event

        try:
            asyncio.create_task(message_processor._run_delivery_automations(event, payload, workspace=ws))
        except Exception:
            pass

        return {"ok": True, "workspace": ws, "event": event}
    finally:
        try:
            _CURRENT_WORKSPACE.reset(ws_token)
        except Exception:
            pass

@app.post("/admin/agents")
async def create_agent_endpoint(payload: dict = Body(...), _: dict = Depends(require_admin)):
    username = (payload.get("username") or "").strip()
    name = (payload.get("name") or username).strip()
    password = payload.get("password") or ""
    is_admin = int(bool(payload.get("is_admin", False)))
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")
    pw_hash = hash_password(password)
    await auth_db_manager.create_agent(username=username, name=name, password_hash=pw_hash, is_admin=is_admin)
    try:
        await redis_manager.set_agent_auth_record(username, pw_hash, is_admin)
    except Exception:
        pass
    return {"ok": True}

@app.delete("/admin/agents/{username}")
async def delete_agent_endpoint(username: str, _: dict = Depends(require_admin)):
    await auth_db_manager.delete_agent(username)
    try:
        await redis_manager.delete_agent_auth_record(username)
    except Exception:
        pass
    return {"ok": True}

def _parse_dt_any(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Normalize common formats: "YYYY-MM-DD HH:MM:SS" -> ISO
    try:
        if "T" not in s and " " in s:
            s = s.replace(" ", "T")
        # Add timezone if missing
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        # Coerce naive to UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def _set_auth_cookies(response: Response, request: Request, access_token: str, refresh_token: str):
    # For SameSite=None, Secure must be true or browsers will drop the cookie.
    secure = _cookie_secure_flag(request) or (AUTH_COOKIE_SAMESITE == "none")
    samesite = AUTH_COOKIE_SAMESITE if AUTH_COOKIE_SAMESITE in ("none", "lax", "strict") else "none"
    cookie_args = {
        "httponly": True,
        "secure": secure,
        "samesite": samesite,
        "path": "/",
    }
    dom = _cookie_domain_for_request(request)
    if dom:
        cookie_args["domain"] = dom
    response.set_cookie(ACCESS_COOKIE_NAME, access_token, max_age=ACCESS_TOKEN_TTL_SECONDS, **cookie_args)
    response.set_cookie(REFRESH_COOKIE_NAME, refresh_token, max_age=REFRESH_TOKEN_TTL_SECONDS, **cookie_args)

def _clear_auth_cookies(response: Response):
    samesite = AUTH_COOKIE_SAMESITE if AUTH_COOKIE_SAMESITE in ("none", "lax", "strict") else "none"
    cookie_args = {"path": "/", "samesite": samesite}
    if AUTH_COOKIE_DOMAIN:
        # Best-effort: allow env-configured domain clearing.
        cookie_args["domain"] = AUTH_COOKIE_DOMAIN
    response.delete_cookie(ACCESS_COOKIE_NAME, **cookie_args)
    response.delete_cookie(REFRESH_COOKIE_NAME, **cookie_args)

async def _auth_db_call(coro, *, op: str):
    """Await a DB coroutine with a hard timeout so auth endpoints don't hang and hit upstream 504s."""
    try:
        return await asyncio.wait_for(coro, timeout=AUTH_DB_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logging.getLogger(__name__).error("Auth DB operation timed out: %s (timeout=%ss)", op, AUTH_DB_TIMEOUT_SECONDS)
        raise HTTPException(status_code=503, detail="Authentication backend timeout")
    except HTTPException:
        raise
    except Exception as exc:
        logging.getLogger(__name__).exception("Auth DB operation failed: %s: %s", op, exc)
        raise HTTPException(status_code=503, detail="Authentication backend unavailable")

async def _get_agent_auth_record_resilient(username: str) -> Optional[dict]:
    """Fetch agent auth record with Redis-first strategy and DB fallback.

    Goal: make /auth/login robust even when Postgres is slow/unreachable.
    """
    u = (username or "").strip()
    if not u:
        return None

    # 1) Redis cache (shared across instances)
    try:
        rec = await redis_manager.get_agent_auth_record(u)
        if rec and rec.get("password_hash"):
            return rec
    except Exception:
        pass

    # Warm Redis agent auth cache (best-effort, non-blocking). This makes logins robust across instances.
    async def _warm_agent_auth_cache() -> None:
        try:
            if not getattr(redis_manager, "redis_client", None):
                return
            records = await auth_db_manager.list_agent_auth_records()
            for r in records or []:
                u = (r.get("username") or "").strip()
                ph = r.get("password_hash") or ""
                ia = int(r.get("is_admin") or 0)
                if u and ph:
                    await redis_manager.set_agent_auth_record(u, str(ph), ia)
        except Exception:
            return

    try:
        asyncio.create_task(_warm_agent_auth_cache())
    except Exception:
        pass

    # 2) DB (short timeout) -> refresh Redis
    try:
        rec = await asyncio.wait_for(auth_db_manager.get_agent_auth_record(u), timeout=max(0.5, float(AUTH_LOGIN_DB_TIMEOUT_SECONDS)))
        if rec and rec.get("password_hash"):
            try:
                await redis_manager.set_agent_auth_record(u, rec.get("password_hash") or "", int(rec.get("is_admin") or 0))
            except Exception:
                pass
            return rec
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass

    # 3) Redis again (race with warmup/other instance)
    try:
        rec = await redis_manager.get_agent_auth_record(u)
        if rec and rec.get("password_hash"):
            return rec
    except Exception:
        pass

    return None

@app.post("/auth/login")
async def auth_login(request: Request, response: Response, payload: dict = Body(...)):
    if DISABLE_AUTH:
        # Bypass credential checks entirely
        username = (payload.get("username") or "admin").strip() or "admin"
        is_admin = True
    else:
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        rec = await _get_agent_auth_record_resilient(username)
        stored = (rec or {}).get("password_hash") or ""
        is_admin = bool((rec or {}).get("is_admin") or 0)
        if not stored:
            # Keep the same observable behavior as before, but distinguish "unavailable" from "invalid credentials"
            # only when the backend cannot retrieve auth records.
            # If user truly doesn't exist, stored will also be empty; treat as invalid credentials (401).
            # However, when Postgres is timing out and Redis is empty, we should return 503 so clients can retry.
            try:
                # Best-effort: if DB is reachable quickly, confirm non-existence.
                quick = await asyncio.wait_for(auth_db_manager.get_agent_auth_record(username), timeout=1.5)
                if not quick or not (quick.get("password_hash") or ""):
                    raise HTTPException(status_code=401, detail="Invalid credentials")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=503, detail="Authentication backend unavailable")
        if not stored or not verify_password(password, stored):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        # is_admin already determined above (single DB hit)

    access_token = issue_access_token(username, bool(is_admin))
    refresh_token = secrets.token_urlsafe(48)
    refresh_hash = _hash_refresh_token(refresh_token)
    expires_at = (datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(seconds=REFRESH_TOKEN_TTL_SECONDS)).isoformat()
    await _auth_db_call(
        auth_db_manager.store_refresh_token(refresh_hash, username, expires_at),
        op=f"store_refresh_token({username})",
    )

    # Set cookies (request/response are always injected by FastAPI)
    _set_auth_cookies(response, request, access_token, refresh_token)
    # Mark agent as active immediately on login (best-effort; used for online presence + inactivity).
    try:
        await redis_manager.touch_agent_last_seen(username, workspace=get_current_workspace())
    except Exception:
        pass
    # Also return access token so clients can fall back to Authorization header
    # if their environment blocks cookies (some browsers/settings/extensions).
    out = {"ok": True, "username": username, "is_admin": bool(is_admin), "access_token": access_token, "token_type": "bearer"}
    # Optional: also return refresh token as a fallback (for clients that can't use cookies).
    try:
        wants = bool(payload.get("token_fallback")) or bool(payload.get("use_token_fallback"))
    except Exception:
        wants = False
    if EXPOSE_REFRESH_TOKEN_FALLBACK and wants:
        out["refresh_token"] = refresh_token
        out["refresh_token_ttl_seconds"] = int(REFRESH_TOKEN_TTL_SECONDS)
    return out

@app.post("/auth/refresh")
async def auth_refresh(request: Request, response: Response):
    if DISABLE_AUTH:
        return {"ok": True, "username": "admin", "is_admin": True}
    refresh = request.cookies.get(REFRESH_COOKIE_NAME) or ""
    # Fallback: accept refresh token from header for clients that can't store cookies
    if not refresh:
        try:
            refresh = (request.headers.get("x-refresh-token") or request.headers.get("X-Refresh-Token") or "").strip()
        except Exception:
            refresh = ""
    if not refresh:
        # Optional: accept JSON body {refresh_token:"..."} (no dependency on cookies)
        try:
            body = await request.json()
            refresh = str((body or {}).get("refresh_token") or "").strip()
        except Exception:
            refresh = ""
    if not refresh:
        raise HTTPException(status_code=401, detail="Unauthorized")
    refresh_hash = _hash_refresh_token(refresh)
    row = await _auth_db_call(auth_db_manager.get_refresh_token(refresh_hash), op="get_refresh_token(hash)")
    if not row:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if row.get("revoked_at"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    exp = _parse_dt_any(row.get("expires_at"))
    if not exp or exp < datetime.now(timezone.utc):
        try:
            await auth_db_manager.revoke_refresh_token(refresh_hash)
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Unauthorized")

    username = str(row.get("agent_username") or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    is_admin = bool(await _auth_db_call(auth_db_manager.get_agent_is_admin(username), op=f"get_agent_is_admin({username})"))

    # Issue a new access token. By default we DO NOT rotate refresh tokens on every refresh
    # to avoid multi-tab/device race conditions that can log users out.
    access_token = issue_access_token(username, is_admin)

    if REFRESH_ROTATE_ON_REFRESH:
        new_refresh = secrets.token_urlsafe(48)
        new_refresh_hash = _hash_refresh_token(new_refresh)
        new_expires = (datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(seconds=REFRESH_TOKEN_TTL_SECONDS)).isoformat()
        await _auth_db_call(auth_db_manager.store_refresh_token(new_refresh_hash, username, new_expires), op=f"store_refresh_token({username})")
        await _auth_db_call(auth_db_manager.revoke_refresh_token(refresh_hash), op="revoke_refresh_token(hash)")
        _set_auth_cookies(response, request, access_token, new_refresh)
        out_refresh = new_refresh
    else:
        # Keep the same refresh token; just refresh the access cookie.
        # (Keep refresh cookie as-is; browsers will continue to send it.)
        try:
            response.set_cookie(
                ACCESS_COOKIE_NAME,
                access_token,
                max_age=ACCESS_TOKEN_TTL_SECONDS,
                httponly=True,
                secure=_cookie_secure_flag(request) or (AUTH_COOKIE_SAMESITE == "none"),
                samesite=(AUTH_COOKIE_SAMESITE if AUTH_COOKIE_SAMESITE in ("none", "lax", "strict") else "none"),
                path="/",
                **({"domain": _cookie_domain_for_request(request)} if _cookie_domain_for_request(request) else {}),
            )
        except Exception:
            # Fallback to helper (will also rewrite refresh cookie, but with same token if caller had it)
            _set_auth_cookies(response, request, access_token, refresh)
        out_refresh = refresh

    return {
        "ok": True,
        "username": username,
        "is_admin": bool(is_admin),
        "access_token": access_token,
        "token_type": "bearer",
        **({"refresh_token": out_refresh, "refresh_token_ttl_seconds": int(REFRESH_TOKEN_TTL_SECONDS)} if EXPOSE_REFRESH_TOKEN_FALLBACK else {}),
    }

@app.post("/auth/logout")
async def auth_logout(request: Request, response: Response):
    if DISABLE_AUTH:
        return {"ok": True}
    refresh = request.cookies.get(REFRESH_COOKIE_NAME) or ""
    if not refresh:
        try:
            refresh = (request.headers.get("x-refresh-token") or request.headers.get("X-Refresh-Token") or "").strip()
        except Exception:
            refresh = ""

    # We revoke ALL refresh tokens for this agent on logout so they disappear from "online" immediately
    # and we don't leave other sessions hanging around (multi-tab / old devices).
    username: str | None = None
    if refresh:
        try:
            row = await auth_db_manager.get_refresh_token(_hash_refresh_token(refresh))
            username = str((row or {}).get("agent_username") or "").strip() or None
        except Exception:
            username = None

    if not username:
        # Fallback: use access token cookie/header if present
        try:
            token = _extract_access_token_from_request(request)
            parsed = parse_access_token(token or "")
            username = str((parsed or {}).get("username") or "").strip() or None
        except Exception:
            username = None

    if username:
        try:
            await auth_db_manager.revoke_all_refresh_tokens_for_agent(username)
        except Exception:
            pass
        # Clear presence/activity for all workspaces so admin view updates even after hard refresh
        try:
            for _w in (WORKSPACES or [DEFAULT_WORKSPACE]):
                try:
                    await redis_manager.clear_agent_last_seen(username, workspace=_w)
                except Exception:
                    continue
        except Exception:
            pass
    else:
        # Best-effort: revoke the presented refresh token only
        if refresh:
            try:
                await auth_db_manager.revoke_refresh_token(_hash_refresh_token(refresh))
            except Exception:
                pass
    _clear_auth_cookies(response)
    return {"ok": True}

@app.get("/auth/me")
async def auth_me(agent: dict = Depends(get_current_agent)):
    return {"username": agent["username"], "is_admin": bool(agent.get("is_admin"))}

@app.post("/auth/change-password")
async def auth_change_password(payload: dict = Body(...), agent: dict = Depends(get_current_agent)):
    username = (payload.get("username") or agent.get("username") or "").strip()
    old_password = payload.get("old_password") or ""
    new_password = payload.get("new_password") or ""
    if not username or not new_password:
        raise HTTPException(status_code=400, detail="username and new_password are required")
    # Non-admins can only change their own password and must provide old password
    if not agent.get("is_admin"):
        if username != agent.get("username"):
            raise HTTPException(status_code=403, detail="Forbidden")
        stored = await auth_db_manager.get_agent_password_hash(username)
        if not stored or not verify_password(old_password, stored):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    # Admin changing someone else's password: allow without old_password
    new_hash = hash_password(new_password)
    await auth_db_manager.set_agent_password_hash(username, new_hash)
    # Refresh Redis auth cache for robustness
    try:
        ia = 0
        try:
            ia = int(await auth_db_manager.get_agent_is_admin(username))
        except Exception:
            # Best-effort: keep whatever Redis already had
            cached = await redis_manager.get_agent_auth_record(username)
            ia = int((cached or {}).get("is_admin") or 0)
        await redis_manager.set_agent_auth_record(username, new_hash, ia)
    except Exception:
        pass
    return {"ok": True}

@app.post("/conversations/{user_id}/assign")
async def assign_conversation(user_id: str, payload: dict = Body(...), actor: dict = Depends(get_current_agent)):
    target_agent = payload.get("agent")  # string or None
    # Non-admin agents may only "claim" a conversation for themselves (or clear their own claim).
    if not actor.get("is_admin"):
        me = actor.get("username")
        if target_agent not in (None, "", me):
            raise HTTPException(status_code=403, detail="Forbidden")
        # Prevent stealing: if currently assigned to someone else, only admin may change it.
        meta = await db_manager.get_conversation_meta(user_id)
        current = (meta.get("assigned_agent") or "").strip() or None
        if current not in (None, me):
            raise HTTPException(status_code=403, detail="Forbidden")
        # Normalize empty to None for "unassigned"
        if target_agent == "":
            target_agent = None
    await db_manager.set_conversation_assignment(user_id, target_agent)
    return {"ok": True, "user_id": user_id, "assigned_agent": target_agent}

@app.post("/conversations/{user_id}/tags")
async def update_conversation_tags(user_id: str, payload: dict = Body(...), actor: dict = Depends(get_current_agent)):
    tags = payload.get("tags") or []
    if not isinstance(tags, list):
        raise HTTPException(status_code=400, detail="tags must be a list")
    # Ensure caller can access this conversation
    if not actor.get("is_admin"):
        meta = await db_manager.get_conversation_meta(user_id)
        assignee = (meta.get("assigned_agent") or "").strip() or None
        if assignee not in (None, actor.get("username")):
            raise HTTPException(status_code=403, detail="Forbidden")
    await db_manager.set_conversation_tags(user_id, tags)
    return {"ok": True, "user_id": user_id, "tags": tags}

@app.get("/health")
async def health_check():
    """Health check endpoint"""  
    redis_status = "connected" if redis_manager.redis_client else "disconnected"
    db_backend = "postgres" if db_manager.use_postgres else "sqlite"
    db_ok = False
    try:
        db_ok = await asyncio.wait_for(db_manager.ping(), timeout=HEALTH_DB_TIMEOUT_SECONDS)
    except Exception:
        db_ok = False
    expose_internals = bool(HEALTH_EXPOSE_INTERNALS or LOG_VERBOSE)
    # Best-effort effective inbox env (admin-safe subset)
    try:
        env_cfg = await message_processor._get_inbox_env(get_current_workspace())
        allowed_ids = sorted(list((env_cfg or {}).get("allowed_phone_number_ids") or []))[:20]
    except Exception:
        allowed_ids = sorted(list(ALLOWED_PHONE_NUMBER_IDS or set()))[:20]
    return {
        "status": "healthy",
        "redis": redis_status,
        "workspace": get_current_workspace(),
        "multi_workspace": {
            "enabled": bool(ENABLE_MULTI_WORKSPACE),
            "workspaces": WORKSPACES,
            "default": DEFAULT_WORKSPACE,
        },
        "db": {
            "backend": db_backend,
            "ok": bool(db_ok),
            # expose path only for sqlite to aid debugging; avoid leaking connection strings
            "db_path": (
                ((TENANT_DB_PATHS or {}).get(get_current_workspace()) or DB_PATH)
                if (db_backend == "sqlite" and expose_internals)
                else None
            ),
            "auth_db_path": (AUTH_DB_PATH if (db_backend == "sqlite" and expose_internals) else None),
            # safe summaries for Postgres routing (no passwords)
            "tenant_db": _safe_db_url_summary(getattr(db_manager, "db_url", None)),
            "auth_db": _safe_db_url_summary(getattr(auth_db_manager, "db_url", None)),
        },
        "whatsapp": {
            "allowed_phone_number_ids": allowed_ids,
            "phone_id_to_workspace": PHONE_ID_TO_WORKSPACE,
        },
        "webhook": {
            "backend": webhook_runtime.backend_name(),
            "queue_size": getattr(WEBHOOK_QUEUE, "qsize", lambda: None)(),
            "queue_maxsize": int(WEBHOOK_QUEUE_MAXSIZE),
            "workers": int(max(1, int(WEBHOOK_WORKERS))),
            "use_redis_stream": bool(WEBHOOK_USE_REDIS_STREAM and bool(redis_manager.redis_client)),
            "stream_key": WEBHOOK_STREAM_KEY if (WEBHOOK_USE_REDIS_STREAM and redis_manager.redis_client) else None,
            "dlq_key": WEBHOOK_STREAM_DLQ_KEY if (WEBHOOK_USE_REDIS_STREAM and redis_manager.redis_client) else None,
            "use_db_queue": bool(getattr(db_manager, "use_postgres", False) and WEBHOOK_USE_DB_QUEUE and bool(webhook_runtime.state.db_ready)),
            "db_queue_ready": bool(webhook_runtime.state.db_ready),
        },
        "active_connections": len(connection_manager.active_connections),
        "timestamp": datetime.utcnow().isoformat(),
        "whatsapp_config": {
            "access_token_configured": bool(ACCESS_TOKEN and ACCESS_TOKEN != "your_access_token_here"),
            "phone_number_id_configured": bool(PHONE_NUMBER_ID and PHONE_NUMBER_ID != "your_phone_number_id"),
            "verify_token_configured": bool(VERIFY_TOKEN)
        }
    }

# ----- Payout and archive endpoints -----

@app.post("/orders/{order_id}/delivered")
async def order_delivered(order_id: str):
    """Record a delivered order in the payouts list."""
    await db_manager.add_delivered_order(order_id)
    return {"status": ORDER_STATUS_PAYOUT, "order_id": order_id}


@app.post("/payouts/{order_id}/mark-paid")
async def mark_payout_paid_endpoint(order_id: str):
    """Mark payout as paid and archive the order."""
    await db_manager.mark_payout_paid(order_id)
    return {"status": ORDER_STATUS_ARCHIVED, "order_id": order_id}


@app.get("/payouts")
async def list_payouts():
    """List orders awaiting payout."""
    return await db_manager.get_payouts()


@app.get("/archive")
async def list_archive():
    """List archived (paid) orders."""
    return await db_manager.get_archived_orders()

@app.post("/orders/created/log")
async def log_order_created(payload: dict = Body(...), actor: dict = Depends(get_current_agent)):
    order_id = (payload.get("order_id") or "").strip()
    user_id = (payload.get("user_id") or None)
    agent = actor.get("username")
    if not order_id:
        raise HTTPException(status_code=400, detail="order_id is required")
    await db_manager.log_order_created(order_id=order_id, user_id=user_id, agent_username=agent)
    try:
        await db_manager.log_agent_event(
            event_type="order_created",
            ts=datetime.utcnow().isoformat(),
            user_id=str(user_id) if user_id else None,
            agent_username=str(agent) if agent else None,
            order_id=str(order_id),
        )
    except Exception:
        pass
    return {"ok": True}


@app.post("/track/whatsapp-click")
async def track_whatsapp_click(
    request: Request,
    payload: dict = Body(...),
    _: Any = Depends(_optional_rate_limit_track),
):
    """Public endpoint called from the Shopify theme to record WhatsApp icon clicks."""
    try:
        origin = (request.headers.get("origin") or "").strip()
        if TRACK_ALLOWED_ORIGINS and origin:
            try:
                host = (urlparse(origin).hostname or "").lower()
            except Exception:
                host = ""
            allowed = False
            for a in TRACK_ALLOWED_ORIGINS:
                a = (a or "").lower().strip()
                if not a:
                    continue
                try:
                    ahost = (urlparse(a).hostname or "").lower() if "://" in a else a
                except Exception:
                    ahost = a
                if origin.lower() == a or host == ahost or (host and ahost and host.endswith(ahost.lstrip("."))):
                    allowed = True
                    break
            if not allowed:
                raise HTTPException(status_code=403, detail="Origin not allowed")

        page_url = (payload.get("page_url") or payload.get("url") or "").strip() or None
        product_id = (payload.get("product_id") or "").strip() or None
        shop_domain = (payload.get("shop_domain") or payload.get("shop") or "").strip() or None

        ua = (request.headers.get("user-agent") or "").strip() or None
        if ua and len(ua) > 300:
            ua = ua[:300]
        ip = None
        try:
            ip = request.client.host  # type: ignore[union-attr]
        except Exception:
            ip = None
        ip_hash = None
        if ip:
            try:
                ip_hash = hashlib.sha256(f"{TRACK_IP_SALT}|{ip}".encode("utf-8")).hexdigest()[:32]
            except Exception:
                ip_hash = None

        proposed = (payload.get("click_id") or "").strip().lower()
        if proposed and re.fullmatch(r"[a-f0-9]{16,64}", proposed):
            click_id = proposed
        else:
            click_id = uuid.uuid4().hex
        ts = datetime.utcnow().isoformat()
        try:
            await asyncio.wait_for(
                db_manager.log_whatsapp_click(
                    click_id=click_id,
                    ts=ts,
                    page_url=page_url,
                    product_id=product_id,
                    shop_domain=shop_domain,
                    ua=ua,
                    ip_hash=ip_hash,
                ),
                timeout=max(0.2, float(TRACK_DB_TIMEOUT_SECONDS)),
            )
        except Exception:
            # Best-effort only; never block the user from opening WhatsApp.
            pass
        return {"ok": True, "click_id": click_id, "ts": ts}
    except HTTPException:
        raise
    except Exception as exc:
        # Never block the user from opening WhatsApp because analytics failed
        logging.getLogger(__name__).warning("track_whatsapp_click failed: %s", exc)
        return {"ok": False}

@app.get("/messages/{user_id}")
async def get_messages_endpoint(user_id: str, offset: int = 0, limit: int = 50, since: str | None = None, before: str | None = None, actor: dict = Depends(get_current_agent)):
    """Cursor-friendly fetch: use since/before OR legacy offset.

    - since: return messages newer than this timestamp (ascending)
    - before: return messages older than this timestamp (ascending)
    - else: use legacy offset/limit window (ascending)
    """
    try:
        if since:
            return await asyncio.wait_for(
                db_manager.get_messages_since(user_id, since, limit=max(1, min(limit, 500))),
                timeout=max(0.5, float(MESSAGES_DB_TIMEOUT_SECONDS)),
            )
        if before:
            return await asyncio.wait_for(
                db_manager.get_messages_before(user_id, before, limit=max(1, min(limit, 200))),
                timeout=max(0.5, float(MESSAGES_DB_TIMEOUT_SECONDS)),
            )
        # First try to get from cache for the newest window
        if offset == 0:
            cached_messages = await redis_manager.get_recent_messages(user_id, limit)
            if cached_messages:
                return cached_messages
        messages = await asyncio.wait_for(
            db_manager.get_messages(user_id, offset, limit),
            timeout=max(0.5, float(MESSAGES_DB_TIMEOUT_SECONDS)),
        )
        return messages
    except asyncio.TimeoutError:
        # Degrade gracefully: serve cached recent window if available, else return empty quickly.
        try:
            cached_messages = await redis_manager.get_recent_messages(user_id, max(1, min(limit, 200)))
            if cached_messages:
                return cached_messages
        except Exception:
            pass
        return []
    except Exception as e:
        print(f"Error fetching messages: {e}")
        return []

@app.get("/version")
async def get_version():
    try:
        commit = os.getenv("GIT_COMMIT", "")
    except Exception:
        commit = ""
    return {
        "build_id": APP_BUILD_ID,
        "started_at": APP_STARTED_AT,
        **({"commit": commit} if commit else {}),
    }


@app.post("/admin/db/init")
async def admin_init_db(workspace: str | None = None, _: dict = Depends(require_admin)):
    """Admin-only: (re)initialize DB schema for the selected workspace.

    Useful when a new Supabase DB (e.g. NOVA) is added and needs tables created.
    """
    w = _coerce_workspace(workspace or get_current_workspace())
    tok = _CURRENT_WORKSPACE.set(w)
    try:
        await asyncio.wait_for(db_manager.init_db(), timeout=60.0)
        return {
            "ok": True,
            "workspace": w,
            "db": {
                "tenant_db": _safe_db_url_summary(getattr(db_manager, "db_url", None)),
            },
        }
    finally:
        try:
            _CURRENT_WORKSPACE.reset(tok)
        except Exception:
            pass


@app.get("/debug/workspace")
async def debug_workspace(request: Request, _: dict = Depends(require_admin)):
    """Admin-only: show resolved workspace + DB routing info (safe)."""
    ws = get_current_workspace()
    try:
        env_cfg = await message_processor._get_inbox_env(ws)
        allowed_ids = sorted(list((env_cfg or {}).get("allowed_phone_number_ids") or []))[:50]
        survey_tests = sorted(list((env_cfg or {}).get("survey_test_numbers") or []))[:50]
        auto_reply_tests = sorted(list((env_cfg or {}).get("auto_reply_test_numbers") or []))[:50]
    except Exception:
        allowed_ids = sorted(list(ALLOWED_PHONE_NUMBER_IDS or set()))[:50]
        survey_tests = sorted(list(SURVEY_TEST_NUMBERS or set()))[:50]
        auto_reply_tests = sorted(list(AUTO_REPLY_TEST_NUMBERS or set()))[:50]
    return {
        "workspace": ws,
        "multi_workspace": {"enabled": bool(ENABLE_MULTI_WORKSPACE), "workspaces": WORKSPACES, "default": DEFAULT_WORKSPACE},
        "request": {
            "x_workspace": (request.headers.get("x-workspace") or request.headers.get("X-Workspace")),
            "workspace_qp": request.query_params.get("workspace"),
        },
        "db": {
            "tenant_db": _safe_db_url_summary(getattr(db_manager, "db_url", None)),
            "auth_db": _safe_db_url_summary(getattr(auth_db_manager, "db_url", None)),
        },
        "whatsapp": {
            "allowed_phone_number_ids": allowed_ids,
            "phone_id_to_workspace": PHONE_ID_TO_WORKSPACE,
            "survey_test_numbers": survey_tests,
            "auto_reply_test_numbers": auto_reply_tests,
            "nova_phone_number_id_configured": bool((WHATSAPP_CONFIG_BY_WORKSPACE.get("irranova") or {}).get("phone_number_id")),
            "kids_phone_number_id_configured": bool((WHATSAPP_CONFIG_BY_WORKSPACE.get("irrakids") or {}).get("phone_number_id")),
        },
    }


@app.get("/debug/routes")
async def debug_routes(_: dict = Depends(require_admin)):
    """Admin-only: list registered routes (useful to confirm deployed revision exposes expected endpoints)."""
    try:
        routes = []
        for r in getattr(app, "routes", []) or []:
            try:
                path = getattr(r, "path", None)
                methods = sorted(list(getattr(r, "methods", []) or []))
                name = getattr(r, "name", None)
                if path:
                    routes.append({"path": str(path), "methods": methods, "name": str(name or "")})
            except Exception:
                continue
        routes.sort(key=lambda x: x["path"])
        return {
            "build_id": APP_BUILD_ID,
            "started_at": APP_STARTED_AT,
            "shopify_routes_enabled": bool(SHOPIFY_ROUTES_ENABLED),
            "shopify_error": SHOPIFY_ROUTES_ERROR,
            "count": len(routes),
            "routes": routes,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list routes: {exc}")

# After all routes: mount the static folder for any other assets under /static
try:
    app.mount("/static", StaticFiles(directory=str(ROOT_DIR / "frontend" / "build" / "static")), name="static")
except Exception:
    pass

# ----- Agent analytics -----
@app.get("/analytics/inbox/shopify")
async def analytics_shopify_inbox(start: Optional[str] = None, end: Optional[str] = None, bucket: Optional[str] = None, _: dict = Depends(require_admin)):
    # Auto-pick bucket if not provided
    b = (bucket or "").strip().lower()
    if not b:
        try:
            end_dt = datetime.fromisoformat((end or datetime.utcnow().isoformat()).replace("Z", ""))
            start_dt = datetime.fromisoformat((start or (datetime.utcnow() - timedelta(days=30)).isoformat()).replace("Z", ""))
            span = abs((end_dt - start_dt).total_seconds())
            b = "hour" if span <= (3 * 86400) else "day"
        except Exception:
            b = "day"
    # Compute analytics. If the tenant DB hasn't been initialized yet (tables missing),
    # do a one-time init_db() and retry (admin endpoint; safe).
    try:
        return await db_manager.get_shopify_inbox_analytics(start=start, end=end, bucket=b)
    except Exception as exc:
        # Best-effort schema init (covers "relation does not exist" on fresh Postgres workspaces)
        try:
            await db_manager.init_db()
            return await db_manager.get_shopify_inbox_analytics(start=start, end=end, bucket=b)
        except Exception as exc2:
            logging.getLogger(__name__).exception("Shopify inbox analytics failed (workspace=%s)", get_current_workspace())
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Shopify inbox analytics failed",
                    "workspace": get_current_workspace(),
                    "error": str(exc2) or str(exc) or "unknown_error",
                    "hint": "If this persists, open /debug/workspace (admin) to verify DB routing and run /admin/init-db.",
                },
            )

@app.get("/analytics/agents")
async def get_agents_analytics(start: Optional[str] = None, end: Optional[str] = None, _: dict = Depends(require_admin)):
    agents = await auth_db_manager.list_agents()
    results: List[dict] = []
    for a in agents or []:
        username = (a.get("username") or "").strip()
        if not username:
            continue
        stats = await db_manager.get_agent_analytics(agent_username=username, start=start, end=end)
        if a.get("name"):
            try:
                stats["name"] = a.get("name")
            except Exception:
                pass
        results.append(stats)
    return results

@app.get("/analytics/agents/{username}")
async def get_agent_analytics(username: str, start: Optional[str] = None, end: Optional[str] = None, agent: dict = Depends(get_current_agent)):
    # Admins can view anyone; agents can only view themselves.
    if not agent.get("is_admin") and username != agent.get("username"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return await db_manager.get_agent_analytics(agent_username=username, start=start, end=end)

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    if DISABLE_AUTH:
        return RedirectResponse("/#agent=admin")
    try:
        index_path = ROOT_DIR / "frontend" / "build" / "index.html"
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except Exception:
        return RedirectResponse("/")

@app.get("/favicon.ico")
async def favicon():
    try:
        fav = ROOT_DIR / "frontend" / "build" / "favicon.ico"
        if fav.exists():
            return FileResponse(str(fav))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

# PWA assets at the root (CRA build expects these URLs)
@app.get("/sw.js")
async def service_worker():
    try:
        p = ROOT_DIR / "frontend" / "build" / "sw.js"
        if p.exists():
            return FileResponse(str(p))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.get("/manifest.json")
async def manifest():
    try:
        p = ROOT_DIR / "frontend" / "build" / "manifest.json"
        if p.exists():
            return FileResponse(str(p))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.get("/asset-manifest.json")
async def asset_manifest():
    try:
        p = ROOT_DIR / "frontend" / "build" / "asset-manifest.json"
        if p.exists():
            return FileResponse(str(p))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.get("/robots.txt")
async def robots():
    try:
        p = ROOT_DIR / "frontend" / "build" / "robots.txt"
        if p.exists():
            return FileResponse(str(p))
        return PlainTextResponse("User-agent: *\nDisallow:", media_type="text/plain")
    except Exception:
        return PlainTextResponse("User-agent: *\nDisallow:", media_type="text/plain")

@app.get("/logo192.png")
async def logo192():
    try:
        p = ROOT_DIR / "frontend" / "build" / "logo192.png"
        if p.exists():
            return FileResponse(str(p))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.get("/logo512.png")
async def logo512():
    try:
        p = ROOT_DIR / "frontend" / "build" / "logo512.png"
        if p.exists():
            return FileResponse(str(p))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.get("/broken-image.png")
async def broken_image():
    try:
        # CRA build often includes this helper image in the public root.
        p = ROOT_DIR / "frontend" / "build" / "broken-image.png"
        if p.exists():
            return FileResponse(str(p))
        # fallback to public/ for dev (if build not present)
        p2 = ROOT_DIR / "frontend" / "public" / "broken-image.png"
        if p2.exists():
            return FileResponse(str(p2))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.get("/")
async def index_page():
    try:
        build_dir = ROOT_DIR / "frontend" / "build"
        index_path = build_dir / "index.html"
        if not index_path.exists():
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        html = index_path.read_text(encoding="utf-8")
        return HTMLResponse(content=html)
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

# Runtime app configuration for the frontend (allows env-based overrides per workspace)
@app.get("/app-config")
async def app_config(request: Request):
    """
    Lightweight runtime config consumed by the React frontend.

    Supports:
    - Multi-workspace workspace list + labels (for UI workspace switcher)
    - Catalog filter buttons (labels + match rules), optionally workspace-specific

    Workspace-specific overrides:
      - WORKSPACE_LABEL_<WS>
      - WORKSPACE_SHORT_<WS>
      - CATALOG_FILTER_A_LABEL_<WS>, CATALOG_FILTER_A_QUERY_<WS>, CATALOG_FILTER_A_MATCH_<WS>
      - CATALOG_FILTER_B_LABEL_<WS>, CATALOG_FILTER_B_QUERY_<WS>, CATALOG_FILTER_B_MATCH_<WS>
      - CATALOG_FILTER_ALL_LABEL_<WS>

    Global fallbacks (when no workspace-specific overrides are present):
      - WORKSPACE_LABELS="ws1=Label One,ws2=Label Two"
      - WORKSPACE_SHORTS="ws1=ONE,ws2=TWO"
      - CATALOG_FILTER_A_LABEL, CATALOG_FILTER_A_QUERY, CATALOG_FILTER_A_MATCH
      - CATALOG_FILTER_B_LABEL, CATALOG_FILTER_B_QUERY, CATALOG_FILTER_B_MATCH
      - CATALOG_FILTER_ALL_LABEL
    """
    try:
        ws = get_current_workspace()
        # Load admin-managed workspace labels from shared settings DB (best-effort).
        registry_meta: dict[str, dict] = {}
        try:
            raw_reg = await auth_db_manager.get_setting("workspace_registry")
            reg = json.loads(raw_reg) if raw_reg else []
            if isinstance(reg, list):
                for item in reg:
                    if not isinstance(item, dict):
                        continue
                    wid = _normalize_workspace_id(item.get("id") or "")
                    if not wid:
                        continue
                    registry_meta[wid] = {
                        "label": str(item.get("label") or "").strip(),
                        "short": str(item.get("short") or "").strip(),
                    }
                    # Ensure it is accepted for request routing (no redeploy needed)
                    try:
                        if wid not in WORKSPACES:
                            DYNAMIC_WORKSPACES.add(wid)
                    except Exception:
                        pass
        except Exception:
            registry_meta = {}

        def _ws_suffix(w: str) -> str:
            return re.sub(r"[^A-Z0-9]+", "_", str(w or "").strip().upper())

        def _parse_kv_env(var_name: str) -> dict:
            raw = os.getenv(var_name, "") or ""
            out: dict[str, str] = {}
            for part in raw.split(","):
                part = part.strip()
                if not part or "=" not in part:
                    continue
                k, v = part.split("=", 1)
                k = k.strip().lower()
                v = v.strip()
                if k:
                    out[k] = v
            return out

        _labels = _parse_kv_env("WORKSPACE_LABELS")
        _shorts = _parse_kv_env("WORKSPACE_SHORTS")

        def _short_default(label: str, w: str) -> str:
            s = (label or w or "").strip().upper()
            s = re.sub(r"[^A-Z0-9]+", "", s)
            return (s[:4] or (str(w or "").strip().upper()[:4] or "WS"))

        def _workspace_label(w: str) -> str:
            suf = _ws_suffix(w)
            return (
                os.getenv(f"WORKSPACE_LABEL_{suf}", "")
                or str((registry_meta.get(str(w or "").strip().lower()) or {}).get("label") or "").strip()
                or _labels.get(str(w or "").strip().lower(), "")
                or str(w or "").strip().upper()
            )

        def _workspace_short(w: str, label: str) -> str:
            suf = _ws_suffix(w)
            return (
                os.getenv(f"WORKSPACE_SHORT_{suf}", "")
                or str((registry_meta.get(str(w or "").strip().lower()) or {}).get("short") or "").strip()
                or _shorts.get(str(w or "").strip().lower(), "")
                or _short_default(label, w)
            )

        def _env_ws(name: str) -> str:
            suf = _ws_suffix(ws)
            # workspace-specific override first
            v = os.getenv(f"{name}_{suf}", "")
            if v is not None and str(v).strip() != "":
                return str(v)
            return str(os.getenv(name, "") or "")

        def _parse_str_list(raw: Any) -> list[str]:
            """Parse a config value into a list of strings (supports JSON list or comma/newline)."""
            try:
                if raw is None:
                    return []
                if isinstance(raw, list):
                    out = [str(x).strip() for x in raw if str(x or "").strip()]
                else:
                    s = str(raw or "").strip()
                    if not s:
                        return []
                    # If it looks like JSON, try JSON parse first.
                    if (s.startswith("[") and s.endswith("]")) or (s.startswith('"') and s.endswith('"')):
                        try:
                            tmp = json.loads(s)
                            if isinstance(tmp, list):
                                out = [str(x).strip() for x in tmp if str(x or "").strip()]
                            else:
                                out = [str(tmp).strip()] if str(tmp or "").strip() else []
                        except Exception:
                            out = [x.strip() for x in re.split(r"[,\n\r]+", s) if x and x.strip()]
                    else:
                        out = [x.strip() for x in re.split(r"[,\n\r]+", s) if x and x.strip()]
                # De-dup preserving order
                seen: set[str] = set()
                dedup: list[str] = []
                for x in out:
                    k = x.lower()
                    if not k or k in seen:
                        continue
                    seen.add(k)
                    dedup.append(x)
                return dedup
            except Exception:
                return []

        def _read_filter(suffix: str):
            label = _env_ws(f"CATALOG_FILTER_{suffix}_LABEL").strip()
            query = _env_ws(f"CATALOG_FILTER_{suffix}_QUERY").strip()
            match = (_env_ws(f"CATALOG_FILTER_{suffix}_MATCH") or "includes").strip().lower()
            if label and query:
                return {
                    "label": label,
                    "query": query,
                    "match": "startsWith" if match in ("start", "startswith", "starts_with", "startsWith") else "includes",
                }
            return None

        # Prefer DB overrides for catalog filters (admin-managed per workspace).
        db_filters = None
        try:
            raw_cf = await db_manager.get_setting(_ws_setting_key("catalog_filters", ws))
            if (not raw_cf) and ws == _coerce_workspace(DEFAULT_WORKSPACE):
                raw_cf = await db_manager.get_setting("catalog_filters")
            tmp = json.loads(raw_cf) if raw_cf else None
            if isinstance(tmp, list) and len(tmp) >= 2:
                db_filters = tmp
        except Exception:
            db_filters = None

        if db_filters:
            filters = db_filters
        else:
            fA = _read_filter("A") or {"label": "Girls", "query": "girls", "match": "includes"}
            fB = _read_filter("B") or {"label": "Boys", "query": "boys", "match": "includes"}
            fall_label = (_env_ws("CATALOG_FILTER_ALL_LABEL") or "All").strip() or "All"
            fall = {"label": fall_label, "type": "all"}
            filters = [fA, fB, fall]

        ws_list = []
        for w in sorted(list(_all_workspaces_set() | set(registry_meta.keys()))):
            ww = _normalize_workspace_id(w)
            if not ww:
                continue
            label = _workspace_label(ww)
            ws_list.append({"id": ww, "label": label, "short": _workspace_short(ww, label)})

        # Delivery app statuses for Automation Studio (used to render a dropdown/multi-select).
        # Sources (priority):
        # - DB setting delivery_statuses::<workspace>
        # - DB setting delivery_statuses (default workspace fallback)
        # - env DELIVERY_STATUSES_<WS> or DELIVERY_STATUSES (comma/newline or JSON list)
        delivery_statuses: list[str] = []
        try:
            raw_ds = await db_manager.get_setting(_ws_setting_key("delivery_statuses", ws))
            if (not raw_ds) and ws == _coerce_workspace(DEFAULT_WORKSPACE):
                raw_ds = await db_manager.get_setting("delivery_statuses")
            delivery_statuses = _parse_str_list(raw_ds)
        except Exception:
            delivery_statuses = []
        if not delivery_statuses:
            try:
                delivery_statuses = _parse_str_list(_env_ws("DELIVERY_STATUSES"))
            except Exception:
                delivery_statuses = []
        # Safe fallback: ship with a sane default list so the UI dropdown isn't empty.
        # Override via DB/env as needed per deployment.
        if not delivery_statuses:
            delivery_statuses = [
                "Dispatched",
                "Livré",
                "Paid",
                "En cours",
                "Pas de réponse 1",
                "Pas de réponse 2",
                "Pas de réponse 3",
                "Annulé",
                "Refusé",
                "Rescheduled",
                "Returned",
                "Deleted",
            ]

        return {
            "workspace": ws,
            "defaultWorkspace": DEFAULT_WORKSPACE,
            "workspaces": ws_list,
            "catalogFilters": filters,
            "delivery_statuses": delivery_statuses,
        }
    except Exception:
        # Safe defaults on any failure
        try:
            ws = get_current_workspace()
        except Exception:
            ws = DEFAULT_WORKSPACE
        return {
            "workspace": ws,
            "defaultWorkspace": DEFAULT_WORKSPACE,
            "workspaces": [{"id": w, "label": str(w).upper(), "short": str(w).upper()[:4]} for w in (WORKSPACES or [DEFAULT_WORKSPACE])],
            "catalogFilters": [
                {"label": "Girls", "query": "girls", "match": "includes"},
                {"label": "Boys", "query": "boys", "match": "includes"},
                {"label": "All", "type": "all"},
            ],
            "delivery_statuses": [],
        }

# Serve hashed main bundle filenames for safety even if HTML references are stale
@app.get("/static/js/{filename}")
async def serve_js(filename: str):
    try:
        js_path = ROOT_DIR / "frontend" / "build" / "static" / "js" / filename
        if js_path.exists():
            return FileResponse(str(js_path))
        # Best-effort: fallback to the current main bundle if name changed
        manifest = ROOT_DIR / "frontend" / "build" / "asset-manifest.json"
        if manifest.exists():
            import json as _json
            data = _json.loads(manifest.read_text(encoding="utf-8"))
            main_rel = (data.get("files", {}) or {}).get("main.js")
            if main_rel:
                target = ROOT_DIR / "frontend" / "build" / main_rel.lstrip("/")
                if target.exists():
                    return FileResponse(str(target))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.get("/static/css/{filename}")
async def serve_css(filename: str):
    try:
        css_path = ROOT_DIR / "frontend" / "build" / "static" / "css" / filename
        if css_path.exists():
            return FileResponse(str(css_path))
        # Fallback to current main css from manifest
        manifest = ROOT_DIR / "frontend" / "build" / "asset-manifest.json"
        if manifest.exists():
            import json as _json
            data = _json.loads(manifest.read_text(encoding="utf-8"))
            main_rel = (data.get("files", {}) or {}).get("main.css")
            if main_rel:
                target = ROOT_DIR / "frontend" / "build" / main_rel.lstrip("/")
                if target.exists():
                    return FileResponse(str(target))
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

@app.post("/send-media")
async def send_media(
    user_id: str = Form(...),
    media_type: str = Form(...),
    files: List[UploadFile] = File(...),
    caption: str = Form("", description="Optional caption"),
    price: str = Form("", description="Optional price"),
    _: None = Depends(_optional_rate_limit_media),
):
    """Send media message with proper error handling, plus WebM → OGG conversion"""

    try:
        # ---------- basic validation ----------
        if not user_id:
            return {"error": "user_id is required", "status": "failed"}

        if media_type not in ["image", "audio", "video", "document"]:
            return {
                "error": "Invalid media_type. Must be: image, audio, video, or document",
                "status": "failed",
            }

        if not files:
            return {"error": "No files uploaded", "status": "failed"}

        # ---------- ensure media folder ----------
        media_dir = MEDIA_DIR
        media_dir.mkdir(exist_ok=True)

        saved_results = []

        # ---------- process every uploaded file ----------
        for file in files:
            if not file.filename:
                continue

            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            file_extension = Path(file.filename).suffix or ".bin"
            filename = f"{media_type}_{timestamp}_{uuid.uuid4().hex[:8]}{file_extension}"
            file_path = media_dir / filename

            # --- save the raw upload ---
            try:
                content = await file.read()
                async with aiofiles.open(file_path, "wb") as f:
                    await f.write(content)
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Failed to save file: {exc}")

            # ---------- AUDIO-ONLY: reject non-mono at edge ----------
            if media_type == "audio":
                try:
                    ch = await probe_audio_channels(file_path)
                    if ch and ch != 1:
                        raise HTTPException(status_code=400, detail="Only mono audio is supported for WhatsApp voice notes. Please record in mono and try again.")
                except HTTPException:
                    raise
                except Exception:
                    # If probing fails, continue – conversion will enforce mono
                    pass

            # ---------- AUDIO: re-encode WebM → OGG/Opus 48k mono (skip if already OGG) ----------
            if media_type == "audio":
                try:
                    ext = (Path(file.filename).suffix or file_extension or "").lower()
                    ctype = (getattr(file, "content_type", None) or "").lower()
                    needs_convert = (ext in (".webm", ".weba")) or ("webm" in ctype)
                    if needs_convert:
                        ogg_path = await convert_webm_to_ogg(file_path)
                        try:
                            file_path.unlink(missing_ok=True)  # delete original
                        except Exception:
                            pass
                        file_path = ogg_path
                        filename = ogg_path.name
                except Exception as exc:
                    raise HTTPException(status_code=500, detail=f"Audio conversion failed: {exc}")

            # ---------- audio: compute waveform before upload ----------
            audio_waveform: list[int] | None = None
            if media_type == "audio":
                try:
                    audio_waveform = await compute_audio_waveform(file_path, buckets=56)
                except Exception:
                    audio_waveform = None

            # ---------- upload to Google Cloud Storage ----------
            media_url = await upload_file_to_gcs(
                str(file_path)
            )

            # Build message payload using the public GCS URL instead of a local path
            message_data = {
                "user_id": user_id,
                "message": media_url,
                "url": media_url,
                "type": media_type,
                "from_me": True,
                "caption": caption,
                "price": price,
                "timestamp": datetime.utcnow().isoformat(),
                # Keep absolute path for internal processing/sending to WhatsApp
                "media_path": str(file_path),
                **({"waveform": audio_waveform} if audio_waveform else {}),
            }

            # ---------- enqueue / send ----------
            result = await message_processor.process_outgoing_message(message_data)
            saved_results.append(
                {"filename": filename, "media_url": media_url, "result": result}
            )

        return {"status": "success", "messages": saved_results}

    except HTTPException:
        # Propagate HTTP errors to the client
        raise
    except Exception as exc:
        print(f"❌ Error in /send-media: {exc}")
        return {"error": f"Internal server error: {exc}", "status": "failed"}


@app.post("/send-media-async", status_code=202)
async def send_media_async(
    user_id: str = Form(...),
    media_type: str = Form(...),
    files: List[UploadFile] = File(...),
    caption: str = Form("", description="Optional caption"),
    price: str = Form("", description="Optional price"),
    temp_id: str | None = Form(None),
    _: None = Depends(_optional_rate_limit_media),
):
    """Accept media quickly and process in background. UI updates via WebSocket.

    This endpoint avoids synchronous transcode/upload to keep p95 low under bursts.
    """
    try:
        if not user_id:
            return {"error": "user_id is required", "status": "failed"}
        if media_type not in ["image", "audio", "video", "document"]:
            return {"error": "Invalid media_type. Must be: image, audio, video, or document", "status": "failed"}
        if not files:
            return {"error": "No files uploaded", "status": "failed"}

        media_dir = MEDIA_DIR
        media_dir.mkdir(exist_ok=True)

        accepted: List[dict] = []
        for file in files:
            if not file.filename:
                continue
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            file_extension = Path(file.filename).suffix or ".bin"
            filename = f"{media_type}_{timestamp}_{uuid.uuid4().hex[:8]}{file_extension}"
            file_path = media_dir / filename
            # Save immediately and schedule processing
            content = await file.read()
            async with aiofiles.open(file_path, "wb") as f:
                await f.write(content)

            # ---------- AUDIO-ONLY: reject non-mono at edge ----------
            if media_type == "audio":
                try:
                    ch = await probe_audio_channels(file_path)
                    if ch and ch != 1:
                        raise HTTPException(status_code=400, detail="Only mono audio is supported for WhatsApp voice notes. Please record in mono and try again.")
                except HTTPException:
                    raise
                except Exception:
                    pass

            # ---------- AUDIO: re-encode WebM → OGG/Opus 48k mono (skip if already OGG) ----------
            if media_type == "audio":
                try:
                    ext = (Path(file.filename).suffix or file_extension or "").lower()
                    ctype = (getattr(file, "content_type", None) or "").lower()
                    needs_convert = (ext in (".webm", ".weba")) or ("webm" in ctype)
                    if needs_convert:
                        ogg_path = await convert_webm_to_ogg(file_path)
                        try:
                            file_path.unlink(missing_ok=True)
                        except Exception:
                            pass
                        file_path = ogg_path
                except Exception as exc:
                    raise HTTPException(status_code=500, detail=f"Audio conversion failed: {exc}")

            optimistic_payload = {
                "user_id": user_id,
                "message": str(file_path),
                "url": str(file_path),
                "type": media_type,
                "from_me": True,
                "caption": caption,
                "price": price,
                "timestamp": datetime.utcnow().isoformat(),
                "media_path": str(file_path),
            }
            if temp_id:
                optimistic_payload["temp_id"] = temp_id

            asyncio.create_task(message_processor.process_outgoing_message(optimistic_payload))
            accepted.append({"filename": filename, **({"temp_id": temp_id} if temp_id else {})})

        return {"status": "accepted", "accepted": accepted}
    except HTTPException:
        raise
    except Exception as exc:
        print(f"❌ Error in /send-media-async: {exc}")
        return {"error": f"Internal server error: {exc}", "status": "failed"}

@app.post("/send-catalog-set")
async def send_catalog_set_endpoint(
    user_id: str = Form(...),
    product_ids: str = Form(...),
    _: None = Depends(_optional_rate_limit_text),
):
    try:
        product_id_list = json.loads(product_ids)
        customer_phone = await lookup_phone(user_id) or user_id
        results = await messenger.send_catalog_products(customer_phone, product_id_list)
        return {"status": "ok", "results": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/send-catalog-item")
async def send_catalog_item_endpoint(
    user_id: str = Form(...),
    product_retailer_id: str = Form(...),
    caption: str = Form(""),
    _: None = Depends(_optional_rate_limit_text),
):
    customer_phone = await lookup_phone(user_id) or user_id
    cid = await _get_effective_catalog_id(get_current_workspace())
    response = await messenger.send_single_catalog_item(customer_phone, product_retailer_id, caption, catalog_id=cid)
    return {"status": "ok", "response": response}


@app.post("/send-catalog-all")
async def send_catalog_all_endpoint(
    user_id: str = Form(...),
    caption: str = Form(""),
    _: None = Depends(_optional_rate_limit_text),
):
    customer_phone = await lookup_phone(user_id) or user_id
    results = await messenger.send_full_catalog(customer_phone, caption)
    return {"status": "ok", "results": results}


@app.post("/send-catalog-set-all")
async def send_catalog_set_all_endpoint(
    background_tasks: BackgroundTasks,
    user_id: str = Form(...),
    set_id: str = Form(...),
    caption: str = Form(""),
    _: None = Depends(_optional_rate_limit_text),
):
    customer_phone = await lookup_phone(user_id) or user_id
    job_id = str(uuid.uuid4())
    # Emit optimistic message immediately for instant UI feedback
    temp_id = f"temp_{uuid.uuid4().hex}"
    timestamp = datetime.now(timezone.utc).isoformat()
    optimistic_record = {
        "id": temp_id,
        "temp_id": temp_id,
        "user_id": user_id,
        "message": caption or f"Catalog set {set_id}",
        "type": "catalog_set",
        "from_me": True,
        "status": "sending",
        "timestamp": timestamp,
        "caption": caption,
    }
    await redis_manager.cache_message(user_id, optimistic_record)
    await connection_manager.send_to_user(
        user_id, {"type": "message_sent", "data": optimistic_record}
    )

    async def run_send_full_set():
        try:
            await messenger.send_full_set(customer_phone, set_id, caption)
            print(f"Successfully sent catalog set {set_id} to {customer_phone}")
            # Update UI status to 'sent' and persist
            await connection_manager.send_to_user(
                user_id,
                {"type": "message_status_update", "data": {"temp_id": temp_id, "status": "sent"}},
            )
            final_record = {**optimistic_record, "status": "sent"}
            await db_manager.upsert_message(final_record)
            await redis_manager.cache_message(user_id, final_record)
        except Exception as exc:
            error_message = f"Error sending catalog set {set_id} to {customer_phone}: {exc}"
            print(error_message)
            await connection_manager.send_to_user(
                user_id,
                {
                    "type": "catalog_set_send_error",
                    "job_id": job_id,
                    "error": str(exc),
                },
            )

    background_tasks.add_task(run_send_full_set)
    return {"status": "started", "job_id": job_id}


@app.get("/catalog-sets")
async def get_catalog_sets():
    try:
        ws = get_current_workspace()
        cid = await _get_effective_catalog_id(ws)
        sets = await CatalogManager.get_catalog_sets(catalog_id=cid)
        return sets
    except Exception as exc:
        print(f"Error fetching catalog sets: {exc}")
        # Fallback to All Products
        try:
            ws = get_current_workspace()
            cid = await _get_effective_catalog_id(ws)
        except Exception:
            cid = str(CATALOG_ID or "").strip()
        return [{"id": cid, "name": "All Products"}]


@app.get("/catalog-all-products")
async def get_catalog_products_endpoint(force_refresh: bool = False, background_tasks: BackgroundTasks = None):
    """Return cached catalog products quickly.

    Important: do NOT block this endpoint on a full remote refresh (can exceed Cloud Run timeouts),
    instead trigger a background refresh and serve stale cache immediately.
    """
    ws = get_current_workspace()
    cid = await _get_effective_catalog_id(ws)
    cache_file = _catalog_cache_file_for(ws, cid)

    # Refresh cache if forced or stale/missing; otherwise serve cached for speed
    need_refresh = bool(force_refresh)
    try:
        if not os.path.exists(cache_file):
            need_refresh = True
        else:
            import time as _time
            age_sec = _time.time() - os.path.getmtime(cache_file)
            if age_sec > CATALOG_CACHE_TTL_SEC:
                need_refresh = True
    except Exception:
        need_refresh = True

    if need_refresh:
        try:
            # Fire-and-forget refresh to avoid request timeouts.
            if background_tasks is not None:
                background_tasks.add_task(catalog_manager.refresh_catalog_cache, cid, cache_file)
            else:
                asyncio.create_task(catalog_manager.refresh_catalog_cache(cid, cache_file))
        except Exception as exc:
            logging.getLogger(__name__).warning("Catalog cache refresh scheduling failed: %s", exc)

    # Always serve current cache (may be stale, but fast).
    return catalog_manager.get_cached_products(cache_file=cache_file) or []


@app.get("/catalog-set-products")
async def get_catalog_set_products(set_id: str, limit: int = 60):
    """Return products for the requested set (or full catalog)."""
    try:
        ws = get_current_workspace()
        cid = await _get_effective_catalog_id(ws)
        cache_file = _catalog_cache_file_for(ws, cid)
        products = await CatalogManager.get_products_for_set(set_id, limit=limit, catalog_id=cid, cache_file=cache_file)
        print(f"Catalog: returning {len(products)} products for set_id={set_id}")
        return products
    except Exception as exc:
        print(f"Error fetching set products: {exc}")
        return []

@app.api_route("/refresh-catalog-cache", methods=["GET", "POST"])
async def refresh_catalog_cache_endpoint(background_tasks: BackgroundTasks):
    # Kick off a background refresh to avoid request timeouts
    ws = get_current_workspace()
    cid = await _get_effective_catalog_id(ws)
    cache_file = _catalog_cache_file_for(ws, cid)
    background_tasks.add_task(catalog_manager.refresh_catalog_cache, cid, cache_file)
    return {"status": "started", "workspace": ws, "catalog_id": cid}


@app.get("/all-catalog-products")
async def get_all_catalog_products():
    try:
        ws = get_current_workspace()
        cid = await _get_effective_catalog_id(ws)
        products = await CatalogManager.get_catalog_products(catalog_id=cid)
        return products
    except Exception as e:
        print(f"Error fetching catalog: {e}")
        return []


@app.get("/proxy-audio")
async def proxy_audio(url: str, request: StarletteRequest):
    """Proxy/redirect remote audio with Range support.

    Prefer 302 redirect to a short‑lived GCS signed URL when possible (direct CDN
    delivery, best for scale). Fallback to streaming proxy with Range pass-through.
    Important when streaming: keep the upstream httpx response open until done.
    """
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid url")
    try:
        # Try to redirect to a signed GCS URL if applicable (only if object exists)
        signed = maybe_signed_url_for(url, ttl_seconds=600)
        if signed:
            try:
                # Lightweight existence check to avoid redirecting to GCS 403 when bucket is private but URL is wrong
                bucket, blob = _parse_gcs_url(url)
                if bucket and blob:
                    client = _get_client()
                    if client.bucket(bucket).blob(blob).exists():
                        return RedirectResponse(url=signed, status_code=302)
            except Exception:
                # If anything goes wrong, fall back to proxying
                pass

        range_header = request.headers.get("range") or request.headers.get("Range")

        # If the URL is a GCS object and signing failed, stream directly via GCS SDK with auth
        bucket_name, blob_name = _parse_gcs_url(url)
        if bucket_name and blob_name:
            try:
                client_gcs = _get_client()
                bucket = client_gcs.bucket(bucket_name)
                blob = bucket.blob(blob_name)
                # Ensure metadata loaded
                try:
                    blob.reload()
                except Exception:
                    pass
                size = getattr(blob, "size", None)
                ctype = blob.content_type or "audio/ogg"

                # Parse Range header (single range only)
                start = end = None
                if range_header and range_header.lower().startswith("bytes="):
                    try:
                        r = range_header.split("=", 1)[1]
                        s, e = (r.split("-", 1) + [""])[:2]
                        start = int(s) if s else None
                        end = int(e) if e else None
                    except Exception:
                        start = end = None

                if start is not None and size is not None:
                    end = end if end is not None else int(size) - 1
                    data = blob.download_as_bytes(start=start, end=end)
                    headers = {
                        "Accept-Ranges": "bytes",
                        "Content-Range": f"bytes {start}-{end}/{size}",
                        "Content-Length": str(len(data)),
                        "Cache-Control": "public, max-age=86400",
                    }
                    return StarletteResponse(content=data, media_type=ctype, headers=headers, status_code=206)
                else:
                    # Full download (small files) – return 200
                    data = blob.download_as_bytes()
                    headers = {
                        "Accept-Ranges": "bytes",
                        "Content-Length": str(len(data)),
                        "Cache-Control": "public, max-age=86400",
                    }
                    return StarletteResponse(content=data, media_type=ctype, headers=headers, status_code=200)
            except Exception:
                # Fall back to HTTP proxy below
                pass

        fwd_headers = {"User-Agent": "Mozilla/5.0"}
        if range_header:
            fwd_headers["Range"] = range_header

        timeout = httpx.Timeout(connect=10.0, read=120.0, write=120.0, pool=30.0)
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        req = client.build_request("GET", url, headers=fwd_headers)
        resp = await client.send(req, stream=True)

        status_code = resp.status_code
        media_type = resp.headers.get("Content-Type", "audio/ogg")
        passthrough = {"Cache-Control": "public, max-age=86400"}
        for h in ("Content-Length", "Content-Range", "Accept-Ranges"):
            v = resp.headers.get(h)
            if v:
                passthrough[h] = v
        if "Accept-Ranges" not in passthrough:
            passthrough["Accept-Ranges"] = "bytes"

        async def body_iter():
            try:
                async for chunk in resp.aiter_bytes():
                    if chunk:
                        yield chunk
            finally:
                try:
                    await resp.aclose()
                finally:
                    await client.aclose()

        return StreamingResponse(body_iter(), status_code=status_code, media_type=media_type, headers=passthrough)
    except Exception as exc:
        print(f"Proxy audio error: {exc}")
        raise HTTPException(status_code=502, detail="Proxy fetch failed")


@app.get("/proxy-image")
async def proxy_image(request: Request, url: str, w: int | None = None, q: int | None = None):
    """Proxy/redirect images.

    Prefer 302 redirect to signed GCS URL when our bucket; otherwise fetch and
    return bytes (to avoid CORS and allow caching via our domain).
    """
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid url")
    # Public access is ONLY allowed for safe, whitelisted hosts (e.g., Shopify CDN).
    # Any other host requires a valid app auth token, to avoid turning this into an open proxy
    # and to avoid accidentally exposing private GCS objects via server credentials.
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except Exception:
        host = ""
    # Allow Shopify CDN images without auth (catalog thumbnails in <img> tags don't carry Authorization headers).
    PUBLIC_PROXY_IMAGE_HOSTS = ("cdn.shopify.com",)
    is_public_host = any(host == h or host.endswith("." + h) for h in PUBLIC_PROXY_IMAGE_HOSTS)
    if not is_public_host:
        agent = _maybe_get_agent_from_request(request)
        if not agent:
            raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        # Encourage long-lived caching of successful thumbnails, and avoid caching error responses.
        DEFAULT_OK_CACHE_CONTROL = "public, max-age=86400, stale-while-revalidate=600, stale-if-error=86400"
        signed = maybe_signed_url_for(url, ttl_seconds=600)
        # Only redirect to signed URL when not resizing
        if signed and not w:
            try:
                bucket, blob = _parse_gcs_url(url)
                if bucket and blob:
                    client = _get_client()
                    if client.bucket(bucket).blob(blob).exists():
                        return RedirectResponse(url=signed, status_code=302)
            except Exception:
                pass
        # If GCS signed URL isn't available, attempt authenticated fetch via GCS SDK
        bucket_name, blob_name = _parse_gcs_url(url)
        if bucket_name and blob_name:
            try:
                client_gcs = _get_client()
                bucket = client_gcs.bucket(bucket_name)
                blob = bucket.blob(blob_name)
                try:
                    blob.reload()
                except Exception:
                    pass
                data = blob.download_as_bytes()
                ctype = blob.content_type or "image/jpeg"
                # If a thumbnail width is requested, downscale on the fly
                if w and isinstance(w, int) and w > 0:
                    try:
                        quality = int(q) if q is not None else 72
                        quality = max(40, min(92, quality))
                        im = Image.open(io.BytesIO(data))
                        im = im.convert("RGB")
                        # Contain within width, preserve aspect ratio
                        im = ImageOps.contain(im, (int(w), int(w) * 10))
                        buf = io.BytesIO()
                        im.save(buf, format="JPEG", quality=quality, optimize=True)
                        thumb_bytes = buf.getvalue()
                        return StarletteResponse(
                            content=thumb_bytes,
                            media_type="image/jpeg",
                            headers={
                                "Cache-Control": DEFAULT_OK_CACHE_CONTROL,
                            },
                        )
                    except Exception:
                        # Fall back to original if resize fails
                        pass
                return StarletteResponse(
                    content=data,
                    media_type=ctype,
                    headers={
                        "Cache-Control": DEFAULT_OK_CACHE_CONTROL,
                    },
                )
            except Exception:
                # Fall back to generic HTTP fetch below
                pass
        # Clamp resizing parameters to avoid excessive CPU/memory usage per request.
        if w is not None:
            try:
                w = int(w)
            except Exception:
                w = None
            if w is not None:
                w = max(1, min(1024, w))
        if q is not None:
            try:
                q = int(q)
            except Exception:
                q = None
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        media_type = resp.headers.get("Content-Type", "image/jpeg")
        # Forward upstream status code and caching headers to enable proper browser caching/conditional requests
        passthrough: dict[str, str] = {}
        if resp.status_code >= 400:
            # Never cache rate limit / error pages; otherwise clients can get stuck until cache expiry.
            passthrough["Cache-Control"] = "no-store"
        else:
            passthrough["Cache-Control"] = resp.headers.get("Cache-Control") or DEFAULT_OK_CACHE_CONTROL
        # Only forward Vary if upstream explicitly sets it (do NOT force Vary: Accept,
        # because our resized thumbnails don't vary by Accept and it breaks SW/browser cache hits).
        try:
            vary = resp.headers.get("Vary")
            if vary:
                passthrough["Vary"] = vary
        except Exception:
            pass
        for h in ("ETag", "Last-Modified", "Content-Length"):
            v = resp.headers.get(h)
            if v:
                passthrough[h] = v
        # If resize requested and content seems image-like, attempt downscale
        if w and isinstance(w, int) and w > 0 and ("image" in media_type or media_type.startswith("application/octet-stream")) and resp.status_code < 400:
            try:
                quality = int(q) if q is not None else 72
                quality = max(40, min(92, quality))
                im = Image.open(io.BytesIO(resp.content))
                im = im.convert("RGB")
                im = ImageOps.contain(im, (int(w), int(w) * 10))
                buf = io.BytesIO()
                im.save(buf, format="JPEG", quality=quality, optimize=True)
                thumb_bytes = buf.getvalue()
                # Remove upstream length since content length changed
                passthrough.pop("Content-Length", None)
                # Resized thumbnails are always JPEG and do not depend on request headers
                passthrough.pop("Vary", None)
                return StarletteResponse(
                    content=thumb_bytes,
                    media_type="image/jpeg",
                    headers=passthrough,
                    status_code=200,
                )
            except Exception:
                # Fall back to original bytes on failure
                pass
        return StarletteResponse(
            content=resp.content,
            media_type=media_type,
            headers=passthrough,
            status_code=resp.status_code,
        )
    except Exception as exc:
        print(f"Proxy image error: {exc}")
        raise HTTPException(status_code=502, detail="Proxy fetch failed")


@app.get("/proxy-media")
async def proxy_media(url: str, request: StarletteRequest):
    """Generic media proxy for videos/documents with signed redirect when possible.

    - If GCS: redirect to V4 signed URL (302) for direct CDN delivery with Range.
    - Else: stream with Range pass-through like proxy_audio.
    """
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid url")
    try:
        signed = maybe_signed_url_for(url, ttl_seconds=600)
        if signed:
            try:
                bucket, blob = _parse_gcs_url(url)
                if bucket and blob:
                    client_gcs = _get_client()
                    if client_gcs.bucket(bucket).blob(blob).exists():
                        return RedirectResponse(url=signed, status_code=302)
            except Exception:
                pass

        # GCS authenticated streaming fallback
        range_header = request.headers.get("range") or request.headers.get("Range")
        bucket_name, blob_name = _parse_gcs_url(url)
        if bucket_name and blob_name:
            try:
                client_gcs = _get_client()
                bucket = client_gcs.bucket(bucket_name)
                blob = bucket.blob(blob_name)
                try:
                    blob.reload()
                except Exception:
                    pass
                size = getattr(blob, "size", None)
                ctype = blob.content_type or "application/octet-stream"

                start = end = None
                if range_header and range_header.lower().startswith("bytes="):
                    try:
                        r = range_header.split("=", 1)[1]
                        s, e = (r.split("-", 1) + [""])[:2]
                        start = int(s) if s else None
                        end = int(e) if e else None
                    except Exception:
                        start = end = None
                if start is not None and size is not None:
                    end = end if end is not None else int(size) - 1
                    data = blob.download_as_bytes(start=start, end=end)
                    headers = {
                        "Accept-Ranges": "bytes",
                        "Content-Range": f"bytes {start}-{end}/{size}",
                        "Content-Length": str(len(data)),
                        "Cache-Control": "public, max-age=86400",
                    }
                    return StarletteResponse(content=data, media_type=ctype, headers=headers, status_code=206)
                else:
                    data = blob.download_as_bytes()
                    headers = {
                        "Accept-Ranges": "bytes",
                        "Content-Length": str(len(data)),
                        "Cache-Control": "public, max-age=86400",
                    }
                    return StarletteResponse(content=data, media_type=ctype, headers=headers, status_code=200)
            except Exception:
                pass

        # Generic HTTP proxy fallback
        fwd_headers = {"User-Agent": "Mozilla/5.0"}
        if range_header:
            fwd_headers["Range"] = range_header
        timeout = httpx.Timeout(connect=10.0, read=120.0, write=120.0, pool=30.0)
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        req = client.build_request("GET", url, headers=fwd_headers)
        resp = await client.send(req, stream=True)

        status_code = resp.status_code
        media_type = resp.headers.get("Content-Type", "application/octet-stream")
        passthrough = {"Cache-Control": "public, max-age=86400"}
        for h in ("Content-Length", "Content-Range", "Accept-Ranges"):
            v = resp.headers.get(h)
            if v:
                passthrough[h] = v
        if "Accept-Ranges" not in passthrough:
            passthrough["Accept-Ranges"] = "bytes"

        async def body_iter():
            try:
                async for chunk in resp.aiter_bytes():
                    if chunk:
                        yield chunk
            finally:
                try:
                    await resp.aclose()
                finally:
                    await client.aclose()

        return StreamingResponse(body_iter(), status_code=status_code, media_type=media_type, headers=passthrough)
    except Exception as exc:
        print(f"Proxy media error: {exc}")
        raise HTTPException(status_code=502, detail="Proxy fetch failed")

# Lightweight link preview endpoint to extract OG metadata (title/image)
@app.get("/link-preview")
async def link_preview(url: str):
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid url")
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        html = resp.text or ""
        # Local import to avoid global dependency if unused on cold paths
        try:
            from bs4 import BeautifulSoup  # type: ignore
        except Exception:
            BeautifulSoup = None  # type: ignore
        title = ""
        description = ""
        image = ""
        if html and BeautifulSoup is not None:
            soup = BeautifulSoup(html, "html.parser")
            def get_meta(name: str):
                tag = soup.find("meta", {"property": name}) or soup.find("meta", {"name": name})
                return (tag.get("content") or "").strip() if tag else ""
            title = get_meta("og:title") or (soup.title.string.strip() if getattr(soup, "title", None) and getattr(soup.title, "string", None) else "")
            description = get_meta("og:description") or get_meta("description")
            image = get_meta("og:image") or get_meta("twitter:image")

        # Encourage browser/proxy caching to avoid repeated refetches
        headers = {
            "Cache-Control": "public, max-age=3600, stale-while-revalidate=60",
            "Vary": "Accept",
        }
        return JSONResponse(content={"url": url, "title": title, "description": description, "image": image}, headers=headers)
    except Exception as exc:
        print(f"Link preview error: {exc}")
        raise HTTPException(status_code=502, detail="Preview fetch failed")

META_CATALOG_URL = f"https://graph.facebook.com/v19.0/{CATALOG_ID}/products"

async def fetch_meta_catalog():
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(META_CATALOG_URL, headers=headers)
        response.raise_for_status()
        return response.json().get("data", [])


async def get_whatsapp_headers() -> Dict[str, str]:
    """Return auth headers for WhatsApp API"""
    return {"Authorization": f"Bearer {ACCESS_TOKEN}"}


class CatalogManager:
    # Simple in-memory cache for set products to speed up responses
    _SET_CACHE: dict[str, list[Dict[str, Any]]] = {}
    _SET_CACHE_TS: dict[str, float] = {}
    _SET_CACHE_TTL_SEC: int = 15 * 60

    @staticmethod
    def _set_cache_filename(set_id: str, catalog_id: str | None = None) -> str:
        # Include catalog_id to avoid cross-workspace collisions if different catalogs reuse set ids.
        cid = _safe_cache_token(catalog_id or "")
        sid = _safe_cache_token(set_id)
        return f"catalog_{cid + '_' if cid else ''}set_{sid}.json"

    @staticmethod
    def _load_persisted_set(set_id: str, catalog_id: str | None = None) -> list[dict]:
        """Load a persisted set cache from local disk or GCS if present."""
        filename = CatalogManager._set_cache_filename(set_id, catalog_id=catalog_id)
        try:
            if not os.path.exists(filename):
                try:
                    download_file_from_gcs(filename, filename)
                except Exception:
                    return []
            if os.path.getsize(filename) == 0:
                return []
            with open(filename, "r", encoding="utf8") as f:
                data = json.load(f)
            # Normalize
            return [CatalogManager._format_product(p) for p in data if CatalogManager._is_product_available(p)]
        except Exception:
            return []

    @staticmethod
    async def _persist_set_async(set_id: str, products: list[dict], catalog_id: str | None = None) -> None:
        """Persist set products to local disk and upload to GCS (best-effort)."""
        filename = CatalogManager._set_cache_filename(set_id, catalog_id=catalog_id)
        try:
            with open(filename, "w", encoding="utf8") as f:
                json.dump(products, f, ensure_ascii=False)
            try:
                await upload_file_to_gcs(filename)
            except Exception:
                pass
        except Exception:
            pass

    @staticmethod
    async def get_catalog_sets(catalog_id: str | None = None) -> List[Dict[str, Any]]:
        """Return available product sets (collections) for the configured catalog.

        Graph API: /{catalog_id}/product_sets?fields=id,name
        """
        cid = str(catalog_id or CATALOG_ID or "").strip()
        url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{cid}/product_sets"
        params = {"fields": "id,name", "limit": 200}
        headers = await get_whatsapp_headers()

        # Always include the whole catalog as a fallback option
        result: List[Dict[str, Any]] = [{"id": cid, "name": "All Products"}]
        seen: set[str] = {cid}

        async with httpx.AsyncClient(timeout=30.0) as client:
            while url:
                response = await client.get(url, headers=headers, params=params)
                data = response.json()
                sets = data.get("data", [])
                for s in sets:
                    try:
                        sid = str(s.get("id"))
                        name = s.get("name")
                        if sid and name and sid not in seen:
                            seen.add(sid)
                            result.append({"id": sid, "name": name})
                    except Exception:
                        continue
                # Follow pagination if present
                url = data.get("paging", {}).get("next")
                params = None
        return result

    @staticmethod
    async def get_catalog_products(catalog_id: str | None = None) -> List[Dict[str, Any]]:
        products: List[Dict[str, Any]] = []
        cid = str(catalog_id or CATALOG_ID or "").strip()
        url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{cid}/products"
        params = {
            # Ask Graph for image URLs explicitly to ensure we receive usable links
            "fields": "retailer_id,name,price,images{url},availability,quantity",
            "limit": 25,
        }
        headers = await get_whatsapp_headers()

        async with httpx.AsyncClient(timeout=40.0) as client:
            while url:
                response = await client.get(url, headers=headers, params=params if params else None)
                data = response.json()
                for product in data.get("data", []):
                    if CatalogManager._is_product_available(product):
                        products.append(CatalogManager._format_product(product))
                url = data.get("paging", {}).get("next")
                params = None
        return products

    @staticmethod
    async def get_products_for_set(set_id: str, limit: int = 60, catalog_id: str | None = None, cache_file: str | None = None) -> List[Dict[str, Any]]:
        """Return products for a specific product set.

        Graph API: /{product_set_id}/products
        Fallback: fetch entire catalog if set_id equals the catalog id.
        """
        cid = str(catalog_id or CATALOG_ID or "").strip()
        cache_file = cache_file or CATALOG_CACHE_FILE
        cache_key = f"{cid}:{str(set_id or '').strip()}"
        # If requesting the full catalog, serve from on-disk cache instantly
        if not set_id or str(set_id).strip() == cid:
            cached = catalog_manager.get_cached_products(cache_file=cache_file)
            if cached:
                return cached[: max(1, int(limit))]
            # Fallback to live fetch if cache empty; also persist to cache for next requests
            products_live = await CatalogManager.get_catalog_products(catalog_id=cid)
            try:
                with open(cache_file, "w", encoding="utf8") as f:
                    json.dump(products_live, f, ensure_ascii=False)
                try:
                    await upload_file_to_gcs(cache_file)
                except Exception as _exc:
                    print(f"GCS upload failed after live fetch: {_exc}")
            except Exception as _exc:
                print(f"Writing local catalog cache failed: {_exc}")
            return products_live[: max(1, int(limit))]

        # Serve from persisted cache if fresh
        use_persisted = False
        try:
            filename = CatalogManager._set_cache_filename(set_id, catalog_id=cid)
            if os.path.exists(filename):
                import time as _time
                if (_time.time() - os.path.getmtime(filename)) < CatalogManager._SET_CACHE_TTL_SEC:
                    use_persisted = True
        except Exception:
            use_persisted = False

        if use_persisted:
            persisted = CatalogManager._load_persisted_set(set_id, catalog_id=cid)
            if persisted:
                return persisted[: max(1, int(limit))]

        # Serve from in-memory cache if fresh (warm instance)
        import time as _time
        ts = CatalogManager._SET_CACHE_TS.get(cache_key)
        if ts and (_time.time() - ts) < CatalogManager._SET_CACHE_TTL_SEC:
            cached_list = CatalogManager._SET_CACHE.get(cache_key, [])
            if cached_list:
                return cached_list[: max(1, int(limit))]

        products: List[Dict[str, Any]] = []
        url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{set_id}/products"
        params = {
            "fields": "retailer_id,name,price,images{url},availability,quantity",
            "limit": 25,
        }
        headers = await get_whatsapp_headers()

        async with httpx.AsyncClient(timeout=40.0) as client:
            while url:
                response = await client.get(url, headers=headers, params=params if params else None)
                data = response.json()
                for product in data.get("data", []):
                    if CatalogManager._is_product_available(product):
                        products.append(CatalogManager._format_product(product))
                        if len(products) >= max(1, int(limit)):
                            return products
                url = data.get("paging", {}).get("next")
                params = None
        # Store in memory and persist for fast subsequent responses across instances
        try:
            CatalogManager._SET_CACHE[cache_key] = products
            CatalogManager._SET_CACHE_TS[cache_key] = _time.time()
            try:
                await CatalogManager._persist_set_async(set_id, products, catalog_id=cid)
            except Exception:
                pass
        except Exception:
            pass
        return products

    @staticmethod
    def _is_product_available(product: Dict[str, Any]) -> bool:
        availability = str(product.get("availability", "")).lower()
        # Be permissive: include everything except explicit out_of_stock.
        # Many catalogs omit quantity; filtering by quantity hides valid items.
        return availability != "out_of_stock"

    @staticmethod
    def _format_product(product: Dict[str, Any]) -> Dict[str, Any]:
        images = product.get("images", [])
        # Facebook can return images as an array, or as an object with a data array
        if isinstance(images, dict) and "data" in images:
            images = images["data"]

        formatted_images: list[dict] = []
        for img in images:
            # Normalize to dict form
            if isinstance(img, str):
                # Some APIs return a bare URL string
                url_string = img
                try:
                    # Rarely images are JSON-encoded strings
                    possible = json.loads(img)
                    if isinstance(possible, dict):
                        img = possible
                    else:
                        img = {"url": url_string}
                except Exception:
                    img = {"url": url_string}

            if isinstance(img, dict):
                # Normalize common keys to `url`
                url = (
                    img.get("url")
                    or img.get("src")
                    or img.get("image_url")
                    or img.get("original_url")
                    or img.get("href")
                )
                if url:
                    formatted_images.append({"url": url})

        return {
            "retailer_id": product.get("retailer_id", product.get("id")),
            "name": product.get("name"),
            "price": product.get("price"),
            "availability": product.get("availability"),
            "quantity": product.get("quantity"),
            "images": formatted_images,
        }

    @staticmethod
    async def refresh_catalog_cache(catalog_id: str | None = None, cache_file: str | None = None) -> int:
        cid = str(catalog_id or CATALOG_ID or "").strip()
        cache_file = cache_file or CATALOG_CACHE_FILE
        products = await CatalogManager.get_catalog_products(catalog_id=cid)
        with open(cache_file, "w", encoding="utf8") as f:
            json.dump(products, f, ensure_ascii=False)
        try:
            await upload_file_to_gcs(cache_file)
        except Exception as exc:
            print(f"GCS upload failed: {exc}")
        return len(products)

    @staticmethod
    def get_cached_products(cache_file: str | None = None) -> List[Dict[str, Any]]:
        cache_file = cache_file or CATALOG_CACHE_FILE
        if not os.path.exists(cache_file):
            try:
                download_file_from_gcs(
                    cache_file, cache_file
                )
            except Exception:
                return []
        # If file exists but is empty or invalid, return empty list gracefully
        try:
            if os.path.getsize(cache_file) == 0:
                return []
        except Exception:
            return []

        try:
            with open(cache_file, "r", encoding="utf8") as f:
                products = json.load(f)
        except Exception:
            return []

        # Ensure images normalized on cached entries as well
        normalized: list[dict] = []
        for prod in products:
            try:
                normalized.append(CatalogManager._format_product(prod))
            except Exception:
                # If formatting fails, skip that product
                continue
        return [p for p in normalized if CatalogManager._is_product_available(p)]


catalog_manager = CatalogManager()

# 1. Fix the port in main block
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)


# ------------------------- Cash-in endpoint -------------------------
@app.post("/cashin")
async def cashin(
    user_id: str = Form(...),
    amount: str = Form(...),
    file: UploadFile | None = File(None),
):
    """Record a cash-in receipt and notify the UI immediately.

    - If an image file is provided, it is saved locally and uploaded to GCS.
    - A message is created as an image with caption 'cashin' and price set to the amount.
    - The message is sent via the existing real-time flow (optimistic update + WhatsApp send).
    """
    try:
        media_url: str | None = None
        media_path: str | None = None

        if file and file.filename:
            # Ensure media folder exists
            media_dir = MEDIA_DIR
            media_dir.mkdir(exist_ok=True)

            # Persist upload
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            file_extension = Path(file.filename).suffix or ".bin"
            filename = f"cashin_{timestamp}_{uuid.uuid4().hex[:8]}{file_extension}"
            file_path = media_dir / filename

            content = await file.read()
            async with aiofiles.open(file_path, "wb") as f:
                await f.write(content)

            # Upload to Google Cloud Storage
            media_url = await upload_file_to_gcs(
                str(file_path)
            )
            media_path = str(file_path)

        # Build message payload
        message_data = {
            "user_id": user_id,
            # Use image type so WhatsApp accepts it as media. Use caption to mark as cashin.
            "type": "image" if media_url else "text",
            "from_me": True,
            "timestamp": datetime.utcnow().isoformat(),
            "price": amount,              # store amount in price field
            "caption": "cashin",         # marker for UI rendering
        }
        if media_url:
            message_data["message"] = media_path  # local path for internal handling
            message_data["url"] = media_url       # public URL for UI
            message_data["media_path"] = media_path
        else:
            message_data["message"] = f"Cash-in: {amount}"

        # Send through the normal pipeline (triggers immediate WS update)
        result = await message_processor.process_outgoing_message(message_data)
        return {"status": "success", "message": result}

    except HTTPException:
        raise
    except Exception as exc:
        print(f"❌ Error in /cashin: {exc}")
        return {"error": f"Internal server error: {exc}", "status": "failed"}


# ───────────────────────── Conversation Notes API ─────────────────────────
@app.get("/conversations/{user_id}/notes")
async def get_conversation_notes(user_id: str):
    try:
        notes = await asyncio.wait_for(
            db_manager.list_notes(user_id),
            timeout=max(0.5, float(NOTES_DB_TIMEOUT_SECONDS)),
        )
        # Attach signed URLs for any GCS-backed media so browser can access
        enriched = []
        for n in notes:
            try:
                url = n.get("url")
                signed = maybe_signed_url_for(url, ttl_seconds=3600) if url else None
                if signed:
                    n = { **n, "signed_url": signed }
            except Exception:
                pass
            enriched.append(n)
        return enriched
    except asyncio.TimeoutError:
        # Notes are non-critical; avoid blocking the UI under DB load.
        return []
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list notes: {exc}")


@app.post("/conversations/{user_id}/notes")
async def create_conversation_note(
    user_id: str,
    note_type: str = Body("text"),
    text: str | None = Body(None),
    url: str | None = Body(None),
    agent_username: str | None = Body(None),
):
    try:
        payload = {
            "user_id": user_id,
            "type": (note_type or "text").lower(),
            "text": (text or None),
            "url": (url or None),
            "agent_username": agent_username,
            "created_at": datetime.utcnow().isoformat(),
        }
        if payload["type"] not in ("text", "audio"):
            payload["type"] = "text"
        stored = await asyncio.wait_for(
            db_manager.add_note(payload),
            timeout=max(0.5, float(NOTES_DB_TIMEOUT_SECONDS)),
        )
        # Include signed_url in the response for immediate playback
        try:
            media_url = stored.get("url")
            signed = maybe_signed_url_for(media_url, ttl_seconds=3600) if media_url else None
            if signed:
                stored = { **stored, "signed_url": signed }
        except Exception:
            pass
        return stored
    except HTTPException:
        raise
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="Notes temporarily busy, please retry")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to add note: {exc}")


@app.delete("/conversations/notes/{note_id}")
async def delete_conversation_note(note_id: int):
    try:
        await asyncio.wait_for(
            db_manager.delete_note(note_id),
            timeout=max(0.5, float(NOTES_DB_TIMEOUT_SECONDS)),
        )
        return {"ok": True}
    except asyncio.TimeoutError:
        raise HTTPException(status_code=503, detail="Notes temporarily busy, please retry")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete note: {exc}")
