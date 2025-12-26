from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Optional
import uuid

# NOTE: These are request-scoped for HTTP handlers. Background tasks/workers will typically
# have empty values unless explicitly set.
_REQUEST_ID: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_AGENT_USERNAME: ContextVar[Optional[str]] = ContextVar("agent_username", default=None)


def get_request_id() -> Optional[str]:
    return _REQUEST_ID.get()


def set_request_id(value: Optional[str] = None) -> tuple[str, Token[Optional[str]]]:
    rid = (value or "").strip() or uuid.uuid4().hex
    tok = _REQUEST_ID.set(rid)
    return rid, tok


def clear_request_id() -> None:
    _REQUEST_ID.set(None)

def reset_request_id(token: Token[Optional[str]]) -> None:
    _REQUEST_ID.reset(token)


def get_agent_username() -> Optional[str]:
    return _AGENT_USERNAME.get()


def set_agent_username(value: Optional[str]) -> Token[Optional[str]]:
    v = (value or "").strip() if value else None
    return _AGENT_USERNAME.set(v or None)


def clear_agent_username() -> None:
    _AGENT_USERNAME.set(None)

def reset_agent_username(token: Token[Optional[str]]) -> None:
    _AGENT_USERNAME.reset(token)


