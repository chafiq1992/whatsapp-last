from __future__ import annotations

import logging
from typing import Callable, Optional


class _ContextFilter(logging.Filter):
    def __init__(
        self,
        *,
        workspace_getter: Optional[Callable[[], str]] = None,
        request_id_getter: Optional[Callable[[], Optional[str]]] = None,
        agent_getter: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        super().__init__()
        self._workspace_getter = workspace_getter
        self._request_id_getter = request_id_getter
        self._agent_getter = agent_getter

    def filter(self, record: logging.LogRecord) -> bool:
        # Inject defaults so formatters can always reference these fields.
        record.workspace = None
        record.request_id = None
        record.agent_username = None
        try:
            if self._workspace_getter:
                record.workspace = self._workspace_getter()
        except Exception:
            record.workspace = None
        try:
            if self._request_id_getter:
                record.request_id = self._request_id_getter()
        except Exception:
            record.request_id = None
        try:
            if self._agent_getter:
                record.agent_username = self._agent_getter()
        except Exception:
            record.agent_username = None
        return True


def configure_logging(
    *,
    level: str = "INFO",
    workspace_getter: Optional[Callable[[], str]] = None,
    request_id_getter: Optional[Callable[[], Optional[str]]] = None,
    agent_getter: Optional[Callable[[], Optional[str]]] = None,
) -> None:
    """Configure root logging with consistent contextual fields.

    This intentionally does not use third-party JSON logging deps to keep deploys safe.
    """
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(lvl)

    # If something already configured handlers (uvicorn), avoid duplicating them.
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(lvl)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s "
                "request_id=%(request_id)s workspace=%(workspace)s agent=%(agent_username)s "
                "%(message)s"
            )
        )
        root.addHandler(handler)

    # Always attach the context filter (idempotent-ish).
    ctx_filter = _ContextFilter(
        workspace_getter=workspace_getter,
        request_id_getter=request_id_getter,
        agent_getter=agent_getter,
    )
    root.addFilter(ctx_filter)


