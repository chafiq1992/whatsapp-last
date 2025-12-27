from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Set


@dataclass
class WebhookState:
    db_ready: bool = False


@dataclass
class WebhookRuntime:
    # Core dependencies (injected from backend.main)
    db_manager: Any
    redis_manager: Any
    message_processor: Any
    webhook_queue: Any

    # Helpers injected from backend.main (keep behavior stable)
    coerce_workspace: Callable[[str], str]
    vlog: Callable[[str], None]

    # Webhook verification/config
    verify_token: str
    meta_app_secret: str
    allowed_phone_number_ids: Set[str]
    phone_id_to_workspace: Dict[str, str]
    default_workspace: str

    # Queue config
    use_redis_stream: bool
    stream_key: str
    stream_group: str
    stream_dlq_key: str
    max_attempts: int
    claim_min_idle_ms: int

    use_db_queue: bool
    db_batch_size: int
    db_poll_interval_sec: float
    enqueue_timeout_seconds: float
    workers: int
    processing_timeout_seconds: float

    state: WebhookState

    def backend_name(self) -> str:
        try:
            if bool(getattr(self.db_manager, "use_postgres", False)) and bool(self.use_db_queue) and bool(self.state.db_ready):
                return "db"
        except Exception:
            pass
        try:
            if bool(self.use_redis_stream) and bool(getattr(self.redis_manager, "redis_client", None)):
                return "redis_stream"
        except Exception:
            pass
        return "memory"


