from __future__ import annotations

import logging

from .runtime import WebhookRuntime


async def ensure_webhook_stream_group(rt: WebhookRuntime) -> bool:
    """Ensure Redis Stream + consumer group exists (durable webhook queue)."""
    try:
        r = getattr(rt.redis_manager, "redis_client", None)
        if not r or not bool(rt.use_redis_stream):
            return False
        try:
            await r.xgroup_create(rt.stream_key, rt.stream_group, id="0-0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc).upper():
                raise
        return True
    except Exception as exc:
        logging.getLogger(__name__).warning("Failed to ensure webhook redis stream group: %s", exc)
        return False


