from __future__ import annotations

import asyncio
import logging
import os
import time

from .runtime import WebhookRuntime

log = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return int(default)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return float(default)


async def _trim_redis_streams_forever(rt: WebhookRuntime) -> None:
    """Bound Redis memory usage for webhook streams."""
    interval = max(5.0, _env_float("WEBHOOK_STREAM_TRIM_INTERVAL_SEC", 60.0))
    maxlen = max(1000, _env_int("WEBHOOK_STREAM_MAXLEN", 50_000))
    dlq_maxlen = max(100, _env_int("WEBHOOK_STREAM_DLQ_MAXLEN", 10_000))

    while True:
        try:
            r = getattr(rt.redis_manager, "redis_client", None)
            if not (r and bool(rt.use_redis_stream)):
                await asyncio.sleep(interval)
                continue
            # Use "~" (approximate) trimming to keep this low-overhead.
            try:
                await r.xtrim(rt.stream_key, maxlen=maxlen, approximate=True)
            except TypeError:
                # Some redis clients use a different signature; fallback to raw command.
                await r.execute_command("XTRIM", rt.stream_key, "MAXLEN", "~", int(maxlen))
            try:
                await r.xtrim(rt.stream_dlq_key, maxlen=dlq_maxlen, approximate=True)
            except TypeError:
                await r.execute_command("XTRIM", rt.stream_dlq_key, "MAXLEN", "~", int(dlq_maxlen))
        except Exception as exc:
            log.warning("Webhook Redis stream trim failed (will retry): %s", exc)
        await asyncio.sleep(interval)


async def _cleanup_db_webhook_events_forever(rt: WebhookRuntime) -> None:
    """Prevent webhook_events from growing without bound when DB queue is used."""
    interval = max(30.0, _env_float("WEBHOOK_DB_CLEANUP_INTERVAL_SEC", 3600.0))
    done_days = max(1, _env_int("WEBHOOK_DB_RETENTION_DAYS_DONE", 14))
    dead_days = max(1, _env_int("WEBHOOK_DB_RETENTION_DAYS_DEAD", 60))
    max_rows = max(100, _env_int("WEBHOOK_DB_CLEANUP_MAX_ROWS", 5000))

    # Throttle logs
    last_log = 0.0

    while True:
        try:
            if not (bool(getattr(rt.db_manager, "use_postgres", False)) and bool(rt.use_db_queue)):
                await asyncio.sleep(interval)
                continue

            async with rt.db_manager._conn() as db:
                # Helpful for retention deletes; safe/idempotent.
                try:
                    await db.execute(
                        "CREATE INDEX IF NOT EXISTS idx_webhook_events_status_created_at ON webhook_events (status, created_at, id)"
                    )
                except Exception:
                    pass

                # Chunked deletes to avoid long-running transactions.
                # Prefer deleting DONE first, then DEAD.
                deleted_total = 0

                for status, days in (("done", done_days), ("dead", dead_days)):
                    remaining = int(max_rows) - int(deleted_total)
                    if remaining <= 0:
                        break
                    try:
                        res = await db.execute(
                            """
                            WITH cte AS (
                              SELECT id
                              FROM webhook_events
                              WHERE status = $1
                                AND created_at < NOW() - ($2 * INTERVAL '1 day')
                              ORDER BY id
                              LIMIT $3
                            )
                            DELETE FROM webhook_events
                            WHERE id IN (SELECT id FROM cte)
                            """,
                            str(status),
                            int(days),
                            int(remaining),
                        )
                        # asyncpg returns a string like "DELETE <n>"
                        try:
                            if isinstance(res, str) and res.upper().startswith("DELETE"):
                                deleted_total += int(res.split()[-1])
                        except Exception:
                            pass
                    except Exception as exc:
                        # If table doesn't exist yet, just wait.
                        if "webhook_events" in str(exc).lower() or "undefinedtable" in str(exc).lower():
                            break
                        raise

            now = time.time()
            if deleted_total and (now - last_log > 300):
                last_log = now
                log.info("Webhook DB retention cleanup deleted_rows=%s", deleted_total)
        except Exception as exc:
            log.warning("Webhook DB retention cleanup failed (will retry): %s", exc)

        await asyncio.sleep(interval)


def start_webhook_maintenance(rt: WebhookRuntime) -> None:
    """Fire-and-forget maintenance tasks (safe to call at startup)."""
    try:
        # Redis stream trimming is useful whenever Redis Streams is enabled.
        asyncio.create_task(_trim_redis_streams_forever(rt))
    except Exception:
        pass
    try:
        # DB retention matters only when the DB queue is used.
        asyncio.create_task(_cleanup_db_webhook_events_forever(rt))
    except Exception:
        pass

