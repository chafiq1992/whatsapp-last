from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid

from .db_queue import (
    db_claim_webhook_events,
    db_mark_webhook_done,
    db_reschedule_webhook,
    ensure_webhook_events_table,
)
from .redis_stream import ensure_webhook_stream_group
from .runtime import WebhookRuntime


async def webhook_worker(rt: WebhookRuntime, worker_id: int):
    log = logging.getLogger(__name__)
    consumer = f"w{worker_id}-{uuid.uuid4().hex[:10]}"
    last_claim = 0.0

    async def process_one(payload: dict, *, source_id: str | None = None):
        _ = source_id  # reserved for future logging/metrics; keep signature stable
        await asyncio.wait_for(
            rt.message_processor.process_incoming_message(payload),
            timeout=max(1.0, float(rt.processing_timeout_seconds)),
        )

    while True:
        r = getattr(rt.redis_manager, "redis_client", None)
        use_stream = bool(r and bool(rt.use_redis_stream))

        # Preferred: Redis Streams (durable)
        if use_stream:
            now = time.time()
            try:
                if now - last_claim > 15:
                    last_claim = now
                    try:
                        res = await r.xautoclaim(
                            rt.stream_key,
                            rt.stream_group,
                            consumer,
                            min_idle_time=max(1, int(rt.claim_min_idle_ms)),
                            start_id="0-0",
                            count=25,
                        )
                        claimed = res[1] if isinstance(res, (list, tuple)) and len(res) >= 2 else []
                    except Exception:
                        claimed = []

                    for msg_id, fields in claimed or []:
                        try:
                            raw = fields.get("payload") if isinstance(fields, dict) else None
                            if raw is None and isinstance(fields, dict):
                                raw = fields.get(b"payload")
                            payload = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
                            if isinstance(payload, (bytes, bytearray)):
                                payload = json.loads(payload.decode("utf-8"))
                            if not isinstance(payload, dict):
                                raise ValueError("bad payload")
                            await process_one(payload, source_id=str(msg_id))
                            await r.xack(rt.stream_key, rt.stream_group, msg_id)
                            try:
                                await r.hdel("wa:webhooks:attempts", str(msg_id))
                            except Exception:
                                pass
                        except Exception as exc:
                            try:
                                attempts = await r.hincrby("wa:webhooks:attempts", str(msg_id), 1)
                            except Exception:
                                attempts = 1
                            if int(attempts) >= int(rt.max_attempts):
                                try:
                                    await r.xadd(
                                        rt.stream_dlq_key,
                                        {
                                            "id": str(msg_id),
                                            "error": str(exc),
                                            "payload": raw
                                            if isinstance(raw, str)
                                            else (
                                                raw.decode("utf-8", "ignore")
                                                if isinstance(raw, (bytes, bytearray))
                                                else ""
                                            ),
                                        },
                                    )
                                except Exception:
                                    pass
                                await r.xack(rt.stream_key, rt.stream_group, msg_id)
                            log.exception("Webhook worker %s: redis-stream claimed msg failed: %s", worker_id, exc)

                resp = await r.xreadgroup(
                    rt.stream_group,
                    consumer,
                    streams={rt.stream_key: ">"},
                    count=25,
                    block=5000,
                )
                if resp:
                    for _stream, messages in resp:
                        for msg_id, fields in messages:
                            raw = None
                            try:
                                raw = fields.get("payload") if isinstance(fields, dict) else None
                                if raw is None and isinstance(fields, dict):
                                    raw = fields.get(b"payload")
                                payload = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else None
                                if isinstance(payload, (bytes, bytearray)):
                                    payload = json.loads(payload.decode("utf-8"))
                                if not isinstance(payload, dict):
                                    raise ValueError("bad payload")
                                await process_one(payload, source_id=str(msg_id))
                                await r.xack(rt.stream_key, rt.stream_group, msg_id)
                                try:
                                    await r.hdel("wa:webhooks:attempts", str(msg_id))
                                except Exception:
                                    pass
                            except asyncio.TimeoutError:
                                log.error(
                                    "Webhook worker %s: msg %s timed out after %ss",
                                    worker_id,
                                    msg_id,
                                    rt.processing_timeout_seconds,
                                )
                                try:
                                    attempts = await r.hincrby("wa:webhooks:attempts", str(msg_id), 1)
                                except Exception:
                                    attempts = 1
                                if int(attempts) >= int(rt.max_attempts):
                                    try:
                                        await r.xadd(
                                            rt.stream_dlq_key,
                                            {
                                                "id": str(msg_id),
                                                "error": "timeout",
                                                "payload": raw
                                                if isinstance(raw, str)
                                                else (
                                                    raw.decode("utf-8", "ignore")
                                                    if isinstance(raw, (bytes, bytearray))
                                                    else ""
                                                ),
                                            },
                                        )
                                    except Exception:
                                        pass
                                    await r.xack(rt.stream_key, rt.stream_group, msg_id)
                            except Exception as exc:
                                try:
                                    attempts = await r.hincrby("wa:webhooks:attempts", str(msg_id), 1)
                                except Exception:
                                    attempts = 1
                                if int(attempts) >= int(rt.max_attempts):
                                    try:
                                        await r.xadd(
                                            rt.stream_dlq_key,
                                            {
                                                "id": str(msg_id),
                                                "error": str(exc),
                                                "payload": raw
                                                if isinstance(raw, str)
                                                else (
                                                    raw.decode("utf-8", "ignore")
                                                    if isinstance(raw, (bytes, bytearray))
                                                    else ""
                                                ),
                                            },
                                        )
                                    except Exception:
                                        pass
                                    await r.xack(rt.stream_key, rt.stream_group, msg_id)
                                log.exception("Webhook worker %s: msg %s failed: %s", worker_id, msg_id, exc)
                continue
            except Exception as exc:
                log.warning(
                    "Webhook worker %s: redis stream read failed, falling back to in-memory: %s",
                    worker_id,
                    exc,
                )

        # Fallback: in-memory queue (not durable)
        data = await rt.webhook_queue.get()
        try:
            await process_one(data)
        except asyncio.TimeoutError:
            log.error(
                "Webhook worker %s: in-memory processing timed out after %ss",
                worker_id,
                rt.processing_timeout_seconds,
            )
        except Exception as exc:
            log.exception("Webhook worker %s: in-memory processing failed: %s", worker_id, exc)
        finally:
            try:
                rt.webhook_queue.task_done()
            except Exception:
                pass


async def webhook_db_worker(rt: WebhookRuntime, worker_id: int):
    """Postgres-backed webhook worker (no Redis required)."""
    log = logging.getLogger(__name__)
    lock_owner = f"dbw{worker_id}-{uuid.uuid4().hex[:10]}"
    batch = max(1, int(rt.db_batch_size))
    poll = max(0.1, float(rt.db_poll_interval_sec))
    while True:
        try:
            events = await db_claim_webhook_events(rt, batch, lock_owner)
            if not events:
                await asyncio.sleep(poll)
                continue
            for ev in events:
                eid = int(ev.get("id") or 0)
                payload = ev.get("payload") or {}
                attempts = int(ev.get("attempts") or 0)
                try:
                    await asyncio.wait_for(
                        rt.message_processor.process_incoming_message(payload),
                        timeout=max(1.0, float(rt.processing_timeout_seconds)),
                    )
                    await db_mark_webhook_done(rt, eid)
                except asyncio.TimeoutError:
                    log.error(
                        "DB webhook worker %s: event %s timed out after %ss",
                        worker_id,
                        eid,
                        rt.processing_timeout_seconds,
                    )
                    await db_reschedule_webhook(rt, eid, attempts=attempts, error="timeout")
                except Exception as exc:
                    log.exception("DB webhook worker %s: event %s failed: %s", worker_id, eid, exc)
                    await db_reschedule_webhook(rt, eid, attempts=attempts, error=str(exc))
        except Exception as outer:
            if "webhook_events" in str(outer).lower() or "undefinedtable" in str(outer).lower():
                await ensure_webhook_events_table(rt)
                log.warning(
                    "DB webhook worker %s: webhook_events missing/unready; backing off: %s",
                    worker_id,
                    outer,
                )
                await asyncio.sleep(max(5.0, poll))
                continue
            log.exception("DB webhook worker %s: loop error: %s", worker_id, outer)
            await asyncio.sleep(poll)


async def start_webhook_workers(rt: WebhookRuntime) -> None:
    """Start webhook background workers so /webhook can ACK quickly."""
    try:
        r = getattr(rt.redis_manager, "redis_client", None)
        use_stream = bool(r and bool(rt.use_redis_stream))

        # Prefer Redis Streams when available (durable + avoids growing webhook_events in Postgres).
        if use_stream:
            await ensure_webhook_stream_group(rt)
            for i in range(max(1, int(rt.workers))):
                asyncio.create_task(webhook_worker(rt, i + 1))
            print(f"Webhook Redis-stream workers started: {max(1, int(rt.workers))} (stream={rt.stream_key})")
            return

        # Fallback (no Redis): Postgres-backed queue table.
        if bool(getattr(rt.db_manager, "use_postgres", False)) and bool(rt.use_db_queue):
            await ensure_webhook_events_table(rt)
            if bool(rt.state.db_ready):
                for i in range(max(1, int(rt.workers))):
                    asyncio.create_task(webhook_db_worker(rt, i + 1))
                print(f"Webhook DB workers started: {max(1, int(rt.workers))} (batch={rt.db_batch_size})")
                return

        # Last resort: in-memory queue (not durable).
        for i in range(max(1, int(rt.workers))):
            asyncio.create_task(webhook_worker(rt, i + 1))
        print(
            f"Webhook in-memory workers started: {max(1, int(rt.workers))} (queue maxsize={getattr(rt.webhook_queue,'maxsize',None)})"
        )
    except Exception as exc:
        print(f"Webhook worker startup failed: {exc}")


