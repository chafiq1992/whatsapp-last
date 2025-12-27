from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List

from .runtime import WebhookRuntime

_webhook_db_ready_last_log_ts: float = 0.0


async def db_enqueue_webhook(rt: WebhookRuntime, payload: dict) -> None:
    """Persist webhook payload into Postgres-backed queue before ACKing."""
    async with rt.db_manager._conn() as db:
        if not getattr(rt.db_manager, "use_postgres", False):
            raise RuntimeError("DB queue requires Postgres")
        await db.execute(
            "INSERT INTO webhook_events (payload, status, next_attempt_at) VALUES ($1::jsonb, 'pending', NOW())",
            json.dumps(payload),
        )


async def ensure_webhook_events_table(rt: WebhookRuntime) -> bool:
    """Best-effort: ensure Postgres webhook_events table exists before using DB queue.

    Returns True when the table appears ready, False otherwise.
    """
    global _webhook_db_ready_last_log_ts

    if not (bool(getattr(rt.db_manager, "use_postgres", False)) and bool(rt.use_db_queue)):
        rt.state.db_ready = False
        return False

    try:
        async with rt.db_manager._conn() as db:
            if not getattr(rt.db_manager, "use_postgres", False):
                rt.state.db_ready = False
                return False
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
        rt.state.db_ready = True
        return True
    except Exception as exc:
        rt.state.db_ready = False
        now = time.time()
        if now - float(_webhook_db_ready_last_log_ts) > 60.0:
            _webhook_db_ready_last_log_ts = now
            logging.getLogger(__name__).warning("Webhook DB queue not ready (will fallback): %s", exc)
        return False


async def db_claim_webhook_events(rt: WebhookRuntime, batch_size: int, lock_owner: str) -> List[Dict[str, Any]]:
    """Claim a batch of due webhook events (Postgres) using SKIP LOCKED."""
    async with rt.db_manager._conn() as db:
        if not getattr(rt.db_manager, "use_postgres", False):
            return []
        try:
            rows = await db.fetch(
                """
                WITH cte AS (
                  SELECT id
                  FROM webhook_events
                  WHERE status IN ('pending','retry')
                    AND next_attempt_at <= NOW()
                  ORDER BY id
                  FOR UPDATE SKIP LOCKED
                  LIMIT $1
                )
                UPDATE webhook_events e
                SET status='processing',
                    locked_at=NOW(),
                    lock_owner=$2,
                    attempts=e.attempts+1,
                    updated_at=NOW()
                FROM cte
                WHERE e.id = cte.id
                RETURNING e.id, e.payload, e.attempts
                """,
                int(batch_size),
                str(lock_owner),
            )
        except Exception as exc:
            if "webhook_events" in str(exc).lower() or "undefinedtable" in str(exc).lower():
                await ensure_webhook_events_table(rt)
                return []
            raise

        out: List[Dict[str, Any]] = []
        for r in rows or []:
            try:
                payload = r["payload"]
                if isinstance(payload, str):
                    payload = json.loads(payload)
            except Exception:
                payload = {}
            out.append({"id": int(r["id"]), "payload": payload, "attempts": int(r["attempts"] or 0)})
        return out


async def db_mark_webhook_done(rt: WebhookRuntime, event_id: int) -> None:
    async with rt.db_manager._conn() as db:
        if not getattr(rt.db_manager, "use_postgres", False):
            return
        await db.execute(
            "UPDATE webhook_events SET status='done', last_error=NULL, locked_at=NULL, lock_owner=NULL, updated_at=NOW() WHERE id=$1",
            int(event_id),
        )


async def db_reschedule_webhook(rt: WebhookRuntime, event_id: int, *, attempts: int, error: str) -> None:
    """Reschedule with backoff; mark dead after max_attempts."""
    async with rt.db_manager._conn() as db:
        if not getattr(rt.db_manager, "use_postgres", False):
            return
        dead = int(attempts) >= int(rt.max_attempts)
        delay = min(300, max(1, int(2 ** min(int(attempts), 8))))
        if dead:
            await db.execute(
                "UPDATE webhook_events SET status='dead', last_error=$2, locked_at=NULL, lock_owner=NULL, updated_at=NOW() WHERE id=$1",
                int(event_id),
                str(error)[:4000],
            )
        else:
            await db.execute(
                """
                UPDATE webhook_events
                SET status='retry',
                    last_error=$2,
                    next_attempt_at=NOW() + ($3 * INTERVAL '1 second'),
                    locked_at=NULL,
                    lock_owner=NULL,
                    updated_at=NOW()
                WHERE id=$1
                """,
                int(event_id),
                str(error)[:4000],
                int(delay),
            )


