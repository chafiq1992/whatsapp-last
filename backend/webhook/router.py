from __future__ import annotations

import asyncio
import hashlib
import hmac
import json

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import PlainTextResponse

from .db_queue import db_enqueue_webhook, ensure_webhook_events_table
from .runtime import WebhookRuntime


def create_webhook_router(rt: WebhookRuntime) -> APIRouter:
    router = APIRouter()

    @router.api_route("/webhook", methods=["GET", "POST"])
    async def webhook(request: Request, background_tasks: BackgroundTasks):
        """WhatsApp webhook endpoint (ingress)."""
        if request.method == "GET":
            params = dict(request.query_params)
            mode = params.get("hub.mode")
            token = params.get("hub.verify_token")
            challenge = params.get("hub.challenge")

            rt.vlog(f"🔐 Webhook verification: mode={mode}, token={token}, challenge={challenge}")
            ok_token = False
            try:
                ok_token = bool(token) and (
                    token == rt.verify_token or token in (rt.verify_tokens or set())
                )
            except Exception:
                ok_token = bool(token) and (token == rt.verify_token)
            if mode == "subscribe" and ok_token and challenge:
                rt.vlog("✅ Webhook verified successfully")
                return PlainTextResponse(challenge)
            rt.vlog("❌ Webhook verification failed")
            return PlainTextResponse("Verification failed", status_code=403)

        # POST
        try:
            if rt.meta_app_secret:
                body_bytes = await request.body()
                sig_header = request.headers.get("X-Hub-Signature-256", "")
                expected = hmac.new(rt.meta_app_secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
                presented = sig_header.split("=", 1)[1] if "=" in sig_header else sig_header
                if not presented or not hmac.compare_digest(presented, expected):
                    rt.vlog("❌ Invalid webhook signature")
                    return PlainTextResponse("Invalid signature", status_code=401)
                data = json.loads(body_bytes.decode("utf-8") or "{}")
            else:
                data = await request.json()
        except Exception:
            return PlainTextResponse("Bad Request", status_code=400)

        rt.vlog("📥 Incoming Webhook Payload:")
        try:
            rt.vlog(json.dumps(data, indent=2))
        except Exception:
            pass

        # Attach workspace hint derived from the phone_number_id (lets async workers route to the correct tenant DB)
        try:
            value = data.get("entry", [{}])[0].get("changes", [{}])[0].get("value", {})
            meta = value.get("metadata") or {}
            incoming_phone_id = str(meta.get("phone_number_id") or "")
            if rt.allowed_phone_number_ids and incoming_phone_id and (incoming_phone_id not in rt.allowed_phone_number_ids):
                rt.vlog(
                    f"⏭️ Webhook ignored at ingress for phone_number_id {incoming_phone_id} (allowed {sorted(list(rt.allowed_phone_number_ids))[:10]})"
                )
                return {"ok": True}
            # Prefer a shared mapping (Redis) so multi-instance deployments don't rely on per-instance memory.
            ws = None
            try:
                r = getattr(rt.redis_manager, "redis_client", None)
                if r and incoming_phone_id:
                    raw = await r.hget("wa:phone_id_to_workspace", incoming_phone_id)
                    if raw is not None:
                        if isinstance(raw, (bytes, bytearray)):
                            raw = raw.decode("utf-8", "ignore")
                        ws = str(raw or "").strip()
            except Exception:
                ws = None
            # Fallback to in-memory mapping (seeded from env and updated on admin save).
            if not ws:
                ws = rt.phone_id_to_workspace.get(incoming_phone_id) if incoming_phone_id else None
            if ws:
                data["_workspace"] = rt.coerce_workspace(ws)
        except Exception:
            pass

        # ACK fast: enqueue for background processing. Avoid slow DB calls here to prevent 504s.
        try:
            # Preferred durable backend: Redis Streams (fast + keeps Postgres small when both are enabled).
            r = getattr(rt.redis_manager, "redis_client", None)
            if r and bool(rt.use_redis_stream):
                await r.xadd(rt.stream_key, {"payload": json.dumps(data)})
            # Fallback durable backend (no Redis): Postgres-backed queue table.
            elif bool(getattr(rt.db_manager, "use_postgres", False)) and bool(rt.use_db_queue):
                if await ensure_webhook_events_table(rt):
                    await asyncio.wait_for(
                        db_enqueue_webhook(rt, data),
                        timeout=max(0.2, float(rt.enqueue_timeout_seconds)),
                    )
                else:
                    rt.webhook_queue.put_nowait(data)
            # Last resort: in-memory queue (not durable).
            else:
                rt.webhook_queue.put_nowait(data)
        except asyncio.QueueFull:
            return PlainTextResponse("Webhook queue full", status_code=503)
        except Exception:
            return PlainTextResponse("Webhook enqueue failed", status_code=503)

        background_tasks.add_task(lambda: None)
        return {"ok": True}

    return router


