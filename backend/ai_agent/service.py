from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable

import httpx

from .tools import AIAgentToolDependencies, AIAgentToolbox

DEFAULT_AGENT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "run_mode": "shadow",
    "model": "gpt-5.1",
    "api_base": "https://api.openai.com/v1",
    "max_output_tokens": 900,
    "max_context_messages": 12,
    "catalog_results_limit": 6,
    "send_catalog_when_possible": True,
    "supported_languages": ["darija", "ar", "fr", "en"],
    "tone": "Brief, polite, commerce-native Moroccan retail customer service tone.",
    "handoff_enabled": True,
    "handoff_on_human_request": True,
    "low_confidence_threshold": 0.58,
    "anger_handoff_threshold": "frustrated",
    "instructions": (
        "You are the AI customer service assistant for a Moroccan clothing and shoes retailer. "
        "Reply briefly, clearly, and in the customer's language. Never invent stock, policies, "
        "prices, delivery details, or order facts. Ask at most one useful clarification question. "
        "Prefer recommending products that exist in the provided catalog candidates. Escalate when "
        "the customer is angry, asks for a human, or raises a refund, dispute, or legal-risk issue."
    ),
    "business_context": (
        "Business type: clothing and shoes retailer in Morocco. "
        "Primary channel: WhatsApp. Languages: Darija, Arabic, French, English. "
        "Common tasks: product discovery, size help, availability, delivery, COD, exchange/return, "
        "complaints, refund requests, order follow-up, and human handoff."
    ),
}

@dataclass
class AIAgentDependencies:
    db_manager: Any
    message_processor: Any
    get_workspace: Callable[[], str]
    normalize_workspace: Callable[[str | None], str]
    make_settings_key: Callable[[str, str | None], str]
    decrypt_secret: Callable[[Any], str]
    catalog_provider: Callable[[str], Awaitable[list[dict[str, Any]]]]
    fetch_customer_by_phone: Callable[[str, str], Awaitable[dict[str, Any] | None]]
    fetch_orders_for_customer: Callable[[str, str, int], Awaitable[list[dict[str, Any]]]]
    fetch_delivery_snapshot: Callable[[str, str | None, str], Awaitable[dict[str, Any] | None]]
    list_agents: Callable[[], Awaitable[list[dict[str, Any]]]]
    get_agent_last_seen: Callable[[str, str], Awaitable[float | None]]
    get_agent_assignment_count: Callable[[str, str], Awaitable[int]]
    set_conversation_assignment: Callable[[str, str | None], Awaitable[None]]
    logger: logging.Logger


class AIAgentService:
    def __init__(self, deps: AIAgentDependencies):
        self.db_manager = deps.db_manager
        self.message_processor = deps.message_processor
        self.get_workspace = deps.get_workspace
        self.normalize_workspace = deps.normalize_workspace
        self.make_settings_key = deps.make_settings_key
        self.decrypt_secret = deps.decrypt_secret
        self.catalog_provider = deps.catalog_provider
        self.log = deps.logger
        self.tools = AIAgentToolbox(
            AIAgentToolDependencies(
                normalize_workspace=self.normalize_workspace,
                fetch_customer_by_phone=deps.fetch_customer_by_phone,
                fetch_orders_for_customer=deps.fetch_orders_for_customer,
                fetch_delivery_snapshot=deps.fetch_delivery_snapshot,
                list_agents=deps.list_agents,
                get_agent_last_seen=deps.get_agent_last_seen,
                get_agent_assignment_count=deps.get_agent_assignment_count,
                set_conversation_assignment=deps.set_conversation_assignment,
                get_conversation_meta=self.db_manager.get_conversation_meta,
                catalog_provider=self.catalog_provider,
                logger=self.log,
            )
        )

    async def ensure_schema(self) -> None:
        async with self.db_manager._conn() as db:
            statements = [
                """
                CREATE TABLE IF NOT EXISTS ai_policy_docs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    locale TEXT NOT NULL DEFAULT 'fr',
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'approved',
                    version TEXT NOT NULL DEFAULT '1',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ai_conversation_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'bot_managed',
                    owner_type TEXT NOT NULL DEFAULT 'bot',
                    openai_conversation_id TEXT,
                    summary TEXT,
                    last_language TEXT,
                    last_intent TEXT,
                    slots_json TEXT,
                    risk_json TEXT,
                    counters_json TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ai_turns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    inbound_wa_message_id TEXT,
                    openai_response_id TEXT,
                    openai_conversation_id TEXT,
                    turn_mode TEXT NOT NULL DEFAULT 'shadow',
                    turn_status TEXT NOT NULL DEFAULT 'completed',
                    detected_language TEXT,
                    detected_intent TEXT,
                    emotion TEXT,
                    confidence REAL,
                    action TEXT,
                    reply_text TEXT,
                    request_json TEXT,
                    response_json TEXT,
                    usage_json TEXT,
                    error_text TEXT,
                    latency_ms INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ai_tool_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    turn_id INTEGER,
                    tool_name TEXT NOT NULL,
                    ok INTEGER NOT NULL DEFAULT 1,
                    request_json TEXT,
                    response_json TEXT,
                    error_code TEXT,
                    latency_ms INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ai_handoff_tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    priority TEXT NOT NULL DEFAULT 'normal',
                    status TEXT NOT NULL DEFAULT 'open',
                    assigned_agent TEXT,
                    summary TEXT,
                    context_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TEXT
                )
                """,
                "CREATE UNIQUE INDEX IF NOT EXISTS uniq_ai_state_ws_user ON ai_conversation_state (workspace, user_id)",
                "CREATE INDEX IF NOT EXISTS idx_ai_turns_ws_user_created ON ai_turns (workspace, user_id, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ai_policy_ws_topic ON ai_policy_docs (workspace, topic, locale, status)",
                "CREATE INDEX IF NOT EXISTS idx_ai_handoff_ws_user_status ON ai_handoff_tickets (workspace, user_id, status, created_at DESC)",
            ]
            for statement in statements:
                stmt = statement.strip()
                if self.db_manager.use_postgres:
                    stmt = stmt.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
                    await db.execute(stmt)
                else:
                    await db.execute(stmt)
            if not self.db_manager.use_postgres:
                await db.commit()

    async def get_config(self, workspace: str | None = None) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        raw = await self.db_manager.get_setting(self.make_settings_key("ai_agent_config", ws))
        payload = json.loads(raw) if raw else {}
        if not isinstance(payload, dict):
            payload = {}
        config = {**DEFAULT_AGENT_CONFIG, **payload}
        enc = str(payload.get("openai_api_key_enc") or "").strip()
        api_key = ""
        if enc:
            try:
                api_key = self.decrypt_secret(enc)
            except Exception:
                api_key = ""
        config["_openai_api_key"] = api_key
        config["openai_api_key_present"] = bool(api_key)
        config["openai_api_key_hint"] = api_key[-4:] if len(api_key) >= 4 else ""
        return config

    async def save_config(self, payload: dict[str, Any], workspace: str | None = None) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        current_raw = await self.db_manager.get_setting(self.make_settings_key("ai_agent_config", ws))
        current = json.loads(current_raw) if current_raw else {}
        if not isinstance(current, dict):
            current = {}
        merged = {**DEFAULT_AGENT_CONFIG, **current}
        for key in (
            "enabled",
            "run_mode",
            "model",
            "api_base",
            "max_output_tokens",
            "max_context_messages",
            "catalog_results_limit",
            "send_catalog_when_possible",
            "tone",
            "handoff_enabled",
            "handoff_on_human_request",
            "low_confidence_threshold",
            "anger_handoff_threshold",
            "instructions",
            "business_context",
            "supported_languages",
        ):
            if key in payload:
                merged[key] = payload.get(key)
        if "openai_api_key_enc" in current:
            merged["openai_api_key_enc"] = current["openai_api_key_enc"]
        await self.db_manager.set_setting(self.make_settings_key("ai_agent_config", ws), merged)
        return await self.get_config(ws)

    async def list_policies(self, workspace: str | None = None) -> list[dict[str, Any]]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                "SELECT * FROM ai_policy_docs WHERE workspace = ? ORDER BY topic ASC, locale ASC, updated_at DESC"
            )
            if self.db_manager.use_postgres:
                rows = await db.fetch(query, ws)
            else:
                cur = await db.execute(query, (ws,))
                rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def upsert_policy(self, payload: dict[str, Any], workspace: str | None = None) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        topic = str(payload.get("topic") or "").strip().lower()
        locale = str(payload.get("locale") or "fr").strip().lower() or "fr"
        title = str(payload.get("title") or "").strip()
        content = str(payload.get("content") or "").strip()
        status = str(payload.get("status") or "approved").strip().lower() or "approved"
        version = str(payload.get("version") or "1").strip() or "1"
        if not topic or not title or not content:
            raise ValueError("topic, title, and content are required")
        async with self.db_manager._conn() as db:
            policy_id = payload.get("id")
            now_iso = datetime.utcnow().isoformat()
            if policy_id:
                query = self.db_manager._convert(
                    """
                    UPDATE ai_policy_docs
                    SET topic = ?, locale = ?, title = ?, content = ?, status = ?, version = ?, updated_at = ?
                    WHERE id = ? AND workspace = ?
                    """
                )
                params = (topic, locale, title, content, status, version, now_iso, int(policy_id), ws)
                if self.db_manager.use_postgres:
                    await db.execute(query, *params)
                else:
                    await db.execute(query, params)
                    await db.commit()
                out_id = int(policy_id)
            else:
                query = self.db_manager._convert(
                    """
                    INSERT INTO ai_policy_docs (workspace, topic, locale, title, content, status, version, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                )
                params = (ws, topic, locale, title, content, status, version, now_iso)
                if self.db_manager.use_postgres:
                    await db.execute(query, *params)
                    row = await db.fetchrow(
                        self.db_manager._convert(
                            "SELECT id FROM ai_policy_docs WHERE workspace = ? AND topic = ? AND locale = ? ORDER BY id DESC LIMIT 1"
                        ),
                        ws,
                        topic,
                        locale,
                    )
                    out_id = int(row["id"]) if row else 0
                else:
                    cur = await db.execute(query, params)
                    await db.commit()
                    out_id = int(cur.lastrowid or 0)
        items = await self.list_policies(ws)
        for item in items:
            if int(item.get("id") or 0) == out_id:
                return item
        return {"id": out_id, "workspace": ws, "topic": topic, "locale": locale, "title": title, "content": content, "status": status, "version": version}

    async def delete_policy(self, policy_id: int, workspace: str | None = None) -> None:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert("DELETE FROM ai_policy_docs WHERE id = ? AND workspace = ?")
            if self.db_manager.use_postgres:
                await db.execute(query, int(policy_id), ws)
            else:
                await db.execute(query, (int(policy_id), ws))
                await db.commit()

    async def list_recent_turns(self, workspace: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert("SELECT * FROM ai_turns WHERE workspace = ? ORDER BY created_at DESC LIMIT ?")
            lim = max(1, min(limit, 100))
            if self.db_manager.use_postgres:
                rows = await db.fetch(query, ws, lim)
            else:
                cur = await db.execute(query, (ws, lim))
                rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def list_recent_turns_for_user(self, user_id: str, workspace: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        uid = str(user_id or "").strip()
        if not uid:
            return []
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                "SELECT * FROM ai_turns WHERE workspace = ? AND user_id = ? ORDER BY created_at DESC LIMIT ?"
            )
            lim = max(1, min(limit, 50))
            if self.db_manager.use_postgres:
                rows = await db.fetch(query, ws, uid, lim)
            else:
                cur = await db.execute(query, (ws, uid, lim))
                rows = await cur.fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            for key in ("request_json", "response_json", "usage_json"):
                try:
                    item[key] = json.loads(item.get(key) or "{}")
                except Exception:
                    item[key] = {}
            items.append(item)
        return items

    async def get_open_handoff_ticket(self, user_id: str, workspace: str | None = None) -> dict[str, Any] | None:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        uid = str(user_id or "").strip()
        if not uid:
            return None
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                SELECT * FROM ai_handoff_tickets
                WHERE workspace = ? AND user_id = ? AND status IN ('open', 'assigned')
                ORDER BY created_at DESC
                LIMIT 1
                """
            )
            if self.db_manager.use_postgres:
                row = await db.fetchrow(query, ws, uid)
            else:
                cur = await db.execute(query, (ws, uid))
                row = await cur.fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            item["context_json"] = json.loads(item.get("context_json") or "{}")
        except Exception:
            item["context_json"] = {}
        return item

    async def get_conversation_overview(self, user_id: str, workspace: str | None = None, limit: int = 8) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        uid = str(user_id or "").strip()
        state = await self._get_conversation_state(user_id=uid, workspace=ws)
        turns = await self.list_recent_turns_for_user(uid, ws, limit=limit)
        ticket = await self.get_open_handoff_ticket(uid, ws)
        last_turn = turns[0] if turns else None
        return {
            "workspace": ws,
            "user_id": uid,
            "state": state,
            "open_handoff_ticket": ticket,
            "recent_turns": turns,
            "last_turn": last_turn,
        }

    async def update_conversation_mode(
        self,
        *,
        user_id: str,
        status: str,
        workspace: str | None = None,
        actor_username: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        uid = str(user_id or "").strip()
        normalized_status = str(status or "").strip().lower()
        if normalized_status not in {"bot_managed", "hybrid", "human_managed", "closed"}:
            raise ValueError("invalid status")

        current = await self._get_conversation_state(user_id=uid, workspace=ws)
        owner_type = {
            "bot_managed": "bot",
            "hybrid": "hybrid",
            "human_managed": "human",
            "closed": str(current.get("owner_type") or "human"),
        }.get(normalized_status, "bot")
        updated_state = {
            "status": normalized_status,
            "owner_type": owner_type,
        }
        await self._upsert_conversation_state(user_id=uid, workspace=ws, state=updated_state)
        if normalized_status == "human_managed" and actor_username:
            try:
                await self.tools.assign_human_agent(user_id=uid, workspace=ws, preferred_agent=actor_username)
            except Exception:
                pass

        add_tags: list[str] = []
        remove_tags: list[str] = []
        if normalized_status == "human_managed":
            add_tags = ["human-managed", "needs-human"]
            remove_tags = ["ai-resolved"]
        elif normalized_status == "hybrid":
            add_tags = ["needs-human"]
            remove_tags = ["human-managed", "ai-resolved"]
        else:
            add_tags = ["ai-resolved"] if normalized_status == "closed" else []
            remove_tags = ["human-managed", "needs-human"]
        await self._sync_conversation_tags(user_id=uid, add_tags=add_tags, remove_tags=remove_tags)

        if normalized_status in {"bot_managed", "closed"}:
            await self._resolve_open_handoff_tickets(
                user_id=uid,
                workspace=ws,
                resolved_by=actor_username,
                resolution_note=note or normalized_status,
            )

        note_lines = [
            f"AI conversation mode changed to {normalized_status}.",
            f"Actor: {actor_username or 'system'}",
        ]
        if note:
            note_lines.append(f"Note: {note}")
        try:
            await self.db_manager.add_note(
                {
                    "user_id": uid,
                    "agent_username": actor_username or "ai-agent",
                    "type": "text",
                    "text": "\n".join(note_lines).strip(),
                    "created_at": datetime.utcnow().isoformat(),
                }
            )
        except Exception:
            pass

        return await self.get_conversation_overview(uid, ws, limit=8)

    async def maybe_handle_incoming_message(self, message_obj: dict[str, Any]) -> dict[str, Any]:
        ws = self.normalize_workspace(self.get_workspace())
        config = await self.get_config(ws)
        if not bool(config.get("enabled")):
            return {"handled": False, "skip_legacy": False, "reason": "disabled"}
        if str(message_obj.get("type") or "") != "text":
            return {"handled": False, "skip_legacy": False, "reason": "non_text"}
        if not str(config.get("_openai_api_key") or "").strip():
            return {"handled": False, "skip_legacy": False, "reason": "missing_api_key"}

        user_id = str(message_obj.get("user_id") or "").strip()
        inbound_wamid = str(message_obj.get("wa_message_id") or "").strip()
        incoming_text = str(message_obj.get("message") or "").strip()
        if not user_id or not incoming_text:
            return {"handled": False, "skip_legacy": False, "reason": "missing_input"}

        await self.ensure_schema()
        meta = await self.db_manager.get_conversation_meta(user_id)
        assigned_agent = str((meta or {}).get("assigned_agent") or "").strip()
        if assigned_agent:
            return {"handled": False, "skip_legacy": False, "reason": "human_assigned"}

        state = await self._get_conversation_state(user_id=user_id, workspace=ws)
        if str(state.get("status") or "") == "human_managed":
            return {"handled": False, "skip_legacy": False, "reason": "human_managed"}

        recent_messages = await self.db_manager.get_messages(user_id, offset=0, limit=int(config.get("max_context_messages") or 12))
        turn_payload = {
            "workspace": ws,
            "user_id": user_id,
            "inbound_wa_message_id": inbound_wamid,
            "conversation_state": state,
            "recent_messages": recent_messages,
            "incoming_message": incoming_text,
        }

        started = time.perf_counter()
        response_id = ""
        openai_conversation_id = str(state.get("openai_conversation_id") or "").strip()
        output_data: dict[str, Any] = {}
        tool_entries: list[dict[str, Any]] = []
        try:
            output_data, response_id, openai_conversation_id, usage, executed_tools = await self._run_openai_turn(
                config=config,
                turn_payload=turn_payload,
                previous_conversation_id=openai_conversation_id or None,
            )
            reply_text = str(output_data.get("reply_text") or "").strip()
            should_handoff = bool(output_data.get("should_handoff"))
            confidence = self._safe_float(output_data.get("confidence"), default=0.0)
            effective_mode = str(config.get("run_mode") or "shadow").strip().lower()
            action_tool_names = {
                str(entry.get("tool_name") or "")
                for entry in (executed_tools or [])
                if str(entry.get("tool_name") or "") in {
                    "send_text_reply",
                    "send_whatsapp_product_message",
                    "send_whatsapp_catalog_message",
                    "send_whatsapp_product_carousel",
                    "mark_conversation_status",
                    "assign_human_agent",
                    "create_handoff_ticket",
                }
            }
            send_action_used = bool(action_tool_names.intersection({
                "send_text_reply",
                "send_whatsapp_product_message",
                "send_whatsapp_catalog_message",
                "send_whatsapp_product_carousel",
            }))
            if confidence < self._safe_float(config.get("low_confidence_threshold"), default=0.58):
                should_handoff = True
                if not str(output_data.get("handoff_reason") or "").strip():
                    output_data["handoff_reason"] = "low_confidence"
            if not bool(config.get("handoff_enabled")):
                should_handoff = False
            action = "shadow" if effective_mode == "shadow" else ("suggest" if effective_mode == "suggest" else "no_reply")
            handled = False
            skip_legacy = False
            handoff_meta: dict[str, Any] = {}
            if effective_mode == "autonomous":
                if should_handoff:
                    if reply_text and "send_text_reply" not in action_tool_names:
                        try:
                            await self.message_processor.whatsapp_messenger.send_text_message(user_id, reply_text)
                        except Exception as handoff_reply_exc:
                            self.log.warning("ai_agent handoff reply send failed workspace=%s user=%s err=%s", ws, user_id, handoff_reply_exc)
                    if "create_handoff_ticket" not in action_tool_names and "assign_human_agent" not in action_tool_names:
                        handoff_meta = await self._mark_handoff(user_id=user_id, output_data=output_data, workspace=ws)
                    action = "handoff"
                    handled = True
                    skip_legacy = True
                elif reply_text and "send_text_reply" not in action_tool_names:
                    await self.message_processor.whatsapp_messenger.send_text_message(user_id, reply_text)
                    action = "send_text_reply"
                    handled = True
                    skip_legacy = True
                    if bool(config.get("send_catalog_when_possible")) and output_data.get("recommended_product_ids") and "send_whatsapp_product_carousel" not in action_tool_names:
                        product_ids = [
                            str(x).strip()
                            for x in (output_data.get("recommended_product_ids") or [])
                            if str(x).strip()
                        ][: max(1, min(6, int(config.get("catalog_results_limit") or 6)))]
                        if product_ids:
                            try:
                                await self.message_processor.whatsapp_messenger.send_catalog_products(user_id, product_ids)
                                action = "send_text_plus_catalog"
                            except Exception as catalog_exc:
                                self.log.warning("ai_agent catalog send failed workspace=%s user=%s err=%s", ws, user_id, catalog_exc)
                elif send_action_used:
                    handled = True
                    skip_legacy = True
                    action = "tool_driven_reply"
            new_state = {
                "status": (
                    "hybrid" if should_handoff else str(output_data.get("conversation_status") or "bot_managed")
                ),
                "owner_type": (
                    "human" if should_handoff else (
                        "human" if str(output_data.get("conversation_status") or "") == "human_managed" else "bot"
                    )
                ),
                "summary": str(output_data.get("state_summary") or state.get("summary") or "").strip(),
                "last_language": str(output_data.get("language") or state.get("last_language") or "").strip(),
                "last_intent": str(output_data.get("intent") or state.get("last_intent") or "").strip(),
                "slots_json": output_data.get("entities") or {},
                "risk_json": {
                    "emotion": output_data.get("emotion"),
                    "urgency": output_data.get("urgency"),
                    "handoff_reason": output_data.get("handoff_reason"),
                    "should_handoff": bool(should_handoff),
                },
                "counters_json": {
                    **(state.get("counters_json") or {}),
                    "turns": int((state.get("counters_json") or {}).get("turns") or 0) + 1,
                },
                "openai_conversation_id": openai_conversation_id or None,
            }
            await self._upsert_conversation_state(user_id=user_id, workspace=ws, state=new_state)
            latency_ms = int((time.perf_counter() - started) * 1000)
            turn_id = await self._log_turn(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                turn_mode=str(config.get("run_mode") or "shadow"),
                turn_status="completed",
                detected_language=str(output_data.get("language") or ""),
                detected_intent=str(output_data.get("intent") or ""),
                emotion=str(output_data.get("emotion") or ""),
                confidence=self._safe_float(output_data.get("confidence"), default=0.0),
                action=action,
                reply_text=reply_text,
                openai_response_id=response_id,
                openai_conversation_id=openai_conversation_id,
                request_json=turn_payload,
                response_json=output_data,
                usage_json=usage,
                error_text=None,
                latency_ms=latency_ms,
            )
            for tool_entry in executed_tools or []:
                await self._log_tool(
                    workspace=ws,
                    user_id=user_id,
                    turn_id=turn_id,
                    tool_name=str(tool_entry.get("tool_name") or ""),
                    ok=bool(tool_entry.get("ok")),
                    request_json=tool_entry.get("request_json") or {},
                    response_json=tool_entry.get("response_json") or {},
                    error_code=tool_entry.get("error_code"),
                    latency_ms=int(tool_entry.get("latency_ms") or 0),
                )
            if handoff_meta.get("assign_human_agent"):
                tool_entries.append(
                    self._tool_entry(
                        "assign_human_agent",
                        request_json={"user_id": user_id},
                        result=handoff_meta.get("assign_human_agent") or {},
                    )
                )
            if handoff_meta.get("create_handoff_ticket"):
                tool_entries.append(
                    self._tool_entry(
                        "create_handoff_ticket",
                        request_json={"user_id": user_id, "reason": output_data.get("handoff_reason")},
                        result=handoff_meta.get("create_handoff_ticket") or {},
                    )
                )
            for tool_entry in tool_entries:
                await self._log_tool(
                    workspace=ws,
                    user_id=user_id,
                    turn_id=turn_id,
                    tool_name=str(tool_entry.get("tool_name") or ""),
                    ok=bool(tool_entry.get("ok")),
                    request_json=tool_entry.get("request_json") or {},
                    response_json=tool_entry.get("response_json") or {},
                    error_code=tool_entry.get("error_code"),
                    latency_ms=int(tool_entry.get("latency_ms") or 0),
                )
            await self._log_tool(
                workspace=ws,
                user_id=user_id,
                turn_id=turn_id,
                tool_name="get_business_policies",
                ok=True,
                request_json={"topics": output_data.get("policy_topics") or []},
                response_json={"count": len(output_data.get("policy_topics") or [])},
            )
            return {"handled": handled, "skip_legacy": skip_legacy, "reason": action, "turn_id": turn_id}
        except Exception as exc:
            self.log.exception("ai_agent turn failed workspace=%s user=%s err=%s", ws, user_id, exc)
            latency_ms = int((time.perf_counter() - started) * 1000)
            await self._log_turn(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                turn_mode=str(config.get("run_mode") or "shadow"),
                turn_status="failed",
                detected_language="",
                detected_intent="",
                emotion="",
                confidence=0.0,
                action="error",
                reply_text="",
                openai_response_id=response_id,
                openai_conversation_id=openai_conversation_id,
                request_json=turn_payload,
                response_json=output_data,
                usage_json={},
                error_text=str(exc),
                latency_ms=latency_ms,
            )
            return {"handled": False, "skip_legacy": False, "reason": "error", "error": str(exc)}

    async def _run_openai_turn(
        self,
        *,
        config: dict[str, Any],
        turn_payload: dict[str, Any],
        previous_conversation_id: str | None = None,
    ) -> tuple[dict[str, Any], str, str, dict[str, Any], list[dict[str, Any]]]:
        endpoint = str(config.get("api_base") or "https://api.openai.com/v1").rstrip("/") + "/responses"
        headers = {
            "Authorization": f"Bearer {config.get('_openai_api_key')}",
            "Content-Type": "application/json",
        }
        timeout = httpx.Timeout(45.0, connect=10.0)
        input_items: list[Any] = [self._build_user_prompt(turn_payload)]
        usage_totals = {
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 0,
        }
        executed_tools: list[dict[str, Any]] = []
        response_id = ""
        conv_id = ""
        final_json: dict[str, Any] | None = None
        max_rounds = 6
        for _ in range(max_rounds):
            body: dict[str, Any] = {
                "model": str(config.get("model") or DEFAULT_AGENT_CONFIG["model"]),
                "instructions": self._build_system_prompt(config),
                "input": input_items,
                "max_output_tokens": int(config.get("max_output_tokens") or 900),
                "tools": self._response_tools(),
                "metadata": {
                    "workspace": str(turn_payload.get("workspace") or ""),
                    "user_id": str(turn_payload.get("user_id") or ""),
                    "source": "whatsapp_inbox_ai_agent",
                },
            }
            if previous_conversation_id:
                body["conversation"] = previous_conversation_id
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(endpoint, headers=headers, json=body)
            if resp.status_code >= 400:
                raise RuntimeError(f"Responses API error {resp.status_code}: {resp.text[:500]}")
            data = resp.json()
            response_id = str(data.get("id") or "").strip()
            conv = data.get("conversation") or {}
            if isinstance(conv, dict):
                conv_id = str(conv.get("id") or "").strip()
            elif isinstance(conv, str):
                conv_id = str(conv).strip()
            usage = data.get("usage") or {}
            input_tokens = self._safe_int(usage.get("input_tokens"), default=0)
            output_tokens = self._safe_int(usage.get("output_tokens"), default=0)
            reasoning_tokens = self._safe_int((usage.get("output_tokens_details") or {}).get("reasoning_tokens"), default=0)
            usage_totals["input_tokens"] += input_tokens
            usage_totals["output_tokens"] += output_tokens
            usage_totals["reasoning_tokens"] += reasoning_tokens
            usage_totals["total_tokens"] += input_tokens + output_tokens

            outputs = data.get("output") or []
            function_calls = [
                item for item in outputs
                if isinstance(item, dict) and str(item.get("type") or "") == "function_call"
            ]
            if function_calls:
                next_items: list[dict[str, Any]] = []
                for tool_call in function_calls:
                    name = str(tool_call.get("name") or "").strip()
                    call_id = str(tool_call.get("call_id") or "").strip()
                    raw_arguments = str(tool_call.get("arguments") or "{}")
                    try:
                        arguments = json.loads(raw_arguments or "{}")
                    except Exception:
                        arguments = {}
                    tool_result = await self._execute_response_tool(
                        name=name,
                        arguments=arguments if isinstance(arguments, dict) else {},
                        turn_payload=turn_payload,
                        config=config,
                    )
                    executed_tools.append(
                        self._tool_entry(
                            name,
                            request_json=arguments if isinstance(arguments, dict) else {},
                            result=tool_result,
                        )
                    )
                    next_items.append(
                        {
                            "type": "function_call_output",
                            "call_id": call_id,
                            "output": json.dumps(tool_result, ensure_ascii=False),
                        }
                    )
                input_items = [*outputs, *next_items]
                previous_conversation_id = None
                continue

            parsed = self._extract_json_object(self._extract_output_text(data))
            if isinstance(parsed, dict):
                final_json = parsed
                break
            raise RuntimeError("AI response did not return valid JSON")

        if not isinstance(final_json, dict):
            raise RuntimeError("AI tool-calling loop did not finish with a valid JSON response")
        return final_json, response_id, conv_id, usage_totals, executed_tools

    async def _get_conversation_state(self, *, user_id: str, workspace: str) -> dict[str, Any]:
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert("SELECT * FROM ai_conversation_state WHERE workspace = ? AND user_id = ? LIMIT 1")
            if self.db_manager.use_postgres:
                row = await db.fetchrow(query, workspace, user_id)
            else:
                cur = await db.execute(query, (workspace, user_id))
                row = await cur.fetchone()
            if not row:
                return {
                    "workspace": workspace,
                    "user_id": user_id,
                    "status": "bot_managed",
                    "owner_type": "bot",
                    "slots_json": {},
                    "risk_json": {},
                    "counters_json": {"turns": 0},
                }
            item = dict(row)
            for key in ("slots_json", "risk_json", "counters_json"):
                try:
                    item[key] = json.loads(item.get(key) or "{}")
                except Exception:
                    item[key] = {}
            return item

    async def _upsert_conversation_state(self, *, user_id: str, workspace: str, state: dict[str, Any]) -> None:
        existing = await self._get_conversation_state(user_id=user_id, workspace=workspace)
        merged = {**existing, **state}
        params = (
            workspace, user_id, str(merged.get("status") or "bot_managed"), str(merged.get("owner_type") or "bot"),
            str(merged.get("openai_conversation_id") or "") or None, str(merged.get("summary") or "") or None,
            str(merged.get("last_language") or "") or None, str(merged.get("last_intent") or "") or None,
            json.dumps(merged.get("slots_json") or {}, ensure_ascii=False),
            json.dumps(merged.get("risk_json") or {}, ensure_ascii=False),
            json.dumps(merged.get("counters_json") or {}, ensure_ascii=False),
            datetime.utcnow().isoformat(),
        )
        async with self.db_manager._conn() as db:
            if self.db_manager.use_postgres:
                query = self.db_manager._convert(
                    """
                    INSERT INTO ai_conversation_state
                    (workspace, user_id, status, owner_type, openai_conversation_id, summary, last_language, last_intent, slots_json, risk_json, counters_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (workspace, user_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        owner_type = EXCLUDED.owner_type,
                        openai_conversation_id = EXCLUDED.openai_conversation_id,
                        summary = EXCLUDED.summary,
                        last_language = EXCLUDED.last_language,
                        last_intent = EXCLUDED.last_intent,
                        slots_json = EXCLUDED.slots_json,
                        risk_json = EXCLUDED.risk_json,
                        counters_json = EXCLUDED.counters_json,
                        updated_at = EXCLUDED.updated_at
                    """
                )
                await db.execute(query, *params)
            else:
                query = self.db_manager._convert(
                    """
                    INSERT INTO ai_conversation_state
                    (workspace, user_id, status, owner_type, openai_conversation_id, summary, last_language, last_intent, slots_json, risk_json, counters_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(workspace, user_id) DO UPDATE SET
                        status = excluded.status,
                        owner_type = excluded.owner_type,
                        openai_conversation_id = excluded.openai_conversation_id,
                        summary = excluded.summary,
                        last_language = excluded.last_language,
                        last_intent = excluded.last_intent,
                        slots_json = excluded.slots_json,
                        risk_json = excluded.risk_json,
                        counters_json = excluded.counters_json,
                        updated_at = excluded.updated_at
                    """
                )
                await db.execute(query, params)
                await db.commit()

    async def _log_turn(self, **kwargs: Any) -> int:
        params = (
            kwargs.get("workspace"), kwargs.get("user_id"), kwargs.get("inbound_wa_message_id"),
            kwargs.get("openai_response_id"), kwargs.get("openai_conversation_id"), kwargs.get("turn_mode"),
            kwargs.get("turn_status"), kwargs.get("detected_language"), kwargs.get("detected_intent"),
            kwargs.get("emotion"), kwargs.get("confidence"), kwargs.get("action"), kwargs.get("reply_text"),
            json.dumps(kwargs.get("request_json") or {}, ensure_ascii=False),
            json.dumps(kwargs.get("response_json") or {}, ensure_ascii=False),
            json.dumps(kwargs.get("usage_json") or {}, ensure_ascii=False), kwargs.get("error_text"), kwargs.get("latency_ms"),
        )
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                INSERT INTO ai_turns
                (workspace, user_id, inbound_wa_message_id, openai_response_id, openai_conversation_id, turn_mode, turn_status, detected_language, detected_intent, emotion, confidence, action, reply_text, request_json, response_json, usage_json, error_text, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            if self.db_manager.use_postgres:
                await db.execute(query, *params)
                row = await db.fetchrow(
                    self.db_manager._convert("SELECT id FROM ai_turns WHERE workspace = ? AND user_id = ? ORDER BY id DESC LIMIT 1"),
                    kwargs.get("workspace"),
                    kwargs.get("user_id"),
                )
                return int(row["id"]) if row else 0
            cur = await db.execute(query, params)
            await db.commit()
            return int(cur.lastrowid or 0)

    async def _log_tool(self, *, workspace: str, user_id: str, turn_id: int, tool_name: str, ok: bool, request_json: dict[str, Any], response_json: dict[str, Any], error_code: str | None = None, latency_ms: int = 0) -> None:
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                "INSERT INTO ai_tool_logs (workspace, user_id, turn_id, tool_name, ok, request_json, response_json, error_code, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            params = (
                workspace, user_id, turn_id, tool_name, 1 if ok else 0,
                json.dumps(request_json or {}, ensure_ascii=False), json.dumps(response_json or {}, ensure_ascii=False), error_code, latency_ms,
            )
            if self.db_manager.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def _mark_handoff(self, *, user_id: str, output_data: dict[str, Any], workspace: str) -> dict[str, Any]:
        await self._sync_conversation_tags(user_id=user_id, add_tags=["ai-handoff", "needs-human"], remove_tags=["ai-resolved"])
        ticket = await self._create_handoff_ticket(
            user_id=user_id,
            workspace=workspace,
            reason_code=str(output_data.get("handoff_reason") or "sensitive_case").strip() or "sensitive_case",
            summary=str(output_data.get("state_summary") or "").strip(),
            priority="high" if str(output_data.get("urgency") or "").strip().lower() == "high" else "normal",
            context={
                "intent": output_data.get("intent"),
                "language": output_data.get("language"),
                "emotion": output_data.get("emotion"),
                "entities": output_data.get("entities") or {},
                "reply_text": output_data.get("reply_text") or "",
            },
        )
        assignment = await self.tools.assign_human_agent(user_id=user_id, workspace=workspace)
        try:
            await self.db_manager.add_note(
                {
                    "user_id": user_id,
                    "agent_username": "ai-agent",
                    "type": "text",
                    "text": (
                        f"AI handoff requested.\n"
                        f"Ticket: #{ticket.get('id') or '?'}\n"
                        f"Assigned agent: {(assignment.data or {}).get('agent_username') if assignment.ok else 'unassigned'}\n"
                        f"Intent: {output_data.get('intent') or ''}\n"
                        f"Reason: {output_data.get('handoff_reason') or 'sensitive_case'}\n"
                        f"Summary: {output_data.get('state_summary') or ''}"
                    ).strip(),
                }
            )
        except Exception:
            pass
        return {
            "create_handoff_ticket": {"ok": True, "data": ticket, "source": "inbox"},
            "assign_human_agent": assignment.as_response(),
        }

    async def _create_handoff_ticket(
        self,
        *,
        user_id: str,
        workspace: str,
        reason_code: str,
        summary: str,
        priority: str = "normal",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace)
        uid = str(user_id or "").strip()
        payload = (
            ws,
            uid,
            str(reason_code or "sensitive_case").strip() or "sensitive_case",
            str(priority or "normal").strip() or "normal",
            "open",
            None,
            summary or None,
            json.dumps(context or {}, ensure_ascii=False),
            datetime.utcnow().isoformat(),
            datetime.utcnow().isoformat(),
            None,
        )
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                INSERT INTO ai_handoff_tickets
                (workspace, user_id, reason_code, priority, status, assigned_agent, summary, context_json, created_at, updated_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            if self.db_manager.use_postgres:
                await db.execute(query, *payload)
                row = await db.fetchrow(
                    self.db_manager._convert(
                        "SELECT * FROM ai_handoff_tickets WHERE workspace = ? AND user_id = ? ORDER BY id DESC LIMIT 1"
                    ),
                    ws,
                    uid,
                )
            else:
                cur = await db.execute(query, payload)
                await db.commit()
                row = await db.execute_fetchone(
                    self.db_manager._convert(
                        "SELECT * FROM ai_handoff_tickets WHERE id = ?"
                    ),
                    (int(cur.lastrowid or 0),),
                ) if hasattr(db, "execute_fetchone") else None
                if row is None:
                    cur2 = await db.execute(
                        self.db_manager._convert(
                            "SELECT * FROM ai_handoff_tickets WHERE workspace = ? AND user_id = ? ORDER BY id DESC LIMIT 1"
                        ),
                        (ws, uid),
                    )
                    row = await cur2.fetchone()
        item = dict(row) if row else {
            "workspace": ws,
            "user_id": uid,
            "reason_code": reason_code,
            "priority": priority,
            "status": "open",
            "summary": summary,
            "context_json": context or {},
        }
        try:
            item["context_json"] = json.loads(item.get("context_json") or "{}")
        except Exception:
            item["context_json"] = context or {}
        return item

    async def _resolve_open_handoff_tickets(
        self,
        *,
        user_id: str,
        workspace: str,
        resolved_by: str | None = None,
        resolution_note: str | None = None,
    ) -> None:
        ws = self.normalize_workspace(workspace)
        uid = str(user_id or "").strip()
        if not uid:
            return
        ticket = await self.get_open_handoff_ticket(uid, ws)
        if not ticket:
            return
        context = dict(ticket.get("context_json") or {})
        if resolved_by:
            context["resolved_by"] = resolved_by
        if resolution_note:
            context["resolution_note"] = resolution_note
        now_iso = datetime.utcnow().isoformat()
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                UPDATE ai_handoff_tickets
                SET status = ?, context_json = ?, updated_at = ?, resolved_at = ?
                WHERE workspace = ? AND user_id = ? AND status IN ('open', 'assigned')
                """
            )
            params = ("resolved", json.dumps(context, ensure_ascii=False), now_iso, now_iso, ws, uid)
            if self.db_manager.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def _sync_conversation_tags(self, *, user_id: str, add_tags: list[str] | None = None, remove_tags: list[str] | None = None) -> list[str]:
        meta = await self.db_manager.get_conversation_meta(user_id)
        tags = [str(tag or "").strip() for tag in (meta.get("tags") or []) if str(tag or "").strip()]
        current = {tag.lower(): tag for tag in tags}
        for tag in add_tags or []:
            clean = str(tag or "").strip()
            if clean and clean.lower() not in current:
                tags.append(clean)
                current[clean.lower()] = clean
        remove_set = {str(tag or "").strip().lower() for tag in (remove_tags or []) if str(tag or "").strip()}
        if remove_set:
            tags = [tag for tag in tags if tag.lower() not in remove_set]
        try:
            await self.db_manager.set_conversation_tags(user_id, tags)
        except Exception:
            pass
        return tags

    async def _load_policy_docs_for_prompt(self, incoming_text: str, *, workspace: str) -> list[dict[str, Any]]:
        policies = await self.list_policies(workspace)
        if not policies:
            return []
        hay = incoming_text.lower()
        matched_topics: set[str] = set()
        for keyword, topic in (
            ("livraison", "delivery"),
            ("delivery", "delivery"),
            ("cod", "cod"),
            ("cash on delivery", "cod"),
            ("return", "return"),
            ("exchange", "exchange"),
            ("refund", "refund"),
            ("complaint", "complaint"),
            ("retour", "return"),
            ("échange", "exchange"),
        ):
            if keyword in hay:
                matched_topics.add(topic)
        if not matched_topics:
            matched_topics = {str(p.get("topic") or "") for p in policies[:4]}
        return [
            {"id": p.get("id"), "topic": p.get("topic"), "locale": p.get("locale"), "title": p.get("title"), "content": p.get("content")}
            for p in policies
            if str(p.get("status") or "approved") == "approved" and str(p.get("topic") or "") in matched_topics
        ][:6]

    async def _search_catalog_products(self, query: str, *, workspace: str, limit: int) -> list[dict[str, Any]]:
        result = await self.tools.search_catalog_products(query=query, workspace=workspace, limit=limit)
        return list(result.data.get("products") or []) if result.ok else []

    def _build_system_prompt(self, config: dict[str, Any]) -> str:
        return (
            f"{config.get('instructions')}\n\n"
            f"Business context:\n{config.get('business_context')}\n\n"
            "You have access to tools for customer lookup, orders, delivery, policies, stock, catalog messages, human assignment, and conversation status.\n"
            "Use tools whenever facts are needed. Use send tools only when you are ready to act. In shadow/suggest modes, send tools may dry-run.\n"
            "Return a JSON object only with this exact shape:\n"
            "{"
            "\"language\":\"darija|ar|fr|en|mixed\","
            "\"intent\":\"product_discovery|size_help|product_availability|delivery_question|cod_question|exchange_return|complaint|refund_request|order_follow_up|human_agent_request|other\","
            "\"confidence\":0.0,"
            "\"emotion\":\"neutral|frustrated|angry|urgent\","
            "\"urgency\":\"low|medium|high\","
            "\"should_handoff\":false,"
            "\"handoff_reason\":\"\","
            "\"conversation_status\":\"bot_managed|hybrid|human_managed|closed\","
            "\"policy_topics\":[],"
            "\"reply_text\":\"\","
            "\"recommended_product_ids\":[],"
            "\"entities\":{\"gender\":null,\"child_age\":null,\"size\":null,\"color\":null,\"product_type\":null,\"budget\":null,\"city\":null,\"order_number\":null},"
            "\"state_summary\":\"\""
            "}\n"
            "Rules: keep reply_text brief, do not invent unavailable products or policies, and hand off if the customer is angry, requests a human, or raises a refund/complaint risk."
        )

    def _build_user_prompt(self, turn_payload: dict[str, Any]) -> str:
        recent_lines = []
        for message in turn_payload.get("recent_messages") or []:
            who = "Agent" if bool(message.get("from_me")) else "Customer"
            body = str(message.get("message") or "").strip()
            if body:
                recent_lines.append(f"{who}: {body}")
        product_lines = [
            f"- {p.get('retailer_id')}: {p.get('name')} | price={p.get('price')} | qty={p.get('quantity')} | availability={p.get('availability')}"
            for p in (turn_payload.get("catalog_candidates") or [])
        ]
        stock_lines = [
            f"- {s.get('retailer_id')}: available={s.get('available')} qty={s.get('quantity')} availability={s.get('availability')}"
            for s in (turn_payload.get("stock_checks") or [])
        ]
        policy_lines = [
            f"- [{p.get('topic')}/{p.get('locale')}] {p.get('title')}: {p.get('content')}"
            for p in (turn_payload.get("policies") or [])
        ]
        return (
            f"Workspace: {turn_payload.get('workspace')}\n"
            f"Customer phone/user id: {turn_payload.get('user_id')}\n"
            f"Conversation state: {json.dumps(turn_payload.get('conversation_state') or {}, ensure_ascii=False)}\n"
            f"Customer profile: {json.dumps(turn_payload.get('customer_profile') or {}, ensure_ascii=False)}\n"
            f"Order context: {json.dumps(turn_payload.get('order_context') or {}, ensure_ascii=False)}\n"
            f"Delivery context: {json.dumps(turn_payload.get('delivery_context') or {}, ensure_ascii=False)}\n"
            f"Latest customer message: {turn_payload.get('incoming_message')}\n\n"
            f"Recent transcript:\n{chr(10).join(recent_lines[-12:]) if recent_lines else '(empty)'}\n\n"
            f"Catalog candidates:\n{chr(10).join(product_lines) if product_lines else '(none)'}\n\n"
            f"Stock checks:\n{chr(10).join(stock_lines) if stock_lines else '(none)'}\n\n"
            f"Approved policies:\n{chr(10).join(policy_lines) if policy_lines else '(none)'}\n"
        )

    def _tool_entry(self, tool_name: str, *, request_json: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return {
            "tool_name": tool_name,
            "ok": bool(result.get("ok")),
            "request_json": request_json,
            "response_json": result,
            "error_code": result.get("error_code"),
            "latency_ms": int(result.get("latency_ms") or 0),
        }

    def _extract_order_reference_candidate(self, text: str) -> str:
        raw = str(text or "")
        if not raw:
            return ""
        match = re.search(r"(?:#\s*)?(\d{4,})", raw)
        if not match:
            return ""
        return str(match.group(1) or "").strip()

    def _message_mentions_delivery(self, text: str) -> bool:
        hay = str(text or "").lower()
        return any(token in hay for token in ("delivery", "livraison", "tracking", "track", "توصيل", "تتبع"))

    def _message_mentions_order(self, text: str) -> bool:
        hay = str(text or "").lower()
        return any(token in hay for token in ("order", "commande", "طلب", "tracking", "delivery", "livraison"))

    def _response_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "name": "find_customer_by_phone",
                "description": "Look up a customer by phone number.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "phone_e164": {"type": "string"},
                    },
                    "required": ["phone_e164"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "search_catalog_products",
                "description": "Search WhatsApp catalog products using customer needs.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["query", "limit"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "check_stock_availability",
                "description": "Check availability for a catalog product.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "product_id": {"type": "string"},
                        "retailer_id": {"type": "string"},
                    },
                    "required": [],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "get_order_by_reference",
                "description": "Look up a Shopify order by reference using the customer phone.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "order_reference": {"type": "string"},
                        "phone_e164": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["order_reference"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "get_delivery_status",
                "description": "Fetch the latest delivery status snapshot for the conversation.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"},
                        "order_reference": {"type": "string"},
                    },
                    "required": ["user_id"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "get_business_policies",
                "description": "Fetch approved business policies by topic.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "topics": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["topics"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "mark_conversation_status",
                "description": "Update conversation ownership mode for bot, hybrid, or human handling.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "note": {"type": "string"},
                    },
                    "required": ["status"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "create_handoff_ticket",
                "description": "Create a formal AI handoff ticket for this conversation.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "reason_code": {"type": "string"},
                        "summary": {"type": "string"},
                        "priority": {"type": "string"},
                    },
                    "required": ["reason_code", "summary"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "assign_human_agent",
                "description": "Assign the conversation to a human agent.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "preferred_agent": {"type": "string"},
                    },
                    "required": [],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "send_text_reply",
                "description": "Send a WhatsApp text reply to the current customer.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                    },
                    "required": ["text"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "send_whatsapp_product_message",
                "description": "Send a single WhatsApp catalog product message.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "product_retailer_id": {"type": "string"},
                        "caption": {"type": "string"},
                    },
                    "required": ["product_retailer_id"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "send_whatsapp_catalog_message",
                "description": "Send a WhatsApp catalog or product set message.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "set_id": {"type": "string"},
                        "caption": {"type": "string"},
                    },
                    "required": ["set_id"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "send_whatsapp_product_carousel",
                "description": "Send multiple WhatsApp catalog products as a carousel/product list.",
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "product_retailer_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                    "required": ["product_retailer_ids"],
                    "additionalProperties": False,
                },
            },
        ]

    async def _execute_response_tool(
        self,
        *,
        name: str,
        arguments: dict[str, Any],
        turn_payload: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, Any]:
        ws = str(turn_payload.get("workspace") or self.get_workspace())
        user_id = str(turn_payload.get("user_id") or "").strip()
        run_mode = str(config.get("run_mode") or "shadow").strip().lower()

        if name == "find_customer_by_phone":
            return (await self.tools.find_customer_by_phone(
                phone_e164=str(arguments.get("phone_e164") or user_id),
                workspace=ws,
            )).as_response()
        if name == "search_catalog_products":
            return (await self.tools.search_catalog_products(
                query=str(arguments.get("query") or turn_payload.get("incoming_message") or ""),
                workspace=ws,
                limit=self._safe_int(arguments.get("limit"), default=int(config.get("catalog_results_limit") or 6)),
            )).as_response()
        if name == "check_stock_availability":
            return (await self.tools.check_stock_availability(
                product_id=str(arguments.get("product_id") or ""),
                retailer_id=str(arguments.get("retailer_id") or ""),
                workspace=ws,
            )).as_response()
        if name == "get_order_by_reference":
            return (await self.tools.get_order_by_reference(
                order_reference=str(arguments.get("order_reference") or ""),
                phone_e164=str(arguments.get("phone_e164") or user_id),
                workspace=ws,
                limit=self._safe_int(arguments.get("limit"), default=20),
            )).as_response()
        if name == "get_delivery_status":
            return (await self.tools.get_delivery_status(
                user_id=str(arguments.get("user_id") or user_id),
                order_reference=str(arguments.get("order_reference") or ""),
                workspace=ws,
            )).as_response()
        if name == "get_business_policies":
            topics = [str(topic or "").strip().lower() for topic in (arguments.get("topics") or []) if str(topic or "").strip()]
            policies = await self._load_policy_docs_for_topics(topics, workspace=ws)
            return {
                "ok": True,
                "data": {"policies": policies, "topics": topics},
                "source": "policy_store",
                "latency_ms": 0,
            }
        if name == "mark_conversation_status":
            status = str(arguments.get("status") or "").strip().lower()
            note = str(arguments.get("note") or "").strip() or None
            if run_mode != "autonomous":
                return {"ok": True, "data": {"dry_run": True, "status": status, "note": note}, "source": "inbox", "latency_ms": 0}
            overview = await self.update_conversation_mode(user_id=user_id, status=status, workspace=ws, actor_username="ai-agent", note=note)
            return {"ok": True, "data": overview, "source": "inbox", "latency_ms": 0}
        if name == "create_handoff_ticket":
            if run_mode != "autonomous":
                return {
                    "ok": True,
                    "data": {
                        "dry_run": True,
                        "reason_code": str(arguments.get("reason_code") or "sensitive_case"),
                        "summary": str(arguments.get("summary") or ""),
                        "priority": str(arguments.get("priority") or "normal"),
                    },
                    "source": "inbox",
                    "latency_ms": 0,
                }
            ticket = await self._create_handoff_ticket(
                user_id=user_id,
                workspace=ws,
                reason_code=str(arguments.get("reason_code") or "sensitive_case"),
                summary=str(arguments.get("summary") or ""),
                priority=str(arguments.get("priority") or "normal"),
                context={},
            )
            return {"ok": True, "data": ticket, "source": "inbox", "latency_ms": 0}
        if name == "assign_human_agent":
            if run_mode != "autonomous":
                return {
                    "ok": True,
                    "data": {
                        "dry_run": True,
                        "preferred_agent": str(arguments.get("preferred_agent") or "").strip() or None,
                    },
                    "source": "inbox",
                    "latency_ms": 0,
                }
            return (await self.tools.assign_human_agent(
                user_id=user_id,
                workspace=ws,
                preferred_agent=str(arguments.get("preferred_agent") or "").strip() or None,
            )).as_response()
        if name == "send_text_reply":
            return await self._execute_send_tool(
                run_mode=run_mode,
                tool_name=name,
                payload={"text": str(arguments.get("text") or "")},
                sender=lambda: self.message_processor.whatsapp_messenger.send_text_message(user_id, str(arguments.get("text") or "")),
            )
        if name == "send_whatsapp_product_message":
            product_retailer_id = str(arguments.get("product_retailer_id") or "").strip()
            caption = str(arguments.get("caption") or "").strip()
            return await self._execute_send_tool(
                run_mode=run_mode,
                tool_name=name,
                payload={"product_retailer_id": product_retailer_id, "caption": caption},
                sender=lambda: self.message_processor.whatsapp_messenger.send_single_catalog_item(user_id, product_retailer_id, caption),
            )
        if name == "send_whatsapp_catalog_message":
            set_id = str(arguments.get("set_id") or "").strip()
            caption = str(arguments.get("caption") or "").strip()
            return await self._execute_send_tool(
                run_mode=run_mode,
                tool_name=name,
                payload={"set_id": set_id, "caption": caption},
                sender=lambda: self.message_processor.whatsapp_messenger.send_full_set(user_id, set_id, caption),
            )
        if name == "send_whatsapp_product_carousel":
            product_ids = [str(item or "").strip() for item in (arguments.get("product_retailer_ids") or []) if str(item or "").strip()]
            return await self._execute_send_tool(
                run_mode=run_mode,
                tool_name=name,
                payload={"product_retailer_ids": product_ids},
                sender=lambda: self.message_processor.whatsapp_messenger.send_catalog_products(user_id, product_ids),
            )
        return {"ok": False, "data": {}, "source": "ai_agent", "error_code": "unknown_tool", "error_message": f"Unknown tool {name}", "latency_ms": 0}

    async def _execute_send_tool(
        self,
        *,
        run_mode: str,
        tool_name: str,
        payload: dict[str, Any],
        sender: Callable[[], Awaitable[Any]],
    ) -> dict[str, Any]:
        if run_mode != "autonomous":
            return {"ok": True, "data": {"dry_run": True, **payload}, "source": "whatsapp", "latency_ms": 0}
        started = time.perf_counter()
        result = await sender()
        return {
            "ok": True,
            "data": {"result": result, **payload},
            "source": "whatsapp",
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }

    async def _load_policy_docs_for_topics(self, topics: list[str], *, workspace: str) -> list[dict[str, Any]]:
        policies = await self.list_policies(workspace)
        topic_set = {str(topic or "").strip().lower() for topic in topics if str(topic or "").strip()}
        if not topic_set:
            return []
        return [
            {"id": p.get("id"), "topic": p.get("topic"), "locale": p.get("locale"), "title": p.get("title"), "content": p.get("content")}
            for p in policies
            if str(p.get("status") or "approved") == "approved" and str(p.get("topic") or "").strip().lower() in topic_set
        ][:8]

    def _extract_output_text(self, payload: dict[str, Any]) -> str:
        direct = payload.get("output_text")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        chunks: list[str] = []
        for item in payload.get("output") or []:
            if not isinstance(item, dict) or str(item.get("type") or "") != "message":
                continue
            for content in item.get("content") or []:
                if not isinstance(content, dict):
                    continue
                if str(content.get("type") or "") not in ("output_text", "text"):
                    continue
                text_value = content.get("text")
                if isinstance(text_value, str):
                    chunks.append(text_value)
                elif isinstance(text_value, dict):
                    maybe_value = text_value.get("value")
                    if isinstance(maybe_value, str):
                        chunks.append(maybe_value)
        return "\n".join([c for c in chunks if c]).strip()

    def _extract_json_object(self, text: str) -> dict[str, Any] | None:
        raw = str(text or "").strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            pass
        match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except Exception:
            return None

    def _safe_float(self, value: Any, *, default: float) -> float:
        try:
            return float(value)
        except Exception:
            return float(default)

    def _safe_int(self, value: Any, *, default: int) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)
