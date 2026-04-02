from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from .copilot import AgentCopilot
from .rag import PolicyRAG
from .validators import OutputValidator

from .tools import AIAgentToolDependencies, AIAgentToolbox
from .evals import load_eval_cases, score_results

DEFAULT_AGENT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "run_mode": "shadow",
    "model": "gpt-5.4-mini",
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
    "autonomous_eval_gate_enabled": True,
    "autonomous_min_fixture_pass_rate": 0.75,
    "autonomous_require_recent_fixture_eval_hours": 72,
    "autonomous_blocked_intents": ["refund_request", "complaint"],
    "replay_schedule_enabled": False,
    "replay_schedule_hour_local": 2,
    "replay_schedule_timezone": "Africa/Casablanca",
    "replay_schedule_sample_size": 10,
    "replay_schedule_transcript_messages": 12,
    "replay_schedule_labeled_only": False,
    "replay_alerts_enabled": True,
    "replay_alert_min_pass_rate": 0.75,
    "replay_alert_max_handoff_rate": 0.45,
    "test_numbers": [],
    "instructions": (
        "You are the AI customer service assistant for a Moroccan clothing and shoes retailer. "
        "LANGUAGE RULE: Always reply in the SAME language the customer is using. "
        "If the customer writes in Darija, reply in simple Arabic script. If they write in French, reply in French. If in English, reply in English. "
        "Never mix languages unless the customer does. Use Arabic script only (never Latin transliteration for Arabic/Darija). "
        "Never invent stock, policies, prices, delivery details, or order facts. "
        "Default to one short message only. Use the minimum words needed, ideally one or two short sentences. Ask at most one useful clarification question. "
        "Prefer recommending products and catalog sets that exist in the current inbox catalog. Escalate when "
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
    catalog_sets_provider: Callable[[str], Awaitable[list[dict[str, Any]]]]
    catalog_set_products_provider: Callable[[str, str, int], Awaitable[list[dict[str, Any]]]]
    catalog_filters_provider: Callable[[str], Awaitable[list[dict[str, Any]]]]
    fetch_customer_by_phone: Callable[[str, str], Awaitable[dict[str, Any] | None]]
    fetch_orders_for_customer: Callable[[str, str, int], Awaitable[list[dict[str, Any]]]]
    fetch_delivery_snapshot: Callable[[str, str | None, str], Awaitable[dict[str, Any] | None]]
    list_agents: Callable[[], Awaitable[list[dict[str, Any]]]]
    get_agent_last_seen: Callable[[str, str], Awaitable[float | None]]
    get_agent_assignment_count: Callable[[str, str], Awaitable[int]]
    set_conversation_assignment: Callable[[str, str | None], Awaitable[None]]
    push_workspace: Callable[[str], Any]
    pop_workspace: Callable[[Any], None]
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
        self.push_workspace = deps.push_workspace
        self.pop_workspace = deps.pop_workspace
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
                catalog_sets_provider=deps.catalog_sets_provider,
                catalog_set_products_provider=deps.catalog_set_products_provider,
                catalog_filters_provider=deps.catalog_filters_provider,
                logger=self.log,
            )
        )
        # --- New modules: RAG, Copilot, Validators ---
        self.rag = PolicyRAG(
            db_manager=self.db_manager,
            get_api_key=self._get_openai_api_key,
        )
        self.copilot = AgentCopilot(
            db_manager=self.db_manager,
            get_api_key=self._get_openai_api_key,
            get_config=self.get_config,
            list_policies=self.list_policies,
        )
        self.validator = OutputValidator()

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
                """
                CREATE TABLE IF NOT EXISTS ai_eval_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    run_type TEXT NOT NULL,
                    label TEXT,
                    model TEXT,
                    status TEXT NOT NULL DEFAULT 'running',
                    sample_size INTEGER DEFAULT 0,
                    config_json TEXT,
                    summary_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    completed_at TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ai_eval_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    workspace TEXT NOT NULL,
                    case_key TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    user_id TEXT,
                    transcript_json TEXT,
                    expected_json TEXT,
                    output_json TEXT,
                    score_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ai_eval_expectations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    label TEXT,
                    expected_intent TEXT,
                    expected_should_handoff INTEGER NOT NULL DEFAULT 0,
                    expected_tool_names_json TEXT,
                    notes TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS ai_eval_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    run_id INTEGER,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    payload_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                "CREATE UNIQUE INDEX IF NOT EXISTS uniq_ai_state_ws_user ON ai_conversation_state (workspace, user_id)",
                "CREATE INDEX IF NOT EXISTS idx_ai_turns_ws_user_created ON ai_turns (workspace, user_id, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ai_policy_ws_topic ON ai_policy_docs (workspace, topic, locale, status)",
                "CREATE INDEX IF NOT EXISTS idx_ai_handoff_ws_user_status ON ai_handoff_tickets (workspace, user_id, status, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ai_eval_runs_ws_created ON ai_eval_runs (workspace, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ai_eval_results_run ON ai_eval_results (run_id, created_at ASC)",
                "CREATE UNIQUE INDEX IF NOT EXISTS uniq_ai_eval_expectations_ws_user ON ai_eval_expectations (workspace, user_id)",
                "CREATE INDEX IF NOT EXISTS idx_ai_eval_alerts_ws_created ON ai_eval_alerts (workspace, created_at DESC)",
                """
                CREATE TABLE IF NOT EXISTS ai_policy_embeddings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    policy_id INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                "CREATE UNIQUE INDEX IF NOT EXISTS uniq_ai_policy_emb_ws_pid ON ai_policy_embeddings (workspace, policy_id)",
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
        if str(config.get("model") or "").strip().lower() in {"", "gpt-5.1"}:
            config["model"] = DEFAULT_AGENT_CONFIG["model"]
        config["test_numbers"] = self._normalize_test_numbers(config.get("test_numbers"))
        config["autonomous_blocked_intents"] = self._normalize_string_list(config.get("autonomous_blocked_intents"))
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
        if str(merged.get("model") or "").strip().lower() in {"", "gpt-5.1"}:
            merged["model"] = DEFAULT_AGENT_CONFIG["model"]
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
            "autonomous_eval_gate_enabled",
            "autonomous_min_fixture_pass_rate",
            "autonomous_require_recent_fixture_eval_hours",
            "autonomous_blocked_intents",
            "replay_schedule_enabled",
            "replay_schedule_hour_local",
            "replay_schedule_timezone",
            "replay_schedule_sample_size",
            "replay_schedule_transcript_messages",
            "replay_schedule_labeled_only",
            "replay_alerts_enabled",
            "replay_alert_min_pass_rate",
            "replay_alert_max_handoff_rate",
            "test_numbers",
            "instructions",
            "business_context",
            "supported_languages",
        ):
            if key in payload:
                if key == "test_numbers":
                    merged[key] = self._normalize_test_numbers(payload.get(key))
                elif key in {"autonomous_blocked_intents"}:
                    merged[key] = self._normalize_string_list(payload.get(key))
                else:
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

    # ------------------------------------------------------------------
    #  Helper: get OpenAI API key (used by RAG + Copilot modules)
    # ------------------------------------------------------------------
    async def _get_openai_api_key(self) -> str:
        ws = self.normalize_workspace(self.get_workspace())
        config = await self.get_config(ws)
        return str(config.get("_openai_api_key") or "").strip()

    # ------------------------------------------------------------------
    #  Copilot: human-assist reply suggestions
    # ------------------------------------------------------------------
    async def get_copilot_suggestion(
        self,
        user_id: str,
        workspace: str | None = None,
        agent_username: str | None = None,
    ) -> dict[str, Any]:
        """Generate a draft reply suggestion for a human agent."""
        ws = self.normalize_workspace(workspace or self.get_workspace())
        return await self.copilot.generate_suggestion(
            user_id=user_id,
            workspace=ws,
            agent_username=agent_username,
        )

    async def get_copilot_summary(
        self,
        user_id: str,
        workspace: str | None = None,
    ) -> dict[str, Any]:
        """Generate a concise conversation summary for handoff."""
        ws = self.normalize_workspace(workspace or self.get_workspace())
        return await self.copilot.summarize_conversation(
            user_id=user_id,
            workspace=ws,
        )

    # ------------------------------------------------------------------
    #  RAG: semantic policy retrieval
    # ------------------------------------------------------------------
    async def rebuild_policy_embeddings(self, workspace: str | None = None) -> dict[str, Any]:
        """Re-embed all policies for semantic search. Call after policy CRUD."""
        ws = self.normalize_workspace(workspace or self.get_workspace())
        await self.ensure_schema()
        policies = await self.list_policies(ws)
        return await self.rag.rebuild_embeddings(workspace=ws, policies=policies)

    async def search_policies_semantic(
        self,
        query: str,
        workspace: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Search policies using semantic vector similarity."""
        ws = self.normalize_workspace(workspace or self.get_workspace())
        policies = await self.list_policies(ws)
        return await self.rag.search_policies(
            query,
            workspace=ws,
            policies=policies,
            limit=limit,
        )

    # ------------------------------------------------------------------
    #  Shopify policy import + Arabic translation
    # ------------------------------------------------------------------
    async def import_shopify_policies(
        self,
        workspace: str | None = None,
        translate_to_arabic: bool = True,
    ) -> dict[str, Any]:
        """Fetch store policies from Shopify and import them as AI policy docs.

        Optionally translates each policy to Arabic and stores both versions.
        After import, rebuilds policy embeddings for semantic search.
        """
        ws = self.normalize_workspace(workspace or self.get_workspace())
        await self.ensure_schema()

        # Resolve Shopify credentials
        try:
            from ..shopify_integration import _shopify_http_context
            base, extra_args, _store_used, _store_prefix = await _shopify_http_context(None, ws)
            shopify_headers = {}
            if isinstance(extra_args, dict):
                shopify_headers = extra_args.get("headers") or {}
        except Exception as exc:
            return {"ok": False, "error": f"Could not resolve Shopify credentials: {exc}"}

        # Define the upsert callback for the RAG module
        async def _upsert_callback(
            workspace: str,
            topic: str,
            locale: str,
            title: str,
            content: str,
            source: str = "",
        ) -> dict[str, Any]:
            return await self.upsert_policy(
                {
                    "topic": topic,
                    "locale": locale,
                    "title": title,
                    "content": content,
                    "status": "approved",
                    "version": f"shopify-import-{source}",
                },
                workspace=workspace,
            )

        result = await self.rag.import_shopify_policies(
            workspace=ws,
            shopify_base=base,
            shopify_headers=shopify_headers,
            upsert_policy=_upsert_callback,
            translate_to_arabic=translate_to_arabic,
        )

        # Rebuild embeddings after import
        if result.get("ok"):
            try:
                embed_result = await self.rebuild_policy_embeddings(ws)
                result["embeddings"] = embed_result
            except Exception as exc:
                result["embeddings_error"] = str(exc)

        return result

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

    async def list_eval_runs(
        self,
        workspace: str | None = None,
        limit: int = 20,
        *,
        run_type: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        lim = max(1, min(int(limit or 20), 100))
        async with self.db_manager._conn() as db:
            clauses = ["workspace = ?"]
            params: list[Any] = [ws]
            clean_run_type = str(run_type or "").strip().lower()
            clean_status = str(status or "").strip().lower()
            if clean_run_type:
                clauses.append("run_type = ?")
                params.append(clean_run_type)
            if clean_status:
                clauses.append("status = ?")
                params.append(clean_status)
            params.append(lim)
            query = self.db_manager._convert(
                f"SELECT * FROM ai_eval_runs WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?"
            )
            if self.db_manager.use_postgres:
                rows = await db.fetch(query, *params)
            else:
                cur = await db.execute(query, tuple(params))
                rows = await cur.fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            for key in ("config_json", "summary_json"):
                try:
                    item[key] = json.loads(item.get(key) or "{}")
                except Exception:
                    item[key] = {}
            items.append(item)
        return items

    async def list_eval_expectations(self, workspace: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        lim = max(1, min(int(limit or 50), 200))
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                "SELECT * FROM ai_eval_expectations WHERE workspace = ? ORDER BY updated_at DESC, id DESC LIMIT ?"
            )
            if self.db_manager.use_postgres:
                rows = await db.fetch(query, ws, lim)
            else:
                cur = await db.execute(query, (ws, lim))
                rows = await cur.fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["expected_tool_names_json"] = json.loads(item.get("expected_tool_names_json") or "[]")
            except Exception:
                item["expected_tool_names_json"] = []
            item["expected_should_handoff"] = bool(item.get("expected_should_handoff"))
            item["active"] = bool(item.get("active"))
            items.append(item)
        return items

    async def upsert_eval_expectation(self, payload: dict[str, Any], workspace: str | None = None) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        user_id = str(payload.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        label = str(payload.get("label") or "").strip()
        expected_intent = str(payload.get("expected_intent") or "").strip()
        expected_should_handoff = bool(payload.get("expected_should_handoff"))
        expected_tool_names = self._normalize_string_list(payload.get("expected_tool_names"))
        notes = str(payload.get("notes") or "").strip()
        active = bool(payload.get("active", True))
        now_iso = datetime.utcnow().isoformat()
        existing = await self.get_eval_expectation_by_user_id(user_id, ws)
        async with self.db_manager._conn() as db:
            if existing:
                query = self.db_manager._convert(
                    """
                    UPDATE ai_eval_expectations
                    SET label = ?, expected_intent = ?, expected_should_handoff = ?, expected_tool_names_json = ?, notes = ?, active = ?, updated_at = ?
                    WHERE workspace = ? AND user_id = ?
                    """
                )
                params = (
                    label,
                    expected_intent,
                    1 if expected_should_handoff else 0,
                    json.dumps(expected_tool_names, ensure_ascii=False),
                    notes,
                    1 if active else 0,
                    now_iso,
                    ws,
                    user_id,
                )
                if self.db_manager.use_postgres:
                    await db.execute(query, *params)
                else:
                    await db.execute(query, params)
                    await db.commit()
            else:
                query = self.db_manager._convert(
                    """
                    INSERT INTO ai_eval_expectations
                    (workspace, user_id, label, expected_intent, expected_should_handoff, expected_tool_names_json, notes, active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                )
                params = (
                    ws,
                    user_id,
                    label,
                    expected_intent,
                    1 if expected_should_handoff else 0,
                    json.dumps(expected_tool_names, ensure_ascii=False),
                    notes,
                    1 if active else 0,
                    now_iso,
                    now_iso,
                )
                if self.db_manager.use_postgres:
                    await db.execute(query, *params)
                else:
                    await db.execute(query, params)
                    await db.commit()
        item = await self.get_eval_expectation_by_user_id(user_id, ws)
        return item or {}

    async def get_eval_expectation_by_user_id(self, user_id: str, workspace: str | None = None) -> dict[str, Any] | None:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        uid = str(user_id or "").strip()
        if not uid:
            return None
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                "SELECT * FROM ai_eval_expectations WHERE workspace = ? AND user_id = ? LIMIT 1"
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
            item["expected_tool_names_json"] = json.loads(item.get("expected_tool_names_json") or "[]")
        except Exception:
            item["expected_tool_names_json"] = []
        item["expected_should_handoff"] = bool(item.get("expected_should_handoff"))
        item["active"] = bool(item.get("active"))
        return item

    async def delete_eval_expectation(self, user_id: str, workspace: str | None = None) -> None:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        uid = str(user_id or "").strip()
        if not uid:
            return
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert("DELETE FROM ai_eval_expectations WHERE workspace = ? AND user_id = ?")
            if self.db_manager.use_postgres:
                await db.execute(query, ws, uid)
            else:
                await db.execute(query, (ws, uid))
                await db.commit()

    async def list_eval_alerts(self, workspace: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        lim = max(1, min(int(limit or 20), 100))
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                "SELECT * FROM ai_eval_alerts WHERE workspace = ? ORDER BY created_at DESC, id DESC LIMIT ?"
            )
            if self.db_manager.use_postgres:
                rows = await db.fetch(query, ws, lim)
            else:
                cur = await db.execute(query, (ws, lim))
                rows = await cur.fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["payload_json"] = json.loads(item.get("payload_json") or "{}")
            except Exception:
                item["payload_json"] = {}
            out.append(item)
        return out

    async def create_eval_alert(
        self,
        *,
        workspace: str,
        run_id: int | None,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace)
        now_iso = datetime.utcnow().isoformat()
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                INSERT INTO ai_eval_alerts
                (workspace, run_id, alert_type, severity, title, message, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            params = (
                ws,
                int(run_id) if run_id else None,
                str(alert_type or "").strip(),
                str(severity or "warning").strip(),
                str(title or "").strip(),
                str(message or "").strip(),
                json.dumps(payload or {}, ensure_ascii=False),
                now_iso,
            )
            if self.db_manager.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()
        items = await self.list_eval_alerts(ws, limit=1)
        return items[0] if items else {}

    async def run_scheduled_replay_if_due(self, workspace: str | None = None, *, force: bool = False) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        config = await self.get_config(ws)
        if (not force) and (not bool(config.get("replay_schedule_enabled"))):
            return {"workspace": ws, "ran": False, "reason": "schedule_disabled"}
        timezone_name = str(config.get("replay_schedule_timezone") or "Africa/Casablanca").strip() or "Africa/Casablanca"
        local_now = self._local_now(timezone_name)
        scheduled_hour = max(0, min(int(config.get("replay_schedule_hour_local") or 2), 23))
        if (not force) and local_now.hour < scheduled_hour:
            return {"workspace": ws, "ran": False, "reason": "before_scheduled_hour", "local_hour": local_now.hour}
        marker_key = self.make_settings_key("ai_agent_replay_schedule_marker", ws)
        marker_value = await self.db_manager.get_setting(marker_key)
        marker_day = str(marker_value or "").strip()
        today_key = local_now.date().isoformat()
        if (not force) and marker_day == today_key:
            return {"workspace": ws, "ran": False, "reason": "already_ran_today", "local_day": today_key}
        run = await self.run_conversation_replay_eval(
            ws,
            limit=max(1, min(int(config.get("replay_schedule_sample_size") or 10), 100)),
            label=f"Nightly replay {local_now.isoformat()}",
            transcript_messages=max(4, min(int(config.get("replay_schedule_transcript_messages") or 12), 40)),
            labeled_only=bool(config.get("replay_schedule_labeled_only")),
        )
        if not force:
            await self.db_manager.set_setting(marker_key, today_key)
        alerts = await self._create_replay_alerts_for_run(ws, run, config)
        return {
            "workspace": ws,
            "ran": True,
            "run": run,
            "alerts": alerts,
            "local_day": today_key,
            "local_hour": local_now.hour,
        }

    async def get_eval_run(self, run_id: int, workspace: str | None = None) -> dict[str, Any] | None:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert("SELECT * FROM ai_eval_runs WHERE workspace = ? AND id = ? LIMIT 1")
            if self.db_manager.use_postgres:
                row = await db.fetchrow(query, ws, int(run_id))
            else:
                cur = await db.execute(query, (ws, int(run_id)))
                row = await cur.fetchone()
            if not row:
                return None
            result_query = self.db_manager._convert(
                "SELECT * FROM ai_eval_results WHERE workspace = ? AND run_id = ? ORDER BY created_at ASC, id ASC"
            )
            if self.db_manager.use_postgres:
                result_rows = await db.fetch(result_query, ws, int(run_id))
            else:
                cur2 = await db.execute(result_query, (ws, int(run_id)))
                result_rows = await cur2.fetchall()
        item = dict(row)
        for key in ("config_json", "summary_json"):
            try:
                item[key] = json.loads(item.get(key) or "{}")
            except Exception:
                item[key] = {}
        results: list[dict[str, Any]] = []
        for row0 in result_rows:
            out = dict(row0)
            for key in ("transcript_json", "expected_json", "output_json", "score_json"):
                try:
                    out[key] = json.loads(out.get(key) or "{}")
                except Exception:
                    out[key] = [] if key == "transcript_json" else {}
            results.append(out)
        item["results"] = results
        return item

    async def compare_eval_runs(
        self,
        left_run_id: int,
        right_run_id: int,
        workspace: str | None = None,
    ) -> dict[str, Any] | None:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        left = await self.get_eval_run(int(left_run_id), ws)
        right = await self.get_eval_run(int(right_run_id), ws)
        if not left or not right:
            return None
        left_summary = dict((left.get("summary_json") or {}).get("summary") or {})
        right_summary = dict((right.get("summary_json") or {}).get("summary") or {})
        numeric_keys = ("pass_rate", "passed_cases", "total_cases", "sampled_conversations", "handoff_count")
        summary_delta: dict[str, Any] = {}
        for key in numeric_keys:
            left_value = self._safe_float(left_summary.get(key), default=0.0)
            right_value = self._safe_float(right_summary.get(key), default=0.0)
            if key in {"passed_cases", "total_cases", "sampled_conversations", "handoff_count"}:
                left_value = int(left_summary.get(key) or 0)
                right_value = int(right_summary.get(key) or 0)
            summary_delta[key] = {
                "left": left_value,
                "right": right_value,
                "delta": round(right_value - left_value, 4) if isinstance(left_value, float) else int(right_value - left_value),
            }
        left_cases = self._build_eval_case_index(left.get("results") or [])
        right_cases = self._build_eval_case_index(right.get("results") or [])
        case_diffs: list[dict[str, Any]] = []
        for case_key in sorted(set(left_cases) | set(right_cases)):
            left_case = left_cases.get(case_key) or {}
            right_case = right_cases.get(case_key) or {}
            left_passed = bool((left_case.get("score_json") or {}).get("passed"))
            right_passed = bool((right_case.get("score_json") or {}).get("passed"))
            changed = (
                left_passed != right_passed
                or str((left_case.get("output_json") or {}).get("intent") or "") != str((right_case.get("output_json") or {}).get("intent") or "")
                or bool((left_case.get("output_json") or {}).get("should_handoff")) != bool((right_case.get("output_json") or {}).get("should_handoff"))
            )
            if not changed:
                continue
            case_diffs.append(
                {
                    "case_key": case_key,
                    "left_passed": left_passed,
                    "right_passed": right_passed,
                    "left_intent": str((left_case.get("output_json") or {}).get("intent") or ""),
                    "right_intent": str((right_case.get("output_json") or {}).get("intent") or ""),
                    "left_should_handoff": bool((left_case.get("output_json") or {}).get("should_handoff")),
                    "right_should_handoff": bool((right_case.get("output_json") or {}).get("should_handoff")),
                }
            )
        return {
            "workspace": ws,
            "left_run": {
                "id": left.get("id"),
                "run_type": left.get("run_type"),
                "label": left.get("label"),
                "created_at": left.get("created_at"),
                "summary": left_summary,
            },
            "right_run": {
                "id": right.get("id"),
                "run_type": right.get("run_type"),
                "label": right.get("label"),
                "created_at": right.get("created_at"),
                "summary": right_summary,
            },
            "summary_delta": summary_delta,
            "case_diffs": case_diffs[:50],
        }

    async def get_autonomous_eval_gate_status(
        self,
        workspace: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        cfg = config or await self.get_config(ws)
        enabled = bool(cfg.get("autonomous_eval_gate_enabled"))
        threshold = self._safe_float(cfg.get("autonomous_min_fixture_pass_rate"), default=0.75)
        freshness_limit_hours = max(1, int(cfg.get("autonomous_require_recent_fixture_eval_hours") or 72))
        latest_runs = await self.list_eval_runs(ws, limit=1, run_type="fixture", status="completed")
        latest_run = latest_runs[0] if latest_runs else None
        pass_rate = self._safe_float(((latest_run or {}).get("summary_json") or {}).get("summary", {}).get("pass_rate"), default=0.0)
        completed_at = str((latest_run or {}).get("completed_at") or (latest_run or {}).get("created_at") or "").strip()
        age_hours: float | None = None
        recent_enough = False
        if completed_at:
            try:
                completed_dt = datetime.fromisoformat(completed_at)
                age_hours = max(0.0, round((datetime.utcnow() - completed_dt).total_seconds() / 3600.0, 2))
                recent_enough = age_hours <= freshness_limit_hours
            except Exception:
                age_hours = None
                recent_enough = False
        threshold_met = pass_rate >= threshold if latest_run else False
        blocking = bool(enabled and (not latest_run or not recent_enough or not threshold_met))
        if not enabled:
            reason_code = "disabled"
            message = "Eval gate is disabled. Autonomous mode will not be blocked by fixture eval freshness or pass rate."
        elif not latest_run:
            reason_code = "missing_fixture_eval"
            message = "Autonomous mode is blocked until a fixture eval has been run for this workspace."
        elif not recent_enough:
            reason_code = "stale_fixture_eval"
            message = f"Autonomous mode is blocked because the latest fixture eval is older than {freshness_limit_hours} hours."
        elif not threshold_met:
            reason_code = "pass_rate_too_low"
            message = f"Autonomous mode is blocked because the latest fixture eval pass rate is below {threshold:.2f}."
        else:
            reason_code = "ready"
            message = "Autonomous mode is allowed by the current fixture eval gate."
        return {
            "workspace": ws,
            "enabled": enabled,
            "blocking": blocking,
            "reason_code": reason_code,
            "message": message,
            "latest_run_id": latest_run.get("id") if latest_run else None,
            "latest_run_label": latest_run.get("label") if latest_run else None,
            "latest_completed_at": completed_at or None,
            "latest_pass_rate": pass_rate if latest_run else None,
            "threshold": threshold,
            "age_hours": age_hours,
            "freshness_limit_hours": freshness_limit_hours,
            "recent_enough": recent_enough,
            "threshold_met": threshold_met,
        }

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

    async def run_fixture_eval(self, workspace: str | None = None, label: str | None = None) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        await self.ensure_schema()
        config = await self.get_config(ws)
        run_id = await self._create_eval_run(
            workspace=ws,
            run_type="fixture",
            label=label or "Fixture eval",
            model=str(config.get("model") or DEFAULT_AGENT_CONFIG["model"]),
            sample_size=0,
            config_json=self._safe_eval_config_snapshot(config),
        )
        try:
            cases = load_eval_cases(Path(__file__).with_name("eval_cases.json"))
            outputs: list[dict[str, Any]] = []
            for case in cases:
                result = await self._run_eval_case(
                    config=config,
                    workspace=ws,
                    transcript=case.transcript,
                    user_id=f"eval:{case.case_id}",
                )
                tool_names = [str(entry.get("tool_name") or "") for entry in (result.get("executed_tools") or []) if str(entry.get("tool_name") or "").strip()]
                outputs.append(
                    {
                        "case_id": case.case_id,
                        "intent": result.get("output", {}).get("intent"),
                        "should_handoff": bool(result.get("output", {}).get("should_handoff")),
                        "tool_names": tool_names,
                    }
                )
                score_blob = {
                    "intent_ok": str(result.get("output", {}).get("intent") or "") == case.expected.intent,
                    "handoff_ok": bool(result.get("output", {}).get("should_handoff")) == case.expected.should_handoff,
                    "tools_present": [tool for tool in case.expected.tool_names if tool in tool_names],
                }
                await self._insert_eval_result(
                    run_id=run_id,
                    workspace=ws,
                    case_key=case.case_id,
                    source_type="fixture",
                    user_id=None,
                    transcript=case.transcript,
                    expected={
                        "intent": case.expected.intent,
                        "should_handoff": case.expected.should_handoff,
                        "tool_names": case.expected.tool_names,
                    },
                    output=result.get("output") or {},
                    score=score_blob,
                )
            report = score_results(cases, outputs)
            await self._complete_eval_run(run_id=run_id, workspace=ws, summary_json=report)
        except Exception as exc:
            await self._complete_eval_run(
                run_id=run_id,
                workspace=ws,
                summary_json={"error": str(exc)},
                status="failed",
            )
            raise
        run = await self.get_eval_run(run_id, ws)
        return run or {"id": run_id, "workspace": ws}

    async def run_conversation_replay_eval(
        self,
        workspace: str | None = None,
        *,
        limit: int = 10,
        label: str | None = None,
        user_ids: list[str] | None = None,
        transcript_messages: int = 12,
        labeled_only: bool = False,
    ) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        await self.ensure_schema()
        config = await self.get_config(ws)
        run_id = await self._create_eval_run(
            workspace=ws,
            run_type="replay",
            label=label or "Replay eval",
            model=str(config.get("model") or DEFAULT_AGENT_CONFIG["model"]),
            sample_size=max(0, len(user_ids or [])) or int(limit or 10),
            config_json=self._safe_eval_config_snapshot(config),
        )
        try:
            expectations = await self.list_eval_expectations(ws, limit=max(10, int(limit or 10) * 5))
            expectations_by_user = {
                str(item.get("user_id") or "").strip(): item
                for item in expectations
                if bool(item.get("active")) and str(item.get("user_id") or "").strip()
            }
            if labeled_only:
                candidates = list(expectations_by_user.keys())[: max(1, min(int(limit or 10), 100))]
            else:
                candidates = user_ids or await self._select_eval_conversations(workspace=ws, limit=max(1, min(int(limit or 10), 50)))
            summary_rows: list[dict[str, Any]] = []
            for user_id in candidates:
                transcript = await self._load_eval_transcript(user_id, workspace=ws, limit=transcript_messages)
                if not transcript:
                    continue
                expectation = expectations_by_user.get(str(user_id))
                result = await self._run_eval_case(
                    config=config,
                    workspace=ws,
                    transcript=transcript,
                    user_id=user_id,
                )
                output = result.get("output") or {}
                executed_tools = result.get("executed_tools") or []
                tool_names = [str(entry.get("tool_name") or "") for entry in executed_tools if str(entry.get("tool_name") or "").strip()]
                expected_tools = self._normalize_string_list((expectation or {}).get("expected_tool_names_json"))
                expected_intent = str((expectation or {}).get("expected_intent") or "").strip()
                has_expectation = bool(expectation and (expected_intent or expected_tools or "expected_should_handoff" in expectation))
                score_blob = self._score_replay_output(
                    expectation=expectation,
                    output=output,
                    tool_names=tool_names,
                )
                await self._insert_eval_result(
                    run_id=run_id,
                    workspace=ws,
                    case_key=str(user_id),
                    source_type="conversation",
                    user_id=str(user_id),
                    transcript=transcript,
                    expected={
                        "label": (expectation or {}).get("label"),
                        "intent": expected_intent,
                        "should_handoff": bool((expectation or {}).get("expected_should_handoff")) if expectation else None,
                        "tool_names": expected_tools,
                        "notes": (expectation or {}).get("notes"),
                    } if expectation else {},
                    output={
                        **output,
                        "tool_names": tool_names,
                    },
                    score=score_blob,
                )
                summary_rows.append(
                    {
                        "user_id": user_id,
                        "intent": output.get("intent"),
                        "should_handoff": bool(output.get("should_handoff")),
                        "tool_names": tool_names,
                        "scored": has_expectation,
                        "passed": score_blob.get("passed"),
                    }
                )
            scored_rows = [row for row in summary_rows if row.get("scored")]
            passed_rows = [row for row in scored_rows if row.get("passed")]
            await self._complete_eval_run(
                run_id=run_id,
                workspace=ws,
                summary_json={
                    "summary": {
                        "sampled_conversations": len(summary_rows),
                        "handoff_count": sum(1 for row in summary_rows if row.get("should_handoff")),
                        "scored_cases": len(scored_rows),
                        "passed_cases": len(passed_rows),
                        "pass_rate": round((len(passed_rows) / len(scored_rows)), 4) if scored_rows else None,
                        "labeled_only": bool(labeled_only),
                    },
                    "rows": summary_rows,
                },
            )
        except Exception as exc:
            await self._complete_eval_run(
                run_id=run_id,
                workspace=ws,
                summary_json={"error": str(exc)},
                status="failed",
            )
            raise
        run = await self.get_eval_run(run_id, ws)
        return run or {"id": run_id, "workspace": ws}

    async def get_conversation_overview(self, user_id: str, workspace: str | None = None, limit: int = 8) -> dict[str, Any]:
        ws = self.normalize_workspace(workspace or self.get_workspace())
        uid = str(user_id or "").strip()
        state = await self._get_conversation_state(user_id=uid, workspace=ws)
        turns = await self.list_recent_turns_for_user(uid, ws, limit=limit)
        ticket = await self.get_open_handoff_ticket(uid, ws)
        last_turn = turns[0] if turns else None
        last_skip_reason = str((state.get("risk_json") or {}).get("last_skip_reason") or "").strip()
        last_skip_turn = next((turn for turn in turns if str(turn.get("turn_status") or "") == "skipped"), None)
        if last_skip_turn and str(last_skip_turn.get("action") or "").strip():
            last_skip_reason = str(last_skip_turn.get("action") or "").strip()
        return {
            "workspace": ws,
            "user_id": uid,
            "state": state,
            "open_handoff_ticket": ticket,
            "recent_turns": turns,
            "last_turn": last_turn,
            "last_skip_reason": last_skip_reason,
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
        user_id = str(message_obj.get("user_id") or "").strip()
        inbound_wamid = str(message_obj.get("wa_message_id") or "").strip()
        incoming_text = str(message_obj.get("message") or "").strip()
        msg_type = str(message_obj.get("type") or "").strip()
        if not bool(config.get("enabled")):
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="disabled",
                config=config,
                message_obj=message_obj,
            )
            return {"handled": False, "skip_legacy": False, "reason": "disabled", "turn_id": turn_id}
        if msg_type != "text":
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="non_text",
                config=config,
                message_obj=message_obj,
            )
            return {"handled": False, "skip_legacy": False, "reason": "non_text", "turn_id": turn_id}
        if not str(config.get("_openai_api_key") or "").strip():
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="missing_api_key",
                config=config,
                message_obj=message_obj,
            )
            return {"handled": False, "skip_legacy": False, "reason": "missing_api_key", "turn_id": turn_id}

        if not user_id or not incoming_text:
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="missing_input",
                config=config,
                message_obj=message_obj,
            )
            return {"handled": False, "skip_legacy": False, "reason": "missing_input", "turn_id": turn_id}
        allowed_test_numbers = self._normalize_test_numbers(config.get("test_numbers"))
        if allowed_test_numbers and not self._is_test_number_allowed(user_id, allowed_test_numbers):
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="not_test_number",
                config=config,
                message_obj=message_obj,
            )
            return {"handled": False, "skip_legacy": False, "reason": "not_test_number", "turn_id": turn_id}

        await self.ensure_schema()
        if inbound_wamid and await self._has_completed_turn_for_inbound_message(workspace=ws, inbound_wa_message_id=inbound_wamid):
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="duplicate_inbound",
                config=config,
                message_obj=message_obj,
            )
            return {"handled": True, "skip_legacy": True, "reason": "duplicate_inbound", "turn_id": turn_id}
        meta = await self.db_manager.get_conversation_meta(user_id)
        assigned_agent = str((meta or {}).get("assigned_agent") or "").strip()
        if assigned_agent:
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="human_assigned",
                config=config,
                message_obj=message_obj,
            )
            return {"handled": False, "skip_legacy": False, "reason": "human_assigned", "turn_id": turn_id}

        state = await self._get_conversation_state(user_id=user_id, workspace=ws)
        if str(state.get("status") or "") == "human_managed":
            turn_id = await self._record_skip(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                reason="human_managed",
                config=config,
                state=state,
                message_obj=message_obj,
            )
            return {"handled": False, "skip_legacy": False, "reason": "human_managed", "turn_id": turn_id}

        requested_run_mode = str(config.get("run_mode") or "shadow").strip().lower()
        eval_gate_status = await self.get_autonomous_eval_gate_status(ws, config) if requested_run_mode == "autonomous" else {
            "enabled": bool(config.get("autonomous_eval_gate_enabled")),
            "blocking": False,
            "reason_code": "not_autonomous",
            "message": "Eval gate only applies when autonomous mode is requested.",
        }
        effective_run_mode = "suggest" if requested_run_mode == "autonomous" and bool(eval_gate_status.get("blocking")) else requested_run_mode
        runtime_config = {**config, "run_mode": effective_run_mode}

        recent_messages = await self.db_manager.get_messages(user_id, offset=0, limit=int(config.get("max_context_messages") or 12))
        turn_payload = {
            "workspace": ws,
            "user_id": user_id,
            "inbound_wa_message_id": inbound_wamid,
            "conversation_state": state,
            "recent_messages": recent_messages,
            "incoming_message": incoming_text,
            "requested_run_mode": requested_run_mode,
            "effective_run_mode": effective_run_mode,
            "eval_gate": eval_gate_status,
        }
        turn_payload.update(
            await self._prefetch_catalog_context(
                incoming_text,
                recent_messages=recent_messages,
                workspace=ws,
                limit=int(config.get("catalog_results_limit") or 6),
            )
        )
        catalog_clarification = dict(turn_payload.get("catalog_clarification") or {})
        if effective_run_mode == "autonomous" and bool(catalog_clarification.get("needed")):
            return await self._handle_catalog_clarification(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                requested_run_mode=requested_run_mode,
                effective_run_mode=effective_run_mode,
                state=state,
                turn_payload=turn_payload,
                clarification=catalog_clarification,
            )

        started = time.perf_counter()
        response_id = ""
        openai_conversation_id = str(state.get("openai_conversation_id") or "").strip()
        output_data: dict[str, Any] = {}
        tool_entries: list[dict[str, Any]] = []
        try:
            output_data, response_id, openai_conversation_id, usage, executed_tools = await self._run_openai_turn(
                config=runtime_config,
                turn_payload=turn_payload,
                previous_conversation_id=openai_conversation_id or None,
            )
            reply_text = str(output_data.get("reply_text") or "").strip()
            should_handoff = bool(output_data.get("should_handoff"))
            confidence = self._safe_float(output_data.get("confidence"), default=0.0)
            effective_mode = effective_run_mode
            # --- Output validation layer ---
            validation_result = self.validator.validate_output(
                output_data=output_data,
                catalog_products=turn_payload.get("catalog_candidates") or [],
                policies=turn_payload.get("policies") or [],
            )
            if not validation_result.get("valid"):
                self.log.warning(
                    "ai_agent output validation warnings workspace=%s user=%s warnings=%s",
                    ws, user_id, validation_result.get("all_warnings"),
                )
                # Auto-correct invalid product IDs
                if validation_result.get("corrected_output"):
                    output_data = validation_result["corrected_output"]
                # If policy compliance failed and mode is autonomous, reduce confidence
                if not validation_result.get("policy_check", {}).get("valid"):
                    confidence = min(confidence, 0.55)
                    output_data["confidence"] = confidence
                    output_data["_validation_warnings"] = validation_result.get("all_warnings", [])
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
            blocked_intents = set(self._normalize_string_list(config.get("autonomous_blocked_intents")))
            if effective_mode == "autonomous" and str(output_data.get("intent") or "").strip() in blocked_intents:
                should_handoff = True
                output_data["handoff_reason"] = str(output_data.get("handoff_reason") or "intent_policy_gate")
            action = "shadow" if effective_mode == "shadow" else ("suggest" if effective_mode == "suggest" else "no_reply")
            handled = False
            skip_legacy = False
            handoff_meta: dict[str, Any] = {}
            matched_catalog_sets = [
                {
                    "id": str(item.get("id") or "").strip(),
                    "name": str(item.get("name") or "").strip(),
                }
                for item in (turn_payload.get("matched_catalog_sets") or [])
                if str(item.get("id") or "").strip()
            ]
            recommended_set_id = (
                str(output_data.get("recommended_catalog_set_id") or "").strip()
                or str(((turn_payload.get("preferred_catalog_set") or {}) if turn_payload.get("catalog_query") else {}).get("id") or "").strip()
            )
            auto_catalog_targets = matched_catalog_sets[:3] if matched_catalog_sets else (
                [{"id": recommended_set_id, "name": str(output_data.get("recommended_catalog_set_name") or ((turn_payload.get("preferred_catalog_set") or {}).get("name") or "")).strip()}]
                if recommended_set_id else []
            )
            auto_catalog_targets = [
                target for target in auto_catalog_targets
                if not self._was_recent_catalog_set_sent(recent_messages, str(target.get("id") or "").strip(), limit=6)
            ][:3]
            auto_catalog_set_possible = bool(
                effective_mode == "autonomous"
                and config.get("send_catalog_when_possible")
                and auto_catalog_targets
                and "send_whatsapp_catalog_message" not in action_tool_names
            )
            auto_product_ids = [
                str(x).strip()
                for x in (output_data.get("recommended_product_ids") or [])
                if str(x).strip()
            ][: max(1, min(6, int(config.get("catalog_results_limit") or 6)))]
            auto_product_carousel_possible = bool(
                effective_mode == "autonomous"
                and config.get("send_catalog_when_possible")
                and auto_product_ids
                and "send_whatsapp_product_carousel" not in action_tool_names
                and not auto_catalog_set_possible
            )
            send_reply_text_separately = self._should_send_reply_text_separately(
                reply_text=reply_text,
                action_tool_names=action_tool_names,
                auto_catalog_set_possible=auto_catalog_set_possible,
                auto_product_carousel_possible=auto_product_carousel_possible,
            )
            if effective_mode == "autonomous":
                if should_handoff:
                    if reply_text and "send_text_reply" not in action_tool_names:
                        try:
                            await self._send_ai_outbound_message(
                                user_id=user_id,
                                message_type="text",
                                text=reply_text,
                            )
                        except Exception as handoff_reply_exc:
                            self.log.warning("ai_agent handoff reply send failed workspace=%s user=%s err=%s", ws, user_id, handoff_reply_exc)
                    if "create_handoff_ticket" not in action_tool_names and "assign_human_agent" not in action_tool_names:
                        handoff_meta = await self._mark_handoff(user_id=user_id, output_data=output_data, workspace=ws)
                    action = "handoff"
                    handled = True
                    skip_legacy = True
                elif auto_catalog_set_possible:
                    for idx, target in enumerate(auto_catalog_targets):
                        await self._send_ai_outbound_message(
                            user_id=user_id,
                            message_type="catalog_set",
                            text=reply_text if idx == 0 else str(target.get("name") or "").strip(),
                            set_id=str(target.get("id") or "").strip(),
                        )
                    action = "send_catalog_set" if len(auto_catalog_targets) == 1 else "send_catalog_sets"
                    handled = True
                    skip_legacy = True
                elif auto_product_carousel_possible:
                    try:
                        await self._send_ai_product_carousel(user_id=user_id, product_ids=auto_product_ids)
                        action = "send_product_carousel"
                    except Exception as catalog_exc:
                        self.log.warning("ai_agent catalog send failed workspace=%s user=%s err=%s", ws, user_id, catalog_exc)
                    handled = True
                    skip_legacy = True
                elif send_reply_text_separately:
                    if not self._was_recent_ai_text_sent(recent_messages, reply_text, limit=4):
                        await self._send_ai_outbound_message(
                            user_id=user_id,
                            message_type="text",
                            text=reply_text,
                        )
                        action = "send_text_reply"
                    else:
                        action = "send_text_reply_suppressed"
                    handled = True
                    skip_legacy = True
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
                turn_mode=effective_run_mode,
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
                tool_name="autonomous_eval_gate",
                ok=not bool(eval_gate_status.get("blocking")),
                request_json={
                    "requested_run_mode": requested_run_mode,
                    "effective_run_mode": effective_run_mode,
                },
                response_json=eval_gate_status,
                error_code=str(eval_gate_status.get("reason_code") or "") if bool(eval_gate_status.get("blocking")) else None,
            )
            await self._log_tool(
                workspace=ws,
                user_id=user_id,
                turn_id=turn_id,
                tool_name="autonomous_intent_gate",
                ok=not (
                    effective_mode == "autonomous"
                    and str(output_data.get("intent") or "").strip() in blocked_intents
                ),
                request_json={"blocked_intents": sorted(blocked_intents)},
                response_json={
                    "intent": str(output_data.get("intent") or "").strip(),
                    "handoff_reason": str(output_data.get("handoff_reason") or ""),
                },
                error_code="intent_blocked"
                if (effective_mode == "autonomous" and str(output_data.get("intent") or "").strip() in blocked_intents)
                else None,
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
            # --- Graceful fallback: send a polite message and mark for human follow-up ---
            fallback_text = ""
            if effective_run_mode == "autonomous":
                fallback_text = "عذرًا، حدث خطأ تقني. سيتواصل معك أحد أعضاء الفريق قريبًا."
                try:
                    await self._send_ai_outbound_message(
                        user_id=user_id, message_type="text", text=fallback_text,
                    )
                    await self._sync_conversation_tags(user_id=user_id, add_tags=["ai-error", "needs-human"])
                except Exception:
                    pass
            await self._log_turn(
                workspace=ws,
                user_id=user_id,
                inbound_wa_message_id=inbound_wamid,
                turn_mode=effective_run_mode,
                turn_status="failed",
                detected_language="",
                detected_intent="",
                emotion="",
                confidence=0.0,
                action="error_fallback" if fallback_text else "error",
                reply_text=fallback_text,
                openai_response_id=response_id,
                openai_conversation_id=openai_conversation_id,
                request_json=turn_payload,
                response_json=output_data,
                usage_json={},
                error_text=str(exc),
                latency_ms=latency_ms,
            )
            return {"handled": bool(fallback_text), "skip_legacy": bool(fallback_text), "reason": "error_fallback" if fallback_text else "error", "error": str(exc)}

    async def _record_skip(
        self,
        *,
        workspace: str,
        user_id: str,
        inbound_wa_message_id: str,
        reason: str,
        config: dict[str, Any],
        state: dict[str, Any] | None = None,
        message_obj: dict[str, Any] | None = None,
    ) -> int:
        ws = self.normalize_workspace(workspace)
        uid = str(user_id or "").strip()
        if not uid:
            self.log.info("ai_agent skip workspace=%s user=<missing> reason=%s", ws, reason)
            return 0
        await self.ensure_schema()
        existing_state = state or await self._get_conversation_state(user_id=uid, workspace=ws)
        counters = dict(existing_state.get("counters_json") or {})
        counters["skipped_turns"] = int(counters.get("skipped_turns") or 0) + 1
        risk = dict(existing_state.get("risk_json") or {})
        risk["last_skip_reason"] = str(reason or "").strip()
        risk["last_skip_at"] = datetime.utcnow().isoformat()
        await self._upsert_conversation_state(
            user_id=uid,
            workspace=ws,
            state={
                "risk_json": risk,
                "counters_json": counters,
            },
        )
        turn_id = await self._log_turn(
            workspace=ws,
            user_id=uid,
            inbound_wa_message_id=inbound_wa_message_id,
            openai_response_id="",
            openai_conversation_id=str(existing_state.get("openai_conversation_id") or "") or None,
            turn_mode=str(config.get("run_mode") or "shadow").strip().lower() or "shadow",
            turn_status="skipped",
            detected_language="",
            detected_intent="",
            emotion="",
            confidence=0.0,
            action=str(reason or "").strip() or "skipped",
            reply_text="",
            request_json={
                "workspace": ws,
                "user_id": uid,
                "message_type": str((message_obj or {}).get("type") or "").strip(),
                "incoming_message": str((message_obj or {}).get("message") or "").strip(),
                "configured_enabled": bool(config.get("enabled")),
                "requested_run_mode": str(config.get("run_mode") or "shadow").strip().lower(),
                "test_numbers": self._normalize_test_numbers(config.get("test_numbers")),
            },
            response_json={
                "reason": str(reason or "").strip(),
                "workspace": ws,
                "state_status": str(existing_state.get("status") or "bot_managed"),
            },
            usage_json={},
            error_text=None,
            latency_ms=0,
        )
        self.log.info("ai_agent skip workspace=%s user=%s reason=%s turn_id=%s", ws, uid, reason, turn_id)
        return turn_id

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
        input_items: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": self._build_user_prompt(turn_payload),
            }
        ]
        usage_totals = {
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 0,
        }
        executed_tools: list[dict[str, Any]] = []
        send_tool_names = {
            "send_text_reply",
            "send_whatsapp_product_message",
            "send_whatsapp_catalog_message",
            "send_whatsapp_product_carousel",
        }
        rich_send_tool_names = {
            "send_whatsapp_product_message",
            "send_whatsapp_catalog_message",
            "send_whatsapp_product_carousel",
        }
        send_tool_executed = False
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
            resp = None
            last_error: Exception | None = None
            for _attempt in range(3):
                try:
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        resp = await client.post(endpoint, headers=headers, json=body)
                    if resp.status_code >= 500:
                        last_error = RuntimeError(f"Responses API server error {resp.status_code}: {resp.text[:300]}")
                        self.log.warning("ai_agent openai retry attempt=%d status=%d", _attempt + 1, resp.status_code)
                        await asyncio.sleep(min(2 ** _attempt, 4))
                        continue
                    break
                except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadTimeout) as net_exc:
                    last_error = net_exc
                    self.log.warning("ai_agent openai retry attempt=%d err=%s", _attempt + 1, net_exc)
                    if _attempt < 2:
                        await asyncio.sleep(min(2 ** _attempt, 4))
                    continue
            if resp is None:
                raise RuntimeError(f"OpenAI API unreachable after 3 attempts: {last_error}")
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
                has_rich_send_call = any(
                    isinstance(item, dict) and str(item.get("name") or "").strip() in rich_send_tool_names
                    for item in function_calls
                )
                for tool_call in function_calls:
                    name = str(tool_call.get("name") or "").strip()
                    call_id = str(tool_call.get("call_id") or "").strip()
                    raw_arguments = str(tool_call.get("arguments") or "{}")
                    try:
                        arguments = json.loads(raw_arguments or "{}")
                    except Exception:
                        arguments = {}
                    if name == "send_text_reply" and has_rich_send_call:
                        tool_result = {
                            "ok": True,
                            "data": {"suppressed": True, "reason": "rich_send_in_same_turn"},
                            "source": "ai_agent",
                            "latency_ms": 0,
                        }
                    elif name in send_tool_names and send_tool_executed:
                        tool_result = {
                            "ok": True,
                            "data": {"suppressed": True, "reason": "single_visible_message_per_turn"},
                            "source": "ai_agent",
                            "latency_ms": 0,
                        }
                    else:
                        tool_result = await self._execute_response_tool(
                            name=name,
                            arguments=arguments if isinstance(arguments, dict) else {},
                            turn_payload=turn_payload,
                            config=config,
                        )
                        if name in send_tool_names and bool(tool_result.get("ok")):
                            send_tool_executed = True
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

    async def _create_eval_run(
        self,
        *,
        workspace: str,
        run_type: str,
        label: str,
        model: str,
        sample_size: int,
        config_json: dict[str, Any],
    ) -> int:
        params = (
            workspace,
            run_type,
            label,
            model,
            "running",
            int(sample_size or 0),
            json.dumps(config_json or {}, ensure_ascii=False),
            json.dumps({}, ensure_ascii=False),
            datetime.utcnow().isoformat(),
            None,
        )
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                INSERT INTO ai_eval_runs
                (workspace, run_type, label, model, status, sample_size, config_json, summary_json, created_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            if self.db_manager.use_postgres:
                await db.execute(query, *params)
                row = await db.fetchrow(
                    self.db_manager._convert(
                        "SELECT id FROM ai_eval_runs WHERE workspace = ? ORDER BY id DESC LIMIT 1"
                    ),
                    workspace,
                )
                return int(row["id"]) if row else 0
            cur = await db.execute(query, params)
            await db.commit()
            return int(cur.lastrowid or 0)

    async def _complete_eval_run(
        self,
        *,
        run_id: int,
        workspace: str,
        summary_json: dict[str, Any],
        status: str = "completed",
    ) -> None:
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                UPDATE ai_eval_runs
                SET status = ?, summary_json = ?, completed_at = ?
                WHERE workspace = ? AND id = ?
                """
            )
            params = (status, json.dumps(summary_json or {}, ensure_ascii=False), datetime.utcnow().isoformat(), workspace, int(run_id))
            if self.db_manager.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    async def _insert_eval_result(
        self,
        *,
        run_id: int,
        workspace: str,
        case_key: str,
        source_type: str,
        user_id: str | None,
        transcript: list[str],
        expected: dict[str, Any],
        output: dict[str, Any],
        score: dict[str, Any],
    ) -> None:
        params = (
            int(run_id),
            workspace,
            case_key,
            source_type,
            user_id,
            json.dumps(transcript or [], ensure_ascii=False),
            json.dumps(expected or {}, ensure_ascii=False),
            json.dumps(output or {}, ensure_ascii=False),
            json.dumps(score or {}, ensure_ascii=False),
            datetime.utcnow().isoformat(),
        )
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                INSERT INTO ai_eval_results
                (run_id, workspace, case_key, source_type, user_id, transcript_json, expected_json, output_json, score_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            if self.db_manager.use_postgres:
                await db.execute(query, *params)
            else:
                await db.execute(query, params)
                await db.commit()

    @asynccontextmanager
    async def _workspace_scope(self, workspace: str):
        token = self.push_workspace(workspace)
        try:
            yield
        finally:
            try:
                self.pop_workspace(token)
            except Exception:
                pass

    async def _select_eval_conversations(self, *, workspace: str, limit: int) -> list[str]:
        async with self._workspace_scope(workspace):
            conversations = await self.db_manager.get_conversations_with_stats(limit=max(1, min(int(limit or 10), 100)))
        user_ids: list[str] = []
        for conv in conversations or []:
            uid = str(conv.get("user_id") or "").strip()
            if not uid or uid.startswith(("team:", "agent:", "dm:", "eval:")):
                continue
            user_ids.append(uid)
        return user_ids[: max(1, min(int(limit or 10), 100))]

    async def _load_eval_transcript(self, user_id: str, *, workspace: str, limit: int = 12) -> list[str]:
        async with self._workspace_scope(workspace):
            messages = await self.db_manager.get_messages(user_id, offset=0, limit=max(1, min(int(limit or 12), 50)))
        transcript: list[str] = []
        for message in messages or []:
            body = str(message.get("message") or "").strip()
            if not body:
                continue
            who = "Agent" if bool(message.get("from_me")) else "Customer"
            transcript.append(f"{who}: {body}")
        return transcript

    async def _run_eval_case(
        self,
        *,
        config: dict[str, Any],
        workspace: str,
        transcript: list[str],
        user_id: str,
    ) -> dict[str, Any]:
        safe_config = {**config, "run_mode": "shadow"}
        latest_customer_message = ""
        for line in reversed(transcript or []):
            if str(line or "").startswith("Customer:"):
                latest_customer_message = str(line.split(":", 1)[1] if ":" in line else line).strip()
                break
        if not latest_customer_message:
            latest_customer_message = str((transcript or [""])[-1] or "").strip()
        recent_messages = []
        for line in transcript or []:
            who, _, body = str(line or "").partition(":")
            recent_messages.append(
                {
                    "from_me": who.strip().lower() == "agent",
                    "message": body.strip(),
                }
            )
        turn_payload = {
            "workspace": workspace,
            "user_id": user_id,
            "inbound_wa_message_id": f"eval-{user_id}",
            "conversation_state": {
                "status": "bot_managed",
                "owner_type": "bot",
                "slots_json": {},
                "risk_json": {},
                "counters_json": {"turns": 0},
            },
            "recent_messages": recent_messages,
            "incoming_message": latest_customer_message,
        }
        output, response_id, conversation_id, usage, executed_tools = await self._run_openai_turn(
            config=safe_config,
            turn_payload=turn_payload,
            previous_conversation_id=None,
        )
        return {
            "output": output,
            "response_id": response_id,
            "conversation_id": conversation_id,
            "usage": usage,
            "executed_tools": executed_tools,
        }

    def _safe_eval_config_snapshot(self, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "model": str(config.get("model") or DEFAULT_AGENT_CONFIG["model"]),
            "run_mode": "shadow",
            "max_output_tokens": int(config.get("max_output_tokens") or 0),
            "max_context_messages": int(config.get("max_context_messages") or 0),
            "low_confidence_threshold": self._safe_float(config.get("low_confidence_threshold"), default=0.0),
        }

    def _build_eval_case_index(self, results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {
            str(item.get("case_key") or "").strip(): item
            for item in (results or [])
            if str(item.get("case_key") or "").strip()
        }

    def _score_replay_output(
        self,
        *,
        expectation: dict[str, Any] | None,
        output: dict[str, Any],
        tool_names: list[str],
    ) -> dict[str, Any]:
        expected_intent = str((expectation or {}).get("expected_intent") or "").strip()
        expected_handoff = bool((expectation or {}).get("expected_should_handoff")) if expectation else False
        expected_tools = set(self._normalize_string_list((expectation or {}).get("expected_tool_names_json")))
        actual_intent = str(output.get("intent") or "").strip()
        actual_handoff = bool(output.get("should_handoff"))
        actual_tools = {str(name or "").strip() for name in (tool_names or []) if str(name or "").strip()}
        has_expectation = bool(expectation and (expected_intent or expected_tools or "expected_should_handoff" in expectation))
        if not has_expectation:
            return {
                "tool_count": len(actual_tools),
                "handoff": actual_handoff,
                "intent": actual_intent,
                "confidence": output.get("confidence"),
                "scored": False,
                "passed": None,
            }
        intent_ok = (not expected_intent) or actual_intent == expected_intent
        handoff_ok = actual_handoff == expected_handoff
        tools_ok = expected_tools.issubset(actual_tools)
        return {
            "tool_count": len(actual_tools),
            "handoff": actual_handoff,
            "intent": actual_intent,
            "confidence": output.get("confidence"),
            "scored": True,
            "intent_ok": intent_ok,
            "handoff_ok": handoff_ok,
            "tools_ok": tools_ok,
            "expected_tools": sorted(expected_tools),
            "actual_tools": sorted(actual_tools),
            "passed": bool(intent_ok and handoff_ok and tools_ok),
        }

    def _normalize_test_numbers(self, raw_value: Any) -> list[str]:
        if isinstance(raw_value, str):
            candidates = re.split(r"[\s,;\n\r]+", raw_value)
        elif isinstance(raw_value, (list, tuple, set)):
            candidates = [str(item or "") for item in raw_value]
        else:
            candidates = []
        normalized: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            phone = self._normalize_phone_like(candidate)
            if not phone or phone in seen:
                continue
            seen.add(phone)
            normalized.append(phone)
        return normalized

    def _normalize_string_list(self, raw_value: Any) -> list[str]:
        if isinstance(raw_value, str):
            candidates = re.split(r"[\s,;\n\r]+", raw_value)
        elif isinstance(raw_value, (list, tuple, set)):
            candidates = [str(item or "") for item in raw_value]
        else:
            candidates = []
        normalized: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            clean = str(candidate or "").strip()
            if not clean:
                continue
            if clean in seen:
                continue
            seen.add(clean)
            normalized.append(clean)
        return normalized

    async def _create_replay_alerts_for_run(self, workspace: str, run: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        if not bool(config.get("replay_alerts_enabled")):
            return []
        summary = dict((run.get("summary_json") or {}).get("summary") or {})
        alerts: list[dict[str, Any]] = []
        scored_cases = int(summary.get("scored_cases") or 0)
        pass_rate = summary.get("pass_rate")
        handoff_count = int(summary.get("handoff_count") or 0)
        sampled = int(summary.get("sampled_conversations") or 0)
        handoff_rate = round((handoff_count / sampled), 4) if sampled else 0.0
        min_pass_rate = self._safe_float(config.get("replay_alert_min_pass_rate"), default=0.75)
        max_handoff_rate = self._safe_float(config.get("replay_alert_max_handoff_rate"), default=0.45)
        if scored_cases > 0 and pass_rate is not None and self._safe_float(pass_rate, default=0.0) < min_pass_rate:
            alerts.append(
                await self.create_eval_alert(
                    workspace=workspace,
                    run_id=int(run.get("id") or 0),
                    alert_type="pass_rate_regression",
                    severity="high",
                    title="Nightly replay pass rate dropped",
                    message=f"Replay run #{run.get('id')} fell below the minimum pass rate of {min_pass_rate:.2f}.",
                    payload={"pass_rate": pass_rate, "threshold": min_pass_rate, "summary": summary},
                )
            )
        if sampled > 0 and handoff_rate > max_handoff_rate:
            alerts.append(
                await self.create_eval_alert(
                    workspace=workspace,
                    run_id=int(run.get("id") or 0),
                    alert_type="handoff_rate_spike",
                    severity="warning",
                    title="Nightly replay handoff rate is high",
                    message=f"Replay run #{run.get('id')} exceeded the maximum handoff rate of {max_handoff_rate:.2f}.",
                    payload={"handoff_rate": handoff_rate, "threshold": max_handoff_rate, "summary": summary},
                )
            )
        return alerts

    def _local_now(self, timezone_name: str) -> datetime:
        try:
            from zoneinfo import ZoneInfo
            return datetime.now(ZoneInfo(timezone_name))
        except Exception:
            return datetime.utcnow()

    def _normalize_phone_like(self, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        plus = raw.startswith("+")
        digits = re.sub(r"\D+", "", raw)
        if not digits:
            return ""
        return f"+{digits}" if plus else digits

    def _is_test_number_allowed(self, user_id: str, allowed_numbers: list[str]) -> bool:
        incoming = self._normalize_phone_like(user_id)
        incoming_digits = incoming.lstrip("+")
        for item in allowed_numbers:
            candidate = self._normalize_phone_like(item)
            if not candidate:
                continue
            candidate_digits = candidate.lstrip("+")
            if incoming == candidate or incoming_digits == candidate_digits:
                return True
            if incoming_digits.endswith(candidate_digits) or candidate_digits.endswith(incoming_digits):
                return True
        return False

    async def _load_policy_docs_for_prompt(self, incoming_text: str, *, workspace: str) -> list[dict[str, Any]]:
        policies = await self.list_policies(workspace)
        if not policies:
            return []
        hay = incoming_text.lower()
        matched_topics: set[str] = set()
        # Multilingual keyword → topic mapping (darija, ar, fr, en)
        _POLICY_KEYWORDS: list[tuple[str, str]] = [
            # Delivery
            ("livraison", "delivery"), ("delivery", "delivery"), ("توصيل", "delivery"),
            ("تسليم", "delivery"), ("شحن", "delivery"), ("shipping", "delivery"),
            ("fin wsel", "delivery"), ("wsel", "delivery"), ("tracking", "delivery"),
            ("track", "delivery"), ("تتبع", "delivery"), ("suivi", "delivery"),
            # COD
            ("cod", "cod"), ("cash on delivery", "cod"), ("الدفع عند الاستلام", "cod"),
            ("paiement à la livraison", "cod"), ("nkhelso m3a delivery", "cod"),
            ("pay on delivery", "cod"), ("contre remboursement", "cod"),
            # Return
            ("return", "return"), ("retour", "return"), ("إرجاع", "return"),
            ("رجع", "return"), ("nrej3", "return"), ("rendre", "return"),
            # Exchange
            ("exchange", "exchange"), ("échange", "exchange"), ("echange", "exchange"),
            ("تبديل", "exchange"), ("بدل", "exchange"), ("nbedel", "exchange"),
            ("changer", "exchange"), ("استبدال", "exchange"),
            # Refund
            ("refund", "refund"), ("remboursement", "refund"), ("استرجاع", "refund"),
            ("رد المال", "refund"), ("rembourser", "refund"), ("flous", "refund"),
            ("استرداد", "refund"), ("money back", "refund"),
            # Complaint
            ("complaint", "complaint"), ("plainte", "complaint"), ("réclamation", "complaint"),
            ("reclamation", "complaint"), ("شكاية", "complaint"), ("شكوى", "complaint"),
            ("problème", "complaint"), ("problem", "complaint"), ("مشكلة", "complaint"),
            ("مشكل", "complaint"),
        ]
        for keyword, topic in _POLICY_KEYWORDS:
            if keyword in hay:
                matched_topics.add(topic)
        if not matched_topics:
            matched_topics = {str(p.get("topic") or "") for p in policies[:4]}
        return [
            {"id": p.get("id"), "topic": p.get("topic"), "locale": p.get("locale"), "title": p.get("title"), "content": p.get("content")}
            for p in policies
            if str(p.get("status") or "approved") == "approved" and str(p.get("topic") or "") in matched_topics
        ][:8]

    async def _search_catalog_products(self, query: str, *, workspace: str, limit: int) -> list[dict[str, Any]]:
        result = await self.tools.search_catalog_products(query=query, workspace=workspace, limit=limit)
        return list(result.data.get("products") or []) if result.ok else []

    def _build_system_prompt(self, config: dict[str, Any]) -> str:
        supported_langs = config.get("supported_languages") or ["darija", "ar", "fr", "en"]
        lang_list = ", ".join(supported_langs) if isinstance(supported_langs, list) else str(supported_langs)
        return (
            f"{config.get('instructions')}\n\n"
            f"Business context:\n{config.get('business_context')}\n\n"
            f"Supported languages: {lang_list}\n\n"
            "You have access to tools for customer lookup, orders, delivery, policies, stock, catalog messages, human assignment, and conversation status.\n"
            "Before answering delivery, COD, exchange, return, refund, or complaint-policy questions, call get_business_policies and rely only on approved policies.\n"
            "CRITICAL LANGUAGE RULE: Detect the customer's language and write reply_text in that SAME language. "
            "If they write Darija or Arabic, reply in Arabic script. If they write French, reply in French. If English, reply in English. "
            "Never transliterate Arabic in Latin letters. Never reply in a different language than the customer used.\n"
            "For catalog browsing requests, use the current inbox catalog structure. Prefer a matching product set when the customer is browsing by gender, age, size, or category, and prefer specific products only when you have clear item matches.\n"
            "When you use send_whatsapp_catalog_message or send_whatsapp_product_message, put the customer-facing sentence in the tool caption and leave reply_text empty unless you intentionally want a second separate message.\n"
            "Default to one customer-visible message per turn. Keep wording minimal and direct, usually one or two short sentences.\n"
            "Use tools whenever facts are needed. Use send tools only when you are ready to act. In shadow/suggest modes, send tools may dry-run.\n"
            "CONFIDENCE SCORING: Set confidence based on how certain you are about the correct action. "
            "Set confidence >= 0.85 only when you have retrieved real data (policy, order, product) that directly answers the question. "
            "Set confidence 0.5-0.84 when you are making a reasonable inference without full data. "
            "Set confidence < 0.5 when the query is ambiguous or you lack information to answer well.\n"
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
            "\"recommended_catalog_set_id\":\"\","
            "\"recommended_catalog_set_name\":\"\","
            "\"entities\":{\"gender\":null,\"child_age\":null,\"size\":null,\"color\":null,\"product_type\":null,\"budget\":null,\"city\":null,\"order_number\":null},"
            "\"state_summary\":\"\""
            "}\n"
            "Rules: keep reply_text brief (1-2 sentences max), do not invent unavailable products or policies, "
            "always reply in the customer's language, and hand off if the customer is angry, requests a human, or raises a refund/complaint risk."
        )

    def _build_user_prompt(self, turn_payload: dict[str, Any]) -> str:
        recent_lines = []
        for message in turn_payload.get("recent_messages") or []:
            who = "Agent" if bool(message.get("from_me")) else "Customer"
            body = str(message.get("message") or "").strip()
            if body:
                recent_lines.append(f"{who}: {body}")
        product_lines = [
            f"- {p.get('retailer_id')}: {p.get('name')} | set={p.get('catalog_set_name')} | price={p.get('price')} | qty={p.get('quantity')} | availability={p.get('availability')}"
            for p in (turn_payload.get("catalog_candidates") or [])
        ]
        matched_set_lines = [
            f"- {s.get('id')}: {s.get('name')}"
            for s in (turn_payload.get("matched_catalog_sets") or [])
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
            f"Matched catalog sets:\n{chr(10).join(matched_set_lines) if matched_set_lines else '(none)'}\n\n"
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

    def _message_mentions_catalog_request(self, text: str) -> bool:
        hay = str(text or "").lower()
        if self.tools._extract_catalog_request_specs(hay):
            return True
        return any(
            token in hay
            for token in (
                "catalog", "catalogue", "set", "size", "taille", "pointure", "shoe", "shoes", "sandal", "sandals",
                "chauss", "sneaker", "girls", "boys", "girl", "boy", "بنات", "بنت", "أولاد", "اولاد",
                "ولد", "قياس", "مقاس", "سباط", "حذاء", "صندل", "كاتالوغ",
            )
        )

    def _build_catalog_context_query(self, text: str, recent_messages: list[dict[str, Any]] | None = None) -> str:
        latest = " ".join(str(text or "").strip().split())
        pieces: list[str] = []
        seen: set[str] = set()
        history: list[str] = []
        for message in recent_messages or []:
            if bool(message.get("from_me")):
                continue
            body = " ".join(str(message.get("message") or "").strip().split())
            if not body or body.lower() in seen or not self._message_mentions_catalog_request(body):
                continue
            history.append(body)
            seen.add(body.lower())
            if len(history) >= 3:
                break
        for body in reversed(history):
            pieces.append(body)
        if latest:
            latest_key = latest.lower()
            if latest_key not in seen and (self._message_mentions_catalog_request(latest) or pieces):
                pieces.append(latest)
        return " ".join(part for part in pieces if part).strip()

    def _normalized_message_text(self, text: str) -> str:
        return " ".join(str(text or "").strip().split()).lower()

    def _was_recent_ai_text_sent(self, recent_messages: list[dict[str, Any]] | None, text: str, *, limit: int = 6) -> bool:
        target = self._normalized_message_text(text)
        if not target:
            return False
        checked = 0
        for message in recent_messages or []:
            if not bool(message.get("from_me")):
                continue
            checked += 1
            if self._normalized_message_text(message.get("message") or "") == target:
                return True
            if checked >= max(1, int(limit or 6)):
                break
        return False

    def _was_recent_catalog_set_sent(self, recent_messages: list[dict[str, Any]] | None, set_id: str, *, limit: int = 6) -> bool:
        target = str(set_id or "").strip()
        if not target:
            return False
        checked = 0
        for message in recent_messages or []:
            if not bool(message.get("from_me")):
                continue
            checked += 1
            if str(message.get("set_id") or "") == target:
                return True
            if checked >= max(1, int(limit or 6)):
                break
        return False

    async def _prefetch_catalog_context(
        self,
        text: str,
        *,
        recent_messages: list[dict[str, Any]] | None = None,
        workspace: str,
        limit: int,
    ) -> dict[str, Any]:
        catalog_query = self._build_catalog_context_query(text, recent_messages)
        if not catalog_query:
            return {}
        try:
            result = await self.tools.search_catalog_products(
                query=catalog_query,
                workspace=workspace,
                limit=max(1, min(int(limit or 6), 12)),
            )
            if not result.ok:
                return {}
            data = result.data or {}
            return {
                "catalog_query": catalog_query,
                "catalog_candidates": list(data.get("products") or []),
                "matched_catalog_sets": list(data.get("matched_sets") or []),
                "preferred_catalog_set": data.get("preferred_set") or None,
                "catalog_clarification": data.get("clarification") or None,
            }
        except Exception:
            return {}

    def _build_catalog_clarification_reply(self, clarification: dict[str, Any]) -> str:
        reason = str((clarification or {}).get("reason") or "").strip()
        age = int(clarification.get("age") or 0)
        size = int(clarification.get("size") or 0)
        if reason == "missing_gender_for_age" and age > 0:
            return f"هل تريدين ملابس البنات أم الأولاد لعمر {age} سنوات؟ وإذا كنت تريدين الأحذية أيضًا فأرسلي القياس."
        if reason == "missing_gender_for_size" and size > 0:
            return f"هل هذا قياس {size} للبنات أم للأولاد؟ وإذا كنت تريدين الملابس أيضًا فأرسلي العمر."
        return "هل تريدين منتجات البنات أم الأولاد؟"

    async def _handle_catalog_clarification(
        self,
        *,
        workspace: str,
        user_id: str,
        inbound_wa_message_id: str,
        requested_run_mode: str,
        effective_run_mode: str,
        state: dict[str, Any],
        turn_payload: dict[str, Any],
        clarification: dict[str, Any],
    ) -> dict[str, Any]:
        reply_text = self._build_catalog_clarification_reply(clarification)
        started = time.perf_counter()
        suppressed_duplicate = self._was_recent_ai_text_sent(turn_payload.get("recent_messages") or [], reply_text, limit=4)
        if not suppressed_duplicate:
            await self._send_ai_outbound_message(
                user_id=user_id,
                message_type="text",
                text=reply_text,
            )
        output_data = {
            "language": "ar",
            "intent": "product_discovery",
            "emotion": "neutral",
            "confidence": 0.99,
            "reply_text": "" if suppressed_duplicate else reply_text,
            "should_handoff": False,
            "conversation_status": "bot_managed",
            "entities": {
                "gender": None,
                "child_age": clarification.get("age"),
                "size": clarification.get("size"),
            },
            "state_summary": str(state.get("summary") or "").strip(),
            "handoff_reason": "",
        }
        new_state = {
            "status": "bot_managed",
            "owner_type": "bot",
            "summary": str(state.get("summary") or "").strip(),
            "last_language": "ar",
            "last_intent": "product_discovery",
            "slots_json": output_data.get("entities") or {},
            "risk_json": {
                "emotion": "neutral",
                "urgency": "",
                "handoff_reason": "",
                "should_handoff": False,
            },
            "counters_json": {
                **(state.get("counters_json") or {}),
                "turns": int((state.get("counters_json") or {}).get("turns") or 0) + 1,
            },
            "openai_conversation_id": str(state.get("openai_conversation_id") or "") or None,
        }
        await self._upsert_conversation_state(user_id=user_id, workspace=workspace, state=new_state)
        latency_ms = int((time.perf_counter() - started) * 1000)
        turn_id = await self._log_turn(
            workspace=workspace,
            user_id=user_id,
            inbound_wa_message_id=inbound_wa_message_id,
            turn_mode=effective_run_mode,
            turn_status="completed",
            detected_language="ar",
            detected_intent="product_discovery",
            emotion="neutral",
            confidence=0.99,
            action="catalog_clarification_suppressed" if suppressed_duplicate else "catalog_clarification",
            reply_text="" if suppressed_duplicate else reply_text,
            openai_response_id="",
            openai_conversation_id=str(state.get("openai_conversation_id") or "").strip(),
            request_json=turn_payload,
            response_json=output_data,
            usage_json={},
            error_text=None,
            latency_ms=latency_ms,
        )
        await self._log_tool(
            workspace=workspace,
            user_id=user_id,
            turn_id=turn_id,
            tool_name="catalog_clarification",
            ok=True,
            request_json={
                "clarification": clarification,
                "requested_run_mode": requested_run_mode,
            },
            response_json={"reply_text": reply_text, "suppressed_duplicate": suppressed_duplicate},
            error_code=None,
            latency_ms=latency_ms,
        )
        return {
            "handled": True,
            "skip_legacy": True,
            "reason": "catalog_clarification_suppressed" if suppressed_duplicate else "catalog_clarification",
            "turn_id": turn_id,
        }

    def _should_send_reply_text_separately(
        self,
        *,
        reply_text: str,
        action_tool_names: set[str],
        auto_catalog_set_possible: bool = False,
        auto_product_carousel_possible: bool = False,
    ) -> bool:
        if not str(reply_text or "").strip():
            return False
        if "send_text_reply" in action_tool_names:
            return False
        if action_tool_names.intersection({
            "send_whatsapp_product_message",
            "send_whatsapp_catalog_message",
            "send_whatsapp_product_carousel",
        }):
            return False
        if auto_catalog_set_possible or auto_product_carousel_possible:
            return False
        return True

    async def _has_completed_turn_for_inbound_message(self, *, workspace: str, inbound_wa_message_id: str) -> bool:
        ws = self.normalize_workspace(workspace)
        wamid = str(inbound_wa_message_id or "").strip()
        if not wamid:
            return False
        async with self.db_manager._conn() as db:
            query = self.db_manager._convert(
                """
                SELECT 1
                FROM ai_turns
                WHERE workspace = ?
                  AND inbound_wa_message_id = ?
                  AND turn_status = 'completed'
                ORDER BY id DESC
                LIMIT 1
                """
            )
            if self.db_manager.use_postgres:
                row = await db.fetchrow(query, ws, wamid)
            else:
                cur = await db.execute(query, (ws, wamid))
                row = await cur.fetchone()
            return bool(row)

    def _compact_ai_text(self, text: str, *, max_chars: int = 250) -> str:
        raw = " ".join(str(text or "").strip().split())
        if not raw:
            return ""
        first_line = raw.split("\n", 1)[0].strip()
        if first_line:
            raw = first_line
        if len(raw) <= max_chars:
            return raw
        # Try to cut at a sentence boundary within the limit
        best_cut = -1
        for delimiter in ("؟", "!", ".", "…", "?", ";"):
            idx = raw.rfind(delimiter, 0, max_chars)
            if idx > 0 and idx > best_cut:
                best_cut = idx + 1
        if best_cut > max(20, max_chars // 3):
            return raw[:best_cut].strip()
        # Fall back to word boundary
        shortened = raw[:max_chars].rsplit(" ", 1)[0].rstrip(" ,;:.-،")
        return shortened + "…"

    async def _send_ai_outbound_message(
        self,
        *,
        user_id: str,
        message_type: str,
        text: str = "",
        set_id: str | None = None,
        product_retailer_id: str | None = None,
        reply_to: str | None = None,
    ) -> Any:
        payload: dict[str, Any] = {
            "user_id": str(user_id or "").strip(),
            "type": str(message_type or "text").strip() or "text",
            "from_me": True,
            "message": self._compact_ai_text(
                text,
                max_chars=220 if str(message_type or "").strip() == "text" else 250,
            ),
            "timestamp": datetime.utcnow().isoformat(),
            "temp_id": f"ai-agent:{time.time_ns()}",
            "agent_username": "ai-agent",
        }
        if reply_to:
            payload["reply_to"] = str(reply_to or "").strip()
        if set_id:
            payload["set_id"] = str(set_id or "").strip()
        if product_retailer_id:
            rid = str(product_retailer_id or "").strip()
            payload["product_retailer_id"] = rid
            payload["retailer_id"] = rid
            payload["product_id"] = rid
        return await self.message_processor.process_outgoing_message(payload)

    async def _send_ai_product_carousel(self, *, user_id: str, product_ids: list[str]) -> list[Any]:
        sent: list[Any] = []
        for product_id in product_ids:
            rid = str(product_id or "").strip()
            if not rid:
                continue
            sent.append(
                await self._send_ai_outbound_message(
                    user_id=user_id,
                    message_type="catalog_item",
                    text="",
                    product_retailer_id=rid,
                )
            )
        return sent

    async def _send_ai_catalog_sets(self, *, user_id: str, sets: list[dict[str, Any]], caption: str = "") -> list[Any]:
        sent: list[Any] = []
        for idx, item in enumerate(sets or []):
            set_id = str((item or {}).get("id") or "").strip()
            if not set_id:
                continue
            sent.append(
                await self._send_ai_outbound_message(
                    user_id=user_id,
                    message_type="catalog_set",
                    text=caption if idx == 0 else str((item or {}).get("name") or "").strip(),
                    set_id=set_id,
                )
            )
        return sent

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
                        "product_id": {"type": ["string", "null"]},
                        "retailer_id": {"type": ["string", "null"]},
                    },
                    "required": ["product_id", "retailer_id"],
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
                        "phone_e164": {"type": ["string", "null"]},
                        "limit": {"type": ["integer", "null"]},
                    },
                    "required": ["order_reference", "phone_e164", "limit"],
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
                        "order_reference": {"type": ["string", "null"]},
                    },
                    "required": ["user_id", "order_reference"],
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
                        "note": {"type": ["string", "null"]},
                    },
                    "required": ["status", "note"],
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
                        "priority": {"type": ["string", "null"]},
                    },
                    "required": ["reason_code", "summary", "priority"],
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
                        "preferred_agent": {"type": ["string", "null"]},
                    },
                    "required": ["preferred_agent"],
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
                        "caption": {"type": ["string", "null"]},
                    },
                    "required": ["product_retailer_id", "caption"],
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
                        "caption": {"type": ["string", "null"]},
                    },
                    "required": ["set_id", "caption"],
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
                sender=lambda: self._send_ai_outbound_message(
                    user_id=user_id,
                    message_type="text",
                    text=str(arguments.get("text") or ""),
                ),
            )
        if name == "send_whatsapp_product_message":
            product_retailer_id = str(arguments.get("product_retailer_id") or "").strip()
            caption = str(arguments.get("caption") or "").strip()
            return await self._execute_send_tool(
                run_mode=run_mode,
                tool_name=name,
                payload={"product_retailer_id": product_retailer_id, "caption": caption},
                sender=lambda: self._send_ai_outbound_message(
                    user_id=user_id,
                    message_type="catalog_item",
                    text=caption,
                    product_retailer_id=product_retailer_id,
                ),
            )
        if name == "send_whatsapp_catalog_message":
            set_id = str(arguments.get("set_id") or "").strip()
            caption = str(arguments.get("caption") or "").strip()
            matched_catalog_sets = [
                {
                    "id": str(item.get("id") or "").strip(),
                    "name": str(item.get("name") or "").strip(),
                }
                for item in (turn_payload.get("matched_catalog_sets") or [])
                if str(item.get("id") or "").strip()
            ]
            exact_targets = matched_catalog_sets[:3]
            send_targets = exact_targets if exact_targets else (
                [{"id": set_id, "name": str(arguments.get("caption") or "").strip()}] if set_id else []
            )
            return await self._execute_send_tool(
                run_mode=run_mode,
                tool_name=name,
                payload={"set_ids": [item.get("id") for item in send_targets], "caption": caption},
                sender=lambda: self._send_ai_catalog_sets(
                    user_id=user_id,
                    sets=send_targets,
                    caption=caption,
                ),
            )
        if name == "send_whatsapp_product_carousel":
            product_ids = [str(item or "").strip() for item in (arguments.get("product_retailer_ids") or []) if str(item or "").strip()]
            return await self._execute_send_tool(
                run_mode=run_mode,
                tool_name=name,
                payload={"product_retailer_ids": product_ids},
                sender=lambda: self._send_ai_product_carousel(user_id=user_id, product_ids=product_ids),
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
