"""Human-assist copilot for AI customer support.

Generates draft reply suggestions and conversation summaries for human agents
when they take over a conversation from the AI.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any, Awaitable, Callable

import httpx

log = logging.getLogger(__name__)


class AgentCopilot:
    """Provides AI-powered assistance to human agents handling customer conversations."""

    def __init__(
        self,
        db_manager: Any,
        get_api_key: Callable[[], Awaitable[str]],
        get_config: Callable[[str], Awaitable[dict[str, Any]]],
        list_policies: Callable[[str], Awaitable[list[dict[str, Any]]]],
    ):
        self.db_manager = db_manager
        self._get_api_key = get_api_key
        self._get_config = get_config
        self._list_policies = list_policies

    async def generate_suggestion(
        self,
        *,
        user_id: str,
        workspace: str,
        agent_username: str | None = None,
        context_limit: int = 15,
    ) -> dict[str, Any]:
        """Generate a draft reply and conversation summary for a human agent.

        Returns:
            {
                "suggestion": "draft reply text",
                "summary": "conversation summary",
                "intent": "detected intent",
                "key_facts": ["fact1", "fact2"],
                "recommended_actions": ["action1", "action2"],
                "sentiment": "neutral|frustrated|angry",
                "language": "ar|fr|en|darija",
                "latency_ms": 1234,
            }
        """
        started = time.perf_counter()
        config = await self._get_config(workspace)
        api_key = await self._get_api_key()
        if not api_key:
            return {"error": "missing_api_key", "suggestion": "", "summary": ""}

        # Load conversation context
        messages = await self.db_manager.get_messages(user_id, offset=0, limit=context_limit)
        if not messages:
            return {"error": "no_messages", "suggestion": "", "summary": ""}

        # Load relevant policies
        policies = await self._list_policies(workspace)
        policy_snippets = [
            f"[{p.get('topic')}/{p.get('locale')}] {p.get('title')}: {p.get('content')}"
            for p in (policies or [])
            if str(p.get("status") or "approved") == "approved"
        ][:8]

        # Build transcript
        transcript_lines = []
        for msg in messages:
            who = "Agent" if bool(msg.get("from_me")) else "Customer"
            body = str(msg.get("message") or "").strip()
            if body:
                transcript_lines.append(f"{who}: {body}")

        # Load AI turns context if available
        ai_context = await self._get_recent_ai_context(user_id, workspace)

        system_prompt = self._build_copilot_system_prompt(config, policy_snippets)
        user_prompt = self._build_copilot_user_prompt(
            transcript_lines=transcript_lines,
            ai_context=ai_context,
            agent_username=agent_username,
        )

        # Call OpenAI
        try:
            result = await self._call_llm(
                api_key=api_key,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                config=config,
            )
        except Exception as exc:
            log.warning("Copilot suggestion failed: %s", exc)
            return {"error": str(exc), "suggestion": "", "summary": ""}

        latency_ms = int((time.perf_counter() - started) * 1000)
        result["latency_ms"] = latency_ms
        return result

    async def summarize_conversation(
        self,
        *,
        user_id: str,
        workspace: str,
        message_limit: int = 20,
    ) -> dict[str, Any]:
        """Generate a concise conversation summary for agent handoff."""
        started = time.perf_counter()
        api_key = await self._get_api_key()
        if not api_key:
            return {"error": "missing_api_key", "summary": ""}

        messages = await self.db_manager.get_messages(user_id, offset=0, limit=message_limit)
        if not messages:
            return {"error": "no_messages", "summary": ""}

        transcript = []
        for msg in messages:
            who = "Agent" if bool(msg.get("from_me")) else "Customer"
            body = str(msg.get("message") or "").strip()
            if body:
                transcript.append(f"{who}: {body}")

        config = await self._get_config(workspace)
        prompt = (
            "Summarize this customer support conversation in 2-3 sentences. "
            "Include: what the customer wants, what has been done so far, and what the next step should be. "
            "Write the summary in the customer's language (Arabic/French/English).\n\n"
            "Conversation:\n" + "\n".join(transcript[-20:])
        )

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": str(config.get("model") or "gpt-5.4-mini"),
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 400,
                    },
                )
            if resp.status_code >= 400:
                return {"error": f"API error {resp.status_code}", "summary": ""}
            data = resp.json()
            summary = str((data.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
        except Exception as exc:
            return {"error": str(exc), "summary": ""}

        latency_ms = int((time.perf_counter() - started) * 1000)
        return {"summary": summary, "latency_ms": latency_ms}

    # ---- Internal helpers ----

    async def _get_recent_ai_context(self, user_id: str, workspace: str) -> dict[str, Any]:
        """Load the most recent AI turn's context for this conversation."""
        try:
            async with self.db_manager._conn() as db:
                q = self.db_manager._convert(
                    """
                    SELECT detected_intent, emotion, confidence, reply_text, action, response_json
                    FROM ai_turns
                    WHERE workspace = ? AND user_id = ? AND turn_status = 'completed'
                    ORDER BY id DESC LIMIT 1
                    """
                )
                if self.db_manager.use_postgres:
                    row = await db.fetchrow(q, workspace, user_id)
                else:
                    cur = await db.execute(q, (workspace, user_id))
                    row = await cur.fetchone()
            if not row:
                return {}
            item = dict(row)
            try:
                item["response_json"] = json.loads(item.get("response_json") or "{}")
            except Exception:
                item["response_json"] = {}
            return item
        except Exception:
            return {}

    def _build_copilot_system_prompt(
        self,
        config: dict[str, Any],
        policy_snippets: list[str],
    ) -> str:
        policies_text = "\n".join(policy_snippets) if policy_snippets else "(no policies loaded)"
        return (
            "You are an AI copilot assisting a human customer support agent. "
            "Your job is to help the agent respond quickly and accurately.\n\n"
            f"Business: {config.get('business_context') or 'Moroccan e-commerce retailer'}\n\n"
            f"Available policies:\n{policies_text}\n\n"
            "Return a JSON object with these fields:\n"
            "{\n"
            '  "suggestion": "A draft reply the agent can send (in the customer\'s language)",\n'
            '  "summary": "Brief summary of the conversation so far (2-3 sentences)",\n'
            '  "intent": "The customer\'s primary intent",\n'
            '  "key_facts": ["Extracted facts: order numbers, sizes, products, dates"],\n'
            '  "recommended_actions": ["Specific actions the agent should take"],\n'
            '  "sentiment": "neutral|frustrated|angry|urgent",\n'
            '  "language": "ar|fr|en|darija"\n'
            "}\n\n"
            "Rules:\n"
            "- Write the suggestion in the customer's language\n"
            "- Base policy answers ONLY on the loaded policies above\n"
            "- If you don't have enough information, say so in recommended_actions\n"
            "- Keep the suggestion concise (1-3 sentences)\n"
            "- Be professional and empathetic"
        )

    def _build_copilot_user_prompt(
        self,
        *,
        transcript_lines: list[str],
        ai_context: dict[str, Any],
        agent_username: str | None = None,
    ) -> str:
        transcript_text = "\n".join(transcript_lines[-15:]) if transcript_lines else "(empty)"

        ai_section = ""
        if ai_context:
            ai_section = (
                f"\nPrevious AI analysis:\n"
                f"- Intent: {ai_context.get('detected_intent') or 'unknown'}\n"
                f"- Emotion: {ai_context.get('emotion') or 'unknown'}\n"
                f"- Confidence: {ai_context.get('confidence') or 0}\n"
                f"- AI's last reply: {ai_context.get('reply_text') or '(none)'}\n"
                f"- Last action: {ai_context.get('action') or '(none)'}\n"
            )

        return (
            f"Agent: {agent_username or 'unknown'}\n\n"
            f"Conversation transcript:\n{transcript_text}\n"
            f"{ai_section}\n"
            "Generate a draft reply suggestion and conversation analysis."
        )

    async def _call_llm(
        self,
        *,
        api_key: str,
        system_prompt: str,
        user_prompt: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": str(config.get("model") or "gpt-5.4-mini"),
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "max_tokens": 800,
                    "response_format": {"type": "json_object"},
                },
            )
        if resp.status_code >= 400:
            raise RuntimeError(f"Copilot LLM error {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        text = str((data.get("choices") or [{}])[0].get("message", {}).get("content") or "{}").strip()
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = {"suggestion": text, "summary": "", "error": "json_parse_failed"}

        return {
            "suggestion": str(parsed.get("suggestion") or "").strip(),
            "summary": str(parsed.get("summary") or "").strip(),
            "intent": str(parsed.get("intent") or "").strip(),
            "key_facts": list(parsed.get("key_facts") or []),
            "recommended_actions": list(parsed.get("recommended_actions") or []),
            "sentiment": str(parsed.get("sentiment") or "neutral").strip(),
            "language": str(parsed.get("language") or "").strip(),
        }
