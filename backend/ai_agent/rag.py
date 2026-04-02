"""Semantic RAG for AI agent policy retrieval.

Provides vector-embedding-based policy search using OpenAI text-embedding-3-small,
Shopify store policy import with Arabic translation, and a rebuild pipeline.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import time
from datetime import datetime
from typing import Any, Awaitable, Callable

import httpx

log = logging.getLogger(__name__)

EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIMENSIONS = 1536


# ---------------------------------------------------------------------------
# Cosine similarity (pure Python – policies are few, no numpy needed)
# ---------------------------------------------------------------------------
def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# PolicyRAG
# ---------------------------------------------------------------------------
class PolicyRAG:
    """Manages embedding generation, storage, and semantic retrieval for AI policies."""

    def __init__(
        self,
        db_manager: Any,
        get_api_key: Callable[[], Awaitable[str]],
    ):
        self.db_manager = db_manager
        self._get_api_key = get_api_key

    # ---- Schema ----
    async def ensure_schema(self) -> None:
        async with self.db_manager._conn() as db:
            stmt = self.db_manager._convert(
                """
                CREATE TABLE IF NOT EXISTS ai_policy_embeddings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workspace TEXT NOT NULL,
                    policy_id INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(workspace, policy_id)
                )
                """
            )
            if self.db_manager.use_postgres:
                stmt = stmt.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
                stmt = stmt.replace("UNIQUE(workspace, policy_id)", "UNIQUE (workspace, policy_id)")
            await db.execute(stmt) if self.db_manager.use_postgres else await _sqlite_exec(db, stmt)

    # ---- Embedding generation ----
    async def _embed_text(self, text: str) -> list[float]:
        api_key = await self._get_api_key()
        if not api_key:
            raise RuntimeError("Missing OpenAI API key for embeddings")
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
            resp = await client.post(
                "https://api.openai.com/v1/embeddings",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": EMBEDDING_MODEL,
                    "input": text[:8000],
                    "dimensions": EMBEDDING_DIMENSIONS,
                },
            )
        if resp.status_code >= 400:
            raise RuntimeError(f"Embedding API error {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        return list((data.get("data") or [{}])[0].get("embedding") or [])

    async def _embed_texts_batch(self, texts: list[str]) -> list[list[float]]:
        api_key = await self._get_api_key()
        if not api_key:
            raise RuntimeError("Missing OpenAI API key for embeddings")
        truncated = [t[:8000] for t in texts]
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            resp = await client.post(
                "https://api.openai.com/v1/embeddings",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": EMBEDDING_MODEL,
                    "input": truncated,
                    "dimensions": EMBEDDING_DIMENSIONS,
                },
            )
        if resp.status_code >= 400:
            raise RuntimeError(f"Embedding API error {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        items = sorted(data.get("data") or [], key=lambda x: x.get("index", 0))
        return [list(item.get("embedding") or []) for item in items]

    # ---- Storage ----
    async def upsert_policy_embedding(
        self,
        *,
        workspace: str,
        policy_id: int,
        content: str,
    ) -> None:
        await self.ensure_schema()
        chash = _content_hash(content)
        # Check if content unchanged
        existing = await self._get_embedding_row(workspace, policy_id)
        if existing and existing.get("content_hash") == chash:
            return  # already up to date
        embedding = await self._embed_text(content)
        emb_json = json.dumps(embedding)
        now = datetime.utcnow().isoformat()
        async with self.db_manager._conn() as db:
            if self.db_manager.use_postgres:
                q = self.db_manager._convert(
                    """
                    INSERT INTO ai_policy_embeddings (workspace, policy_id, content_hash, embedding_json, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (workspace, policy_id) DO UPDATE SET
                        content_hash = EXCLUDED.content_hash,
                        embedding_json = EXCLUDED.embedding_json,
                        updated_at = EXCLUDED.updated_at
                    """
                )
                await db.execute(q, workspace, policy_id, chash, emb_json, now)
            else:
                q = self.db_manager._convert(
                    """
                    INSERT INTO ai_policy_embeddings (workspace, policy_id, content_hash, embedding_json, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(workspace, policy_id) DO UPDATE SET
                        content_hash = excluded.content_hash,
                        embedding_json = excluded.embedding_json,
                        updated_at = excluded.updated_at
                    """
                )
                await db.execute(q, (workspace, policy_id, chash, emb_json, now))
                await db.commit()

    async def _get_embedding_row(self, workspace: str, policy_id: int) -> dict[str, Any] | None:
        async with self.db_manager._conn() as db:
            q = self.db_manager._convert(
                "SELECT * FROM ai_policy_embeddings WHERE workspace = ? AND policy_id = ? LIMIT 1"
            )
            if self.db_manager.use_postgres:
                row = await db.fetchrow(q, workspace, policy_id)
            else:
                cur = await db.execute(q, (workspace, policy_id))
                row = await cur.fetchone()
        return dict(row) if row else None

    # ---- Semantic search ----
    async def search_policies(
        self,
        query: str,
        *,
        workspace: str,
        policies: list[dict[str, Any]],
        limit: int = 5,
        min_score: float = 0.25,
    ) -> list[dict[str, Any]]:
        """Search policies by semantic similarity. Returns policies ranked by relevance."""
        if not query.strip() or not policies:
            return policies[:limit]

        await self.ensure_schema()
        # Load all embeddings for workspace
        async with self.db_manager._conn() as db:
            q = self.db_manager._convert(
                "SELECT policy_id, embedding_json FROM ai_policy_embeddings WHERE workspace = ?"
            )
            if self.db_manager.use_postgres:
                rows = await db.fetch(q, workspace)
            else:
                cur = await db.execute(q, (workspace,))
                rows = await cur.fetchall()

        if not rows:
            # No embeddings yet, fall back to returning all policies
            return policies[:limit]

        # Build embeddings index
        emb_by_id: dict[int, list[float]] = {}
        for row in rows:
            row_dict = dict(row)
            pid = int(row_dict.get("policy_id") or 0)
            try:
                emb = json.loads(row_dict.get("embedding_json") or "[]")
                if emb and len(emb) == EMBEDDING_DIMENSIONS:
                    emb_by_id[pid] = emb
            except Exception:
                continue

        if not emb_by_id:
            return policies[:limit]

        # Embed the query
        try:
            query_emb = await self._embed_text(query)
        except Exception as exc:
            log.warning("Failed to embed query for RAG search: %s", exc)
            return policies[:limit]

        # Score each policy
        scored: list[tuple[float, dict[str, Any]]] = []
        for policy in policies:
            pid = int(policy.get("id") or 0)
            if pid not in emb_by_id:
                scored.append((0.0, policy))
                continue
            score = _cosine_similarity(query_emb, emb_by_id[pid])
            scored.append((score, policy))

        # Sort by score descending, filter by min_score
        scored.sort(key=lambda x: x[0], reverse=True)
        results = [
            {**policy, "_rag_score": round(score, 4)}
            for score, policy in scored
            if score >= min_score
        ][:limit]

        return results if results else policies[:limit]

    # ---- Rebuild all embeddings ----
    async def rebuild_embeddings(
        self,
        *,
        workspace: str,
        policies: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Re-embed all policies for a workspace. Returns summary."""
        await self.ensure_schema()
        updated = 0
        skipped = 0
        errors = 0
        for policy in policies:
            pid = int(policy.get("id") or 0)
            content = f"{policy.get('topic') or ''} | {policy.get('title') or ''} | {policy.get('content') or ''}"
            try:
                await self.upsert_policy_embedding(
                    workspace=workspace,
                    policy_id=pid,
                    content=content,
                )
                existing = await self._get_embedding_row(workspace, pid)
                if existing and existing.get("content_hash") == _content_hash(content):
                    updated += 1
                else:
                    skipped += 1
            except Exception as exc:
                log.warning("Failed to embed policy %d: %s", pid, exc)
                errors += 1
        return {
            "workspace": workspace,
            "total_policies": len(policies),
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
        }

    # ---- Shopify policy import ----
    async def import_shopify_policies(
        self,
        *,
        workspace: str,
        shopify_base: str,
        shopify_headers: dict[str, str],
        upsert_policy: Callable[..., Awaitable[dict[str, Any]]],
        translate_to_arabic: bool = True,
    ) -> dict[str, Any]:
        """Import store policies from Shopify and optionally translate to Arabic."""
        # Fetch Shopify policies via REST Admin API
        url = f"{shopify_base}/policies.json"
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            resp = await client.get(url, headers=shopify_headers)
        if resp.status_code >= 400:
            return {"ok": False, "error": f"Shopify API error {resp.status_code}: {resp.text[:200]}"}

        data = resp.json()
        shopify_policies = data.get("policies") or []
        imported: list[dict[str, Any]] = []

        # Topic mapping from Shopify policy types
        _TYPE_TO_TOPIC: dict[str, str] = {
            "refund_policy": "return",
            "privacy_policy": "privacy",
            "terms_of_service": "terms",
            "shipping_policy": "delivery",
            "legal_notice": "legal",
            "subscription_policy": "subscription",
            "contact_information": "contact",
        }

        for sp in shopify_policies:
            title = str(sp.get("title") or "").strip()
            body = str(sp.get("body") or "").strip()
            if not body:
                continue
            # Strip HTML tags for clean policy text
            import re
            clean_body = re.sub(r"<[^>]+>", " ", body)
            clean_body = " ".join(clean_body.split()).strip()
            if not clean_body:
                continue

            sp_type = str(sp.get("type") or sp.get("handle") or "").strip().lower().replace(" ", "_").replace("-", "_")
            topic = _TYPE_TO_TOPIC.get(sp_type, sp_type or "general")

            # Save original (French/English) version
            original_doc = await upsert_policy(
                workspace=workspace,
                topic=topic,
                locale="fr",
                title=title,
                content=clean_body,
                source="shopify_import",
            )
            imported.append({"policy_id": original_doc.get("id"), "topic": topic, "locale": "fr", "title": title})

            # Translate to Arabic and save
            if translate_to_arabic:
                try:
                    ar_title, ar_body = await self._translate_policy_to_arabic(
                        title=title,
                        content=clean_body,
                    )
                    ar_doc = await upsert_policy(
                        workspace=workspace,
                        topic=topic,
                        locale="ar",
                        title=ar_title,
                        content=ar_body,
                        source="shopify_import_translated",
                    )
                    imported.append({"policy_id": ar_doc.get("id"), "topic": topic, "locale": "ar", "title": ar_title})
                except Exception as exc:
                    log.warning("Failed to translate policy '%s' to Arabic: %s", title, exc)

        return {
            "ok": True,
            "imported_count": len(imported),
            "policies": imported,
        }

    async def _translate_policy_to_arabic(self, *, title: str, content: str) -> tuple[str, str]:
        """Translate a policy title and content to Arabic using OpenAI."""
        api_key = await self._get_api_key()
        prompt = (
            "Translate the following store policy to Arabic (Modern Standard Arabic). "
            "Keep the translation professional, clear, and suitable for a customer-facing e-commerce store. "
            "Return ONLY a JSON object with two keys: \"title\" and \"content\".\n\n"
            f"Title: {title}\n\nContent:\n{content[:4000]}"
        )
        async with httpx.AsyncClient(timeout=httpx.Timeout(45.0, connect=10.0)) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-5.4-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 2000,
                    "response_format": {"type": "json_object"},
                },
            )
        if resp.status_code >= 400:
            raise RuntimeError(f"Translation API error: {resp.status_code}")
        data = resp.json()
        text = str((data.get("choices") or [{}])[0].get("message", {}).get("content") or "{}").strip()
        parsed = json.loads(text)
        return str(parsed.get("title") or title), str(parsed.get("content") or content)


async def _sqlite_exec(db: Any, stmt: str) -> None:
    await db.execute(stmt)
    await db.commit()
