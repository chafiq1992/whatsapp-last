from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "are", "you", "pls", "svp", "pour", "avec",
    "bonjour", "salut", "hello", "salam", "slm", "ana", "bghit", "mabghitch", "wach", "had",
    "hada", "hadi", "fin", "ila", "size", "taille", "pointure",
}


@dataclass
class ToolResult:
    ok: bool
    data: dict[str, Any]
    source: str
    error_code: str | None = None
    error_message: str | None = None
    latency_ms: int = 0

    def as_response(self) -> dict[str, Any]:
        payload = {
            "ok": bool(self.ok),
            "data": self.data,
            "source": self.source,
            "latency_ms": int(self.latency_ms or 0),
        }
        if self.error_code:
            payload["error_code"] = self.error_code
        if self.error_message:
            payload["error_message"] = self.error_message
        return payload


@dataclass
class AIAgentToolDependencies:
    normalize_workspace: Callable[[str | None], str]
    fetch_customer_by_phone: Callable[[str, str], Awaitable[dict[str, Any] | None]]
    fetch_orders_for_customer: Callable[[str, str, int], Awaitable[list[dict[str, Any]]]]
    fetch_delivery_snapshot: Callable[[str, str | None, str], Awaitable[dict[str, Any] | None]]
    list_agents: Callable[[], Awaitable[list[dict[str, Any]]]]
    get_agent_last_seen: Callable[[str, str], Awaitable[float | None]]
    get_agent_assignment_count: Callable[[str, str], Awaitable[int]]
    set_conversation_assignment: Callable[[str, str | None], Awaitable[None]]
    get_conversation_meta: Callable[[str], Awaitable[dict[str, Any]]]
    catalog_provider: Callable[[str], Awaitable[list[dict[str, Any]]]]
    logger: logging.Logger


class AIAgentToolbox:
    def __init__(self, deps: AIAgentToolDependencies):
        self.normalize_workspace = deps.normalize_workspace
        self.fetch_customer_by_phone = deps.fetch_customer_by_phone
        self.fetch_orders_for_customer = deps.fetch_orders_for_customer
        self.fetch_delivery_snapshot = deps.fetch_delivery_snapshot
        self.list_agents = deps.list_agents
        self.get_agent_last_seen = deps.get_agent_last_seen
        self.get_agent_assignment_count = deps.get_agent_assignment_count
        self.set_conversation_assignment = deps.set_conversation_assignment
        self.get_conversation_meta = deps.get_conversation_meta
        self.catalog_provider = deps.catalog_provider
        self.log = deps.logger

    async def find_customer_by_phone(self, *, phone_e164: str, workspace: str) -> ToolResult:
        started = time.perf_counter()
        ws = self.normalize_workspace(workspace)
        phone = self._normalize_phone(phone_e164)
        if not phone:
            return self._error("validation_error", "phone_e164 is required", "shopify", started)
        try:
            customer = await self.fetch_customer_by_phone(phone, ws)
        except Exception as exc:
            self.log.warning("ai_tool find_customer_by_phone failed ws=%s phone=%s err=%s", ws, self._mask_phone(phone), exc)
            return self._error("temporary_unavailable", str(exc), "shopify", started)
        if not customer or (isinstance(customer, dict) and customer.get("error")):
            detail = ""
            if isinstance(customer, dict):
                detail = str(customer.get("detail") or customer.get("error") or "")
            return self._error("not_found", detail or "customer not found", "shopify", started)
        payload = {
            "found": True,
            "customer": {
                "customer_id": customer.get("customer_id"),
                "name": customer.get("name"),
                "email": customer.get("email"),
                "phone": customer.get("phone"),
                "address": customer.get("address"),
                "total_orders": customer.get("total_orders"),
                "last_order": customer.get("last_order"),
            },
        }
        return self._ok(payload, "shopify", started)

    async def get_order_by_reference(self, *, order_reference: str, phone_e164: str | None, workspace: str, limit: int = 20) -> ToolResult:
        started = time.perf_counter()
        ws = self.normalize_workspace(workspace)
        ref = self._normalize_order_ref(order_reference)
        phone = self._normalize_phone(phone_e164 or "")
        if not ref and not phone:
            return self._error("validation_error", "order_reference or phone_e164 is required", "shopify", started)

        customer: dict[str, Any] | None = None
        if phone:
            customer_result = await self.find_customer_by_phone(phone_e164=phone, workspace=ws)
            if customer_result.ok:
                customer = dict(customer_result.data.get("customer") or {})

        customer_id = str((customer or {}).get("customer_id") or "").strip()
        if not customer_id:
            return self._error("not_found", "customer not found for order lookup", "shopify", started)

        try:
            orders = await self.fetch_orders_for_customer(customer_id, ws, max(1, min(int(limit), 50)))
        except Exception as exc:
            self.log.warning("ai_tool get_order_by_reference failed ws=%s customer=%s err=%s", ws, customer_id, exc)
            return self._error("temporary_unavailable", str(exc), "shopify", started)

        matched = None
        if ref:
            for order in orders:
                candidates = {
                    self._normalize_order_ref(order.get("order_number")),
                    self._normalize_order_ref(order.get("id")),
                }
                candidates.discard("")
                if ref in candidates:
                    matched = order
                    break
        elif orders:
            matched = orders[0]

        if not matched:
            return self._error("not_found", "order not found", "shopify", started)

        payload = {
            "found": True,
            "order": {
                "order_id": matched.get("id"),
                "reference": matched.get("order_number"),
                "financial_status": matched.get("financial_status"),
                "fulfillment_status": matched.get("fulfillment_status"),
                "total_price": matched.get("total_price"),
                "currency": matched.get("currency"),
                "tags": matched.get("tags") or [],
                "note": matched.get("note") or "",
                "created_at": matched.get("created_at"),
                "admin_url": matched.get("admin_url"),
            },
            "customer": customer or {},
        }
        return self._ok(payload, "shopify", started)

    async def search_catalog_products(self, *, query: str, workspace: str, limit: int = 6) -> ToolResult:
        started = time.perf_counter()
        ws = self.normalize_workspace(workspace)
        try:
            products = await self.catalog_provider(ws)
        except Exception as exc:
            self.log.warning("ai_tool search_catalog_products failed ws=%s err=%s", ws, exc)
            return self._error("temporary_unavailable", str(exc), "whatsapp_catalog", started)
        tokens = [
            t for t in re.findall(r"[\w\u0600-\u06FF]+", str(query or "").lower())
            if len(t) >= 2 and t not in STOPWORDS
        ]
        scored: list[tuple[float, dict[str, Any]]] = []
        for item in products or []:
            name = str(item.get("name") or "").strip()
            retailer_id = str(item.get("retailer_id") or item.get("id") or "").strip()
            if not name or not retailer_id:
                continue
            hay = f"{name} {json.dumps(item, ensure_ascii=False)}".lower()
            score = 0.0
            for token in tokens:
                if token in hay:
                    score += 1.0
                if token in name.lower():
                    score += 1.25
            if not tokens:
                score = 0.1
            if score <= 0:
                continue
            scored.append((
                score,
                {
                    "product_id": retailer_id,
                    "retailer_id": retailer_id,
                    "name": name,
                    "price": item.get("price"),
                    "availability": item.get("availability"),
                    "quantity": item.get("quantity"),
                    "images": item.get("images") or [],
                },
            ))
        scored.sort(key=lambda row: (-row[0], str(row[1].get("name") or "")))
        return self._ok({"products": [row[1] for row in scored[: max(1, min(int(limit), 20))]]}, "whatsapp_catalog", started)

    async def check_stock_availability(self, *, product_id: str | None, retailer_id: str | None, workspace: str) -> ToolResult:
        started = time.perf_counter()
        ws = self.normalize_workspace(workspace)
        target = str(retailer_id or product_id or "").strip()
        if not target:
            return self._error("validation_error", "product_id or retailer_id is required", "whatsapp_catalog", started)
        try:
            products = await self.catalog_provider(ws)
        except Exception as exc:
            self.log.warning("ai_tool check_stock_availability failed ws=%s target=%s err=%s", ws, target, exc)
            return self._error("temporary_unavailable", str(exc), "whatsapp_catalog", started)
        match = None
        for item in products or []:
            candidate = str(item.get("retailer_id") or item.get("id") or "").strip()
            if candidate and candidate == target:
                match = item
                break
        if not match:
            return self._error("not_found", "product not found", "whatsapp_catalog", started)
        availability = str(match.get("availability") or "").strip().lower()
        qty = self._safe_int(match.get("quantity"))
        payload = {
            "available": availability not in {"out_of_stock", "discontinued"} and (qty is None or qty > 0),
            "quantity": qty,
            "availability": availability or None,
            "retailer_id": str(match.get("retailer_id") or match.get("id") or "").strip(),
            "name": match.get("name"),
        }
        return self._ok(payload, "whatsapp_catalog", started)

    async def get_delivery_status(self, *, user_id: str, order_reference: str | None, workspace: str) -> ToolResult:
        started = time.perf_counter()
        ws = self.normalize_workspace(workspace)
        uid = str(user_id or "").strip()
        ref = self._normalize_order_ref(order_reference)
        if not uid:
            return self._error("validation_error", "user_id is required", "delivery", started)
        try:
            snapshot = await self.fetch_delivery_snapshot(uid, ref or None, ws)
        except Exception as exc:
            self.log.warning("ai_tool get_delivery_status failed ws=%s user=%s err=%s", ws, uid, exc)
            return self._error("temporary_unavailable", str(exc), "delivery", started)
        if not snapshot:
            return self._error("not_found", "delivery status not found", "delivery", started)
        return self._ok(snapshot, "delivery", started)

    async def assign_human_agent(self, *, user_id: str, workspace: str, preferred_agent: str | None = None) -> ToolResult:
        started = time.perf_counter()
        ws = self.normalize_workspace(workspace)
        uid = str(user_id or "").strip()
        if not uid:
            return self._error("validation_error", "user_id is required", "inbox", started)

        meta = await self.get_conversation_meta(uid)
        current = str((meta or {}).get("assigned_agent") or "").strip()
        if current:
            return self._ok(
                {
                    "assigned": True,
                    "agent_username": current,
                    "strategy": "existing_assignment",
                    "reason": "conversation already assigned",
                },
                "inbox",
                started,
            )

        try:
            agents = await self.list_agents()
        except Exception as exc:
            return self._error("temporary_unavailable", str(exc), "inbox", started)

        clean_agents = []
        for agent in agents or []:
            username = str(agent.get("username") or "").strip()
            if username:
                clean_agents.append(agent)
        if not clean_agents:
            return self._error("no_agent_available", "no agents configured", "inbox", started)

        chosen = None
        strategy = "auto_presence_load"
        preferred = str(preferred_agent or "").strip()
        if preferred:
            chosen = next((agent for agent in clean_agents if str(agent.get("username") or "").strip() == preferred), None)
            strategy = "preferred_agent"
            if not chosen:
                return self._error("not_found", "preferred agent not found", "inbox", started)
        else:
            ranked: list[tuple[int, int, float, str, dict[str, Any]]] = []
            for agent in clean_agents:
                username = str(agent.get("username") or "").strip()
                try:
                    load = int(await self.get_agent_assignment_count(username, ws))
                except Exception:
                    load = 999999
                try:
                    last_seen = float(await self.get_agent_last_seen(username, ws) or 0.0)
                except Exception:
                    last_seen = 0.0
                is_online_rank = 0 if last_seen and (time.time() - last_seen) <= 15 * 60 else 1
                admin_rank = 1 if int(agent.get("is_admin") or 0) else 0
                ranked.append((is_online_rank, admin_rank, load, -last_seen, username, agent))
            ranked.sort(key=lambda row: (row[0], row[1], row[2], row[3], row[4]))
            chosen = ranked[0][5] if ranked else None

        if not chosen:
            return self._error("no_agent_available", "no eligible agent found", "inbox", started)

        username = str(chosen.get("username") or "").strip()
        try:
            await self.set_conversation_assignment(uid, username)
        except Exception as exc:
            return self._error("temporary_unavailable", str(exc), "inbox", started)
        return self._ok(
            {
                "assigned": True,
                "agent_username": username,
                "strategy": strategy,
                "agent_name": chosen.get("name"),
                "is_admin": bool(chosen.get("is_admin")),
            },
            "inbox",
            started,
        )

    def _ok(self, data: dict[str, Any], source: str, started: float) -> ToolResult:
        return ToolResult(ok=True, data=data, source=source, latency_ms=int((time.perf_counter() - started) * 1000))

    def _error(self, code: str, message: str, source: str, started: float) -> ToolResult:
        return ToolResult(
            ok=False,
            data={},
            source=source,
            error_code=code,
            error_message=message,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )

    def _normalize_phone(self, value: str) -> str:
        raw = str(value or "").strip().replace(" ", "").replace("-", "")
        if not raw:
            return ""
        if raw.startswith("+"):
            return raw
        if raw.startswith("212"):
            return "+" + raw
        if raw.startswith("0") and len(raw) >= 10:
            return "+212" + raw[1:]
        return raw

    def _normalize_order_ref(self, value: Any) -> str:
        s = str(value or "").strip()
        if s.startswith("#"):
            s = s[1:]
        if re.fullmatch(r"\d+\.\d+", s):
            s = s.split(".", 1)[0]
        return s.strip().lower()

    def _mask_phone(self, value: str) -> str:
        clean = str(value or "").strip()
        if len(clean) <= 4:
            return clean
        return "*" * max(0, len(clean) - 4) + clean[-4:]

    def _safe_int(self, value: Any) -> int | None:
        try:
            if value is None or value == "":
                return None
            return int(float(value))
        except Exception:
            return None
