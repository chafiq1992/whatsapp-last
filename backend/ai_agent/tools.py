from __future__ import annotations

import asyncio
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
    "من", "الى", "إلى", "على", "في", "مع", "هذا", "هذه", "هاد", "شنو", "عفاك", "بغيت", "كاين",
    "كاينة", "عندكم", "لو", "واش", "ممكن", "بدي", "اريد", "أريد", "ابغى", "أبغى",
}

GENDER_HINTS: dict[str, tuple[str, ...]] = {
    "girls": ("girls", "girl", "fille", "filles", "femme", "femmes", "women", "woman", "lady", "ladies", "بنت", "بنات", "للبنات", "نسائي", "نساء"),
    "boys": ("boys", "boy", "garcon", "garcons", "garçon", "garçons", "men", "man", "homme", "hommes", "ولد", "اولاد", "أولاد", "للأولاد", "رجالي", "رجال"),
}
SHOE_HINTS: tuple[str, ...] = (
    "shoe", "shoes", "sneaker", "sneakers", "sandale", "sandales", "sandal", "sandals",
    "chaussure", "chaussures", "chauss", "boot", "boots", "sabato", "sabat", "sbat",
    "Ø­Ø°Ø§Ø¡", "Ø£Ø­Ø°ÙŠØ©", "Ø­Ø¯Ø§Ø¡", "Ø³Ù†ÙŠÙƒØ±", "Ø³Ù†ÙŠÙƒØ±Ø²", "ØµØ¨Ø§Ø·", "Ø³Ø¨Ø§Ø·", "ØµÙ†Ø¯Ù„", "ØµÙ†Ø§Ø¯Ù„",
)

CLOTHING_HINTS: tuple[str, ...] = (
    "clothes", "clothing", "dress", "dresses", "shirt", "shirts", "pants", "trouser", "trousers",
    "jogger", "joggers", "survet", "survetement", "survÃªtement", "robe", "robes", "vetement", "vetements",
    "vÃªtement", "vÃªtements", "outfit", "outfits", "wear", "kidswear", "babywear",
    "Ù„Ø¨Ø§Ø³", "Ù…Ù„Ø§Ø¨Ø³", "Ø­ÙˆØ§ÙŠØ¬", "Ù‚Ù…ÙŠØµ", "Ù‚Ù…ØµØ§Ù†", "Ø³Ø±ÙˆØ§Ù„", "Ø³Ø±Ø§ÙˆÙ„", "ÙØ³ØªØ§Ù†", "ÙØ³Ø§ØªÙŠÙ†",
)


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
    catalog_sets_provider: Callable[[str], Awaitable[list[dict[str, Any]]]]
    catalog_set_products_provider: Callable[[str, str, int], Awaitable[list[dict[str, Any]]]]
    catalog_filters_provider: Callable[[str], Awaitable[list[dict[str, Any]]]]
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
        self.catalog_sets_provider = deps.catalog_sets_provider
        self.catalog_set_products_provider = deps.catalog_set_products_provider
        self.catalog_filters_provider = deps.catalog_filters_provider
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
            scoped_sets = await self._select_catalog_sets(query=query, workspace=ws, limit=limit)
            products = await self._load_catalog_scope_products(workspace=ws, scoped_sets=scoped_sets, limit=limit)
            if not products and not scoped_sets:
                products = await self.catalog_provider(ws)
        except Exception as exc:
            self.log.warning("ai_tool search_catalog_products failed ws=%s err=%s", ws, exc)
            return self._error("temporary_unavailable", str(exc), "whatsapp_catalog", started)
        tokens = self._query_tokens(query)
        scored: list[tuple[float, dict[str, Any]]] = []
        for item in products or []:
            name = str(item.get("name") or "").strip()
            retailer_id = str(item.get("retailer_id") or item.get("id") or "").strip()
            if not name or not retailer_id:
                continue
            set_name = str(item.get("catalog_set_name") or "").strip()
            hay = f"{name} {set_name} {json.dumps(item, ensure_ascii=False)}".lower()
            score = 0.0
            for token in tokens:
                if token in hay:
                    score += 1.0
                if token in name.lower():
                    score += 1.25
                if set_name and token in set_name.lower():
                    score += 1.35
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
                    "catalog_set_id": item.get("catalog_set_id"),
                    "catalog_set_name": item.get("catalog_set_name"),
                },
            ))
        scored.sort(key=lambda row: (-row[0], str(row[1].get("name") or "")))
        matched_sets = [
            {"id": item.get("id"), "name": item.get("name")}
            for item in scoped_sets[:6]
            if str(item.get("id") or "").strip()
        ]
        return self._ok(
            {
                "products": [row[1] for row in scored[: max(1, min(int(limit), 20))]],
                "matched_sets": matched_sets,
                "preferred_set": matched_sets[0] if matched_sets else None,
            },
            "whatsapp_catalog",
            started,
        )

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

    def _query_tokens(self, query: str) -> list[str]:
        return [
            t for t in re.findall(r"[\w\u0600-\u06FF]+", str(query or "").lower())
            if (len(t) >= 2 or t.isdigit()) and t not in STOPWORDS
        ]

    async def _select_catalog_sets(self, *, query: str, workspace: str, limit: int) -> list[dict[str, Any]]:
        sets = await self.catalog_sets_provider(workspace)
        if not sets:
            return []
        filters = await self.catalog_filters_provider(workspace)
        chosen_filter = self._pick_catalog_filter(query=query, filters=filters)
        candidate_sets = self._apply_catalog_filter(sets=sets, selected_filter=chosen_filter)
        if not candidate_sets:
            candidate_sets = [dict(item) for item in sets if str(item.get("id") or "").strip()]
        request_specs = self._extract_catalog_request_specs(query)
        if len({str(spec.get("gender") or "").strip() for spec in request_specs if str(spec.get("gender") or "").strip()}) > 1:
            candidate_sets = [dict(item) for item in sets if str(item.get("id") or "").strip()]
        if request_specs:
            exact_matches: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            for spec in request_specs:
                ranked_structured: list[tuple[float, dict[str, Any]]] = []
                for item in candidate_sets:
                    matched, score = self._structured_set_match_score(item=item, spec=spec)
                    set_id = str(item.get("id") or "").strip()
                    if not matched or not set_id or set_id in seen_ids:
                        continue
                    ranked_structured.append((score, dict(item)))
                ranked_structured.sort(key=lambda row: (-row[0], str(row[1].get("name") or "")))
                if ranked_structured:
                    chosen = ranked_structured[0][1]
                    chosen_id = str(chosen.get("id") or "").strip()
                    if chosen_id and chosen_id not in seen_ids:
                        seen_ids.add(chosen_id)
                        exact_matches.append(chosen)
            if exact_matches:
                return exact_matches[: max(2, min(6, int(limit or 6)))]
            candidate_sets = [item for item in candidate_sets if not self._is_broad_catalog_set(item)]
            if not candidate_sets:
                return []
        tokens = self._query_tokens(query)
        if not tokens:
            return candidate_sets[: max(4, min(8, int(limit or 6) * 2))]

        ranked: list[tuple[float, dict[str, Any]]] = []
        for item in candidate_sets:
            set_id = str(item.get("id") or "").strip()
            set_name = str(item.get("name") or "").strip()
            if not set_id:
                continue
            hay = f"{set_name} {set_id}".lower()
            score = 0.0
            for token in tokens:
                if token in hay:
                    score += 2.0
                if set_name and token in set_name.lower():
                    score += 1.0
            if chosen_filter and str(chosen_filter.get("type") or "").strip().lower() != "all":
                score += 0.25
            if score > 0:
                ranked.append((score, dict(item)))
        ranked.sort(key=lambda row: (-row[0], str(row[1].get("name") or "")))
        if ranked:
            return [row[1] for row in ranked[: max(3, min(6, int(limit or 6)))]]
        return candidate_sets[: max(4, min(8, int(limit or 6) * 2))]

    def _extract_catalog_request_specs(self, query: str) -> list[dict[str, Any]]:
        lowered = str(query or "").lower()
        global_gender = self._detect_gender_bucket(lowered)
        segments = self._split_catalog_query_segments(lowered)
        specs: list[dict[str, Any]] = []
        for segment in segments:
            gender = self._detect_gender_bucket(segment) or global_gender
            ages = self._extract_age_values(segment)
            sizes = self._extract_size_values(segment)
            category = self._detect_catalog_category(segment)
            if not gender and not ages and not sizes:
                continue
            specs.append(
                {
                    "segment": segment,
                    "gender": gender,
                    "ages": ages,
                    "sizes": sizes,
                    "category": category,
                }
            )
        return specs

    def _split_catalog_query_segments(self, query: str) -> list[str]:
        raw_segments = re.split(r"\s+(?:and|et)\s+|\s+و\s+|[،,;+]+", str(query or "").lower())
        cleaned = [" ".join(segment.split()) for segment in raw_segments if str(segment or "").strip()]
        return cleaned or ([str(query or "").lower().strip()] if str(query or "").strip() else [])

    def _extract_age_values(self, text: str) -> list[int]:
        values: list[int] = []
        lowered = str(text or "").lower()
        for match in re.finditer(r"(?<!\d)(\d{1,2})\s*(ans?|years?|yrs?|yo|y/o|an)(?!\d)", lowered):
            age = self._safe_int(match.group(1))
            if age is not None and 0 <= age <= 14 and age not in values:
                values.append(age)
        return values

    def _extract_size_values(self, text: str) -> list[int]:
        values: list[int] = []
        lowered = str(text or "").lower()
        for match in re.finditer(r"(?<!\d)(\d{2})(?!\d)", lowered):
            size = self._safe_int(match.group(1))
            if size is None:
                continue
            if 15 <= size <= 45 and size not in values:
                values.append(size)
        return values

    def _detect_catalog_category(self, text: str) -> str | None:
        lowered = str(text or "").lower()
        if self._text_has_any(lowered, SHOE_HINTS):
            return "shoes"
        if self._text_has_any(lowered, CLOTHING_HINTS):
            return "clothing"
        return None

    def _catalog_set_attributes(self, item: dict[str, Any]) -> dict[str, Any]:
        set_id = str(item.get("id") or "").strip()
        set_name = str(item.get("name") or "").strip()
        hay = f"{set_name} {set_id}".lower()
        ages = self._extract_age_values(hay)
        sizes = self._extract_size_values(hay)
        return {
            "hay": hay,
            "gender": self._detect_gender_bucket(hay),
            "ages": ages,
            "sizes": sizes,
            "category": self._detect_catalog_category(hay),
        }

    def _structured_set_match_score(self, *, item: dict[str, Any], spec: dict[str, Any]) -> tuple[bool, float]:
        attrs = self._catalog_set_attributes(item)
        hay = str(attrs.get("hay") or "")
        requested_gender = str(spec.get("gender") or "").strip()
        requested_ages = [int(v) for v in (spec.get("ages") or []) if isinstance(v, int)]
        requested_sizes = [int(v) for v in (spec.get("sizes") or []) if isinstance(v, int)]
        requested_category = str(spec.get("category") or "").strip()
        if requested_gender and attrs.get("gender") != requested_gender:
            return False, 0.0
        if requested_ages and not any(age in (attrs.get("ages") or []) for age in requested_ages):
            return False, 0.0
        if requested_sizes and not any(size in (attrs.get("sizes") or []) for size in requested_sizes):
            return False, 0.0
        if requested_category == "shoes" and attrs.get("category") != "shoes":
            return False, 0.0
        if requested_category == "clothing" and attrs.get("category") == "shoes":
            return False, 0.0
        score = 0.0
        if requested_gender:
            score += 4.0
        if requested_ages:
            score += 5.0 * len(requested_ages)
        if requested_sizes:
            score += 5.0 * len(requested_sizes)
        if requested_category and attrs.get("category") == requested_category:
            score += 2.0
        if not requested_category and attrs.get("category") == "shoes" and requested_sizes:
            score += 1.5
        if not requested_category and attrs.get("category") == "clothing" and requested_ages:
            score += 1.5
        score += 0.1 * len(hay)
        return True, score

    def _is_broad_catalog_set(self, item: dict[str, Any]) -> bool:
        hay = f"{item.get('name') or ''} {item.get('id') or ''}".strip().lower()
        return bool(
            "all products" in hay
            or "all-products" in hay
            or re.search(r"\ball\b", hay)
            or "catalog" in hay
            or "catalogue" in hay
            or re.search(r"\bfull\b", hay)
        )

    async def _load_catalog_scope_products(self, *, workspace: str, scoped_sets: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        if not scoped_sets:
            return []
        per_set_limit = max(24, min(160, max(1, int(limit or 6)) * 20))
        tasks = [
            self.catalog_set_products_provider(workspace, str(item.get("id") or "").strip(), per_set_limit)
            for item in scoped_sets
            if str(item.get("id") or "").strip()
        ]
        if not tasks:
            return []
        batches = await asyncio.gather(*tasks, return_exceptions=True)
        merged: list[dict[str, Any]] = []
        seen: set[str] = set()
        for idx, batch in enumerate(batches):
            if isinstance(batch, Exception):
                continue
            set_info = scoped_sets[idx]
            set_id = str(set_info.get("id") or "").strip()
            set_name = str(set_info.get("name") or "").strip()
            for item in batch or []:
                retailer_id = str(item.get("retailer_id") or item.get("id") or "").strip()
                if not retailer_id or retailer_id in seen:
                    continue
                seen.add(retailer_id)
                merged.append({
                    **dict(item),
                    "catalog_set_id": set_id,
                    "catalog_set_name": set_name,
                })
        return merged

    def _pick_catalog_filter(self, *, query: str, filters: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not filters:
            return None
        lowered = str(query or "").lower()
        detected_gender = self._detect_gender_bucket(lowered)
        best: tuple[float, dict[str, Any]] | None = None
        for item in filters:
            if not isinstance(item, dict):
                continue
            if str(item.get("type") or "").strip().lower() == "all":
                continue
            score = 0.0
            label = str(item.get("label") or "").strip().lower()
            query_hint = str(item.get("query") or "").strip().lower()
            for candidate in (label, query_hint):
                if candidate and candidate in lowered:
                    score += 3.0
            if detected_gender == "girls" and self._text_has_any(f"{label} {query_hint}", GENDER_HINTS["girls"]):
                score += 4.0
            if detected_gender == "boys" and self._text_has_any(f"{label} {query_hint}", GENDER_HINTS["boys"]):
                score += 4.0
            if score <= 0:
                continue
            if best is None or score > best[0]:
                best = (score, item)
        return best[1] if best else None

    def _apply_catalog_filter(self, *, sets: list[dict[str, Any]], selected_filter: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not selected_filter or str(selected_filter.get("type") or "").strip().lower() == "all":
            return [dict(item) for item in sets if str(item.get("id") or "").strip()]
        query = str(selected_filter.get("query") or "").strip().lower()
        match_mode = str(selected_filter.get("match") or "includes").strip().lower()
        if not query:
            return [dict(item) for item in sets if str(item.get("id") or "").strip()]
        out: list[dict[str, Any]] = []
        for item in sets:
            set_id = str(item.get("id") or "").strip()
            name_or_id = f"{item.get('name') or ''} {set_id}".strip().lower()
            if not set_id:
                continue
            if match_mode in {"start", "startswith", "starts_with"}:
                if name_or_id.startswith(query):
                    out.append(dict(item))
            elif query in name_or_id:
                out.append(dict(item))
        return out

    def _detect_gender_bucket(self, lowered_query: str) -> str | None:
        if self._text_has_any(lowered_query, GENDER_HINTS["girls"]):
            return "girls"
        if self._text_has_any(lowered_query, GENDER_HINTS["boys"]):
            return "boys"
        return None

    def _text_has_any(self, text: str, candidates: tuple[str, ...]) -> bool:
        lowered = str(text or "").lower()
        return any(candidate and candidate in lowered for candidate in candidates)
