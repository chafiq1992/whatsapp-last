import logging

import pytest

from backend.ai_agent.service import AIAgentDependencies, AIAgentService, DEFAULT_AGENT_CONFIG
from backend.ai_agent.tools import AIAgentToolDependencies, AIAgentToolbox


async def _noop_customer(*args, **kwargs):
    return None


async def _noop_orders(*args, **kwargs):
    return []


async def _noop_delivery(*args, **kwargs):
    return None


async def _noop_agents(*args, **kwargs):
    return []


async def _noop_last_seen(*args, **kwargs):
    return None


async def _noop_assignment_count(*args, **kwargs):
    return 0


async def _noop_assignment(*args, **kwargs):
    return None


async def _noop_meta(*args, **kwargs):
    return {}


def _make_toolbox() -> AIAgentToolbox:
    sets = [
        {"id": "boys-2ans", "name": "Boys 2 ans"},
        {"id": "girls-2ans", "name": "Girls 2 ans"},
        {"id": "girls-24", "name": "Girls Shoes 24"},
        {"id": "boys-22", "name": "Boys Shoes 22"},
        {"id": "boys-24", "name": "Boys Shoes 24"},
        {"id": "all-products", "name": "All Products"},
    ]
    filters = [
        {"label": "Girls", "query": "girls", "match": "includes"},
        {"label": "Boys", "query": "boys", "match": "includes"},
        {"label": "All", "type": "all"},
    ]
    set_products = {
        "boys-2ans": [
            {
                "retailer_id": "B-2A-1",
                "name": "Boys Outfit 2 ans",
                "availability": "in stock",
                "quantity": 4,
                "images": [],
            }
        ],
        "girls-2ans": [
            {
                "retailer_id": "G-2A-1",
                "name": "Girls Outfit 2 ans",
                "availability": "in stock",
                "quantity": 5,
                "images": [],
            }
        ],
        "girls-24": [
            {
                "retailer_id": "G-24-1",
                "name": "صندل بنات 24",
                "availability": "in stock",
                "quantity": 4,
                "images": [],
            }
        ],
        "boys-22": [
            {
                "retailer_id": "B-22-1",
                "name": "Boys Sneakers 22",
                "availability": "in stock",
                "quantity": 6,
                "images": [],
            }
        ],
        "boys-24": [
            {
                "retailer_id": "B-24-1",
                "name": "صندل أولاد 24",
                "availability": "in stock",
                "quantity": 3,
                "images": [],
            }
        ],
    }

    async def catalog_provider(workspace: str):
        return [
            {
                "retailer_id": "fallback-1",
                "name": "منتج عام",
                "availability": "in stock",
                "quantity": 8,
                "images": [],
            }
        ]

    async def catalog_sets_provider(workspace: str):
        return sets

    async def catalog_set_products_provider(workspace: str, set_id: str, limit: int):
        return set_products.get(set_id, [])[:limit]

    async def catalog_filters_provider(workspace: str):
        return filters

    return AIAgentToolbox(
        AIAgentToolDependencies(
            normalize_workspace=lambda ws: str(ws or "default"),
            fetch_customer_by_phone=_noop_customer,
            fetch_orders_for_customer=_noop_orders,
            fetch_delivery_snapshot=_noop_delivery,
            list_agents=_noop_agents,
            get_agent_last_seen=_noop_last_seen,
            get_agent_assignment_count=_noop_assignment_count,
            set_conversation_assignment=_noop_assignment,
            get_conversation_meta=_noop_meta,
            catalog_provider=catalog_provider,
            catalog_sets_provider=catalog_sets_provider,
            catalog_set_products_provider=catalog_set_products_provider,
            catalog_filters_provider=catalog_filters_provider,
            logger=logging.getLogger("test.ai_agent.toolbox"),
        )
    )


def _make_service() -> AIAgentService:
    class _DBManager:
        async def get_conversation_meta(self, user_id: str):
            return {}

    class _MessageProcessor:
        pass

    async def _catalog_provider(workspace: str):
        return []

    async def _catalog_sets_provider(workspace: str):
        return []

    async def _catalog_set_products_provider(workspace: str, set_id: str, limit: int):
        return []

    async def _catalog_filters_provider(workspace: str):
        return []

    return AIAgentService(
        AIAgentDependencies(
            db_manager=_DBManager(),
            message_processor=_MessageProcessor(),
            get_workspace=lambda: "default",
            normalize_workspace=lambda ws: str(ws or "default"),
            make_settings_key=lambda key, ws=None: key,
            decrypt_secret=lambda value: str(value or ""),
            catalog_provider=_catalog_provider,
            catalog_sets_provider=_catalog_sets_provider,
            catalog_set_products_provider=_catalog_set_products_provider,
            catalog_filters_provider=_catalog_filters_provider,
            fetch_customer_by_phone=_noop_customer,
            fetch_orders_for_customer=_noop_orders,
            fetch_delivery_snapshot=_noop_delivery,
            list_agents=_noop_agents,
            get_agent_last_seen=_noop_last_seen,
            get_agent_assignment_count=_noop_assignment_count,
            set_conversation_assignment=_noop_assignment,
            push_workspace=lambda ws: None,
            pop_workspace=lambda token: None,
            logger=logging.getLogger("test.ai_agent.service"),
        )
    )


@pytest.mark.asyncio
async def test_search_catalog_products_uses_inbox_sets_and_returns_set_metadata():
    toolbox = _make_toolbox()

    result = await toolbox.search_catalog_products(
        query="بغيت صندل للبنات مقاس 24",
        workspace="default",
        limit=4,
    )

    assert result.ok is True
    products = result.data["products"]
    assert products
    assert products[0]["retailer_id"] == "G-24-1"
    assert products[0]["catalog_set_id"] == "girls-24"
    assert products[0]["catalog_set_name"] == "Girls Shoes 24"
    assert result.data["preferred_set"] == {"id": "girls-24", "name": "Girls Shoes 24"}


@pytest.mark.asyncio
async def test_search_catalog_products_prefers_exact_age_set_over_full_catalog():
    toolbox = _make_toolbox()

    result = await toolbox.search_catalog_products(
        query="girls 2 ans clothes",
        workspace="default",
        limit=4,
    )

    assert result.ok is True
    assert result.data["matched_sets"][0] == {"id": "girls-2ans", "name": "Girls 2 ans"}
    assert {item["id"] for item in result.data["matched_sets"]} == {"girls-2ans"}
    assert result.data["products"][0]["catalog_set_id"] == "girls-2ans"


@pytest.mark.asyncio
async def test_search_catalog_products_requests_clarification_for_age_only_query():
    toolbox = _make_toolbox()

    result = await toolbox.search_catalog_products(
        query="2 years",
        workspace="default",
        limit=4,
    )

    assert result.ok is True
    assert result.data["matched_sets"] == []
    assert result.data["products"] == []
    assert result.data["clarification"] == {
        "needed": True,
        "reason": "missing_gender_for_age",
        "age": 2,
    }


@pytest.mark.asyncio
async def test_search_catalog_products_returns_multiple_exact_sets_for_multi_request():
    toolbox = _make_toolbox()

    result = await toolbox.search_catalog_products(
        query="boys 22 and girls 2 ans",
        workspace="default",
        limit=6,
    )

    assert result.ok is True
    matched_ids = [item["id"] for item in result.data["matched_sets"]]
    assert matched_ids == ["boys-22", "girls-2ans"]


def test_system_prompt_forces_arabic_script_and_catalog_set_fields():
    service = _make_service()

    prompt = service._build_system_prompt(DEFAULT_AGENT_CONFIG)

    assert "Arabic script" in prompt
    assert "never Latin letters" in prompt
    assert "\"recommended_catalog_set_id\":\"\"" in prompt
    assert "\"recommended_catalog_set_name\":\"\"" in prompt


@pytest.mark.asyncio
async def test_prefetch_catalog_context_returns_preferred_set_and_candidates():
    service = _make_service()

    async def fake_search_catalog_products(*, query: str, workspace: str, limit: int):
        class _Result:
            ok = True
            data = {
                "products": [{"retailer_id": "G-25-1", "name": "حذاء بنات 25", "catalog_set_name": "Girls 25"}],
                "matched_sets": [{"id": "girls-25", "name": "Girls 25"}],
                "preferred_set": {"id": "girls-25", "name": "Girls 25"},
            }

        return _Result()

    service.tools.search_catalog_products = fake_search_catalog_products

    context = await service._prefetch_catalog_context(
        "send me catalog set for size 25 girls",
        workspace="default",
        limit=6,
    )

    assert context["preferred_catalog_set"] == {"id": "girls-25", "name": "Girls 25"}
    assert context["matched_catalog_sets"] == [{"id": "girls-25", "name": "Girls 25"}]
    assert context["catalog_candidates"][0]["retailer_id"] == "G-25-1"


@pytest.mark.asyncio
async def test_prefetch_catalog_context_combines_recent_customer_measurements():
    service = _make_service()
    captured: list[str] = []

    async def fake_search_catalog_products(*, query: str, workspace: str, limit: int):
        captured.append(query)

        class _Result:
            ok = True
            data = {
                "products": [],
                "matched_sets": [{"id": "girls-2ans", "name": "Girls 2 ans"}],
                "preferred_set": {"id": "girls-2ans", "name": "Girls 2 ans"},
                "clarification": None,
            }

        return _Result()

    service.tools.search_catalog_products = fake_search_catalog_products

    context = await service._prefetch_catalog_context(
        "girls only clothes",
        recent_messages=[
            {"from_me": False, "message": "2 years"},
            {"from_me": True, "message": "question"},
        ],
        workspace="default",
        limit=6,
    )

    assert "2 years" in captured[0]
    assert "girls only clothes" in captured[0]
    assert context["catalog_query"] == captured[0]
    assert context["preferred_catalog_set"] == {"id": "girls-2ans", "name": "Girls 2 ans"}


def test_reply_text_is_suppressed_when_catalog_send_is_planned():
    service = _make_service()

    assert service._should_send_reply_text_separately(
        reply_text="ها هو الكتالوج",
        action_tool_names={"send_whatsapp_catalog_message"},
    ) is False
    assert service._should_send_reply_text_separately(
        reply_text="ها هو الكتالوج",
        action_tool_names=set(),
        auto_catalog_set_possible=True,
    ) is False


def test_reply_text_is_allowed_when_no_catalog_delivery_exists():
    service = _make_service()

    assert service._should_send_reply_text_separately(
        reply_text="مرحبا",
        action_tool_names=set(),
    ) is True


def test_compact_ai_text_keeps_one_short_sentence():
    service = _make_service()

    compact = service._compact_ai_text("ها هو الكتالوج ديال البنات. شوفي وزيدي قولي ليا اللون.")

    assert compact == "ها هو الكتالوج ديال البنات."


@pytest.mark.asyncio
async def test_duplicate_inbound_message_is_skipped(monkeypatch):
    service = _make_service()

    async def fake_get_config(workspace: str):
        return {
            **DEFAULT_AGENT_CONFIG,
            "enabled": True,
            "run_mode": "autonomous",
            "_openai_api_key": "test-key",
        }

    async def fake_completed(*, workspace: str, inbound_wa_message_id: str):
        return True

    async def fake_record_skip(**kwargs):
        return 99

    service.get_config = fake_get_config
    service.ensure_schema = _noop_customer
    service._has_completed_turn_for_inbound_message = fake_completed
    service._record_skip = fake_record_skip

    result = await service.maybe_handle_incoming_message(
        {
            "user_id": "212600000000",
            "wa_message_id": "wamid.123",
            "type": "text",
            "message": "سلام",
        }
    )

    assert result["reason"] == "duplicate_inbound"
    assert result["handled"] is True
    assert result["skip_legacy"] is True


@pytest.mark.asyncio
async def test_age_only_message_sends_short_catalog_clarification():
    service = _make_service()
    sent_messages: list[dict[str, str]] = []
    logged_turns: list[dict[str, object]] = []

    async def fake_get_config(workspace: str):
        return {
            **DEFAULT_AGENT_CONFIG,
            "enabled": True,
            "run_mode": "autonomous",
            "_openai_api_key": "test-key",
            "catalog_results_limit": 6,
        }

    async def fake_not_completed(*, workspace: str, inbound_wa_message_id: str):
        return False

    async def fake_get_state(*, user_id: str, workspace: str):
        return {
            "status": "bot_managed",
            "owner_type": "bot",
            "summary": "",
            "last_language": "",
            "last_intent": "",
            "slots_json": {},
            "risk_json": {},
            "counters_json": {"turns": 0},
            "openai_conversation_id": None,
        }

    async def fake_eval_gate(workspace: str, config: dict[str, object]):
        return {
            "enabled": True,
            "blocking": False,
            "reason_code": "ok",
            "message": "",
        }

    async def fake_get_messages(user_id: str, offset: int = 0, limit: int = 12):
        return [{"from_me": False, "message": "2 years"}]

    async def fake_search_catalog_products(*, query: str, workspace: str, limit: int):
        class _Result:
            ok = True
            data = {
                "products": [],
                "matched_sets": [],
                "preferred_set": None,
                "clarification": {
                    "needed": True,
                    "reason": "missing_gender_for_age",
                    "age": 2,
                },
            }

        return _Result()

    async def fake_send_ai_outbound_message(*, user_id: str, message_type: str, text: str = "", **kwargs):
        sent_messages.append({"user_id": user_id, "message_type": message_type, "text": text})
        return {"id": 1}

    async def fake_upsert_conversation_state(*, user_id: str, workspace: str, state: dict[str, object]):
        return None

    async def fake_log_turn(**kwargs):
        logged_turns.append(kwargs)
        return 321

    async def fake_log_tool(**kwargs):
        return None

    service.get_config = fake_get_config
    service.ensure_schema = _noop_customer
    service._has_completed_turn_for_inbound_message = fake_not_completed
    service._get_conversation_state = fake_get_state
    service.get_autonomous_eval_gate_status = fake_eval_gate
    service.db_manager.get_messages = fake_get_messages
    service.tools.search_catalog_products = fake_search_catalog_products
    service._send_ai_outbound_message = fake_send_ai_outbound_message
    service._upsert_conversation_state = fake_upsert_conversation_state
    service._log_turn = fake_log_turn
    service._log_tool = fake_log_tool

    result = await service.maybe_handle_incoming_message(
        {
            "user_id": "212600000000",
            "wa_message_id": "wamid.456",
            "type": "text",
            "message": "2 years",
        }
    )

    assert result["reason"] == "catalog_clarification"
    assert result["handled"] is True
    assert sent_messages == [
        {
            "user_id": "212600000000",
            "message_type": "text",
            "text": "واش باغية حوايج ديال البنات ولا الأولاد لعمر 2 سنين؟ وإذا بغيتي حتى الصبابط عطيني القياس ونصيفط ليك بجوج.",
        }
    ]
    assert logged_turns[0]["action"] == "catalog_clarification"
