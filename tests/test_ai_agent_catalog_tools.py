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
        {"id": "girls-24", "name": "Girls Shoes 24"},
        {"id": "boys-24", "name": "Boys Shoes 24"},
        {"id": "all-products", "name": "All Products"},
    ]
    filters = [
        {"label": "Girls", "query": "girls", "match": "includes"},
        {"label": "Boys", "query": "boys", "match": "includes"},
        {"label": "All", "type": "all"},
    ]
    set_products = {
        "girls-24": [
            {
                "retailer_id": "G-24-1",
                "name": "صندل بنات 24",
                "availability": "in stock",
                "quantity": 4,
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
