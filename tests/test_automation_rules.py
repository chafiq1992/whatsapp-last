import asyncio


def test_automation_rules_api_roundtrip(client):
    payload = {
        "rules": [
            {
                "id": "r1",
                "name": "Auto hello",
                "enabled": True,
                "cooldown_seconds": 0,
                "trigger": {"source": "whatsapp", "event": "incoming_message"},
                "condition": {"match": "contains", "keywords": ["hello"]},
                "actions": [{"type": "send_text", "text": "hi"}],
            }
        ]
    }
    r = client.post("/automation/rules", json=payload)
    assert r.status_code == 200
    out = client.get("/automation/rules")
    assert out.status_code == 200
    data = out.json()
    assert any(x.get("id") == "r1" for x in data)


def test_automation_rules_stats_from_db(db_manager, client, monkeypatch):
    from backend import main
    # clear caches
    try:
        main.message_processor._automation_rules_cache = {}
    except Exception:
        pass

    # store a simple rule
    tok = main._CURRENT_WORKSPACE.set("irranova")
    try:
        asyncio.run(db_manager.set_setting("automation_rules", [{
            "id": "rstats",
            "name": "Stats rule",
            "enabled": True,
            "cooldown_seconds": 0,
            "trigger": {"source": "whatsapp", "event": "incoming_message"},
            "condition": {"match": "contains", "keywords": ["hello"]},
            "actions": [{"type": "send_text", "to": "{{ phone }}", "text": "hi"}],
        }]))
    finally:
        main._CURRENT_WORKSPACE.reset(tok)

    # stub outgoing send
    async def fake_process_outgoing_message(message_data: dict):
        return message_data
    monkeypatch.setattr(main.message_processor, "process_outgoing_message", fake_process_outgoing_message)

    # run automation (workspace bound)
    asyncio.run(main.message_processor._run_simple_automations("212600000000", "hello", {"from_me": False}, workspace="irranova"))

    # stats endpoint should show triggers/messages_sent >= 1 even without redis
    tok2 = main._CURRENT_WORKSPACE.set("irranova")
    try:
        resp = client.get("/automation/rules/stats")
    finally:
        main._CURRENT_WORKSPACE.reset(tok2)
    assert resp.status_code == 200
    s = (resp.json() or {}).get("stats") or {}
    assert int((s.get("rstats") or {}).get("triggers") or 0) >= 1


def test_automation_runner_sends_and_tags(db_manager, monkeypatch):
    from backend import main

    # Ensure no stale cached rules from other tests
    try:
        main.message_processor._automation_rules_cache = {}
    except Exception:
        pass

    asyncio.run(
        db_manager.set_setting(
            "automation_rules",
            [
                {
                    "id": "r2",
                    "name": "Tag + reply",
                    "enabled": True,
                    "cooldown_seconds": 0,
                    "trigger": {"source": "whatsapp", "event": "incoming_message"},
                    "condition": {"match": "contains", "keywords": ["price"]},
                    "actions": [
                        {"type": "send_text", "text": "Our price is 199 MAD."},
                        {"type": "add_tag", "tag": "Auto"},
                    ],
                }
            ],
        )
    )

    sent = []

    async def fake_process_outgoing_message(message_data: dict):
        sent.append(message_data)
        return message_data

    monkeypatch.setattr(main.message_processor, "process_outgoing_message", fake_process_outgoing_message)

    asyncio.run(db_manager.upsert_user("212600000000"))
    asyncio.run(
        main.message_processor._run_simple_automations(
            "212600000000", incoming_text="What is the price?", message_obj={"from_me": False}
        )
    )

    assert any("Our price is 199 MAD." in str(m.get("message") or "") for m in sent)
    meta = asyncio.run(db_manager.get_conversation_meta("212600000000"))
    assert "Auto" in (meta.get("tags") or [])


def test_automation_runner_binds_workspace_context(db_manager, monkeypatch):
    from backend import main

    # Ensure no stale cached rules from other tests
    try:
        main.message_processor._automation_rules_cache = {}
    except Exception:
        pass

    # Save a rule (doesn't matter which workspace since tests use single sqlite),
    # but we verify that the runner binds _CURRENT_WORKSPACE for downstream calls.
    tok_save = main._CURRENT_WORKSPACE.set("irranova")
    try:
        asyncio.run(
            db_manager.set_setting(
                "automation_rules",
                [
                    {
                        "id": "r_ws",
                        "name": "Workspace bind",
                        "enabled": True,
                        "cooldown_seconds": 0,
                        "trigger": {"source": "whatsapp", "event": "incoming_message"},
                        "condition": {"match": "contains", "keywords": ["ping"]},
                        "actions": [{"type": "send_text", "text": "pong"}],
                    }
                ],
            )
        )
    finally:
        main._CURRENT_WORKSPACE.reset(tok_save)

    seen_ws = {"value": None}

    async def fake_process_outgoing_message(message_data: dict):
        seen_ws["value"] = main.get_current_workspace()
        return message_data

    monkeypatch.setattr(main.message_processor, "process_outgoing_message", fake_process_outgoing_message)

    # Force current workspace to something else, then run with explicit workspace arg.
    tok = main._CURRENT_WORKSPACE.set("irrakids")
    try:
        asyncio.run(
            main.message_processor._run_simple_automations(
                "212600000000",
                incoming_text="ping",
                message_obj={"from_me": False},
                workspace="irranova",
            )
        )
    finally:
        main._CURRENT_WORKSPACE.reset(tok)

    assert seen_ws["value"] == "irranova"


def test_inbox_env_endpoints_roundtrip(client):
    payload = {
        "allowed_phone_number_ids": ["pid1", "pid2"],
        "survey_test_numbers": ["+212 600 000 000"],
        "auto_reply_test_numbers": ["212611111111"],
    }
    r = client.post("/admin/inbox-env", json=payload)
    assert r.status_code == 200
    out = client.get("/admin/inbox-env")
    assert out.status_code == 200
    data = out.json()
    assert "pid1" in (data.get("allowed_phone_number_ids") or [])
    # survey should be digits-only in storage/output
    assert "212600000000" in (data.get("survey_test_numbers") or [])


