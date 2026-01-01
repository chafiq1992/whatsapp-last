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


def test_automation_runner_sends_and_tags(db_manager, monkeypatch):
    from backend import main

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


