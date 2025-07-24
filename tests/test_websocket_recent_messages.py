from fastapi.testclient import TestClient
from backend import main


def test_websocket_fetches_db_when_cache_empty(monkeypatch):
    async def fake_get_recent_messages(user_id, limit=20):
        return []

    test_msgs = [{"msg": "hi"}]

    async def fake_get_messages(user_id, offset=0, limit=50):
        fake_get_messages.called = True
        return test_msgs

    async def fake_init_db():
        pass

    async def fake_connect():
        pass

    monkeypatch.setattr(main.redis_manager, "get_recent_messages", fake_get_recent_messages)
    monkeypatch.setattr(main.db_manager, "get_messages", fake_get_messages)
    monkeypatch.setattr(main.db_manager, "init_db", fake_init_db)
    monkeypatch.setattr(main.redis_manager, "connect", fake_connect)

    with TestClient(main.app) as client:
        with client.websocket_connect("/ws/u1") as websocket:
            data = websocket.receive_json()
            assert data["type"] == "recent_messages"
            assert data["data"] == test_msgs

