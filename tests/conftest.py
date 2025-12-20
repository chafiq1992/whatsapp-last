import asyncio
import os
import pytest

# Tests focus on business logic, not authentication; keep auth disabled here.
os.environ.setdefault("DISABLE_AUTH", "1")
# Ensure tests always use SQLite (some environments may export DATABASE_URL).
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("REQUIRE_POSTGRES", "0")

from backend import main
from .utils import bulk_insert_messages


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    dm = main.DatabaseManager(str(db_path))
    asyncio.run(dm.init_db())
    main.db_manager = dm
    main.message_processor.db_manager = dm
    return dm


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def insert_messages():
    def _insert(dm, user_id: str, count: int, start_index: int = 1):
        asyncio.run(bulk_insert_messages(dm, user_id, count, start_index))
    return _insert
