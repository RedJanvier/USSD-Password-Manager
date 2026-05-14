"""Test fixtures.

Each test gets a fresh in-memory SQLite DB so they can run in parallel and
don't depend on each other's state. We re-import `app.config` and `app.db`
under a monkeypatched env so the cached settings pick up the right URL.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Force test env before any app modules are imported.
os.environ.setdefault("APP_PEPPER", secrets.token_hex(32))
# Use a file-backed sqlite per test session so async + sync (Alembic) see
# the same DB.
TEST_DB_PATH = os.path.abspath("./_test_vault.db")
if os.path.exists(TEST_DB_PATH):
    os.remove(TEST_DB_PATH)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB_PATH}"

from app.config import get_settings  # noqa: E402
from app.db import Base, engine  # noqa: E402
from app import models  # noqa: F401, E402  — register tables

get_settings.cache_clear()


@pytest_asyncio.fixture(autouse=True)
async def _reset_schema() -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def msisdn() -> str:
    return "+250788000001"


async def ussd_post(client: AsyncClient, *, msisdn: str, text: str, session_id: str = "s1") -> str:
    resp = await client.post(
        "/ussd",
        data={
            "sessionId": session_id,
            "serviceCode": "*384*0#",
            "phoneNumber": msisdn,
            "text": text,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.text
