"""Integration tests for admin collector controls."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport

from threat_intel.models.base import SourceKind
from threat_intel.models.source import Source

ADMIN_KEY = "test-admin-key-please-rotate"
ADMIN_HEADERS = {"X-Admin-Key": ADMIN_KEY}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_settings(monkeypatch, settings):
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    settings.admin_api_key = ADMIN_KEY
    return settings


@pytest_asyncio.fixture
async def admin_app(factory, admin_settings):
    from threat_intel.main import create_app

    app = create_app(settings=admin_settings)
    app.state.settings = admin_settings
    app.state.session_factory = factory
    app.state.collector_names = ["nvd"]
    app.state.start_time = datetime.now(UTC)
    # Mock the ingestion service so trigger doesn't actually run
    mock_ingestion = MagicMock()
    mock_ingestion.run = AsyncMock(return_value=None)
    app.state.ingestion = mock_ingestion
    app.state.scoring_job = MagicMock()
    app.state.profile_loader = MagicMock()
    return app


@pytest_asyncio.fixture
async def admin_client(admin_app):
    async with httpx.AsyncClient(
        transport=ASGITransport(app=admin_app), base_url="http://test"
    ) as c:
        yield c


@pytest_asyncio.fixture
async def nvd_source(factory):
    """Seed an NVD source row with known state."""
    async with factory() as s:
        src = Source(
            name="nvd",
            kind=SourceKind.cve_feed,
            url="https://nvd.test",
            enabled=True,
            consecutive_failures=0,
            base_interval_minutes=60,
            current_interval_minutes=60,
        )
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


@pytest_asyncio.fixture
async def disabled_source(factory):
    """Seed a source row that is disabled with backoff applied."""
    async with factory() as s:
        src = Source(
            name="nvd",
            kind=SourceKind.cve_feed,
            url="https://nvd.test",
            enabled=False,
            consecutive_failures=5,
            base_interval_minutes=60,
            current_interval_minutes=240,
        )
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_trigger_requires_admin_key(admin_client, nvd_source):
    resp = await admin_client.post("/api/v1/admin/collectors/nvd/trigger")
    assert resp.status_code == 403


async def test_trigger_404_on_unknown_collector(admin_client):
    resp = await admin_client.post("/api/v1/admin/collectors/nope/trigger", headers=ADMIN_HEADERS)
    assert resp.status_code == 404


async def test_trigger_dispatches_in_background(admin_client, nvd_source):
    resp = await admin_client.post("/api/v1/admin/collectors/nvd/trigger", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "nvd"
    assert body["detail"] == "Run dispatched"
    # next_run_at is NOT mutated — must remain None in response
    assert body["next_run_at"] is None


async def test_enable_resets_backoff(admin_client, factory, disabled_source):
    resp = await admin_client.post("/api/v1/admin/collectors/nvd/enable", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["detail"] == "Enabled"
    assert body["next_run_at"] is not None

    # Verify the DB row was updated
    from sqlalchemy import select

    async with factory() as s:
        src = (await s.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    assert src.enabled is True
    assert src.consecutive_failures == 0
    assert src.current_interval_minutes == src.base_interval_minutes
    assert src.next_run_at is not None


async def test_disable_flips_enabled(admin_client, factory, nvd_source):
    resp = await admin_client.post("/api/v1/admin/collectors/nvd/disable", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is False
    assert body["detail"] == "Disabled"

    from sqlalchemy import select

    async with factory() as s:
        src = (await s.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    assert src.enabled is False


async def test_admin_collector_enable_404_on_unknown(admin_client):
    resp = await admin_client.post("/api/v1/admin/collectors/ghost/enable", headers=ADMIN_HEADERS)
    assert resp.status_code == 404


async def test_admin_collector_disable_404_on_unknown(admin_client):
    resp = await admin_client.post("/api/v1/admin/collectors/ghost/disable", headers=ADMIN_HEADERS)
    assert resp.status_code == 404
