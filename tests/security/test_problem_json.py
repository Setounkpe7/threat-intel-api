"""Every 4xx/5xx surface must serve RFC 7807 problem+json.

The README and docs/SECURITY both advertise this; before SEC-1 only the
custom `ThreatNotFoundException` honored the contract. These tests pin the
behaviour across HTTPException-based 404s, admin 403, validation 422, and
CORS preflight rejection.
"""

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport

from threat_intel.core.config import Settings
from threat_intel.main import create_app


async def test_sector_404_returns_problem_json(client):
    resp = await client.get("/api/v1/sectors/does-not-exist/dashboard")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["status"] == 404
    assert body["title"] == "Not Found"
    assert body["detail"] == "Sector not found"
    assert body["instance"] == "/api/v1/sectors/does-not-exist/dashboard"


async def test_admin_403_returns_problem_json(client, app):
    # Without ADMIN_API_KEY configured the route returns 503; configure it
    # so we actually exercise the 403 invalid-key code path.
    app.state.settings.admin_api_key = "test-key"
    resp = await client.post("/api/v1/admin/reload-profiles")
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["status"] == 403
    assert body["title"] == "Forbidden"
    assert "X-Admin-Key" in body["detail"]


async def test_validation_422_returns_problem_json(client):
    resp = await client.get("/api/v1/threats?limit=abc")
    assert resp.status_code == 422
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["status"] == 422
    assert body["title"] == "Validation error"
    assert isinstance(body["errors"], list)
    assert body["errors"][0]["loc"][-1] == "limit"


@pytest_asyncio.fixture
async def cors_client(factory, monkeypatch):
    """Standalone client with CORS configured to a single allowed origin so
    we can exercise the disallowed-origin preflight code path."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("CORS_ORIGINS", "https://allowed.example")
    settings = Settings()  # type: ignore[call-arg]
    from datetime import UTC, datetime

    app = create_app(settings=settings)
    app.state.settings = settings
    app.state.session_factory = factory
    app.state.collector_names = ["nvd"]
    app.state.start_time = datetime.now(UTC)
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    ],
)
async def test_cors_preflight_rejection_returns_problem_json(cors_client, headers):
    resp = await cors_client.options("/api/v1/threats", headers=headers)
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["status"] == 400
    assert body["title"] == "CORS preflight rejected"
    assert "origin" in body["detail"].lower()


async def test_cors_preflight_problem_has_instance(cors_client):
    resp = await cors_client.options(
        "/api/v1/threats",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["instance"] == "/api/v1/threats"
    assert resp.headers.get("cache-control") == "no-store"
    assert resp.headers.get("pragma") == "no-cache"


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/v1/sectors/nope/dashboard"),
        ("GET", "/api/v1/cve/CVE-0000-9999"),
        ("GET", "/api/v1/threats?limit=abc"),
    ],
)
async def test_problem_json_has_cache_control_no_store(client, method, path):
    resp = await client.request(method, path)
    assert resp.headers.get("cache-control") == "no-store"
    assert resp.headers.get("pragma") == "no-cache"
