from unittest.mock import AsyncMock, patch

from sqlalchemy.exc import OperationalError


async def test_livez_returns_200_with_static_body(client):
    resp = await client.get("/livez")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_livez_does_not_query_database(client):
    """Liveness must not depend on DB. Patch session execute to confirm."""
    with patch(
        "threat_intel.api.health.AsyncSession.execute",
        new=AsyncMock(side_effect=AssertionError("livez must not query DB")),
    ):
        resp = await client.get("/livez")
    assert resp.status_code == 200


async def test_readyz_returns_200_when_db_reachable(client):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


async def test_readyz_returns_503_when_db_unreachable(client):
    with patch(
        "threat_intel.api.health.AsyncSession.execute",
        new=AsyncMock(side_effect=OperationalError("stmt", {}, Exception("db down"))),
    ):
        resp = await client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}


async def test_livez_excluded_from_openapi_schema(client):
    resp = await client.get("/openapi.json")
    schema = resp.json()
    assert "/livez" not in schema.get("paths", {})


async def test_readyz_excluded_from_openapi_schema(client):
    resp = await client.get("/openapi.json")
    schema = resp.json()
    assert "/readyz" not in schema.get("paths", {})
