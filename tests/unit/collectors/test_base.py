import httpx
import pytest
import respx

from threat_intel.collectors.base import (
    APIGraphQLCollector,
    APIRestCollector,
)
from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorHTTPError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent


class _DummyRest(APIRestCollector):
    source_name = "dummy"
    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60
    base_url = "https://example.test/api"
    auth_method = "none"
    rate_limit_per_minute = 30

    async def fetch(self, since):
        if False:
            yield  # pragma: no cover

    def to_event(self, raw):
        return CollectedEvent(
            source_name=self.source_name,
            external_id=raw.external_id,
            title="t",
            published_at=raw.fetched_at,
            last_modified_at=raw.fetched_at,
        )


@pytest.mark.asyncio
@respx.mock
async def test_apirest_get_returns_json():
    route = respx.get("https://example.test/api/x").respond(200, json={"ok": True})
    async with httpx.AsyncClient() as http:
        c = _DummyRest(http, Settings())
        data = await c._get("https://example.test/api/x")
    assert data == {"ok": True}
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_apirest_get_raises_on_5xx():
    respx.get("https://example.test/api/x").respond(500, text="boom")
    async with httpx.AsyncClient() as http:
        c = _DummyRest(http, Settings())
        with pytest.raises(CollectorHTTPError) as exc:
            await c._get("https://example.test/api/x")
    assert exc.value.status_code == 500


class _DummyGraphQL(APIGraphQLCollector):
    source_name = "dummy_gql"
    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60
    endpoint_url = "https://gql.example.test/graphql"
    auth_token_env = "TEST_TOKEN"

    async def fetch(self, since):
        if False:
            yield  # pragma: no cover

    def to_event(self, raw):
        return CollectedEvent(
            source_name=self.source_name,
            external_id=raw.external_id,
            title="t",
            published_at=raw.fetched_at,
            last_modified_at=raw.fetched_at,
        )


@pytest.mark.asyncio
async def test_graphql_disabled_when_token_missing(monkeypatch):
    monkeypatch.delenv("TEST_TOKEN", raising=False)
    async with httpx.AsyncClient() as http:
        c = _DummyGraphQL(http, Settings())
    assert c.enabled is False


@pytest.mark.asyncio
@respx.mock
async def test_graphql_execute_query_attaches_bearer(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "secret")
    route = respx.post("https://gql.example.test/graphql").respond(200, json={"data": {"x": 1}})
    async with httpx.AsyncClient() as http:
        c = _DummyGraphQL(http, Settings())
        result = await c._execute_query("query { x }", {})
    assert result == {"data": {"x": 1}}
    sent = route.calls[0].request
    assert sent.headers["authorization"] == "Bearer secret"


@pytest.mark.asyncio
@respx.mock
async def test_graphql_raises_on_errors_field(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "secret")
    respx.post("https://gql.example.test/graphql").respond(
        200, json={"errors": [{"message": "Bad query"}]}
    )
    async with httpx.AsyncClient() as http:
        c = _DummyGraphQL(http, Settings())
        with pytest.raises(CollectorHTTPError):
            await c._execute_query("query { x }", {})
