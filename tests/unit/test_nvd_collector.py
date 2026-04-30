import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx

from threat_intel.collectors.base import RawEvent
from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings
from threat_intel.models.base import Severity
from threat_intel.schemas.ingest import CollectedEvent

FIXTURE = json.loads(Path("tests/fixtures/nvd_sample.json").read_text())


def _make_collector() -> NVDCollector:
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    return NVDCollector(http_client=httpx.AsyncClient(), settings=settings)


def test_normalize_full_record():
    item = FIXTURE["vulnerabilities"][0]
    raw = RawEvent(
        external_id=item["cve"]["id"],
        payload=item,
        fetched_at=datetime.now(UTC),
    )
    event = _make_collector().to_event(raw)

    assert isinstance(event, CollectedEvent)
    assert event.source_name == "nvd"
    assert event.external_id == "CVE-2026-0001"
    assert event.severity is Severity.critical
    assert event.cvss_score == 9.8
    assert event.cvss_version == "3.1"
    assert event.cvss_vector.startswith("CVSS:3.1/")
    assert event.cwe_ids == ["CWE-79"]
    # affected_products now lives in raw_data and indicators
    assert event.raw_data["affected_products"] == ["cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"]
    assert event.raw_data["references"] == ["https://example.test/advisory/1"]
    assert event.published_at.tzinfo is not None
    assert event.title.startswith("Remote code execution")


def test_normalize_minimal_record_falls_back_to_unknown():
    item = FIXTURE["vulnerabilities"][1]
    raw = RawEvent(
        external_id=item["cve"]["id"],
        payload=item,
        fetched_at=datetime.now(UTC),
    )
    event = _make_collector().to_event(raw)

    assert event.severity is Severity.unknown
    assert event.cvss_score is None
    assert event.cwe_ids == []
    assert event.raw_data["affected_products"] == []
    assert event.raw_data["references"] == []


def test_normalize_picks_english_description():
    item = FIXTURE["vulnerabilities"][0]
    raw = RawEvent(external_id=item["cve"]["id"], payload=item, fetched_at=datetime.now(UTC))
    event = _make_collector().to_event(raw)
    assert "código" not in event.summary.lower()
    assert "ExampleProduct" in event.summary


@pytest.mark.asyncio
async def test_fetch_yields_normalized_events():
    payload = FIXTURE
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]

    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            mock.get("/cves/2.0").mock(return_value=httpx.Response(200, json=payload))
            collector = NVDCollector(http_client=client, settings=settings)
            since = datetime.now(UTC) - timedelta(hours=1)
            events = [e async for e in collector.fetch(since)]
    assert [e.external_id for e in events] == ["CVE-2026-0001", "CVE-2026-0002"]


@pytest.mark.asyncio
async def test_fetch_retries_on_429_then_succeeds():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            route = mock.get("/cves/2.0")
            route.side_effect = [
                httpx.Response(429),
                httpx.Response(200, json=FIXTURE),
            ]
            collector = NVDCollector(http_client=client, settings=settings)
            events = [e async for e in collector.fetch(datetime.now(UTC))]
    assert len(events) == 2
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_fetch_raises_on_persistent_5xx():
    from threat_intel.core.exceptions import CollectorHTTPError

    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            mock.get("/cves/2.0").mock(return_value=httpx.Response(500))
            collector = NVDCollector(http_client=client, settings=settings)
            with pytest.raises(CollectorHTTPError):
                async for _ in collector.fetch(datetime.now(UTC)):
                    pass


@pytest.mark.asyncio
async def test_fetch_paginates_until_total_reached():
    page1 = {**FIXTURE, "totalResults": 3, "resultsPerPage": 2, "startIndex": 0}
    extra_cve = {
        "cve": {
            "id": "CVE-2026-0003",
            "published": "2026-04-26T06:00:00.000",
            "lastModified": "2026-04-26T06:00:00.000",
            "descriptions": [{"lang": "en", "value": "third"}],
            "metrics": {},
            "weaknesses": [],
            "configurations": [],
            "references": [],
        }
    }
    page2 = {
        "totalResults": 3,
        "resultsPerPage": 2,
        "startIndex": 2,
        "vulnerabilities": [extra_cve],
    }
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            route = mock.get("/cves/2.0")
            route.side_effect = [
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
            collector = NVDCollector(http_client=client, settings=settings)
            ids = [e.external_id async for e in collector.fetch(datetime.now(UTC))]
    assert ids == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
