from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx

from threat_intel.collectors.rss import RSSCollector
from threat_intel.core.config import Settings
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent

SAMPLE = Path("tests/fixtures/rss_sample.xml").read_bytes()


def _collector(client: httpx.AsyncClient) -> RSSCollector:
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    return RSSCollector(
        http_client=client,
        settings=settings,
        source_name="dfir_report",
        url="https://feeds.test/rss.xml",
        threat_type="report",
        interval_minutes=240,
        indicator_confidence=50,
        default_tags=["rss", "source:dfir_report"],
    )


def test_classvars_and_kind():
    c = _collector(httpx.AsyncClient())
    assert c.source_name == "dfir_report"
    assert c.source_kind is SourceKind.rss
    assert c.base_interval_minutes == 240


@pytest.mark.asyncio
async def test_fetch_yields_one_rawevent_per_item():
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://feeds.test") as mock:
            mock.get("/rss.xml").mock(return_value=httpx.Response(200, content=SAMPLE))
            c = _collector(client)
            # SSRF guard is bypassed because respx intercepts before socket;
            # patch the guard to a no-op for the unit test.
            c._assert_fetchable = lambda url: None  # type: ignore[attr-defined]
            events = [r async for r in c.fetch(datetime.now(UTC) - timedelta(days=1))]
    assert [r.external_id for r in events] == ["post-1", "post-2"]


def test_to_event_extracts_cve_and_sets_enrichment():
    c = _collector(httpx.AsyncClient())
    from threat_intel.collectors.base import RawEvent

    raw = RawEvent(
        external_id="post-1",
        payload={
            "guid": "post-1",
            "link": "https://example.test/post/1",
            "title": "Active exploitation of CVE-2021-44228",
            "summary": (
                "Log4Shell exploited. C2 at hxxp://evil[.]example[.]net/x <script>alert(1)</script>"
            ),
            "published": "Mon, 13 Dec 2021 00:00:00 GMT",
            "tags": ["advisory"],
        },
        fetched_at=datetime.now(UTC),
    )
    ev = c.to_event(raw)
    assert isinstance(ev, CollectedEvent)
    assert ev.enrichment_mode is True
    assert ev.threat_type == "report"
    assert ev.indicator_confidence == 50
    assert ("cve", "CVE-2021-44228") in [(i.type, i.value) for i in ev.indicators]
    assert ("url", "http://evil.example.net/x") in [(i.type, i.value) for i in ev.indicators]
    # script content stripped by clean_text
    assert "<script>" not in (ev.summary or "")
    assert "alert(1)" not in (ev.summary or "")
    # unverified-ioc tag present because network IOCs were extracted
    assert "unverified-ioc" in ev.tags


def test_to_event_no_cve_still_valid():
    c = _collector(httpx.AsyncClient())
    from threat_intel.collectors.base import RawEvent

    raw = RawEvent(
        external_id="post-2",
        payload={
            "guid": "post-2",
            "link": "https://example.test/post/2",
            "title": "Threat actor report",
            "summary": "No CVE here, IP 8.8.8.8",
            "published": "Tue, 14 Dec 2021 00:00:00 GMT",
            "tags": [],
        },
        fetched_at=datetime.now(UTC),
    )
    ev = c.to_event(raw)
    assert ev.indicators  # at least the 8.8.8.8 ip
    assert all(i.type != "cve" for i in ev.indicators)
    assert ev.threat_type == "report"
