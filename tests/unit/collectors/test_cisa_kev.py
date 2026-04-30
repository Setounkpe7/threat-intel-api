import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from threat_intel.collectors.base import RawEvent
from threat_intel.collectors.cisa_kev import CISA_KEV_URL, CISAKEVCollector
from threat_intel.core.config import Settings

FIXTURE = Path(__file__).parent.parent.parent / "fixtures" / "cisa_kev_sample.json"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_yields_one_event_per_vulnerability():
    payload = json.loads(FIXTURE.read_text())
    respx.get(CISA_KEV_URL).respond(200, json=payload)
    async with httpx.AsyncClient() as http:
        c = CISAKEVCollector(http, Settings())
        events = [r async for r in c.fetch(datetime.now(UTC))]
    assert len(events) == 2
    assert events[0].external_id == "CVE-2021-44228"


def test_to_event_maps_log4shell_with_ransomware_tag():
    payload = json.loads(FIXTURE.read_text())
    raw = RawEvent(
        external_id="CVE-2021-44228",
        payload=payload["vulnerabilities"][0],
        fetched_at=datetime.now(UTC),
    )
    c = CISAKEVCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert ev.source_name == "cisa_kev"
    assert ev.external_id == "CVE-2021-44228"
    assert ev.title == "Apache Log4j2 RCE"
    assert ev.summary.startswith("Apache Log4j2 contains a flaw")
    assert {"kev", "actively-exploited", "ransomware"} <= set(ev.tags)
    types = {(i.type, i.value) for i in ev.indicators}
    assert ("cve", "CVE-2021-44228") in types


def test_to_event_no_ransomware_tag_when_unknown():
    payload = json.loads(FIXTURE.read_text())
    raw = RawEvent(
        external_id="CVE-2024-0001",
        payload=payload["vulnerabilities"][1],
        fetched_at=datetime.now(UTC),
    )
    c = CISAKEVCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert "kev" in ev.tags
    assert "actively-exploited" in ev.tags
    assert "ransomware" not in ev.tags
