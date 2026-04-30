import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx

from threat_intel.collectors.base import RawEvent
from threat_intel.collectors.github_advisories import GHSA_ENDPOINT, GitHubAdvisoriesCollector
from threat_intel.core.config import Settings

F1 = Path(__file__).parent.parent.parent / "fixtures" / "ghsa_sample.json"
F2 = Path(__file__).parent.parent.parent / "fixtures" / "ghsa_page2.json"


@pytest.fixture(autouse=True)
def _set_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")


@pytest.mark.asyncio
async def test_disabled_when_token_missing(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    async with httpx.AsyncClient() as http:
        c = GitHubAdvisoriesCollector(http, Settings())
    assert c.enabled is False


@pytest.mark.asyncio
@respx.mock
async def test_fetch_paginates_until_no_next_page():
    page1 = json.loads(F1.read_text())
    page2 = json.loads(F2.read_text())
    route = respx.post(GHSA_ENDPOINT).mock(side_effect=[
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ])
    async with httpx.AsyncClient() as http:
        c = GitHubAdvisoriesCollector(http, Settings())
        events = [r async for r in c.fetch(datetime.now(UTC) - timedelta(days=7))]
    assert route.call_count == 2
    assert len(events) == 2


def test_to_event_maps_log4shell_with_ecosystem_tag():
    page1 = json.loads(F1.read_text())
    advisory = page1["data"]["securityAdvisories"]["nodes"][0]
    raw = RawEvent(external_id=advisory["ghsaId"], payload=advisory, fetched_at=datetime.now(UTC))
    c = GitHubAdvisoriesCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert ev.source_name == "github_advisories"
    assert ev.external_id == "GHSA-jfh8-c2jp-5v3q"
    assert ev.severity is not None
    assert ev.severity.value == "critical"
    assert "github-advisory" in ev.tags
    assert "maven" in ev.tags
    types = {(i.type, i.value) for i in ev.indicators}
    assert ("ghsa", "GHSA-jfh8-c2jp-5v3q") in types
    assert ("cve", "CVE-2021-44228") in types
    assert ("package", "maven:org.apache.logging.log4j:log4j-core") in types
    assert "CWE-502" in ev.cwe_ids


def test_to_event_strips_html_in_description():
    advisory = {
        "ghsaId": "GHSA-aaaa-bbbb-cccc",
        "summary": "<script>alert(1)</script>Plain text title",
        "description": "<p>Hello <b>world</b></p>",
        "severity": "MODERATE",
        "publishedAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-02T00:00:00Z",
        "identifiers": [{"type": "GHSA", "value": "GHSA-aaaa-bbbb-cccc"}],
        "vulnerabilities": {"nodes": []},
        "references": [],
        "cwes": {"nodes": []},
    }
    raw = RawEvent(external_id=advisory["ghsaId"], payload=advisory, fetched_at=datetime.now(UTC))
    c = GitHubAdvisoriesCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert "<" not in ev.title
    assert "<" not in (ev.summary or "")
    assert "alert" not in ev.title.lower()
