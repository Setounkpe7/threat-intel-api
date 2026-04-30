"""Integration tests for GET /api/v1/indicators."""

from datetime import UTC, datetime

from threat_intel.models.base import IndicatorType, Severity, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_threat_with_indicator(
    factory,
    *,
    ind_type: IndicatorType,
    ind_value: str,
    title: str = "Test Threat",
) -> Threat:
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(
            name=f"src-{ind_value[:20]}",
            kind=SourceKind.cve_feed,
            url="https://test.src",
            enabled=True,
            current_interval_minutes=60,
        )
        s.add(src)
        await s.flush()

        threat = Threat(
            title=title,
            severity=Severity.high,
            published_at=now,
            last_modified_at=now,
        )
        s.add(threat)
        await s.flush()

        indicator = ThreatIndicator(
            threat_id=threat.id,
            indicator_type=ind_type,
            value=ind_value,
            first_seen=now,
        )
        s.add(indicator)
        await s.commit()
        await s.refresh(threat)
    return threat


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_indicators_finds_threat_by_cve(client, factory):
    cve_value = "CVE-2025-99999"
    threat = await _seed_threat_with_indicator(
        factory, ind_type=IndicatorType.cve, ind_value=cve_value
    )
    resp = await client.get("/api/v1/indicators", params={"type": "cve", "value": cve_value})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert str(threat.id) == body[0]["id"]


async def test_indicators_finds_by_package(client, factory):
    pkg_value = "npm:react"
    await _seed_threat_with_indicator(factory, ind_type=IndicatorType.package, ind_value=pkg_value)
    resp = await client.get("/api/v1/indicators", params={"type": "package", "value": pkg_value})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1


async def test_indicators_400_on_bad_type(client):
    resp = await client.get("/api/v1/indicators", params={"type": "foobar", "value": "x"})
    assert resp.status_code == 400


async def test_indicators_empty_on_no_match(client):
    resp = await client.get(
        "/api/v1/indicators", params={"type": "cve", "value": "CVE-0000-00000-nonexistent"}
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_indicators_422_on_missing_params(client):
    # FastAPI emits 422 for missing required Query params
    resp = await client.get("/api/v1/indicators")
    assert resp.status_code == 422
