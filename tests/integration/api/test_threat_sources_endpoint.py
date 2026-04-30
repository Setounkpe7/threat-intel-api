"""Integration tests for GET /api/v1/threats/{threat_id}/sources."""

import uuid
from datetime import UTC, datetime

import pytest_asyncio

from threat_intel.models.base import Severity, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def threat_with_two_sources(factory):
    """Seed a Threat with ThreatSource rows for NVD and KEV."""
    now = datetime.now(UTC)
    async with factory() as s:
        nvd = Source(
            name="nvd",
            kind=SourceKind.cve_feed,
            url="https://nvd.test",
            enabled=True,
            current_interval_minutes=60,
        )
        kev = Source(
            name="cisa_kev",
            kind=SourceKind.advisory,
            url="https://cisa.test",
            enabled=True,
            current_interval_minutes=360,
        )
        s.add_all([nvd, kev])
        await s.flush()

        threat = Threat(
            title="Log4Shell",
            severity=Severity.critical,
            published_at=now,
            last_modified_at=now,
        )
        s.add(threat)
        await s.flush()

        ts_nvd = ThreatSource(
            threat_id=threat.id,
            source_id=nvd.id,
            external_id="CVE-2021-44228",
            first_seen_at=now,
            last_seen_at=now,
            tags=["nvd"],
        )
        ts_kev = ThreatSource(
            threat_id=threat.id,
            source_id=kev.id,
            external_id="CVE-2021-44228",
            first_seen_at=now,
            last_seen_at=now,
            tags=["kev", "actively-exploited"],
        )
        s.add_all([ts_nvd, ts_kev])
        await s.commit()
        await s.refresh(threat)
        await s.refresh(nvd)
        await s.refresh(kev)
    return {
        "threat": threat,
        "nvd": nvd,
        "kev": kev,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_threat_sources_returns_all_sources(client, threat_with_two_sources):
    threat = threat_with_two_sources["threat"]
    resp = await client.get(f"/api/v1/threats/{threat.id}/sources")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2

    source_names = {entry["source_name"] for entry in body}
    assert source_names == {"nvd", "cisa_kev"}

    for entry in body:
        assert entry["external_id"] == "CVE-2021-44228"
        assert "first_seen_at" in entry
        assert "last_seen_at" in entry
        assert isinstance(entry["tags"], list)

    # Verify KEV tags
    kev_entry = next(e for e in body if e["source_name"] == "cisa_kev")
    assert "kev" in kev_entry["tags"]
    assert "actively-exploited" in kev_entry["tags"]


async def test_threat_sources_empty_on_unknown_threat(client):
    # Unknown UUID — no rows, returns empty list (not 404, per spec note)
    unknown_id = uuid.uuid4()
    resp = await client.get(f"/api/v1/threats/{unknown_id}/sources")
    assert resp.status_code == 200
    assert resp.json() == []
