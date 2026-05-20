"""SIEM must see the same collector-activity number on /health and /sources."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest_asyncio

from threat_intel.models.base import Severity, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource


@pytest_asyncio.fixture
async def seeded_counters(factory):
    """Seed 1 NVD source, 5 attestations within 24h, 1 outside."""
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x", enabled=True)
        s.add(src)
        await s.flush()
        for i in range(6):
            tid = uuid.uuid4()
            pub = now - timedelta(hours=2 if i < 5 else 48)
            s.add(
                Threat(
                    id=tid,
                    threat_type="cve",
                    title=f"T{i}",
                    summary=".",
                    severity=Severity.high,
                    cvss_score=7.0,
                    published_at=pub,
                    last_modified_at=pub,
                )
            )
            await s.flush()
            s.add(
                ThreatSource(
                    threat_id=tid,
                    source_id=src.id,
                    external_id=f"CVE-2026-{1000 + i}",
                    first_seen_at=pub,
                    last_seen_at=pub,
                    tags=[],
                    affected_products=[],
                    references=[],
                    raw_data={},
                )
            )
        await s.commit()


async def test_health_and_sources_report_same_count(client, seeded_counters):
    h = await client.get("/health")
    s = await client.get("/api/v1/sources")
    h_count = h.json()["collectors"]["nvd"]["threats_collected_24h"]
    s_data = s.json()
    # /api/v1/sources returns a list
    if isinstance(s_data, list):
        s_count = next(x for x in s_data if x["name"] == "nvd")["events_24h"]
    else:
        s_count = s_data["nvd"]["events_24h"]
    assert h_count == s_count
    assert h_count == 5  # 5 attestations within 24h, 1 outside


async def test_attestation_count_includes_reassertions(factory, client):
    """A source asserting distinct threats should all count in the metric."""
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x", enabled=True)
        s.add(src)
        await s.flush()
        # Seed 3 attestations of distinct threats.
        # (threat_id, source_id) is the composite PK so each threat needs a
        # distinct ID. The metric counts rows, not distinct threats.
        for i in range(3):
            tid = uuid.uuid4()
            s.add(
                Threat(
                    id=tid,
                    threat_type="cve",
                    title=f"T{i}",
                    summary=".",
                    severity=Severity.high,
                    cvss_score=7.0,
                    published_at=now,
                    last_modified_at=now,
                )
            )
            await s.flush()
            s.add(
                ThreatSource(
                    threat_id=tid,
                    source_id=src.id,
                    external_id=f"CVE-2026-9000-{i}",
                    first_seen_at=now - timedelta(hours=i),
                    last_seen_at=now,
                    tags=[],
                    affected_products=[],
                    references=[],
                    raw_data={},
                )
            )
        await s.commit()

    h = await client.get("/health")
    assert h.json()["collectors"]["nvd"]["threats_collected_24h"] == 3
