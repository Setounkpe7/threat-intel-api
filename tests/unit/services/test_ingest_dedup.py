"""Unit tests for IngestService.process() — dedup / create / update semantics."""

from datetime import UTC, datetime

import pytest_asyncio
from sqlalchemy import select

from threat_intel.core.db import build_engine
from threat_intel.core.db import session_factory as make_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator
from threat_intel.services.ingest import IngestService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def factory():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = make_factory(engine)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture
async def source_nvd(factory):
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://nvd.test", enabled=True)
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


@pytest_asyncio.fixture
async def source_kev(factory):
    async with factory() as s:
        src = Source(
            name="cisa_kev", kind=SourceKind.advisory, url="https://cisa.test", enabled=True
        )
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


@pytest_asyncio.fixture
async def source_ghsa(factory):
    async with factory() as s:
        src = Source(
            name="github_advisories",
            kind=SourceKind.advisory,
            url="https://ghsa.test",
            enabled=True,
        )
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(
    source_name: str,
    ext_id: str,
    *,
    severity: Severity | None = None,
    cvss: float | None = None,
    tags: list[str] | None = None,
    indicators: list[tuple[str, str]] | None = None,
    summary: str | None = None,
) -> CollectedEvent:
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name=source_name,
        external_id=ext_id,
        title=f"title-{source_name}",
        summary=summary,
        severity=severity,
        cvss_score=cvss,
        tags=tags or [],
        indicators=[CollectedIndicator(type=t, value=v) for t, v in (indicators or [])],
        published_at=now,
        last_modified_at=now,
        raw_data={
            "title": f"title-{source_name}",
            "summary": summary,
            "severity": severity.value if severity else None,
            "cvss_score": cvss,
            "cvss_vector": None,
            "cvss_version": None,
            "cwe_ids": [],
        },
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_create_when_no_match(factory, source_nvd):
    """First ingest for a brand-new CVE returns 'created'."""
    svc = IngestService(factory)
    event = _event(
        "nvd",
        "CVE-2026-1001",
        severity=Severity.high,
        cvss=8.0,
        tags=["nvd"],
        indicators=[("cve", "CVE-2026-1001")],
    )
    outcome, tid = await svc.process(event, source_nvd.id)

    assert outcome == "created"
    assert tid is not None

    async with factory() as s:
        threat = (await s.execute(select(Threat).where(Threat.id == tid))).scalar_one()
        assert threat.threat_type == "cve"
        ts_rows = (
            await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid))
        ).scalars().all()
        assert len(ts_rows) == 1
        assert ts_rows[0].source_id == source_nvd.id


async def test_dedup_same_cve_second_source(factory, source_nvd, source_kev):
    """NVD then KEV for the same CVE — second ingest returns 'updated', same threat_id."""
    svc = IngestService(factory)

    nvd_event = _event(
        "nvd",
        "CVE-2026-2001",
        severity=Severity.high,
        cvss=7.5,
        tags=["nvd"],
        indicators=[("cve", "CVE-2026-2001")],
    )
    outcome1, tid1 = await svc.process(nvd_event, source_nvd.id)
    assert outcome1 == "created"

    kev_event = _event(
        "cisa_kev",
        "CVE-2026-2001",
        tags=["kev", "actively-exploited"],
        indicators=[("cve", "CVE-2026-2001")],
    )
    outcome2, tid2 = await svc.process(kev_event, source_kev.id)
    assert outcome2 == "updated"
    assert tid2 == tid1

    async with factory() as s:
        ts_rows = (
            await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid1))
        ).scalars().all()
        assert len(ts_rows) == 2
        source_ids = {r.source_id for r in ts_rows}
        assert source_nvd.id in source_ids
        assert source_kev.id in source_ids


async def test_ghsa_with_cve_indicator_dedups_against_nvd(factory, source_nvd, source_ghsa):
    """GHSA that carries a CVE indicator deduplicates against the existing NVD threat."""
    svc = IngestService(factory)

    nvd_event = _event(
        "nvd",
        "CVE-2021-44228",
        severity=Severity.high,
        cvss=9.8,
        tags=["nvd"],
        indicators=[("cve", "CVE-2021-44228")],
    )
    outcome1, tid1 = await svc.process(nvd_event, source_nvd.id)
    assert outcome1 == "created"

    ghsa_event = _event(
        "github_advisories",
        "GHSA-jfh8-c2jp-5v3q",
        severity=Severity.critical,
        tags=["github-advisory", "maven"],
        indicators=[
            ("cve", "CVE-2021-44228"),
            ("ghsa", "GHSA-jfh8-c2jp-5v3q"),
        ],
    )
    outcome2, tid2 = await svc.process(ghsa_event, source_ghsa.id)
    assert outcome2 == "updated"
    assert tid2 == tid1  # same underlying threat


async def test_idempotent_same_source_reingest(factory, source_nvd):
    """Ingesting the same source twice returns 'updated' second time (idempotent)."""
    svc = IngestService(factory)

    event = _event(
        "nvd",
        "CVE-2026-3001",
        severity=Severity.medium,
        cvss=5.5,
        tags=["nvd"],
        indicators=[("cve", "CVE-2026-3001")],
    )
    outcome1, tid1 = await svc.process(event, source_nvd.id)
    assert outcome1 == "created"

    # Second identical ingest (same source, same CVE)
    outcome2, tid2 = await svc.process(event, source_nvd.id)
    assert outcome2 == "updated"
    assert tid2 == tid1

    async with factory() as s:
        # Still only one ThreatSource row
        ts_rows = (
            await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid1))
        ).scalars().all()
        assert len(ts_rows) == 1
