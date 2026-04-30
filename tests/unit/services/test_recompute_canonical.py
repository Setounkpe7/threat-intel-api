"""Unit tests for recompute_canonical() — field-level priority and union logic."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from threat_intel.core.db import build_engine, session_factory as make_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource
from threat_intel.services.ingest import recompute_canonical
from sqlalchemy import select


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
async def sources(factory):
    """Insert nvd, github_advisories, and cisa_kev source rows."""
    async with factory() as s:
        nvd = Source(name="nvd", kind=SourceKind.cve_feed, url="https://nvd.test", enabled=True)
        ghsa = Source(
            name="github_advisories",
            kind=SourceKind.advisory,
            url="https://ghsa.test",
            enabled=True,
        )
        kev = Source(
            name="cisa_kev",
            kind=SourceKind.advisory,
            url="https://cisa.test",
            enabled=True,
        )
        s.add_all([nvd, ghsa, kev])
        await s.commit()
        await s.refresh(nvd)
        await s.refresh(ghsa)
        await s.refresh(kev)
    return {"nvd": nvd, "github_advisories": ghsa, "cisa_kev": kev}


def _threat(title: str = "title") -> Threat:
    now = datetime.now(UTC)
    return Threat(
        id=uuid.uuid4(),
        threat_type="cve",
        title=title,
        summary=None,
        severity=Severity.unknown,
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        tags=[],
        published_at=now,
        last_modified_at=now,
    )


def _threat_source(
    threat_id: uuid.UUID,
    source_id: int,
    *,
    raw_data: dict,
    tags: list[str] | None = None,
    offset_hours: int = 0,
) -> ThreatSource:
    now = datetime.now(UTC)
    return ThreatSource(
        threat_id=threat_id,
        source_id=source_id,
        external_id="CVE-TEST",
        first_seen_at=now - timedelta(hours=offset_hours),
        last_seen_at=now,
        tags=tags or [],
        affected_products=[],
        references=[],
        raw_data=raw_data,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_nvd_cvss_wins_over_ghsa(factory, sources):
    """NVD has priority over GHSA for cvss_score when both are present."""
    async with factory() as s:
        threat = _threat()
        s.add(threat)
        await s.flush()

        ts_nvd = _threat_source(
            threat.id,
            sources["nvd"].id,
            raw_data={
                "title": "NVD title",
                "summary": "NVD summary",
                "severity": "high",
                "cvss_score": 8.0,
                "cvss_vector": "CVSS:3.1/AV:N",
                "cvss_version": "3.1",
                "cwe_ids": ["CWE-79"],
            },
            tags=["nvd"],
        )
        ts_ghsa = _threat_source(
            threat.id,
            sources["github_advisories"].id,
            raw_data={
                "title": "GHSA title",
                "summary": "GHSA summary",
                "severity": "critical",
                "cvss_score": 9.5,
                "cvss_vector": "CVSS:3.1/AV:N/OTHER",
                "cvss_version": "3.1",
                "cwe_ids": ["CWE-200"],
            },
            tags=["github-advisory"],
        )
        s.add_all([ts_nvd, ts_ghsa])
        await s.flush()

        await recompute_canonical(s, threat.id)
        await s.commit()

    async with factory() as s:
        row = (await s.execute(select(Threat).where(Threat.id == threat.id))).scalar_one()
        # NVD wins on CVSS
        assert row.cvss_score == 8.0
        assert row.cvss_vector == "CVSS:3.1/AV:N"
        # NVD wins on title
        assert row.title == "NVD title"
        # NVD wins on severity
        assert row.severity == Severity.high


async def test_severity_bumped_to_critical_when_kev_tag(factory, sources):
    """If 'kev' is in the union tags and severity < critical, bump to critical."""
    async with factory() as s:
        threat = _threat()
        s.add(threat)
        await s.flush()

        ts_nvd = _threat_source(
            threat.id,
            sources["nvd"].id,
            raw_data={
                "title": "NVD title",
                "summary": None,
                "severity": "high",
                "cvss_score": 7.5,
                "cvss_vector": None,
                "cvss_version": None,
                "cwe_ids": [],
            },
            tags=["nvd"],
        )
        ts_kev = _threat_source(
            threat.id,
            sources["cisa_kev"].id,
            raw_data={
                "title": None,
                "summary": None,
                "severity": None,
                "cvss_score": None,
                "cvss_vector": None,
                "cvss_version": None,
                "cwe_ids": [],
            },
            tags=["kev", "actively-exploited"],
        )
        s.add_all([ts_nvd, ts_kev])
        await s.flush()

        await recompute_canonical(s, threat.id)
        await s.commit()

    async with factory() as s:
        row = (await s.execute(select(Threat).where(Threat.id == threat.id))).scalar_one()
        assert row.severity == Severity.critical
        assert "kev" in row.tags
        assert "nvd" in row.tags
        assert "actively-exploited" in row.tags


async def test_tags_and_cwe_ids_unioned_across_sources(factory, sources):
    """Tags and CWE IDs are unioned from all ThreatSource rows, no duplicates."""
    async with factory() as s:
        threat = _threat()
        s.add(threat)
        await s.flush()

        ts_nvd = _threat_source(
            threat.id,
            sources["nvd"].id,
            raw_data={
                "title": "title",
                "summary": None,
                "severity": "medium",
                "cvss_score": 5.5,
                "cvss_vector": None,
                "cvss_version": None,
                "cwe_ids": ["CWE-79", "CWE-89"],
            },
            tags=["nvd", "shared-tag"],
        )
        ts_ghsa = _threat_source(
            threat.id,
            sources["github_advisories"].id,
            raw_data={
                "title": None,
                "summary": None,
                "severity": None,
                "cvss_score": None,
                "cvss_vector": None,
                "cvss_version": None,
                "cwe_ids": ["CWE-89", "CWE-200"],
            },
            tags=["github-advisory", "shared-tag"],
        )
        s.add_all([ts_nvd, ts_ghsa])
        await s.flush()

        await recompute_canonical(s, threat.id)
        await s.commit()

    async with factory() as s:
        row = (await s.execute(select(Threat).where(Threat.id == threat.id))).scalar_one()

        # Tags union, no duplication
        assert "nvd" in row.tags
        assert "github-advisory" in row.tags
        assert "shared-tag" in row.tags
        assert row.tags.count("shared-tag") == 1

        # CWE union — check via cwes relationship
        cwe_ids = {c.id for c in row.cwes}
        assert "CWE-79" in cwe_ids
        assert "CWE-89" in cwe_ids
        assert "CWE-200" in cwe_ids
        assert len(cwe_ids) == 3
