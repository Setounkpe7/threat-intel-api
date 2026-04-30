"""
Integration test: cross-source dedup on Log4Shell (CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q).

Three sources ingest the same vulnerability — NVD first (severity=high, cvss=9.8),
then CISA KEV (no CVSS, carries kev/ransomware tags), then GitHub Advisories
(severity=critical, includes both the CVE and GHSA indicators + a package indicator).

Expected outcomes after all three:
- All three calls share the same threat_id.
- Three ThreatSource rows exist.
- Canonical cvss_score == 9.8  (NVD wins CVSS priority).
- Canonical severity == critical  (kev tag bumps from high to critical).
- Union tags include values from all three sources.
"""

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

CVE_ID = "CVE-2021-44228"
GHSA_ID = "GHSA-jfh8-c2jp-5v3q"


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
    async with factory() as s:
        nvd = Source(name="nvd", kind=SourceKind.cve_feed, url="https://nvd.test", enabled=True)
        kev = Source(
            name="cisa_kev", kind=SourceKind.advisory, url="https://cisa.test", enabled=True
        )
        ghsa = Source(
            name="github_advisories",
            kind=SourceKind.advisory,
            url="https://ghsa.test",
            enabled=True,
        )
        s.add_all([nvd, kev, ghsa])
        await s.commit()
        await s.refresh(nvd)
        await s.refresh(kev)
        await s.refresh(ghsa)
    return {"nvd": nvd, "cisa_kev": kev, "github_advisories": ghsa}


def _make(
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


async def test_cross_source_dedup_log4shell(factory, sources):
    """Full three-source dedup scenario for Log4Shell."""
    svc = IngestService(factory)

    # 1. NVD ingests first — creates the Threat
    nvd_event = _make(
        "nvd",
        CVE_ID,
        severity=Severity.high,
        cvss=9.8,
        tags=["nvd"],
        indicators=[("cve", CVE_ID)],
        summary="Log4Shell remote code execution",
    )
    outcome1, tid1 = await svc.process(nvd_event, sources["nvd"].id)
    assert outcome1 == "created"

    # 2. CISA KEV ingests — no CVSS, carries exploit tags
    kev_event = _make(
        "cisa_kev",
        CVE_ID,
        tags=["kev", "actively-exploited", "ransomware"],
        indicators=[("cve", CVE_ID)],
    )
    outcome2, tid2 = await svc.process(kev_event, sources["cisa_kev"].id)
    assert outcome2 == "updated"
    assert tid2 == tid1

    # 3. GitHub Advisories ingests — adds GHSA indicator + package indicator
    ghsa_event = _make(
        "github_advisories",
        GHSA_ID,
        severity=Severity.critical,
        tags=["github-advisory", "maven"],
        indicators=[
            ("cve", CVE_ID),
            ("ghsa", GHSA_ID),
            ("package", "org.apache.logging.log4j:log4j-core"),
        ],
        summary="GHSA advisory for Log4Shell",
    )
    outcome3, tid3 = await svc.process(ghsa_event, sources["github_advisories"].id)
    assert outcome3 == "updated"
    assert tid3 == tid1

    # Assertions on final state
    async with factory() as s:
        threat = (await s.execute(select(Threat).where(Threat.id == tid1))).scalar_one()

        # Three ThreatSource rows
        ts_rows = (
            (await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid1)))
            .scalars()
            .all()
        )
        assert len(ts_rows) == 3

        # NVD wins CVSS (priority order: nvd > github_advisories > cisa_kev)
        assert threat.cvss_score == 9.8

        # kev tag present → severity bumped to critical
        assert threat.severity == Severity.critical

        # Union tags contains values from all three sources
        assert "nvd" in threat.tags
        assert "kev" in threat.tags
        assert "actively-exploited" in threat.tags
        assert "ransomware" in threat.tags
        assert "github-advisory" in threat.tags
        assert "maven" in threat.tags
