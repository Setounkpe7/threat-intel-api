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
        nvd = Source(name="nvd", kind=SourceKind.cve_feed, url="https://n", enabled=True)
        rss = Source(name="dfir_report", kind=SourceKind.rss, url="https://r", enabled=True)
        s.add_all([nvd, rss])
        await s.commit()
        await s.refresh(nvd)
        await s.refresh(rss)
    return {"nvd": nvd, "dfir_report": rss}


def _nvd(cve):
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name="nvd",
        external_id=cve,
        title=f"t-{cve}",
        severity=Severity.high,
        cvss_score=9.0,
        indicators=[CollectedIndicator(type="cve", value=cve)],
        published_at=now,
        last_modified_at=now,
        raw_data={"title": f"t-{cve}", "severity": "high", "cvss_score": 9.0, "cwe_ids": []},
    )


def _rss(ext_id, cves, *, tt="report"):
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name="dfir_report",
        external_id=ext_id,
        title="rss",
        summary="s",
        tags=["rss"],
        indicators=[CollectedIndicator(type="cve", value=c) for c in cves],
        published_at=now,
        last_modified_at=now,
        raw_data={"references": [], "cwe_ids": []},
        enrichment_mode=True,
        threat_type=tt,
        indicator_confidence=50,
    )


async def test_rss_single_cve_enriches_existing(factory, sources):
    svc = IngestService(factory)
    _, tid = await svc.process(_nvd("CVE-2021-44228"), sources["nvd"].id)
    out, etid = await svc.process(_rss("post-1", ["CVE-2021-44228"]), sources["dfir_report"].id)
    assert out == "updated"
    assert etid == tid
    async with factory() as s:
        ts = (
            (await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid)))
            .scalars()
            .all()
        )
        assert {t.source_id for t in ts} == {sources["nvd"].id, sources["dfir_report"].id}
        assert "rss" in (await s.execute(select(Threat).where(Threat.id == tid))).scalar_one().tags


async def test_rss_multi_cve_fans_out_no_merge(factory, sources):
    svc = IngestService(factory)
    _, t1 = await svc.process(_nvd("CVE-2024-0001"), sources["nvd"].id)
    _, t2 = await svc.process(_nvd("CVE-2024-0002"), sources["nvd"].id)
    assert t1 != t2
    await svc.process(_rss("multi", ["CVE-2024-0001", "CVE-2024-0002"]), sources["dfir_report"].id)
    async with factory() as s:
        threats = (await s.execute(select(Threat))).scalars().all()
        # still exactly 2 threats — NOT merged into 1
        assert len([t for t in threats if t.threat_type == "cve"]) == 2
        for tid in (t1, t2):
            ts = (
                (await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid)))
                .scalars()
                .all()
            )
            assert sources["dfir_report"].id in {t.source_id for t in ts}


async def test_rss_no_cve_idempotent(factory, sources):
    svc = IngestService(factory)
    o1, tid1 = await svc.process(_rss("orphan-1", []), sources["dfir_report"].id)
    o2, tid2 = await svc.process(_rss("orphan-1", []), sources["dfir_report"].id)
    assert o1 == "created" and o2 == "updated"
    assert tid1 == tid2
    async with factory() as s:
        threats = (await s.execute(select(Threat))).scalars().all()
        assert len(threats) == 1
        assert threats[0].threat_type == "report"
        # Exactly one ThreatSource row must exist for (dfir_report, "orphan-1")
        ts_rows = (
            (
                await s.execute(
                    select(ThreatSource).where(
                        ThreatSource.source_id == sources["dfir_report"].id,
                        ThreatSource.external_id == "orphan-1",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(ts_rows) == 1


async def test_rss_never_overrides_canonical_cvss(factory, sources):
    svc = IngestService(factory)
    _, tid = await svc.process(_nvd("CVE-2025-1234"), sources["nvd"].id)

    now = datetime.now(UTC)
    rss_with_bogus_cvss = CollectedEvent(
        source_name="dfir_report",
        external_id="p9",
        title="rss",
        indicators=[CollectedIndicator(type="cve", value="CVE-2025-1234")],
        published_at=now,
        last_modified_at=now,
        # a malicious/low-quality feed claiming cvss 1.0 in raw_data
        raw_data={
            "title": "rss",
            "summary": "x",
            "cvss_score": 1.0,
            "severity": "low",
            "cwe_ids": [],
        },
        enrichment_mode=True,
        threat_type="report",
        indicator_confidence=50,
    )
    await svc.process(rss_with_bogus_cvss, sources["dfir_report"].id)
    async with factory() as s:
        t = (await s.execute(select(Threat).where(Threat.id == tid))).scalar_one()
        assert t.cvss_score == 9.0  # NVD value preserved, RSS ignored
        assert t.severity == Severity.high  # NVD-derived severity unchanged by RSS bogus "low"
