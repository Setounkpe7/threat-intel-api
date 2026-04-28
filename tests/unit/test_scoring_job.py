import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.cwe import CWE
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.services.scoring_job import ThreatScoringJob


@pytest.fixture
async def factory():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield session_factory(engine)
    await engine.dispose()


async def _seed(factory, *, threat_count: int = 1, cwe_id: str = "CWE-79"):
    now = datetime.now(UTC)
    threat_ids: list[uuid.UUID] = []
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x")
        s.add(src)
        await s.flush()
        cwe = CWE(id=cwe_id, name="X")
        s.add(cwe)
        for i in range(threat_count):
            tid = uuid.uuid4()
            t = Threat(
                id=tid,
                source_id=src.id,
                external_id=f"CVE-{i}",
                title="Apache Tomcat RCE",
                description="Apache Tomcat payment processing flaw.",
                severity=Severity.high,
                cvss_score=8.0,
                cvss_vector="CVSS:3.1/X",
                cvss_version="3.1",
                affected_products=["cpe:2.3:a:apache:tomcat:9.0"],
                references=[],
                published_at=now,
                last_modified_at=now,
                raw_data={},
                cwes=[cwe],
            )
            s.add(t)
            threat_ids.append(tid)
        s.add(
            SectorProfile(
                id="finance",
                name="Finance",
                sector="banking",
                keywords=["payment"],
                technologies=["Tomcat"],
                cwe_priorities=["CWE-79"],
                cvss_threshold=7.0,
                loaded_at=now,
            )
        )
        s.add(
            SectorProfile(
                id="other",
                name="Other",
                sector="x",
                keywords=["unrelated"],
                cvss_threshold=99.0,
                loaded_at=now,
            )
        )
        await s.commit()
    return threat_ids


@pytest.mark.asyncio
async def test_score_threat_ids_writes_one_row_per_profile(factory):
    [tid] = await _seed(factory)
    job = ThreatScoringJob(factory)
    res = await job.score_threat_ids([tid])
    assert res.threats_scored == 1
    assert res.profiles_count == 2
    assert res.rows_written == 2

    async with factory() as s:
        rows = (await s.execute(select(ThreatSectorScore))).scalars().all()
        by_sid = {r.sector_id: r for r in rows}
        # tech 30 + kw 25 + cwe 20 + cvss 15 = 90 (no boost configured)
        assert by_sid["finance"].score == 90.0
        assert by_sid["other"].score == 0.0
        assert "final_score" in by_sid["finance"].score_breakdown


@pytest.mark.asyncio
async def test_score_is_idempotent_and_updates_existing_row(factory):
    [tid] = await _seed(factory)
    job = ThreatScoringJob(factory)
    await job.score_threat_ids([tid])

    # Mutate the profile, re-score; existing row should UPDATE, not duplicate
    async with factory() as s:
        prof = (
            await s.execute(select(SectorProfile).where(SectorProfile.id == "finance"))
        ).scalar_one()
        prof.cvss_threshold = 99.0  # now cvss rule fails
        await s.commit()

    res = await job.score_threat_ids([tid])
    assert res.rows_written == 2  # both profiles re-written, no new rows

    async with factory() as s:
        rows = (await s.execute(select(ThreatSectorScore))).scalars().all()
        assert len(rows) == 2  # still 2 — composite PK held
        finance_row = next(r for r in rows if r.sector_id == "finance")
        # 90 - 15 (cvss no longer hits) = 75
        assert finance_row.score == 75.0


@pytest.mark.asyncio
async def test_score_with_no_profiles_writes_nothing(factory):
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    f = session_factory(engine)
    now = datetime.now(UTC)
    async with f() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x")
        s.add(src)
        await s.flush()
        tid = uuid.uuid4()
        s.add(
            Threat(
                id=tid,
                source_id=src.id,
                external_id="CVE-1",
                title="x",
                description="x",
                severity=Severity.high,
                cvss_score=1.0,
                affected_products=[],
                references=[],
                published_at=now,
                last_modified_at=now,
                raw_data={},
            )
        )
        await s.commit()

    res = await ThreatScoringJob(f).score_threat_ids([tid])
    assert res.profiles_count == 0
    assert res.rows_written == 0
    async with f() as s:
        rows = (await s.execute(select(ThreatSectorScore))).scalars().all()
        assert rows == []
    await engine.dispose()


@pytest.mark.asyncio
async def test_score_threats_since_picks_recent(factory):
    threat_ids = await _seed(factory, threat_count=3)
    # Backdate one threat
    async with factory() as s:
        t0 = (await s.execute(select(Threat).where(Threat.id == threat_ids[0]))).scalar_one()
        t0.last_modified_at = datetime.now(UTC) - timedelta(days=30)
        await s.commit()

    job = ThreatScoringJob(factory)
    res = await job.score_threats_since(datetime.now(UTC) - timedelta(days=7))
    assert res.threats_scored == 2  # only the 2 recent ones


@pytest.mark.asyncio
async def test_rescore_all(factory):
    await _seed(factory, threat_count=2)
    job = ThreatScoringJob(factory)
    res = await job.rescore_all()
    assert res.threats_scored == 2
    assert res.rows_written == 4  # 2 threats × 2 profiles
    async with factory() as s:
        count = (await s.execute(select(ThreatSectorScore))).scalars().all()
        assert len(count) == 4
