import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat


async def _make_threat(session, source_id=None):
    now = datetime.now(UTC)
    threat = Threat(
        id=uuid.uuid4(),
        threat_type="cve",
        title="t",
        summary="d",
        severity=Severity.high,
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N",
        cvss_version="3.1",
        tags=[],
        published_at=now,
        last_modified_at=now,
    )
    session.add(threat)
    await session.flush()
    return threat


async def _setup():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # SQLite needs FK enforcement turned on per-connection to test cascades
        from sqlalchemy import text

        await conn.execute(text("PRAGMA foreign_keys=ON"))
        await conn.run_sync(Base.metadata.create_all)
    return engine, session_factory(engine)


@pytest.mark.asyncio
async def test_threat_sector_score_roundtrip():
    engine, factory = await _setup()
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x")
        s.add(src)
        await s.flush()
        threat = await _make_threat(s, src.id)
        s.add(
            SectorProfile(
                id="finance",
                name="F",
                sector="banking",
                loaded_at=now,
            )
        )
        await s.flush()
        s.add(
            ThreatSectorScore(
                threat_id=threat.id,
                sector_id="finance",
                score=82.5,
                score_breakdown={"keyword_match": 25, "tech_match": 30},
                calculated_at=now,
            )
        )
        await s.commit()

    async with factory() as s:
        row = (await s.execute(select(ThreatSectorScore))).scalar_one()
        assert row.score == 82.5
        assert row.score_breakdown["keyword_match"] == 25
        assert row.calculated_at.tzinfo is not None

    await engine.dispose()


@pytest.mark.asyncio
async def test_composite_pk_prevents_duplicates():
    engine, factory = await _setup()
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x")
        s.add(src)
        await s.flush()
        threat = await _make_threat(s, src.id)
        threat_id = threat.id
        s.add(SectorProfile(id="finance", name="F", sector="banking", loaded_at=now))
        await s.flush()
        s.add(
            ThreatSectorScore(
                threat_id=threat_id,
                sector_id="finance",
                score=50.0,
                score_breakdown={},
                calculated_at=now,
            )
        )
        await s.commit()

    with pytest.raises(IntegrityError):
        async with factory() as s:
            s.add(
                ThreatSectorScore(
                    threat_id=threat_id,
                    sector_id="finance",
                    score=99.0,
                    score_breakdown={},
                    calculated_at=now,
                )
            )
            await s.commit()

    await engine.dispose()
