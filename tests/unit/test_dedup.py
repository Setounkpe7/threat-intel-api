from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from threat_intel.analyzers.dedup import upsert_threat
from threat_intel.collectors.base import ThreatDraft
from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.cve import CVE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat


def _draft(cve_id: str, modified: datetime) -> ThreatDraft:
    return ThreatDraft(
        source_name="nvd",
        external_id=cve_id,
        title="t",
        description="d",
        severity=Severity.high,
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/X",
        cvss_version="3.1",
        cwe_ids=["CWE-79"],
        affected_products=["cpe:2.3:a:x:y:1.0"],
        references=["https://x"],
        published_at=modified,
        last_modified_at=modified,
        raw_data={"k": "v"},
    )


@pytest.fixture
async def session():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)
    async with factory() as s:
        s.add(Source(name="nvd", kind=SourceKind.cve_feed, url="https://x"))
        await s.commit()
    async with factory() as s:
        yield s
    await engine.dispose()


async def test_upsert_inserts_new(session):
    now = datetime.now(timezone.utc)
    src = (await session.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    result = await upsert_threat(session, src, _draft("CVE-2026-100", now))
    await session.commit()
    assert result == "inserted"
    cve_row = (await session.execute(select(CVE).where(CVE.cve_id == "CVE-2026-100"))).scalar_one()
    assert cve_row.threat_id is not None


async def test_upsert_noop_when_unchanged(session):
    now = datetime.now(timezone.utc)
    src = (await session.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    await upsert_threat(session, src, _draft("CVE-2026-101", now))
    await session.commit()
    result = await upsert_threat(session, src, _draft("CVE-2026-101", now))
    await session.commit()
    assert result == "unchanged"


async def test_upsert_updates_when_modified(session):
    now = datetime.now(timezone.utc)
    later = now + timedelta(hours=1)
    src = (await session.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    await upsert_threat(session, src, _draft("CVE-2026-102", now))
    await session.commit()
    result = await upsert_threat(session, src, _draft("CVE-2026-102", later))
    await session.commit()
    assert result == "updated"
    row = (
        await session.execute(select(Threat).where(Threat.external_id == "CVE-2026-102"))
    ).scalar_one()
    assert row.last_modified_at == later
