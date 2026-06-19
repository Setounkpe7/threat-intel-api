from datetime import UTC, datetime

import pytest_asyncio
from sqlalchemy import select

from threat_intel.core.db import build_engine
from threat_intel.core.db import session_factory as make_factory
from threat_intel.models.base import Base, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
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
async def rss_source(factory):
    async with factory() as s:
        src = Source(name="dfir_report", kind=SourceKind.rss, url="https://x", enabled=True)
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


def _rss_event(ext_id, *, indicators=None, threat_type="report", confidence=50, tags=None):
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name="dfir_report",
        external_id=ext_id,
        title=f"t-{ext_id}",
        summary="s",
        tags=tags or [],
        indicators=[CollectedIndicator(type=t, value=v) for t, v in (indicators or [])],
        published_at=now,
        last_modified_at=now,
        raw_data={"references": [], "cwe_ids": []},
        enrichment_mode=True,
        threat_type=threat_type,
        indicator_confidence=confidence,
    )


async def test_create_threat_uses_explicit_report_type(factory, rss_source):
    svc = IngestService(factory)
    out, tid = await svc.process(_rss_event("post-1"), rss_source.id)
    assert out == "created"
    async with factory() as s:
        t = (await s.execute(select(Threat).where(Threat.id == tid))).scalar_one()
        assert t.threat_type == "report"


async def test_rss_ioc_confidence_is_degraded(factory, rss_source):
    svc = IngestService(factory)
    _, tid = await svc.process(
        _rss_event("post-2", indicators=[("ip", "8.8.8.8")], confidence=50), rss_source.id
    )
    async with factory() as s:
        ind = (
            await s.execute(select(ThreatIndicator).where(ThreatIndicator.threat_id == tid))
        ).scalar_one()
        assert ind.confidence == 50
