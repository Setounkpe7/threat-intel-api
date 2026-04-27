import pytest
from sqlalchemy import select

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base, SourceKind
from threat_intel.models.source import Source


@pytest.mark.asyncio
async def test_source_round_trip():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async with factory() as session:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x", enabled=True)
        session.add(src)
        await session.commit()

    async with factory() as session:
        row = (await session.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
        assert row.kind is SourceKind.cve_feed
        assert row.enabled is True
        assert row.created_at is not None
        assert row.created_at.tzinfo is not None  # tz-aware

    await engine.dispose()
