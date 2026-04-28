from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base
from threat_intel.models.sector_profile import SectorProfile


@pytest.mark.asyncio
async def test_sector_profile_persistence_roundtrip():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    now = datetime.now(UTC)
    async with factory() as s:
        s.add(
            SectorProfile(
                id="finance",
                name="Finance",
                sector="banking",
                description="Retail and corporate banking",
                keywords=["payment", "swift"],
                technologies=["Java", "PostgreSQL"],
                cwe_priorities=["CWE-79", "CWE-89"],
                excluded_keywords=["minecraft"],
                compliance=["PCI-DSS"],
                priority_boost_keywords=["wire transfer"],
                cvss_threshold=7.5,
                visibility="public",
                source_file="profiles/public/finance.yaml",
                loaded_at=now,
            )
        )
        await s.commit()

    async with factory() as s:
        row = (
            await s.execute(select(SectorProfile).where(SectorProfile.id == "finance"))
        ).scalar_one()
        assert row.sector == "banking"
        assert row.cvss_threshold == 7.5
        assert row.keywords == ["payment", "swift"]
        assert row.cwe_priorities == ["CWE-79", "CWE-89"]
        assert row.visibility == "public"
        # UtcDateTime decorator must reattach UTC tzinfo
        assert row.loaded_at.tzinfo is not None
        assert row.created_at.tzinfo is not None

    await engine.dispose()


@pytest.mark.asyncio
async def test_sector_profile_defaults():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async with factory() as s:
        s.add(
            SectorProfile(
                id="bare",
                name="Bare",
                sector="generic",
                loaded_at=datetime.now(UTC),
            )
        )
        await s.commit()

    async with factory() as s:
        row = (await s.execute(select(SectorProfile))).scalar_one()
        assert row.keywords == []
        assert row.technologies == []
        assert row.cwe_priorities == []
        assert row.excluded_keywords == []
        assert row.compliance == []
        assert row.priority_boost_keywords == []
        assert row.cvss_threshold == 7.0
        assert row.visibility == "public"

    await engine.dispose()
