import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.cve import CVE
from threat_intel.models.cwe import CWE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat


@pytest.mark.asyncio
async def test_threat_with_cve_and_cwes():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    now = datetime.now(UTC)

    async with factory() as session:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x")
        session.add(src)
        await session.flush()

        cwe = CWE(id="CWE-79", name="XSS")
        session.add(cwe)

        threat = Threat(
            id=uuid.uuid4(),
            source_id=src.id,
            external_id="CVE-2026-1",
            title="t",
            description="d",
            severity=Severity.high,
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N",
            cvss_version="3.1",
            affected_products=["cpe:2.3:a:vendor:product:1.0"],
            references=["https://example.test/x"],
            published_at=now,
            last_modified_at=now,
            raw_data={"cve": {"id": "CVE-2026-1"}},
            cwes=[cwe],
        )
        session.add(threat)

        cve_idx = CVE(cve_id="CVE-2026-1", threat_id=threat.id)
        session.add(cve_idx)
        await session.commit()

    async with factory() as session:
        stmt = (
            select(Threat)
            .options(selectinload(Threat.cwes))
            .where(Threat.external_id == "CVE-2026-1")
        )
        row = (await session.execute(stmt)).scalar_one()
        assert row.cvss_score == 8.1
        assert row.affected_products == ["cpe:2.3:a:vendor:product:1.0"]
        assert [c.id for c in row.cwes] == ["CWE-79"]

        cve_row = (
            await session.execute(select(CVE).where(CVE.cve_id == "CVE-2026-1"))
        ).scalar_one()
        assert cve_row.threat_id == row.id

    await engine.dispose()
