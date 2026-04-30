"""Unit tests for the Threat ORM model (M3a schema)."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.cwe import CWE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource


@pytest.mark.asyncio
async def test_threat_with_cwes_and_source():
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
            threat_type="cve",
            title="Log4Shell RCE",
            summary="Remote code execution via JNDI lookup",
            severity=Severity.critical,
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cvss_version="3.1",
            tags=["nvd"],
            published_at=now,
            last_modified_at=now,
            cwes=[cwe],
        )
        session.add(threat)
        await session.flush()

        ts = ThreatSource(
            threat_id=threat.id,
            source_id=src.id,
            external_id="CVE-2021-44228",
            first_seen_at=now,
            last_seen_at=now,
            tags=["nvd"],
            affected_products=["cpe:2.3:a:apache:log4j:2.0:*"],
            references=["https://example.test/advisory"],
            raw_data={"cvss_score": 10.0},
        )
        session.add(ts)
        await session.commit()

    async with factory() as session:
        stmt = (
            select(Threat).options(selectinload(Threat.cwes)).where(Threat.title == "Log4Shell RCE")
        )
        row = (await session.execute(stmt)).scalar_one()
        assert row.cvss_score == 10.0
        assert row.threat_type == "cve"
        assert "nvd" in row.tags
        assert [c.id for c in row.cwes] == ["CWE-79"]

        ts_row = (
            await session.execute(select(ThreatSource).where(ThreatSource.threat_id == row.id))
        ).scalar_one()
        assert ts_row.external_id == "CVE-2021-44228"
        assert ts_row.affected_products == ["cpe:2.3:a:apache:log4j:2.0:*"]

    await engine.dispose()
