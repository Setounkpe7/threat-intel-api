"""End-to-end test: ingest CVE fixture → auto-score → query via API (M2 phase 8)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import select

from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings
from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base, SourceKind
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.source import Source
from threat_intel.services.ingestion import IngestionService
from threat_intel.services.scoring_job import ThreatScoringJob


@pytest.mark.asyncio
async def test_ingestion_triggers_scoring_against_seeded_profiles():
    payload = json.loads(Path("tests/fixtures/nvd_sample.json").read_text())
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    engine = build_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    now = datetime.now(UTC)
    async with factory() as s:
        s.add(Source(name="nvd", kind=SourceKind.cve_feed, url=settings.nvd_base_url, enabled=True))
        s.add(SectorProfile(
            id="generic", name="Generic", sector="x",
            keywords=["remote code execution"],
            cvss_threshold=7.0,
            visibility="public", loaded_at=now,
        ))
        s.add(SectorProfile(
            id="zero", name="Zero", sector="x",
            keywords=["definitely-not-in-the-fixture"],
            cvss_threshold=99.0,
            visibility="public", loaded_at=now,
        ))
        await s.commit()

    scoring_job = ThreatScoringJob(factory)
    async with httpx.AsyncClient() as http, respx.mock(base_url="https://nvd.test") as mock:
        mock.get("/cves/2.0").mock(return_value=httpx.Response(200, json=payload))
        collector = NVDCollector(http_client=http, settings=settings)
        service = IngestionService(
            session_factory=factory, collectors=[collector], scoring_job=scoring_job
        )
        result = await service.run("nvd")

    assert result.inserted == 2

    async with factory() as s:
        rows = (await s.execute(select(ThreatSectorScore))).scalars().all()
        # 2 threats × 2 profiles = 4 rows
        assert len(rows) == 4
        by_sector: dict[str, list[float]] = {}
        for r in rows:
            by_sector.setdefault(r.sector_id, []).append(r.score)
        # 'generic' should score above zero on at least one threat
        assert max(by_sector["generic"]) > 0
        # 'zero' threshold is unreachable → both scores at 0
        assert all(s == 0.0 for s in by_sector["zero"])

    await engine.dispose()
