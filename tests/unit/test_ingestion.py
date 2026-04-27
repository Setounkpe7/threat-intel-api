import json
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import func, select

from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings
from threat_intel.core.db import build_engine, session_factory
from threat_intel.core.exceptions import CollectorHTTPError
from threat_intel.models.base import Base, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.services.ingestion import IngestionService


@pytest.mark.asyncio
async def test_ingestion_runs_end_to_end(tmp_path):
    payload = json.loads(Path("tests/fixtures/nvd_sample.json").read_text())
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    engine = build_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async with factory() as s:
        s.add(Source(name="nvd", kind=SourceKind.cve_feed, url=settings.nvd_base_url, enabled=True))
        await s.commit()

    async with httpx.AsyncClient() as client, respx.mock(base_url="https://nvd.test") as mock:
        mock.get("/cves/2.0").mock(return_value=httpx.Response(200, json=payload))
        collector = NVDCollector(http_client=client, settings=settings)
        service = IngestionService(session_factory=factory, collectors=[collector])
        result = await service.run("nvd")

    assert result.inserted == 2
    assert result.updated == 0

    async with factory() as s:
        total = (await s.execute(select(func.count(Threat.id)))).scalar_one()
        src = (await s.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
        assert total == 2
        assert src.last_run_at is not None
        assert src.last_success_at is not None
        assert src.last_error is None

    await engine.dispose()


@pytest.mark.asyncio
async def test_ingestion_records_error_on_failure():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    engine = build_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = session_factory(engine)

    async with factory() as s:
        s.add(Source(name="nvd", kind=SourceKind.cve_feed, url=settings.nvd_base_url, enabled=True))
        await s.commit()

    async with httpx.AsyncClient() as client, respx.mock(base_url="https://nvd.test") as mock:
        mock.get("/cves/2.0").mock(return_value=httpx.Response(500))
        collector = NVDCollector(http_client=client, settings=settings)
        service = IngestionService(session_factory=factory, collectors=[collector])
        with pytest.raises(CollectorHTTPError):
            await service.run("nvd")

    async with factory() as s:
        src = (await s.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
        assert src.last_error is not None
        assert src.last_success_at is None

    await engine.dispose()
