import os
import uuid
from datetime import UTC, datetime, timedelta

# Module-level env defaults so that importing threat_intel.main (which calls
# create_app() at module scope to support `uvicorn threat_intel.main:app`)
# does not error on a missing DATABASE_URL during test collection.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("APP_ENV", "dev")
os.environ.setdefault("CORS_ORIGINS", "")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker  # noqa: E402

from threat_intel.core.config import Settings  # noqa: E402
from threat_intel.core.db import build_engine, session_factory  # noqa: E402
from threat_intel.main import create_app  # noqa: E402
from threat_intel.models.base import Base, Severity, SourceKind  # noqa: E402
from threat_intel.models.cve import CVE  # noqa: E402
from threat_intel.models.cwe import CWE  # noqa: E402
from threat_intel.models.source import Source  # noqa: E402
from threat_intel.models.threat import Threat  # noqa: E402


@pytest.fixture
def settings(monkeypatch) -> Settings:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("CORS_ORIGINS", "")
    monkeypatch.setenv("NVD_BASE_URL", "https://nvd.test/cves/2.0")
    monkeypatch.setenv("NVD_FETCH_INTERVAL_MINUTES", "60")
    return Settings()  # type: ignore[call-arg]


@pytest_asyncio.fixture
async def engine(settings):
    eng = build_engine(settings.database_url)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def factory(engine) -> async_sessionmaker:
    return session_factory(engine)


@pytest_asyncio.fixture
async def seeded_db(factory):
    """Seed: 1 source 'nvd', 3 threats with varied severities and dates, CVE index rows."""
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(
            name="nvd",
            kind=SourceKind.cve_feed,
            url="https://x",
            enabled=True,
            last_run_at=now,
            last_success_at=now,
        )
        s.add(src)
        await s.flush()

        cwe = CWE(id="CWE-79", name="XSS")
        s.add(cwe)

        rows = []
        for i, (sev, age_h) in enumerate(
            [(Severity.critical, 1), (Severity.high, 5), (Severity.low, 30)]
        ):
            cve_id = f"CVE-2026-{1000 + i}"
            tid = uuid.uuid4()
            t = Threat(
                id=tid,
                source_id=src.id,
                external_id=cve_id,
                title=f"Title {i}",
                description=f"Desc {i}",
                severity=sev,
                cvss_score=8.0 if sev != Severity.low else 3.0,
                cvss_vector="CVSS:3.1/AV:N",
                cvss_version="3.1",
                affected_products=[f"cpe:2.3:a:x:y:{i}"],
                references=[f"https://r/{i}"],
                published_at=now - timedelta(hours=age_h),
                last_modified_at=now - timedelta(hours=age_h),
                raw_data={"cve": {"id": cve_id}},
                cwes=[cwe] if i == 0 else [],
            )
            s.add(t)
            s.add(CVE(cve_id=cve_id, threat_id=tid))
            rows.append(t)
        await s.commit()
    return rows


@pytest_asyncio.fixture
async def app(factory, settings):
    app = create_app(settings=settings)
    # Bypass the real lifespan to avoid starting APScheduler and skipping
    # _ensure_source_row in tests; install only the state the routes read.
    app.state.settings = settings
    app.state.session_factory = factory
    app.state.collector_names = ["nvd"]
    app.state.start_time = datetime.now(UTC)
    return app


@pytest_asyncio.fixture
async def client(app):
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
