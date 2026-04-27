# CyberThreat Intelligence API — Milestone 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working FastAPI service that ingests NVD CVEs hourly, persists them with deduplication, and exposes `/health`, `/api/v1/threats`, and `/api/v1/cve/{cve_id}`, all runnable via `docker compose up`.

**Architecture:** Async Python 3.12 service with three layers — collectors (NVD via `BaseCollector` ABC), services (ingestion + queries), API (FastAPI v1 router). PostgreSQL in prod via `asyncpg`, SQLite in-memory in tests via `aiosqlite`. APScheduler triggers hourly NVD pulls. Structured logging with `structlog`.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, Pydantic 2, httpx, APScheduler 3.10, Alembic, structlog, pytest + respx, Docker Compose.

**Spec reference:** [`docs/superpowers/specs/2026-04-27-threat-intel-api-m1-design.md`](../specs/2026-04-27-threat-intel-api-m1-design.md)

---

## File map

Each file has one responsibility. Created in this order across the tasks below.

| File | Purpose |
|---|---|
| `pyproject.toml` | dependencies, ruff/mypy/pytest config |
| `.gitignore`, `.env.example`, `.dockerignore` | repo hygiene |
| `src/threat_intel/__init__.py` | package init, `__version__` |
| `src/threat_intel/core/config.py` | `Settings` (pydantic-settings) |
| `src/threat_intel/core/logging.py` | `configure_logging()` |
| `src/threat_intel/core/exceptions.py` | exception hierarchy |
| `src/threat_intel/core/db.py` | async engine + sessionmaker + `get_session` |
| `src/threat_intel/models/base.py` | `Base`, `TimestampMixin`, enums |
| `src/threat_intel/models/source.py` | `Source` ORM |
| `src/threat_intel/models/threat.py` | `Threat` ORM |
| `src/threat_intel/models/cve.py` | `CVE` ORM |
| `src/threat_intel/models/cwe.py` | `CWE` + junction |
| `alembic.ini`, `alembic/env.py`, `alembic/versions/0001_*.py` | migrations |
| `src/threat_intel/schemas/threat.py` | `ThreatRead`, `ThreatList`, `ThreatFilters` |
| `src/threat_intel/schemas/cve.py` | `ThreatDetail` |
| `src/threat_intel/schemas/health.py` | health response shapes |
| `src/threat_intel/collectors/base.py` | `RawEvent`, `ThreatDraft`, `BaseCollector` |
| `src/threat_intel/collectors/nvd.py` | `NVDCollector` |
| `src/threat_intel/analyzers/dedup.py` | `upsert_threat` |
| `src/threat_intel/services/ingestion.py` | `IngestionService` |
| `src/threat_intel/services/threats.py` | query/filter logic |
| `src/threat_intel/api/deps.py` | shared FastAPI dependencies |
| `src/threat_intel/api/health.py` | `GET /health` |
| `src/threat_intel/api/v1/__init__.py` | v1 router |
| `src/threat_intel/api/v1/threats.py` | `GET /api/v1/threats` |
| `src/threat_intel/api/v1/cve.py` | `GET /api/v1/cve/{cve_id}` |
| `src/threat_intel/cli/collect_once.py` | one-shot collector for demos |
| `src/threat_intel/main.py` | `create_app()` + lifespan + scheduler hookup |
| `tests/conftest.py` | fixtures (engine, session, client, respx) |
| `tests/unit/test_nvd_collector.py` | normalize + fetch with respx |
| `tests/unit/test_dedup.py` | upsert insert/update/no-op |
| `tests/integration/test_health.py` | `/health` end-to-end |
| `tests/integration/test_threats.py` | `/api/v1/threats` filters and pagination |
| `tests/integration/test_cve.py` | `/api/v1/cve/{cve_id}` 200 + 404 |
| `tests/fixtures/nvd_sample.json` | recorded NVD payload for unit tests |
| `Dockerfile` | multi-stage runtime image |
| `docker-compose.yml` | postgres + app |
| `README.md` | install, run, structure, adding a collector |

---

## Task 1: Initialize repo scaffolding and `pyproject.toml`

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `.env.example`, `.dockerignore`, `README.md` (placeholder), `src/threat_intel/__init__.py`, `tests/__init__.py`, `profiles/public/.gitkeep`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "threat-intel-api"
version = "0.1.0"
description = "CyberThreat Intelligence API — aggregates OSINT CVE feeds"
requires-python = ">=3.12"
authors = [{ name = "Michel-Ange Doubogan", email = "Mdoubogan@yahoo.fr" }]
readme = "README.md"
dependencies = [
  "fastapi>=0.115",
  "uvicorn[standard]>=0.30",
  "httpx[http2]>=0.27",
  "sqlalchemy[asyncio]>=2.0.30",
  "asyncpg>=0.29",
  "aiosqlite>=0.20",
  "alembic>=1.13",
  "pydantic>=2.7",
  "pydantic-settings>=2.3",
  "apscheduler>=3.10,<4",
  "structlog>=24.1",
  "tenacity>=8.3",
  "typer>=0.12",
]

[project.optional-dependencies]
dev = [
  "pytest>=8",
  "pytest-asyncio>=0.23",
  "respx>=0.21",
  "ruff>=0.5",
  "mypy>=1.10",
  "types-pytz",
]

[project.scripts]
threat-intel = "threat_intel.cli.collect_once:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/threat_intel"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "ANN", "S", "T20", "RET", "SIM"]
ignore = ["ANN101", "ANN102", "S101"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["ANN", "S105", "S106"]

[tool.mypy]
python_version = "3.12"
strict = true
plugins = ["pydantic.mypy"]
mypy_path = "src"
namespace_packages = true
explicit_package_bases = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "-ra --strict-markers"
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
venv/
.python-version

# Tooling
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/

# Env / secrets
.env
.env.local
*.pem

# Profiles (private must never be committed)
profiles/private/

# IDE
.vscode/
.idea/

# OS
.DS_Store
```

- [ ] **Step 3: Write `.env.example`**

```dotenv
# App
APP_NAME=threat-intel-api
APP_ENV=dev                    # dev | prod
LOG_LEVEL=INFO

# Database
DATABASE_URL=postgresql+asyncpg://threat:threat@db:5432/threat_intel

# CORS (comma-separated origins)
CORS_ORIGINS=http://localhost:3000

# NVD collector
NVD_BASE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=                   # optional, leave empty to use anonymous rate limits
NVD_FETCH_INTERVAL_MINUTES=60
```

- [ ] **Step 4: Write `.dockerignore`**

```
.git
.venv
__pycache__
*.pyc
.pytest_cache
.mypy_cache
.ruff_cache
tests
docs
profiles/private
.env
.env.local
```

- [ ] **Step 5: Create empty package files**

```bash
mkdir -p src/threat_intel tests/unit tests/integration tests/fixtures profiles/public
touch profiles/public/.gitkeep
touch tests/__init__.py tests/unit/__init__.py tests/integration/__init__.py
```

Write `src/threat_intel/__init__.py`:

```python
"""CyberThreat Intelligence API."""

__version__ = "0.1.0"
```

Write a one-line placeholder `README.md`:

```markdown
# CyberThreat Intelligence API

See `docs/superpowers/specs/2026-04-27-threat-intel-api-m1-design.md`.
```

- [ ] **Step 6: Create venv and install**

Run:
```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```
Expected: install completes without errors.

- [ ] **Step 7: Verify ruff and mypy run on the empty package**

Run:
```bash
ruff check src tests
mypy src
```
Expected: both pass with no errors.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml .gitignore .env.example .dockerignore README.md \
        src/threat_intel/__init__.py tests/__init__.py tests/unit/__init__.py \
        tests/integration/__init__.py profiles/public/.gitkeep
git commit -m "chore: scaffold project (pyproject, gitignore, package stubs)"
```

---

## Task 2: `Settings` configuration

**Files:**
- Create: `src/threat_intel/core/__init__.py`, `src/threat_intel/core/config.py`
- Test: `tests/unit/test_config.py`

- [ ] **Step 1: Create `core/__init__.py`**

```bash
touch src/threat_intel/core/__init__.py
```

- [ ] **Step 2: Write the failing test**

`tests/unit/test_config.py`:

```python
from threat_intel.core.config import Settings


def test_settings_loads_from_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@h:5432/db")
    monkeypatch.setenv("CORS_ORIGINS", "https://a.com,https://b.com")
    monkeypatch.setenv("NVD_FETCH_INTERVAL_MINUTES", "30")

    s = Settings()

    assert s.database_url == "postgresql+asyncpg://u:p@h:5432/db"
    assert s.cors_origins == ["https://a.com", "https://b.com"]
    assert s.nvd_fetch_interval_minutes == 30
    assert s.app_env == "dev"  # default


def test_settings_cors_empty_string_yields_empty_list(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("CORS_ORIGINS", "")
    s = Settings()
    assert s.cors_origins == []
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/unit/test_config.py -v
```
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 4: Write `core/config.py`**

> **Note on `NoDecode`:** pydantic-settings ≥ 2.3 attempts to JSON-decode complex types (like `list[str]`) from env values *before* `field_validator(mode="before")` runs. Without `NoDecode`, `CORS_ORIGINS=https://a.com,https://b.com` would raise `JSONDecodeError`. `NoDecode` opts the field out of pre-decoding so the validator receives the raw string.

```python
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "threat-intel-api"
    app_env: Literal["dev", "prod"] = "dev"
    log_level: str = "INFO"

    database_url: str

    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    nvd_fetch_interval_minutes: int = 60

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v: object) -> object:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 5: Run test to verify it passes**

```bash
pytest tests/unit/test_config.py -v
```
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/core/__init__.py src/threat_intel/core/config.py tests/unit/test_config.py
git commit -m "feat(core): Settings with env-driven config"
```

---

## Task 3: Structured logging

**Files:**
- Create: `src/threat_intel/core/logging.py`
- Test: `tests/unit/test_logging.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_logging.py`:

```python
import json
import logging

import structlog

from threat_intel.core.logging import configure_logging


def test_configure_logging_dev_emits_console(capsys):
    configure_logging(env="dev", level="INFO")
    log = structlog.get_logger()
    log.info("hello", user="me")
    out = capsys.readouterr().out
    assert "hello" in out
    assert "user" in out


def test_configure_logging_prod_emits_json(capsys):
    configure_logging(env="prod", level="INFO")
    log = structlog.get_logger()
    log.info("hello", user="me")
    out = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(out)
    assert payload["event"] == "hello"
    assert payload["user"] == "me"
    assert payload["level"] == "info"


def test_configure_logging_respects_level(capsys):
    configure_logging(env="prod", level="WARNING")
    log = structlog.get_logger()
    log.info("nope")
    log.warning("yep")
    lines = [ln for ln in capsys.readouterr().out.strip().splitlines() if ln]
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "yep"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_logging.py -v
```
Expected: FAIL — `ModuleNotFoundError`.

- [ ] **Step 3: Write `core/logging.py`**

```python
import logging
import sys
from typing import Literal

import structlog


def configure_logging(env: Literal["dev", "prod"], level: str = "INFO") -> None:
    """Configure structlog + stdlib logging.

    dev  → ConsoleRenderer (colorized, human-readable).
    prod → JSONRenderer    (one event per line).
    """
    level_int = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer: structlog.types.Processor = (
        structlog.dev.ConsoleRenderer() if env == "dev" else structlog.processors.JSONRenderer()
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level_int),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        level=level_int,
        stream=sys.stdout,
        force=True,
    )
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_logging.py -v
```
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/core/logging.py tests/unit/test_logging.py
git commit -m "feat(core): structlog setup, env-aware (console dev, json prod)"
```

---

## Task 4: Exception hierarchy

**Files:**
- Create: `src/threat_intel/core/exceptions.py`
- Test: `tests/unit/test_exceptions.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_exceptions.py`:

```python
import pytest

from threat_intel.core.exceptions import (
    CollectorError,
    CollectorHTTPError,
    CollectorParseError,
    ConfigurationError,
    PersistenceError,
    ThreatIntelException,
    ThreatNotFoundException,
)


def test_all_descend_from_base():
    for cls in (
        ConfigurationError,
        CollectorError,
        CollectorHTTPError,
        CollectorParseError,
        PersistenceError,
        ThreatNotFoundException,
    ):
        assert issubclass(cls, ThreatIntelException)


def test_collector_http_and_parse_descend_from_collector_error():
    assert issubclass(CollectorHTTPError, CollectorError)
    assert issubclass(CollectorParseError, CollectorError)


def test_threat_not_found_carries_cve_id():
    err = ThreatNotFoundException(cve_id="CVE-2026-9999")
    assert err.cve_id == "CVE-2026-9999"
    assert "CVE-2026-9999" in str(err)


def test_collector_http_error_carries_status_and_url():
    err = CollectorHTTPError(status_code=502, url="https://x", message="bad gateway")
    assert err.status_code == 502
    assert err.url == "https://x"
    assert "502" in str(err)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_exceptions.py -v
```
Expected: FAIL — module not found.

- [ ] **Step 3: Write `core/exceptions.py`**

```python
class ThreatIntelException(Exception):
    """Base class for all domain exceptions."""


class ConfigurationError(ThreatIntelException):
    """Invalid or missing configuration at boot."""


class CollectorError(ThreatIntelException):
    """Base class for collector failures."""


class CollectorHTTPError(CollectorError):
    def __init__(self, *, status_code: int, url: str, message: str = "") -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"HTTP {status_code} on {url}: {message}".rstrip(": "))


class CollectorParseError(CollectorError):
    """Source returned a payload we cannot parse."""


class PersistenceError(ThreatIntelException):
    """Database error during ingestion or query."""


class ThreatNotFoundException(ThreatIntelException):
    def __init__(self, *, cve_id: str) -> None:
        self.cve_id = cve_id
        super().__init__(f"Threat not found for {cve_id}")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_exceptions.py -v
```
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/core/exceptions.py tests/unit/test_exceptions.py
git commit -m "feat(core): exception hierarchy (ThreatIntelException + subclasses)"
```

---

## Task 5: Async DB engine and session

**Files:**
- Create: `src/threat_intel/core/db.py`
- Test: `tests/unit/test_db.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_db.py`:

```python
import pytest
from sqlalchemy import text

from threat_intel.core.db import build_engine, session_factory


@pytest.mark.asyncio
async def test_engine_executes_simple_query():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    factory = session_factory(engine)
    async with factory() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar_one() == 1
    await engine.dispose()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_db.py -v
```
Expected: FAIL.

- [ ] **Step 3: Write `core/db.py`**

```python
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def build_engine(database_url: str) -> AsyncEngine:
    """Create the async SQLAlchemy engine.

    `pool_pre_ping` is on so we recover gracefully from killed connections —
    relevant when running behind a connection-pooled Postgres.
    """
    return create_async_engine(database_url, pool_pre_ping=True, future=True)


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_session(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields a session, rolls back on exception."""
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_db.py -v
```
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/core/db.py tests/unit/test_db.py
git commit -m "feat(core): async SQLAlchemy engine and session factory"
```

---

## Task 6: Models — base, enums, `Source`

**Files:**
- Create: `src/threat_intel/models/__init__.py`, `src/threat_intel/models/base.py`, `src/threat_intel/models/source.py`
- Test: `tests/unit/test_models_source.py`

- [ ] **Step 1: Create `models/__init__.py` (empty)**

```bash
touch src/threat_intel/models/__init__.py
```

- [ ] **Step 2: Write the failing test**

`tests/unit/test_models_source.py`:

```python
from datetime import datetime, timezone

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
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/unit/test_models_source.py -v
```
Expected: FAIL — modules missing.

- [ ] **Step 4: Write `models/base.py`**

```python
from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"
    unknown = "unknown"


class SourceKind(StrEnum):
    cve_feed = "cve_feed"
    rss = "rss"
    advisory = "advisory"
```

- [ ] **Step 5: Write `models/source.py`**

```python
from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import Base, SourceKind, TimestampMixin


class Source(Base, TimestampMixin):
    __tablename__ = "source"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    kind: Mapped[SourceKind] = mapped_column(String(32))
    url: Mapped[str] = mapped_column(String(512))
    enabled: Mapped[bool] = mapped_column(default=True)

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
```

- [ ] **Step 6: Run test to verify it passes**

```bash
pytest tests/unit/test_models_source.py -v
```
Expected: 1 passed.

- [ ] **Step 7: Commit**

```bash
git add src/threat_intel/models/__init__.py src/threat_intel/models/base.py \
        src/threat_intel/models/source.py tests/unit/test_models_source.py
git commit -m "feat(models): Base, enums, Source ORM"
```

---

## Task 7: Models — `Threat`, `CVE`, `CWE`, junction

**Files:**
- Create: `src/threat_intel/models/threat.py`, `src/threat_intel/models/cve.py`, `src/threat_intel/models/cwe.py`
- Test: `tests/unit/test_models_threat.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_models_threat.py`:

```python
import uuid
from datetime import datetime, timezone

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

    now = datetime.now(timezone.utc)

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
        row = (
            await session.execute(
                select(Threat).options(selectinload(Threat.cwes)).where(Threat.external_id == "CVE-2026-1")
            )
        ).scalar_one()
        assert row.cvss_score == 8.1
        assert row.affected_products == ["cpe:2.3:a:vendor:product:1.0"]
        assert [c.id for c in row.cwes] == ["CWE-79"]

        cve_row = (
            await session.execute(select(CVE).where(CVE.cve_id == "CVE-2026-1"))
        ).scalar_one()
        assert cve_row.threat_id == row.id

    await engine.dispose()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_models_threat.py -v
```
Expected: FAIL.

- [ ] **Step 3: Write `models/cwe.py`**

```python
from sqlalchemy import Column, ForeignKey, String, Table
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import Base

threat_cwe = Table(
    "threat_cwe",
    Base.metadata,
    Column("threat_id", ForeignKey("threat.id", ondelete="CASCADE"), primary_key=True),
    Column("cwe_id", ForeignKey("cwe.id", ondelete="CASCADE"), primary_key=True),
)


class CWE(Base):
    __tablename__ = "cwe"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
```

- [ ] **Step 4: Write `models/threat.py`**

```python
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator, CHAR

from threat_intel.models.base import Base, Severity, TimestampMixin
from threat_intel.models.cwe import threat_cwe

if TYPE_CHECKING:
    from threat_intel.models.cwe import CWE


class GUID(TypeDecorator):  # type: ignore[type-arg]
    """Cross-DB UUID: native UUID on Postgres, CHAR(36) elsewhere."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):  # type: ignore[no-untyped-def]
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return str(value)

    def process_result_value(self, value, dialect):  # type: ignore[no-untyped-def]
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


class Threat(Base, TimestampMixin):
    __tablename__ = "threat"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_threat_source_external"),
        Index("ix_threat_published_at", "published_at"),
        Index("ix_threat_severity", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(128))

    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(String(16), default=Severity.unknown)

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)

    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column("references_json", JSON, default=list)

    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)  # type: ignore[type-arg]

    cwes: Mapped[list["CWE"]] = relationship(secondary=threat_cwe, lazy="selectin")
```

> Note: column name `references` is a Postgres reserved word; we map the Python attribute `references` to physical column `references_json`.

- [ ] **Step 5: Write `models/cve.py`**

```python
import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.models.base import Base
from threat_intel.models.threat import GUID, Threat


class CVE(Base):
    __tablename__ = "cve"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    threat_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat.id", ondelete="CASCADE"), unique=True
    )

    threat: Mapped["Threat"] = relationship(lazy="selectin")
```

- [ ] **Step 6: Run test to verify it passes**

```bash
pytest tests/unit/test_models_threat.py -v
```
Expected: 1 passed.

- [ ] **Step 7: Commit**

```bash
git add src/threat_intel/models/threat.py src/threat_intel/models/cve.py \
        src/threat_intel/models/cwe.py tests/unit/test_models_threat.py
git commit -m "feat(models): Threat, CVE index, CWE + junction"
```

---

## Task 8: Alembic setup and initial migration

**Files:**
- Create: `alembic.ini`, `alembic/env.py`, `alembic/script.py.mako`, `alembic/versions/0001_initial.py`

- [ ] **Step 1: Initialize Alembic**

Run:
```bash
alembic init -t async alembic
```
Expected: creates `alembic/`, `alembic.ini`.

- [ ] **Step 2: Edit `alembic.ini`** — set `sqlalchemy.url` to a placeholder (env will override):

Find the `sqlalchemy.url` line and set it to:
```
sqlalchemy.url = driver://user:pass@host/dbname
```
(value is overridden by `env.py`).

- [ ] **Step 3: Replace `alembic/env.py`**

```python
import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from threat_intel.core.config import get_settings
from threat_intel.models.base import Base
import threat_intel.models.source  # noqa: F401
import threat_intel.models.threat  # noqa: F401
import threat_intel.models.cve  # noqa: F401
import threat_intel.models.cwe  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
```

- [ ] **Step 4: Generate the initial migration**

Set a temporary local DATABASE_URL for the autogenerate step:
```bash
DATABASE_URL=sqlite+aiosqlite:///./_alembic_tmp.db alembic revision --autogenerate -m "initial schema"
```
Expected: a file `alembic/versions/<rev>_initial_schema.py` is generated. Rename it to `0001_initial.py` for clarity:
```bash
mv alembic/versions/*_initial_schema.py alembic/versions/0001_initial.py
rm -f _alembic_tmp.db
```

- [ ] **Step 5: Apply the migration to the temp DB to verify it runs**

```bash
DATABASE_URL=sqlite+aiosqlite:///./_alembic_tmp.db alembic upgrade head
DATABASE_URL=sqlite+aiosqlite:///./_alembic_tmp.db alembic downgrade base
rm -f _alembic_tmp.db
```
Expected: both succeed, no error.

- [ ] **Step 6: Commit**

```bash
git add alembic.ini alembic/
git commit -m "feat(db): alembic async config + initial migration"
```

---

## Task 9: Pydantic schemas

**Files:**
- Create: `src/threat_intel/schemas/__init__.py`, `src/threat_intel/schemas/threat.py`, `src/threat_intel/schemas/cve.py`, `src/threat_intel/schemas/health.py`
- Test: `tests/unit/test_schemas.py`

- [ ] **Step 1: Create `schemas/__init__.py`**

```bash
touch src/threat_intel/schemas/__init__.py
```

- [ ] **Step 2: Write the failing test**

`tests/unit/test_schemas.py`:

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from threat_intel.schemas.cve import ThreatDetail
from threat_intel.schemas.health import CollectorHealth, HealthResponse, Stats
from threat_intel.schemas.threat import ThreatFilters, ThreatRead


def test_threat_filters_rejects_limit_too_large():
    with pytest.raises(ValidationError):
        ThreatFilters(limit=500)


def test_threat_filters_defaults():
    f = ThreatFilters()
    assert f.limit == 50
    assert f.offset == 0
    assert f.severity == []


def test_threat_read_excludes_raw_data_attribute():
    fields = ThreatRead.model_fields
    assert "raw_data" not in fields


def test_threat_detail_includes_raw_data_attribute():
    fields = ThreatDetail.model_fields
    assert "raw_data" in fields


def test_health_response_shape():
    hr = HealthResponse(
        status="ok",
        version="0.1.0",
        uptime_seconds=10,
        database="connected",
        collectors={
            "nvd": CollectorHealth(
                last_run=datetime.now(timezone.utc),
                last_success=True,
                threats_collected_24h=5,
            )
        },
        stats=Stats(total_threats=100, threats_last_24h=5),
    )
    assert hr.status == "ok"
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/unit/test_schemas.py -v
```
Expected: FAIL.

- [ ] **Step 4: Write `schemas/threat.py`**

```python
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from threat_intel.models.base import Severity


class ThreatBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    external_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    affected_products: list[str]
    references: list[str]
    published_at: datetime
    last_modified_at: datetime


class ThreatRead(ThreatBase):
    """List representation. Excludes raw_data."""


class ThreatList(BaseModel):
    items: list[ThreatRead]
    total: int
    limit: int
    offset: int


class ThreatFilters(BaseModel):
    severity: list[Severity] = Field(default_factory=list)
    since: datetime | None = None
    source: str | None = None
    limit: Annotated[int, Field(ge=1, le=200)] = 50
    offset: Annotated[int, Field(ge=0)] = 0
```

- [ ] **Step 5: Write `schemas/cve.py`**

```python
from typing import Any

from threat_intel.schemas.threat import ThreatBase


class ThreatDetail(ThreatBase):
    """Detail view returned by /api/v1/cve/{cve_id}. Includes raw_data."""
    raw_data: dict[str, Any]
    cwe_ids: list[str] = []
```

- [ ] **Step 6: Write `schemas/health.py`**

```python
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class CollectorHealth(BaseModel):
    last_run: datetime | None
    last_success: bool
    threats_collected_24h: int


class Stats(BaseModel):
    total_threats: int
    threats_last_24h: int


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    uptime_seconds: int
    database: Literal["connected", "disconnected"]
    collectors: dict[str, CollectorHealth]
    stats: Stats
```

- [ ] **Step 7: Run test to verify it passes**

```bash
pytest tests/unit/test_schemas.py -v
```
Expected: 5 passed.

- [ ] **Step 8: Commit**

```bash
git add src/threat_intel/schemas/ tests/unit/test_schemas.py
git commit -m "feat(schemas): ThreatRead/Detail/List/Filters + HealthResponse"
```

---

## Task 10: `BaseCollector` interface

**Files:**
- Create: `src/threat_intel/collectors/__init__.py`, `src/threat_intel/collectors/base.py`
- Test: `tests/unit/test_base_collector.py`

- [ ] **Step 1: Create `collectors/__init__.py`**

```bash
touch src/threat_intel/collectors/__init__.py
```

- [ ] **Step 2: Write the failing test**

`tests/unit/test_base_collector.py`:

```python
import inspect
from collections.abc import AsyncIterator

from threat_intel.collectors.base import BaseCollector, RawEvent, ThreatDraft


def test_raw_event_is_immutable():
    e = RawEvent(external_id="x", payload={}, fetched_at=None)  # type: ignore[arg-type]
    import dataclasses
    assert dataclasses.is_dataclass(e)
    fields = {f.name for f in dataclasses.fields(e)}
    assert fields == {"external_id", "payload", "fetched_at"}


def test_threat_draft_validates_required_fields():
    from datetime import datetime, timezone
    from threat_intel.models.base import Severity

    now = datetime.now(timezone.utc)
    d = ThreatDraft(
        source_name="nvd",
        external_id="CVE-2026-1",
        title="t",
        description="d",
        severity=Severity.high,
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        cwe_ids=[],
        affected_products=[],
        references=[],
        published_at=now,
        last_modified_at=now,
        raw_data={},
    )
    assert d.source_name == "nvd"


def test_base_collector_is_abstract():
    assert inspect.isabstract(BaseCollector)
    assert "fetch" in BaseCollector.__abstractmethods__
    assert "normalize" in BaseCollector.__abstractmethods__
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/unit/test_base_collector.py -v
```
Expected: FAIL.

- [ ] **Step 4: Write `collectors/base.py`**

```python
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel

from threat_intel.core.config import Settings
from threat_intel.models.base import Severity, SourceKind


@dataclass(frozen=True)
class RawEvent:
    external_id: str
    payload: dict[str, Any]
    fetched_at: datetime


class ThreatDraft(BaseModel):
    source_name: str
    external_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    cwe_ids: list[str]
    affected_products: list[str]
    references: list[str]
    published_at: datetime
    last_modified_at: datetime
    raw_data: dict[str, Any]


class BaseCollector(ABC):
    source_name: ClassVar[str]
    source_kind: ClassVar[SourceKind]

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None:
        self.http = http_client
        self.settings = settings

    @abstractmethod
    def fetch(self, since: datetime) -> AsyncIterator[RawEvent]: ...

    @abstractmethod
    def normalize(self, raw: RawEvent) -> ThreatDraft: ...
```

- [ ] **Step 5: Run test to verify it passes**

```bash
pytest tests/unit/test_base_collector.py -v
```
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/collectors/__init__.py src/threat_intel/collectors/base.py \
        tests/unit/test_base_collector.py
git commit -m "feat(collectors): BaseCollector ABC, RawEvent, ThreatDraft"
```

---

## Task 11: NVD payload fixture

**Files:**
- Create: `tests/fixtures/nvd_sample.json`

- [ ] **Step 1: Save a representative NVD 2.0 payload**

`tests/fixtures/nvd_sample.json`:

```json
{
  "resultsPerPage": 2,
  "startIndex": 0,
  "totalResults": 2,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-04-26T00:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-0001",
        "published": "2026-04-26T08:00:00.000",
        "lastModified": "2026-04-26T09:30:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
          { "lang": "en", "value": "Remote code execution in ExampleProduct via crafted input." },
          { "lang": "es", "value": "Ejecución remota de código." }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
              }
            }
          ]
        },
        "weaknesses": [
          { "source": "nvd@nist.gov", "type": "Primary",
            "description": [ { "lang": "en", "value": "CWE-79" } ] }
        ],
        "configurations": [
          { "nodes": [
            { "operator": "OR", "negate": false,
              "cpeMatch": [
                { "vulnerable": true, "criteria": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*" }
              ] }
          ] }
        ],
        "references": [
          { "url": "https://example.test/advisory/1", "source": "nvd@nist.gov" }
        ]
      }
    },
    {
      "cve": {
        "id": "CVE-2026-0002",
        "published": "2026-04-26T07:00:00.000",
        "lastModified": "2026-04-26T07:00:00.000",
        "vulnStatus": "Awaiting Analysis",
        "descriptions": [
          { "lang": "en", "value": "Information disclosure in OtherProduct." }
        ],
        "metrics": {},
        "weaknesses": [],
        "configurations": [],
        "references": []
      }
    }
  ]
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/fixtures/nvd_sample.json
git commit -m "test: add NVD 2.0 sample payload fixture"
```

---

## Task 12: `NVDCollector.normalize()`

**Files:**
- Create: `src/threat_intel/collectors/nvd.py`
- Test: `tests/unit/test_nvd_collector.py` (normalize cases only here; fetch tests in Task 13)

- [ ] **Step 1: Write the failing test**

`tests/unit/test_nvd_collector.py`:

```python
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from threat_intel.collectors.base import RawEvent
from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings
from threat_intel.models.base import Severity

FIXTURE = json.loads(Path("tests/fixtures/nvd_sample.json").read_text())


def _make_collector() -> NVDCollector:
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    return NVDCollector(http_client=httpx.AsyncClient(), settings=settings)


def test_normalize_full_record():
    item = FIXTURE["vulnerabilities"][0]
    raw = RawEvent(
        external_id=item["cve"]["id"],
        payload=item,
        fetched_at=datetime.now(timezone.utc),
    )
    draft = _make_collector().normalize(raw)

    assert draft.source_name == "nvd"
    assert draft.external_id == "CVE-2026-0001"
    assert draft.severity is Severity.critical
    assert draft.cvss_score == 9.8
    assert draft.cvss_version == "3.1"
    assert draft.cvss_vector.startswith("CVSS:3.1/")
    assert draft.cwe_ids == ["CWE-79"]
    assert draft.affected_products == ["cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"]
    assert draft.references == ["https://example.test/advisory/1"]
    assert draft.published_at.tzinfo is not None
    assert draft.title.startswith("Remote code execution")


def test_normalize_minimal_record_falls_back_to_unknown():
    item = FIXTURE["vulnerabilities"][1]
    raw = RawEvent(
        external_id=item["cve"]["id"],
        payload=item,
        fetched_at=datetime.now(timezone.utc),
    )
    draft = _make_collector().normalize(raw)

    assert draft.severity is Severity.unknown
    assert draft.cvss_score is None
    assert draft.cwe_ids == []
    assert draft.affected_products == []
    assert draft.references == []


def test_normalize_picks_english_description():
    item = FIXTURE["vulnerabilities"][0]
    raw = RawEvent(external_id=item["cve"]["id"], payload=item, fetched_at=datetime.now(timezone.utc))
    draft = _make_collector().normalize(raw)
    assert "código" not in draft.description.lower()
    assert "ExampleProduct" in draft.description
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_nvd_collector.py -v
```
Expected: FAIL — module missing.

- [ ] **Step 3: Write `collectors/nvd.py` (normalize portion)**

```python
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any, ClassVar

import httpx

from threat_intel.collectors.base import BaseCollector, RawEvent, ThreatDraft
from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorParseError
from threat_intel.models.base import Severity, SourceKind

_SEVERITY_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "NONE": Severity.none,
}


def _parse_dt(value: str) -> datetime:
    # NVD timestamps look like "2026-04-26T08:00:00.000" — naive, UTC by spec.
    if value.endswith("Z"):
        value = value[:-1]
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class NVDCollector(BaseCollector):
    source_name: ClassVar[str] = "nvd"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed

    def normalize(self, raw: RawEvent) -> ThreatDraft:
        try:
            cve = raw.payload["cve"]
            cve_id: str = cve["id"]
            descriptions = cve.get("descriptions") or []
            en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            description = en or (descriptions[0]["value"] if descriptions else "")
            title = description[:150] if description else cve_id

            metrics = cve.get("metrics") or {}
            cvss_score: float | None = None
            cvss_vector: str | None = None
            cvss_version: str | None = None
            severity = Severity.unknown

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                items = metrics.get(key) or []
                if items:
                    data = items[0].get("cvssData", {})
                    cvss_score = data.get("baseScore")
                    cvss_vector = data.get("vectorString")
                    cvss_version = data.get("version")
                    sev_label = (
                        items[0].get("baseSeverity") or data.get("baseSeverity") or ""
                    ).upper()
                    severity = _SEVERITY_MAP.get(sev_label, Severity.unknown)
                    break

            cwe_ids: list[str] = []
            for w in cve.get("weaknesses") or []:
                for d in w.get("description") or []:
                    val = d.get("value", "")
                    if val.startswith("CWE-") and val not in cwe_ids:
                        cwe_ids.append(val)

            products: list[str] = []
            for cfg in cve.get("configurations") or []:
                for node in cfg.get("nodes") or []:
                    for match in node.get("cpeMatch") or []:
                        c = match.get("criteria")
                        if c and c not in products:
                            products.append(c)

            refs = [r["url"] for r in (cve.get("references") or []) if r.get("url")]

            return ThreatDraft(
                source_name=self.source_name,
                external_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                cwe_ids=cwe_ids,
                affected_products=products,
                references=refs,
                published_at=_parse_dt(cve["published"]),
                last_modified_at=_parse_dt(cve["lastModified"]),
                raw_data=raw.payload,
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"NVD payload malformed for {raw.external_id}: {e}") from e

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:  # implemented in next task
        raise NotImplementedError
        yield  # pragma: no cover
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_nvd_collector.py -v
```
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/collectors/nvd.py tests/unit/test_nvd_collector.py
git commit -m "feat(collectors): NVDCollector.normalize() with CVSS/CWE/CPE extraction"
```

---

## Task 13: `NVDCollector.fetch()` with retries and pagination

**Files:**
- Modify: `src/threat_intel/collectors/nvd.py` (replace `fetch` body)
- Modify: `tests/unit/test_nvd_collector.py` (add fetch tests)

- [ ] **Step 1: Add failing tests for `fetch()`**

Append to `tests/unit/test_nvd_collector.py`:

```python
from datetime import timedelta
import respx


@pytest.mark.asyncio
async def test_fetch_yields_normalized_events():
    payload = FIXTURE
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]

    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            mock.get("/cves/2.0").mock(return_value=httpx.Response(200, json=payload))
            collector = NVDCollector(http_client=client, settings=settings)
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            events = [e async for e in collector.fetch(since)]
    assert [e.external_id for e in events] == ["CVE-2026-0001", "CVE-2026-0002"]


@pytest.mark.asyncio
async def test_fetch_retries_on_429_then_succeeds():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            route = mock.get("/cves/2.0")
            route.side_effect = [
                httpx.Response(429),
                httpx.Response(200, json=FIXTURE),
            ]
            collector = NVDCollector(http_client=client, settings=settings)
            events = [e async for e in collector.fetch(datetime.now(timezone.utc))]
    assert len(events) == 2
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_fetch_raises_on_persistent_5xx():
    from threat_intel.core.exceptions import CollectorHTTPError

    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            mock.get("/cves/2.0").mock(return_value=httpx.Response(500))
            collector = NVDCollector(http_client=client, settings=settings)
            with pytest.raises(CollectorHTTPError):
                async for _ in collector.fetch(datetime.now(timezone.utc)):
                    pass


@pytest.mark.asyncio
async def test_fetch_paginates_until_total_reached():
    page1 = {**FIXTURE, "totalResults": 3, "resultsPerPage": 2, "startIndex": 0}
    extra_cve = {
        "cve": {
            "id": "CVE-2026-0003",
            "published": "2026-04-26T06:00:00.000",
            "lastModified": "2026-04-26T06:00:00.000",
            "descriptions": [{"lang": "en", "value": "third"}],
            "metrics": {}, "weaknesses": [], "configurations": [], "references": [],
        }
    }
    page2 = {
        "totalResults": 3, "resultsPerPage": 2, "startIndex": 2,
        "vulnerabilities": [extra_cve],
    }
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        nvd_base_url="https://nvd.test/cves/2.0",
    )  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://nvd.test") as mock:
            route = mock.get("/cves/2.0")
            route.side_effect = [
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
            collector = NVDCollector(http_client=client, settings=settings)
            ids = [e.external_id async for e in collector.fetch(datetime.now(timezone.utc))]
    assert ids == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_nvd_collector.py -v
```
Expected: 4 new tests fail (NotImplementedError or similar).

- [ ] **Step 3: Replace `fetch()` in `collectors/nvd.py`**

In `src/threat_intel/collectors/nvd.py`, add at module top:

```python
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
```

Replace the placeholder `fetch` method with:

```python
    _PAGE_SIZE: ClassVar[int] = 2000
    _RETRY_STATUSES: ClassVar[tuple[int, ...]] = (429, 500, 502, 503, 504)

    async def _request_page(self, params: dict[str, Any]) -> dict[str, Any]:
        url = self.settings.nvd_base_url
        headers: dict[str, str] = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(4),
            wait=wait_exponential(multiplier=1, min=1, max=4),
            retry=retry_if_exception_type((httpx.TransportError, _RetryableHTTPError)),
            reraise=True,
        ):
            with attempt:
                resp = await self.http.get(url, params=params, headers=headers, timeout=30.0)
                if resp.status_code in self._RETRY_STATUSES:
                    raise _RetryableHTTPError(resp.status_code, str(resp.url))
                if resp.status_code >= 400:
                    raise CollectorHTTPError(
                        status_code=resp.status_code,
                        url=str(resp.url),
                        message=resp.text[:200],
                    )
                return resp.json()
        raise CollectorHTTPError(status_code=0, url=url, message="retry loop exhausted")

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:
        start_index = 0
        while True:
            params: dict[str, Any] = {
                "lastModStartDate": since.isoformat(),
                "lastModEndDate": datetime.now(timezone.utc).isoformat(),
                "resultsPerPage": self._PAGE_SIZE,
                "startIndex": start_index,
            }
            page = await self._request_page(params)
            for item in page.get("vulnerabilities") or []:
                cve_id = item.get("cve", {}).get("id", "")
                yield RawEvent(
                    external_id=cve_id,
                    payload=item,
                    fetched_at=datetime.now(timezone.utc),
                )
            total = int(page.get("totalResults", 0))
            start_index += int(page.get("resultsPerPage", self._PAGE_SIZE))
            if start_index >= total:
                break
```

Add this internal exception at the top of the file (after imports):

```python
class _RetryableHTTPError(Exception):
    def __init__(self, status_code: int, url: str) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"retryable HTTP {status_code} on {url}")
```

Also add `CollectorHTTPError` to the imports from `threat_intel.core.exceptions`:

```python
from threat_intel.core.exceptions import CollectorHTTPError, CollectorParseError
```

- [ ] **Step 4: Run all NVD collector tests**

```bash
pytest tests/unit/test_nvd_collector.py -v
```
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/collectors/nvd.py tests/unit/test_nvd_collector.py
git commit -m "feat(collectors): NVDCollector.fetch with retry + pagination"
```

---

## Task 14: Dedup / upsert analyzer

**Files:**
- Create: `src/threat_intel/analyzers/__init__.py`, `src/threat_intel/analyzers/dedup.py`
- Test: `tests/unit/test_dedup.py`

- [ ] **Step 1: Create package init**

```bash
touch src/threat_intel/analyzers/__init__.py
```

- [ ] **Step 2: Write the failing test**

`tests/unit/test_dedup.py`:

```python
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
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/unit/test_dedup.py -v
```
Expected: FAIL.

- [ ] **Step 4: Write `analyzers/dedup.py`**

```python
import uuid
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from threat_intel.collectors.base import ThreatDraft
from threat_intel.models.cve import CVE
from threat_intel.models.cwe import CWE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat

UpsertResult = Literal["inserted", "updated", "unchanged"]


async def _get_or_create_cwes(session: AsyncSession, cwe_ids: list[str]) -> list[CWE]:
    if not cwe_ids:
        return []
    existing = (
        await session.execute(select(CWE).where(CWE.id.in_(cwe_ids)))
    ).scalars().all()
    found = {c.id for c in existing}
    new_rows = [CWE(id=cid) for cid in cwe_ids if cid not in found]
    for row in new_rows:
        session.add(row)
    if new_rows:
        await session.flush()
    return [*existing, *new_rows]


async def upsert_threat(
    session: AsyncSession, source: Source, draft: ThreatDraft
) -> UpsertResult:
    """Insert or update a Threat row keyed by (source_id, external_id).

    Returns one of "inserted", "updated", or "unchanged".
    """
    stmt = (
        select(Threat)
        .options(selectinload(Threat.cwes))
        .where(Threat.source_id == source.id, Threat.external_id == draft.external_id)
    )
    existing = (await session.execute(stmt)).scalar_one_or_none()

    cwes = await _get_or_create_cwes(session, draft.cwe_ids)

    if existing is None:
        threat = Threat(
            id=uuid.uuid4(),
            source_id=source.id,
            external_id=draft.external_id,
            title=draft.title,
            description=draft.description,
            severity=draft.severity,
            cvss_score=draft.cvss_score,
            cvss_vector=draft.cvss_vector,
            cvss_version=draft.cvss_version,
            affected_products=draft.affected_products,
            references=draft.references,
            published_at=draft.published_at,
            last_modified_at=draft.last_modified_at,
            raw_data=draft.raw_data,
            cwes=cwes,
        )
        session.add(threat)
        await session.flush()
        session.add(CVE(cve_id=draft.external_id, threat_id=threat.id))
        return "inserted"

    if existing.last_modified_at == draft.last_modified_at:
        return "unchanged"

    existing.title = draft.title
    existing.description = draft.description
    existing.severity = draft.severity
    existing.cvss_score = draft.cvss_score
    existing.cvss_vector = draft.cvss_vector
    existing.cvss_version = draft.cvss_version
    existing.affected_products = draft.affected_products
    existing.references = draft.references
    existing.published_at = draft.published_at
    existing.last_modified_at = draft.last_modified_at
    existing.raw_data = draft.raw_data
    existing.cwes = cwes
    return "updated"
```

- [ ] **Step 5: Run test to verify it passes**

```bash
pytest tests/unit/test_dedup.py -v
```
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/analyzers/__init__.py src/threat_intel/analyzers/dedup.py \
        tests/unit/test_dedup.py
git commit -m "feat(analyzers): upsert_threat with insert/update/unchanged result"
```

---

## Task 15: `IngestionService`

**Files:**
- Create: `src/threat_intel/services/__init__.py`, `src/threat_intel/services/ingestion.py`
- Test: `tests/unit/test_ingestion.py`

- [ ] **Step 1: Create package init**

```bash
touch src/threat_intel/services/__init__.py
```

- [ ] **Step 2: Write the failing test**

`tests/unit/test_ingestion.py`:

```python
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import func, select

from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings
from threat_intel.core.db import build_engine, session_factory
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
        with pytest.raises(Exception):
            await service.run("nvd")

    async with factory() as s:
        src = (await s.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
        assert src.last_error is not None
        assert src.last_success_at is None

    await engine.dispose()
```

- [ ] **Step 3: Run test to verify it fails**

```bash
pytest tests/unit/test_ingestion.py -v
```
Expected: FAIL.

- [ ] **Step 4: Write `services/ingestion.py`**

```python
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.analyzers.dedup import upsert_threat
from threat_intel.collectors.base import BaseCollector
from threat_intel.core.exceptions import ConfigurationError
from threat_intel.models.source import Source

logger = structlog.get_logger(__name__)


@dataclass
class IngestionResult:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0


class IngestionService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        collectors: list[BaseCollector],
        batch_size: int = 100,
    ) -> None:
        self._sf = session_factory
        self._collectors = {c.source_name: c for c in collectors}
        self._batch_size = batch_size

    async def run(self, source_name: str) -> IngestionResult:
        collector = self._collectors.get(source_name)
        if collector is None:
            raise ConfigurationError(f"No collector registered for source '{source_name}'")

        log = logger.bind(source=source_name)

        async with self._sf() as session:
            src = (
                await session.execute(select(Source).where(Source.name == source_name))
            ).scalar_one_or_none()
            if src is None:
                raise ConfigurationError(f"Source row missing in DB: {source_name}")
            since = src.last_success_at or datetime.now(timezone.utc) - timedelta(hours=24)

        log.info("ingestion.start", since=since.isoformat())

        result = IngestionResult()
        try:
            async with self._sf() as session:
                src = (
                    await session.execute(select(Source).where(Source.name == source_name))
                ).scalar_one()
                src.last_run_at = datetime.now(timezone.utc)
                await session.commit()

                count = 0
                async for raw in collector.fetch(since):
                    draft = collector.normalize(raw)
                    outcome = await upsert_threat(session, src, draft)
                    if outcome == "inserted":
                        result.inserted += 1
                    elif outcome == "updated":
                        result.updated += 1
                    else:
                        result.unchanged += 1
                    count += 1
                    if count % self._batch_size == 0:
                        await session.commit()
                await session.commit()

                src.last_success_at = datetime.now(timezone.utc)
                src.last_error = None
                await session.commit()
            log.info(
                "ingestion.done",
                inserted=result.inserted,
                updated=result.updated,
                unchanged=result.unchanged,
            )
            return result
        except Exception as e:
            log.exception("ingestion.failed", error=str(e))
            async with self._sf() as session:
                src = (
                    await session.execute(select(Source).where(Source.name == source_name))
                ).scalar_one()
                src.last_error = f"{type(e).__name__}: {e}"[:1000]
                await session.commit()
            raise
```

- [ ] **Step 5: Run test to verify it passes**

```bash
pytest tests/unit/test_ingestion.py -v
```
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/services/__init__.py src/threat_intel/services/ingestion.py \
        tests/unit/test_ingestion.py
git commit -m "feat(services): IngestionService orchestrates fetch → normalize → upsert"
```

---

## Task 16: `ThreatService` (query/filter)

**Files:**
- Create: `src/threat_intel/services/threats.py`
- Test: extended in integration tests later (no separate unit test — covered by `tests/integration/test_threats.py`)

- [ ] **Step 1: Write `services/threats.py`**

```python
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.models.base import Severity
from threat_intel.models.cve import CVE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat


@dataclass
class ThreatPage:
    items: list[Threat]
    total: int
    limit: int
    offset: int


async def list_threats(
    session: AsyncSession,
    *,
    severity: list[Severity] | None = None,
    since: datetime | None = None,
    source: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> ThreatPage:
    base = select(Threat)
    count_base = select(func.count(Threat.id))

    conditions: list[Any] = []
    if severity:
        conditions.append(Threat.severity.in_(severity))
    if since:
        conditions.append(Threat.published_at >= since)
    if source:
        base = base.join(Source, Threat.source_id == Source.id)
        count_base = count_base.join(Source, Threat.source_id == Source.id)
        conditions.append(Source.name == source)

    if conditions:
        base = base.where(*conditions)
        count_base = count_base.where(*conditions)

    total = (await session.execute(count_base)).scalar_one()
    rows = (
        await session.execute(
            base.order_by(Threat.published_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return ThreatPage(items=list(rows), total=total, limit=limit, offset=offset)


async def get_threat_by_cve(session: AsyncSession, cve_id: str) -> Threat | None:
    row = (
        await session.execute(select(CVE).where(CVE.cve_id == cve_id))
    ).scalar_one_or_none()
    return row.threat if row else None


async def collector_health(
    session: AsyncSession, source_name: str
) -> tuple[Source | None, int]:
    src = (
        await session.execute(select(Source).where(Source.name == source_name))
    ).scalar_one_or_none()
    if src is None:
        return None, 0
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    count = (
        await session.execute(
            select(func.count(Threat.id)).where(
                Threat.source_id == src.id, Threat.created_at >= yesterday
            )
        )
    ).scalar_one()
    return src, int(count)


async def stats(session: AsyncSession) -> tuple[int, int]:
    yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
    total = (await session.execute(select(func.count(Threat.id)))).scalar_one()
    last_24h = (
        await session.execute(
            select(func.count(Threat.id)).where(Threat.created_at >= yesterday)
        )
    ).scalar_one()
    return int(total), int(last_24h)
```

- [ ] **Step 2: Verify it imports cleanly**

```bash
python -c "from threat_intel.services.threats import list_threats, get_threat_by_cve, collector_health, stats; print('ok')"
```
Expected: prints `ok`.

- [ ] **Step 3: Commit**

```bash
git add src/threat_intel/services/threats.py
git commit -m "feat(services): list_threats / get_threat_by_cve / health helpers"
```

---

## Task 17: API dependencies and exception handlers

**Files:**
- Create: `src/threat_intel/api/__init__.py`, `src/threat_intel/api/deps.py`

- [ ] **Step 1: Create `api/__init__.py`**

```bash
touch src/threat_intel/api/__init__.py
```

- [ ] **Step 2: Write `api/deps.py`**

```python
from collections.abc import AsyncIterator

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.core.config import Settings


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def get_session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory  # type: ignore[no-any-return]


async def get_db(
    factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> AsyncIterator[AsyncSession]:
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
```

- [ ] **Step 3: Commit**

```bash
git add src/threat_intel/api/__init__.py src/threat_intel/api/deps.py
git commit -m "feat(api): shared FastAPI dependencies (settings, db session)"
```

---

## Task 18: `/health` endpoint

**Files:**
- Create: `src/threat_intel/api/health.py`
- Test: deferred to Task 22 (full app required for end-to-end test)

- [ ] **Step 1: Write `api/health.py`**

```python
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel import __version__
from threat_intel.api.deps import get_db
from threat_intel.schemas.health import CollectorHealth, HealthResponse, Stats
from threat_intel.services.threats import collector_health, stats

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request, session: AsyncSession = Depends(get_db)) -> HealthResponse:
    start_time: datetime = request.app.state.start_time
    uptime = int((datetime.now(timezone.utc) - start_time).total_seconds())

    db_status = "connected"
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    collectors_state: dict[str, CollectorHealth] = {}
    overall_status: str = "ok"

    for source_name in request.app.state.collector_names:
        src, count_24h = await collector_health(session, source_name)
        if src is None:
            continue
        collectors_state[source_name] = CollectorHealth(
            last_run=src.last_run_at,
            last_success=src.last_error is None and src.last_success_at is not None,
            threats_collected_24h=count_24h,
        )

    if db_status != "connected":
        overall_status = "degraded"

    total, last_24h = (0, 0) if db_status != "connected" else await stats(session)

    return HealthResponse(
        status="ok" if overall_status == "ok" else "degraded",
        version=__version__,
        uptime_seconds=uptime,
        database=db_status,
        collectors=collectors_state,
        stats=Stats(total_threats=total, threats_last_24h=last_24h),
    )
```

- [ ] **Step 2: Commit**

```bash
git add src/threat_intel/api/health.py
git commit -m "feat(api): GET /health (db, collectors, stats)"
```

---

## Task 19: `/api/v1/threats` endpoint

**Files:**
- Create: `src/threat_intel/api/v1/__init__.py`, `src/threat_intel/api/v1/threats.py`

- [ ] **Step 1: Write `api/v1/threats.py`**

```python
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.models.base import Severity
from threat_intel.schemas.threat import ThreatList, ThreatRead
from threat_intel.services.threats import list_threats

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=ThreatList)
async def get_threats(
    session: Annotated[AsyncSession, Depends(get_db)],
    severity: Annotated[list[Severity] | None, Query()] = None,
    since: datetime | None = None,
    source: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ThreatList:
    page = await list_threats(
        session,
        severity=severity or None,
        since=since,
        source=source,
        limit=limit,
        offset=offset,
    )
    return ThreatList(
        items=[ThreatRead.model_validate(t) for t in page.items],
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )
```

- [ ] **Step 2: Write `api/v1/__init__.py`**

```python
from fastapi import APIRouter

from threat_intel.api.v1 import threats

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(threats.router)
```

- [ ] **Step 3: Commit**

```bash
git add src/threat_intel/api/v1/__init__.py src/threat_intel/api/v1/threats.py
git commit -m "feat(api): GET /api/v1/threats with filters and pagination"
```

---

## Task 20: `/api/v1/cve/{cve_id}` endpoint

**Files:**
- Create: `src/threat_intel/api/v1/cve.py`
- Modify: `src/threat_intel/api/v1/__init__.py`

- [ ] **Step 1: Write `api/v1/cve.py`**

```python
from typing import Annotated

from fastapi import APIRouter, Depends, Path
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.core.exceptions import ThreatNotFoundException
from threat_intel.schemas.cve import ThreatDetail
from threat_intel.services.threats import get_threat_by_cve

router = APIRouter(prefix="/cve", tags=["cve"])

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"


@router.get("/{cve_id}", response_model=ThreatDetail)
async def get_cve(
    session: Annotated[AsyncSession, Depends(get_db)],
    cve_id: Annotated[str, Path(pattern=CVE_PATTERN)],
) -> ThreatDetail:
    threat = await get_threat_by_cve(session, cve_id)
    if threat is None:
        raise ThreatNotFoundException(cve_id=cve_id)
    detail = ThreatDetail.model_validate(threat)
    detail.cwe_ids = [c.id for c in threat.cwes]
    return detail
```

- [ ] **Step 2: Update `api/v1/__init__.py` to include the cve router**

Replace its contents with:

```python
from fastapi import APIRouter

from threat_intel.api.v1 import cve, threats

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(threats.router)
api_v1.include_router(cve.router)
```

- [ ] **Step 3: Commit**

```bash
git add src/threat_intel/api/v1/cve.py src/threat_intel/api/v1/__init__.py
git commit -m "feat(api): GET /api/v1/cve/{cve_id} with 404 handling"
```

---

## Task 21: `main.py`, lifespan, exception handlers, CORS, scheduler

**Files:**
- Create: `src/threat_intel/main.py`, `src/threat_intel/core/scheduler.py`

- [ ] **Step 1: Write `core/scheduler.py`**

```python
from collections.abc import Awaitable, Callable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from threat_intel.core.config import Settings

logger = structlog.get_logger(__name__)


def build_scheduler(
    settings: Settings,
    nvd_runner: Callable[[], Awaitable[None]],
) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        nvd_runner,
        trigger=IntervalTrigger(minutes=settings.nvd_fetch_interval_minutes),
        id="ingest_nvd",
        name="NVD ingestion",
        max_instances=1,
        coalesce=True,
    )
    return scheduler
```

- [ ] **Step 2: Write `main.py`**

```python
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.status import HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR

from threat_intel.api.health import router as health_router
from threat_intel.api.v1 import api_v1
from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings, get_settings
from threat_intel.core.db import build_engine, session_factory
from threat_intel.core.exceptions import (
    CollectorError,
    ConfigurationError,
    PersistenceError,
    ThreatIntelException,
    ThreatNotFoundException,
)
from threat_intel.core.logging import configure_logging
from threat_intel.core.scheduler import build_scheduler
from threat_intel.models.base import SourceKind
from threat_intel.models.source import Source
from threat_intel.services.ingestion import IngestionService

logger = structlog.get_logger(__name__)


def _problem(status: int, title: str, detail: str, type_: str = "about:blank") -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"type": type_, "title": title, "status": status, "detail": detail},
        media_type="application/problem+json",
    )


async def _ensure_source_row(factory, name: str, kind: SourceKind, url: str) -> None:  # type: ignore[no-untyped-def]
    async with factory() as s:
        existing = (
            await s.execute(select(Source).where(Source.name == name))
        ).scalar_one_or_none()
        if existing is None:
            s.add(Source(name=name, kind=kind, url=url, enabled=True))
            await s.commit()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(env=settings.app_env, level=settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        engine = build_engine(settings.database_url)
        factory = session_factory(engine)
        http = httpx.AsyncClient(timeout=30.0)
        nvd = NVDCollector(http_client=http, settings=settings)
        ingestion = IngestionService(session_factory=factory, collectors=[nvd])

        await _ensure_source_row(factory, "nvd", SourceKind.cve_feed, settings.nvd_base_url)

        async def run_nvd() -> None:
            try:
                await ingestion.run("nvd")
            except Exception:  # noqa: BLE001
                logger.exception("scheduled_nvd_run_failed")

        scheduler = build_scheduler(settings, run_nvd)
        scheduler.start()

        app.state.settings = settings
        app.state.session_factory = factory
        app.state.ingestion = ingestion
        app.state.collector_names = ["nvd"]
        app.state.start_time = datetime.now(timezone.utc)

        try:
            yield
        finally:
            scheduler.shutdown(wait=False)
            await http.aclose()
            await engine.dispose()

    app = FastAPI(
        title="CyberThreat Intelligence API",
        version="0.1.0",
        lifespan=lifespan,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["*"],
        )

    @app.exception_handler(ThreatNotFoundException)
    async def _not_found(_: Request, exc: ThreatNotFoundException) -> JSONResponse:
        return _problem(HTTP_404_NOT_FOUND, "Threat not found", str(exc))

    @app.exception_handler(ConfigurationError)
    async def _config_err(_: Request, exc: ConfigurationError) -> JSONResponse:
        return _problem(HTTP_500_INTERNAL_SERVER_ERROR, "Configuration error", str(exc))

    @app.exception_handler(CollectorError)
    async def _collector_err(_: Request, exc: CollectorError) -> JSONResponse:
        return _problem(502, "Upstream collector error", str(exc))

    @app.exception_handler(PersistenceError)
    async def _persistence_err(_: Request, exc: PersistenceError) -> JSONResponse:
        return _problem(HTTP_500_INTERNAL_SERVER_ERROR, "Persistence error", str(exc))

    @app.exception_handler(ThreatIntelException)
    async def _generic(_: Request, exc: ThreatIntelException) -> JSONResponse:
        return _problem(HTTP_500_INTERNAL_SERVER_ERROR, "Internal error", str(exc))

    app.include_router(health_router)
    app.include_router(api_v1)

    return app


app = create_app()
```

- [ ] **Step 3: Verify the app boots in offline mode (no DB needed for import)**

```bash
python -c "from threat_intel.main import create_app; print('ok')"
```
Expected: prints `ok`.

- [ ] **Step 4: Commit**

```bash
git add src/threat_intel/main.py src/threat_intel/core/scheduler.py
git commit -m "feat(app): create_app, lifespan, scheduler, CORS, problem+json handlers"
```

---

## Task 22: Test fixtures and integration tests

**Files:**
- Create: `tests/conftest.py`, `tests/integration/test_health.py`, `tests/integration/test_threats.py`, `tests/integration/test_cve.py`

- [ ] **Step 1: Write `tests/conftest.py`**

```python
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import async_sessionmaker

from threat_intel.core.config import Settings
from threat_intel.core.db import build_engine, session_factory
from threat_intel.main import create_app
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.cve import CVE
from threat_intel.models.cwe import CWE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat


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
    now = datetime.now(timezone.utc)
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x", enabled=True,
                     last_run_at=now, last_success_at=now)
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
    # bypass real lifespan: install state directly
    app.state.settings = settings
    app.state.session_factory = factory
    app.state.collector_names = ["nvd"]
    app.state.start_time = datetime.now(timezone.utc)
    return app


@pytest_asyncio.fixture
async def client(app):
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
```

- [ ] **Step 2: Write `tests/integration/test_health.py`**

```python
async def test_health_returns_ok_with_seeded_data(client, seeded_db):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"
    assert body["database"] == "connected"
    assert "nvd" in body["collectors"]
    assert body["collectors"]["nvd"]["last_success"] is True
    assert body["stats"]["total_threats"] == 3


async def test_health_no_collectors_state_when_no_source(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["collectors"] == {}
    assert body["stats"]["total_threats"] == 0
```

- [ ] **Step 3: Write `tests/integration/test_threats.py`**

```python
from datetime import datetime, timedelta, timezone


async def test_list_threats_empty(client):
    resp = await client.get("/api/v1/threats")
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


async def test_list_threats_filter_by_severity(client, seeded_db):
    resp = await client.get("/api/v1/threats?severity=critical")
    body = resp.json()
    assert resp.status_code == 200
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "critical"


async def test_list_threats_filter_since(client, seeded_db):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat()
    resp = await client.get(f"/api/v1/threats?since={cutoff}")
    body = resp.json()
    assert body["total"] == 2  # only the two recent rows


async def test_list_threats_pagination(client, seeded_db):
    resp = await client.get("/api/v1/threats?limit=2&offset=0")
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert body["limit"] == 2


async def test_list_threats_sorted_desc_by_published(client, seeded_db):
    resp = await client.get("/api/v1/threats")
    items = resp.json()["items"]
    pubs = [i["published_at"] for i in items]
    assert pubs == sorted(pubs, reverse=True)


async def test_list_threats_excludes_raw_data(client, seeded_db):
    resp = await client.get("/api/v1/threats?limit=1")
    item = resp.json()["items"][0]
    assert "raw_data" not in item
```

- [ ] **Step 4: Write `tests/integration/test_cve.py`**

```python
async def test_get_cve_returns_detail(client, seeded_db):
    resp = await client.get("/api/v1/cve/CVE-2026-1000")
    assert resp.status_code == 200
    body = resp.json()
    assert body["external_id"] == "CVE-2026-1000"
    assert "raw_data" in body
    assert body["cwe_ids"] == ["CWE-79"]


async def test_get_cve_404_problem_json(client):
    resp = await client.get("/api/v1/cve/CVE-2026-9999")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["title"] == "Threat not found"
    assert body["status"] == 404


async def test_get_cve_invalid_format_returns_422(client):
    resp = await client.get("/api/v1/cve/NOT-A-CVE")
    assert resp.status_code == 422
```

- [ ] **Step 5: Run the full test suite**

```bash
pytest -v
```
Expected: all tests pass (unit + integration).

- [ ] **Step 6: Run lint and types**

```bash
ruff check src tests
mypy src
```
Expected: zero errors.

- [ ] **Step 7: Commit**

```bash
git add tests/conftest.py tests/integration/test_health.py \
        tests/integration/test_threats.py tests/integration/test_cve.py
git commit -m "test(integration): /health, /api/v1/threats, /api/v1/cve end-to-end"
```

---

## Task 23: One-shot CLI for demos

**Files:**
- Create: `src/threat_intel/cli/__init__.py`, `src/threat_intel/cli/collect_once.py`

- [ ] **Step 1: Create CLI package**

```bash
touch src/threat_intel/cli/__init__.py
```

- [ ] **Step 2: Write `cli/collect_once.py`**

```python
import asyncio

import httpx
import typer

from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import get_settings
from threat_intel.core.db import build_engine, session_factory
from threat_intel.core.logging import configure_logging
from threat_intel.models.base import SourceKind
from threat_intel.models.source import Source
from threat_intel.services.ingestion import IngestionService
from sqlalchemy import select

app = typer.Typer(help="One-shot operations for the threat-intel-api.")


@app.command()
def nvd() -> None:
    """Run a single NVD collection cycle synchronously (useful for demos)."""
    settings = get_settings()
    configure_logging(env=settings.app_env, level=settings.log_level)

    async def _run() -> None:
        engine = build_engine(settings.database_url)
        factory = session_factory(engine)
        async with factory() as s:
            existing = (
                await s.execute(select(Source).where(Source.name == "nvd"))
            ).scalar_one_or_none()
            if existing is None:
                s.add(Source(
                    name="nvd",
                    kind=SourceKind.cve_feed,
                    url=settings.nvd_base_url,
                    enabled=True,
                ))
                await s.commit()

        async with httpx.AsyncClient(timeout=30.0) as http:
            collector = NVDCollector(http_client=http, settings=settings)
            service = IngestionService(session_factory=factory, collectors=[collector])
            result = await service.run("nvd")
            typer.echo(
                f"inserted={result.inserted} updated={result.updated} unchanged={result.unchanged}"
            )
        await engine.dispose()

    asyncio.run(_run())


if __name__ == "__main__":
    app()
```

- [ ] **Step 3: Verify CLI imports**

```bash
python -c "from threat_intel.cli.collect_once import app; print('ok')"
```
Expected: prints `ok`.

- [ ] **Step 4: Commit**

```bash
git add src/threat_intel/cli/__init__.py src/threat_intel/cli/collect_once.py
git commit -m "feat(cli): one-shot 'threat-intel nvd' command for demos"
```

---

## Task 24: `Dockerfile` and `docker-compose.yml`

**Files:**
- Create: `Dockerfile`, `docker-compose.yml`

- [ ] **Step 1: Write `Dockerfile`**

```dockerfile
# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY alembic.ini ./
COPY alembic ./alembic

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install -U pip \
 && /opt/venv/bin/pip install .

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
WORKDIR /app

RUN useradd --create-home --uid 1000 app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app
RUN chown -R app:app /app

USER app
EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn threat_intel.main:app --host 0.0.0.0 --port 8000"]
```

- [ ] **Step 2: Write `docker-compose.yml`**

```yaml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: threat
      POSTGRES_PASSWORD: threat
      POSTGRES_DB: threat_intel
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U threat -d threat_intel"]
      interval: 5s
      timeout: 5s
      retries: 5
    ports:
      - "5432:5432"

  app:
    build: .
    depends_on:
      db:
        condition: service_healthy
    env_file: .env
    environment:
      DATABASE_URL: postgresql+asyncpg://threat:threat@db:5432/threat_intel
      APP_ENV: prod
    ports:
      - "8000:8000"
    volumes:
      - ./profiles/public:/app/profiles/public:ro

volumes:
  pgdata:
```

- [ ] **Step 3: Build and smoke-test**

```bash
docker compose build app
docker compose up -d
sleep 10
curl -fsS http://localhost:8000/health | python -m json.tool
docker compose down
```
Expected: build succeeds, `/health` returns JSON with `status: "ok"`.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile docker-compose.yml
git commit -m "feat(deploy): multi-stage Dockerfile + docker-compose (postgres + app)"
```

---

## Task 25: README

**Files:**
- Modify: `README.md` (replace placeholder)

- [ ] **Step 1: Write the README**

Overwrite `README.md`:

````markdown
# CyberThreat Intelligence API

A REST API that aggregates OSINT cyber-threat feeds, deduplicates them, and exposes them via versioned endpoints. Milestone 1 ships a working ingestion pipeline for the NVD CVE feed plus three endpoints (`/health`, `/api/v1/threats`, `/api/v1/cve/{cve_id}`).

## Local install (no Docker)

Requires Python 3.12+.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# Edit .env if needed (defaults work with docker-compose Postgres)

# For local SQLite dev:
echo "DATABASE_URL=sqlite+aiosqlite:///./threat_intel.db" >> .env

alembic upgrade head
uvicorn threat_intel.main:app --reload
```

Open http://localhost:8000/docs for the interactive Swagger UI.

## Run with Docker

```bash
cp .env.example .env
docker compose up --build
```

The `app` service waits for Postgres, runs migrations on startup, then serves uvicorn on port 8000.

```bash
curl localhost:8000/health
```

## Trigger an ingestion run on demand

By default, NVD is polled every 60 minutes by the in-process scheduler. To force a single run (useful in demos and the first time you bring the stack up):

```bash
docker compose exec app python -m threat_intel.cli.collect_once nvd
```

You should see something like `inserted=27 updated=0 unchanged=0`.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | service status, DB state, per-collector last-run, stats |
| GET | `/api/v1/threats` | paginated list, filters: `severity`, `since`, `source`, `limit`, `offset` |
| GET | `/api/v1/cve/{cve_id}` | full detail (incl. `raw_data`) for a CVE |
| GET | `/docs` | Swagger UI |
| GET | `/openapi.json` | machine-readable schema |

Errors are returned as `application/problem+json` (RFC 7807).

## Project layout

```
src/threat_intel/
├── api/                 FastAPI routers (health, v1.threats, v1.cve)
├── collectors/          Source adapters (BaseCollector + NVDCollector)
├── analyzers/           Dedup, scoring (M2)
├── services/            Ingestion + query layer
├── schemas/             Pydantic request/response models
├── models/              SQLAlchemy ORM
├── core/                Config, DB engine, logging, exceptions, scheduler
├── cli/                 Typer commands for ops/demos
└── main.py              create_app() + lifespan
```

Tests live under `tests/unit/` and `tests/integration/`. Migrations are in `alembic/versions/`.

## Adding a new collector

The whole point of `BaseCollector` is that adding a new source costs you a single file plus a registration. Walking through it:

1. **Create the collector** at `src/threat_intel/collectors/<source>.py`. Inherit `BaseCollector`, set `source_name` and `source_kind` class attributes, and implement `fetch(since)` (returns an `AsyncIterator[RawEvent]`) and `normalize(raw)` (returns a `ThreatDraft`).
2. **Map your source's severity / CVSS / IDs** inside `normalize()` to the `ThreatDraft` fields. Anything you don't have, leave as `None` or empty list — the API model already handles missing data.
3. **Register it** in `src/threat_intel/main.py`: instantiate it inside the lifespan and add it to the `IngestionService` collectors list and to `app.state.collector_names`.
4. **Schedule it** in `core/scheduler.py` if you want a periodic job.
5. **Add unit tests** under `tests/unit/test_<source>_collector.py` using `respx` to stub the upstream HTTP calls. Save a representative payload under `tests/fixtures/`.

Dedup, persistence, API exposure, and `/health` reporting all come for free — they key off `source_name` + `external_id`.

## Development

```bash
pytest               # full suite
ruff check src tests # lint
ruff format src tests
mypy src             # static types
```

## Deliberately out of scope for M1

Other collectors (RSS, GitHub Advisories, OTX), NLP entity extraction, alerting webhooks, STIX export, Redis cache, authentication, sectoral scoring. The data model and collector interface are designed so each of those lands without breaking what's here.
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README — install, run, endpoints, adding a collector"
```

---

## Task 26: Final demo verification

- [ ] **Step 1: Bring the stack up clean**

```bash
docker compose down -v
docker compose up --build -d
sleep 15
```

- [ ] **Step 2: Hit `/health` (cold state)**

```bash
curl -fsS http://localhost:8000/health | python -m json.tool
```
Expected: `status: "ok"`, `database: "connected"`, `collectors.nvd.last_run: null`, `stats.total_threats: 0`.

- [ ] **Step 3: Trigger a one-shot collection**

```bash
docker compose exec app python -m threat_intel.cli.collect_once nvd
```
Expected: `inserted=<N>` with N typically 10–80 depending on NVD activity over the past 24h.

- [ ] **Step 4: Verify `/health` updated**

```bash
curl -fsS http://localhost:8000/health | python -m json.tool
```
Expected: `last_run` now populated, `last_success: true`, `threats_collected_24h > 0`.

- [ ] **Step 5: Query the threats endpoint**

```bash
curl -fsS 'http://localhost:8000/api/v1/threats?severity=critical&limit=5' | python -m json.tool
```
Expected: a JSON list of up to 5 critical CVEs.

- [ ] **Step 6: Pick one CVE-ID from the previous response and fetch its detail**

```bash
curl -fsS 'http://localhost:8000/api/v1/cve/<CVE-ID-FROM-PREVIOUS-CALL>' | python -m json.tool
```
Expected: full record including `raw_data`.

- [ ] **Step 7: Verify Swagger renders**

Open http://localhost:8000/docs in a browser. Expect the three endpoints listed.

- [ ] **Step 8: Tear down**

```bash
docker compose down
```

- [ ] **Step 9: Tag the milestone**

```bash
git tag -a v0.1.0 -m "M1: NVD ingestion + 3 endpoints"
```

---

## Self-review notes

- Spec coverage: every section of the design doc maps to at least one task. Sec 1 stack → Task 1; Sec 3 layout → Tasks 1/6/7/9/10/etc.; Sec 4 model → Tasks 6–8; Sec 5 collector ABC → Task 10; Sec 6 NVD → Tasks 11–13; Sec 7 ingestion → Task 15; Sec 8 endpoints → Tasks 18–20; Sec 9 exceptions → Task 4 + handlers in Task 21; Sec 10 tests → Tasks 14/15/22; Sec 11 Docker → Task 24; Sec 12 CORS → Task 21; Sec 13 demo → Task 26; Sec 14 out-of-scope → Tasks 23 (CLI) + README.
- No placeholders. No TBDs.
- Type consistency verified: `IngestionResult.inserted/updated/unchanged`, `upsert_threat → "inserted"|"updated"|"unchanged"`, `ThreatPage.items`, `BaseCollector.fetch / normalize`, `Settings.nvd_base_url / nvd_api_key / nvd_fetch_interval_minutes` — all match across files.
