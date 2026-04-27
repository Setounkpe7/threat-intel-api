# CyberThreat Intelligence API — Milestone 1 Design

**Date:** 2026-04-27
**Status:** approved
**Scope:** Milestone 1 only. Subsequent milestones (additional collectors, NLP, alerting, STIX export, Redis cache, auth) are explicitly out of scope.

---

## 1. Goal

Stand up a Python REST API that ingests CVE data from the NVD feed on a schedule, persists it with deduplication, and exposes three endpoints (`/health`, `/api/v1/threats`, `/api/v1/cve/{cve_id}`). The data model and collector interface are designed so adding RSS/GitHub Advisories/OTX in later milestones requires no schema migration and no refactor of existing code.

## 2. Stack

| Domain | Choice | Version |
|---|---|---|
| Runtime | Python | 3.12 |
| Web framework | FastAPI | `>=0.115` |
| HTTP client | httpx | `[http2]` |
| ORM | SQLAlchemy (async) | `2.0.x` |
| Validation / settings | Pydantic + pydantic-settings | `2.x` |
| DB driver (prod) | asyncpg | latest |
| DB driver (dev/tests) | aiosqlite | latest |
| Migrations | Alembic | async template |
| Scheduler | APScheduler `AsyncIOScheduler` | 3.10.x (4.x is still beta) |
| Logging | structlog | JSON in prod, ConsoleRenderer in dev |
| Lint / format | ruff | one tool, both jobs |
| Types | mypy | `--strict` |
| Tests | pytest, pytest-asyncio, respx | `httpx.ASGITransport` for integration |
| Container | Docker, docker-compose | postgres:16-alpine + app |

## 3. Repository layout

```
threat-intel-api/
├── src/threat_intel/
│   ├── __init__.py                 # __version__ = "0.1.0"
│   ├── main.py                     # create_app() + lifespan
│   ├── core/
│   │   ├── config.py               # Settings (pydantic-settings)
│   │   ├── db.py                   # async engine, sessionmaker, get_session
│   │   ├── logging.py              # structlog setup, env-aware
│   │   ├── exceptions.py           # ThreatIntelException + subclasses
│   │   └── scheduler.py            # AsyncIOScheduler + register_jobs()
│   ├── models/
│   │   ├── base.py                 # DeclarativeBase + TimestampMixin
│   │   ├── threat.py               # Threat
│   │   ├── source.py               # Source
│   │   ├── cve.py                  # CVE (cve_id index → threat_id)
│   │   └── cwe.py                  # CWE + threat_cwe junction
│   ├── schemas/
│   │   ├── threat.py               # ThreatRead, ThreatList, filters
│   │   ├── cve.py                  # ThreatDetail
│   │   └── health.py               # HealthResponse
│   ├── collectors/
│   │   ├── base.py                 # BaseCollector ABC + RawEvent + ThreatDraft
│   │   └── nvd.py                  # NVDCollector
│   ├── analyzers/
│   │   └── dedup.py                # upsert by (source_id, external_id)
│   ├── services/
│   │   ├── threats.py              # query/filter business logic
│   │   └── ingestion.py            # fetch → normalize → upsert orchestration
│   ├── api/
│   │   ├── deps.py                 # shared FastAPI dependencies
│   │   ├── v1/
│   │   │   ├── __init__.py         # v1 router
│   │   │   ├── threats.py
│   │   │   └── cve.py
│   │   └── health.py               # GET /health (unversioned)
│   └── cli/
│       └── collect_once.py         # one-shot collector trigger for demos
├── tests/
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_nvd_collector.py
│   │   └── test_dedup.py
│   └── integration/
│       ├── test_health.py
│       ├── test_threats.py
│       └── test_cve.py
├── alembic/                        # alembic init -t async
│   ├── env.py
│   └── versions/
├── profiles/
│   ├── public/.gitkeep
│   └── (private/ in .gitignore)
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── alembic.ini
├── .env.example
├── .gitignore
└── README.md
```

**Three deliberate departures from the original spec:**

1. `src/threat_intel/` package root rather than `src/api/`, `src/collectors/`, etc. directly under `src/`. Lets the project install via `pip install -e .` cleanly and keeps imports unambiguous.
2. `/health` is unversioned — health endpoints are consumed by load balancers and monitoring, which need a stable URL across API versions.
3. CWE is a real table with a junction, not a JSON column. The spec asked for a many-to-many relation; honoring that.

## 4. Data model

### Tables

**`source`** — registry of collectors.

| Column | Type | Notes |
|---|---|---|
| id | int PK | |
| name | str unique | `"nvd"`, `"github_advisories"`, ... |
| kind | enum | `cve_feed`, `rss`, `advisory`, ... |
| url | str | base URL of the source |
| enabled | bool | scheduler skips if false |
| last_run_at | datetime tz | |
| last_success_at | datetime tz | |
| last_error | text | last error message, nullable |
| created_at, updated_at | datetime tz | |

**`threat`** — main entity, denormalized for the M2 scoring work.

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| source_id | FK → source | |
| external_id | str | `CVE-YYYY-NNNN` for NVD; URL or GUID for future sources |
| title | text | |
| description | text | |
| severity | enum | `critical`, `high`, `medium`, `low`, `none`, `unknown` |
| cvss_score | float | nullable |
| cvss_vector | str | nullable, e.g. `CVSS:3.1/AV:N/...` |
| cvss_version | str | nullable, e.g. `3.1` |
| affected_products | JSONB list[str] | extracted from CPE |
| references | JSONB list[str] | URLs |
| published_at | datetime tz | indexed |
| last_modified_at | datetime tz | indexed |
| raw_data | JSONB | raw source payload, kept for re-processing |
| created_at, updated_at | datetime tz | |

Constraints: `UNIQUE (source_id, external_id)` — primary dedup key. Indexes on `published_at DESC`, `severity`, `source_id`.

**`cve`** — semantic lookup table for `/api/v1/cve/{cve_id}`.

| Column | Type | Notes |
|---|---|---|
| cve_id | str PK | `CVE-YYYY-NNNN` |
| threat_id | UUID FK → threat, unique | |

Not a duplication: it's a one-row-per-CVE shortcut so the endpoint avoids `WHERE source.name='nvd' AND threat.external_id=...`. When other sources also report the same CVE in M2+, this row continues to point at the canonical threat record.

**`cwe`** — CWE catalog.

| Column | Type | Notes |
|---|---|---|
| id | str PK | `CWE-79` |
| name | text | nullable, populated when known |

**`threat_cwe`** — junction table.

| Column | Type |
|---|---|
| threat_id | FK |
| cwe_id | FK |

### Notes

- All `datetime` columns are timezone-aware UTC (`DateTime(timezone=True)`).
- `affected_products` and `references` stay as JSONB lists for M1. They become normalized tables only when a query like "all threats affecting product X" is needed (M2+). YAGNI applies.
- `Threat.external_id` is generic on purpose. M2 sources without a CVE-ID will still dedup cleanly via `(source_id, external_id)`.

## 5. Collector interface

```python
# src/threat_intel/collectors/base.py

@dataclass(frozen=True)
class RawEvent:
    """Untyped event coming out of a collector's fetch(), before normalization."""
    external_id: str
    payload: dict[str, Any]
    fetched_at: datetime


class ThreatDraft(BaseModel):
    """Domain-level representation produced by normalize().
    Decoupled from SQLAlchemy so collectors don't touch DB sessions."""
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

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None: ...

    @abstractmethod
    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]: ...

    @abstractmethod
    def normalize(self, raw: RawEvent) -> ThreatDraft: ...
```

`fetch()` returns an `AsyncIterator` so paginated sources can stream without holding the full response in memory. The ingestion service owns the unit of work — collectors never see a DB session.

## 6. NVD collector

- Endpoint: NVD REST API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`).
- Window per fetch: `since = max(last_success_at, now() - 24h)`, paginated via `startIndex` / `resultsPerPage` (NVD caps at 2000).
- Rate limit: 5 requests / 30s without API key. The collector uses an async semaphore + `asyncio.sleep` to stay under the limit. API-key support is structured to be added later (env `NVD_API_KEY` already wired through `Settings`, currently unused).
- Retry: tenacity-style decorator on the HTTP call — up to 4 attempts total (1 initial + 3 retries), exponential backoff between retries with sleeps of 1s, 2s, 4s. Retries trigger on 429 / 5xx / network errors only. Permanent 4xx errors raise `CollectorHTTPError` immediately, no retry.
- `normalize()` extracts: title (`cve.descriptions[lang=en]` first 150 chars), description (full), CVSS (prefers v3.1 → v3.0 → v2 metrics, in that order), CWEs, affected products from CPE matches, references.

## 7. Ingestion flow

```
APScheduler tick (hourly)
  └─ IngestionService.run("nvd")
        ├─ resolve last_success_at from Source row → since = since or now-24h
        ├─ NVDCollector.fetch(since)        # async iterator of RawEvent
        ├─ for each event:
        │     draft = collector.normalize(event)
        │     dedup.upsert(session, draft):
        │       SELECT by (source_id, external_id)
        │         INSERT if absent
        │         UPDATE if last_modified_at changed
        │         no-op otherwise
        │       upsert CVE row
        │       upsert CWE rows + junction
        ├─ commit per batch (100 drafts) — bound transaction size, recover gracefully
        └─ update Source.last_run_at / last_success_at / last_error
```

The same flow runs from the `cli/collect_once.py` one-shot for demos — no need to wait for a scheduler tick during an interview.

## 8. API contracts

### `GET /health` (unversioned)

```jsonc
{
  "status": "ok",                          // "degraded" if DB down or collector stale
  "version": "0.1.0",
  "uptime_seconds": 12345,
  "database": "connected",
  "collectors": {
    "nvd": {
      "last_run": "2026-04-26T10:00:00Z",
      "last_success": true,
      "threats_collected_24h": 42
    }
  },
  "stats": {
    "total_threats": 1523,
    "threats_last_24h": 42
  }
}
```

- Returns 200 in both `ok` and `degraded` states. The client reads `status`. Load balancers see the app as up; SLA dashboards read the JSON.
- `degraded` triggers: DB unreachable, OR an enabled collector hasn't run in more than 2× its scheduled interval.
- `uptime_seconds` is computed from a `start_time` set in the FastAPI lifespan.

### `GET /api/v1/threats`

Query parameters:

| Param | Type | Default | Notes |
|---|---|---|---|
| severity | enum, repeatable | — | filters to listed severities |
| since | datetime ISO | — | `published_at >= since` |
| source | str | — | `source.name` filter |
| limit | int | 50 | max 200 |
| offset | int | 0 | |

Response:

```jsonc
{
  "items": [ThreatRead, ...],
  "total": 1523,
  "limit": 50,
  "offset": 0
}
```

`ThreatRead` excludes `raw_data` (too heavy for list views). Sort: `published_at DESC`.

### `GET /api/v1/cve/{cve_id}`

- Path validated by Pydantic regex `^CVE-\d{4}-\d{4,}$`.
- 200: `ThreatDetail` (includes `raw_data`).
- 404: `ThreatNotFoundException` → global handler → `application/problem+json` body per RFC 7807.

## 9. Exceptions

```
ThreatIntelException                 (base)
├── ConfigurationError               invalid Settings at boot
├── CollectorError                   (base for collector failures)
│   ├── CollectorHTTPError           non-retryable HTTP error
│   └── CollectorParseError          unexpected payload shape
├── PersistenceError                 DB error during ingestion
└── ThreatNotFoundException          mapped to API 404
```

A FastAPI exception handler maps each type to an HTTP status + a `problem+json` body. Internal errors are logged with `structlog`, never echoed verbatim to clients.

## 10. Test strategy

**Fixtures (`tests/conftest.py`):**
- `db_engine`: `aiosqlite:///:memory:` with `Base.metadata.create_all` once per session.
- `db_session`: nested transaction + rollback per test for fast isolation.
- `app`: `create_app()` with `Settings` overridden via env.
- `client`: `httpx.AsyncClient(transport=ASGITransport(app=app))` — in-process, no port binding.
- `respx_mock`: intercepts NVD HTTP calls in collector tests.

**Test matrix:**

| File | Cases |
|---|---|
| `unit/test_nvd_collector.py` | `normalize()` on a fixed NVD payload → expected `ThreatDraft`. `fetch()` with `respx`: 200 OK, 429 retry, 500 retry exhaustion. Pagination handling. |
| `unit/test_dedup.py` | Upsert insert. Upsert update when `last_modified_at` changes. No-op on identical payload. |
| `integration/test_health.py` | 200, JSON shape, `database: connected`. |
| `integration/test_threats.py` | Empty list, severity filter, `since` filter, pagination, sort order. |
| `integration/test_cve.py` | 200 on existing CVE, 404 on missing CVE, response is `application/problem+json` on 404. |

Out of scope for M1: scheduler integration test (high mock cost, low value — covered manually via `cli/collect_once.py` during the demo).

## 11. Container & deployment

**`Dockerfile`** — multi-stage:
- Builder stage: `python:3.12-slim`, install `uv`, sync dependencies into a venv.
- Runtime stage: `python:3.12-slim`, copy venv, non-root user, `CMD ["uvicorn", "threat_intel.main:app", "--host", "0.0.0.0", "--port", "8000"]`.

**`docker-compose.yml`** — services:
- `db`: `postgres:16-alpine`, named volume, healthcheck `pg_isready`.
- `app`: `depends_on: { db: { condition: service_healthy } }`, mounts `./profiles/public` read-only, exposes 8000. Entrypoint runs `alembic upgrade head` then launches uvicorn.

A separate `migrations` service is **not** introduced in M1 — entrypoint handles it. If the project grows multi-instance later, that decision flips.

## 12. CORS

Middleware `CORSMiddleware` configured from `Settings.cors_origins: list[str]`. The env var `CORS_ORIGINS` is comma-separated (e.g. `CORS_ORIGINS=https://demo.example.com,https://localhost:3000`). Default in dev: `["http://localhost:3000"]`. Empty list in prod = effectively no cross-origin allowed, which is the safe default.

## 13. End-of-M1 demo flow

1. `cp .env.example .env`
2. `docker compose up --build`
3. `curl localhost:8000/health` — expects `database: connected`, `collectors.nvd.last_run: null`.
4. `docker compose exec app python -m threat_intel.cli.collect_once nvd`
5. `curl localhost:8000/health` — `threats_collected_24h: <N>` populated.
6. `curl 'localhost:8000/api/v1/threats?severity=critical&limit=5'`
7. `curl localhost:8000/api/v1/cve/CVE-2026-XXXX`
8. Open `localhost:8000/docs` — Swagger UI generated.

## 14. Explicitly out of scope for M1

- Other collectors (RSS, GitHub Advisories, OTX) — interface is ready, implementations come in M2+.
- NLP entity extraction (spaCy).
- Webhook alerting.
- STIX export.
- Redis cache.
- Authentication / API keys (the codepath exists in `Settings` for the NVD API key, but no consumer auth).
- Sectoral scoring (M2).
- Frontend dashboard (separate repo).
