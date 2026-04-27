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
