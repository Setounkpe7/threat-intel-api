# Installation

Three supported routes — pick the one that matches your situation.

## Prerequisites

- Python 3.12+ (only for the local route)
- Docker 24+ and Docker Compose v2 (for the Docker route)
- A GitHub personal access token with no scope, exported as `GITHUB_TOKEN`, if you want to enable the GitHub Advisories collector
- An NVD API key (free) is optional but recommended — the public rate limit without one is restrictive

## Route 1 — Docker Compose (recommended for first-time use)

```bash
git clone https://github.com/Setounkpe7/threat-intel-api.git
cd threat-intel-api
cp .env.example .env
docker compose up --build
```

What happens:

1. The `db` service starts a Postgres 16 container.
2. The `migrate` one-shot service runs `alembic upgrade head` against it.
3. The `app` service starts uvicorn on port 8000.

Sanity check:

```bash
curl localhost:8000/health
open http://localhost:8000/docs
```

To force an immediate ingestion run (otherwise the scheduler triggers on its own intervals):

```bash
docker compose exec app python -m threat_intel.cli.collect_once nvd
docker compose exec app python -m threat_intel.cli.collect_once cisa_kev
docker compose exec app python -m threat_intel.cli.collect_once github_advisories
```

You should see something like `inserted=27 updated=0 unchanged=0`.

## Route 2 — Local Python with Postgres

For when you want to attach a debugger or hot-reload on save.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
docker compose up -d db        # only the database container
alembic upgrade head
uvicorn threat_intel.main:app --reload
```

## Route 3 — Local Python with SQLite

The lightest setup; useful for unit work or quick demos. No Docker.

In `.env`, set:

```env
DATABASE_URL=sqlite+aiosqlite:///./threat_intel.db
```

Then:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
alembic upgrade head
uvicorn threat_intel.main:app --reload
```

The `threat_indicator` cross-feed dedup and IOC lookup features are designed against Postgres; they work on SQLite for unit tests but are not the supported path for actual usage.

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://postgres:postgres@db:5432/threat_intel` | Async DSN, see SQLAlchemy docs |
| `ADMIN_API_KEY` | (none — admin endpoints disabled) | 32+ random bytes; required to use `/admin/*` |
| `RATE_LIMIT_DEFAULT` | `100/minute` | Per-IP rate limit on public endpoints |
| `NVD_API_KEY` | (none) | Optional, raises NVD per-window quota |
| `GITHUB_TOKEN` | (none) | Required to enable the GHSA collector |
| `SENTRY_DSN` | (none) | Optional error capture |
| `SENTRY_ENVIRONMENT` | `local` | `production` / `staging` / `local` |
| `LOG_LEVEL` | `INFO` | `DEBUG` for verbose collector tracing |
| `LOG_FORMAT` | `json` | `json` for prod, `console` for dev |

## Production deployment

The reference deployment runs on Railway with a managed Postgres add-on. The full operator runbook (first-time setup, secrets, rollback, troubleshooting) lives in [`docs/DEPLOYMENT.md`](DEPLOYMENT.md).

## Troubleshooting

- **`alembic upgrade head` fails on a fresh DB**: make sure `DATABASE_URL` points to a running database and the user has `CREATE` on the target schema.
- **`/health` says `database: disconnected`**: usually a misnamed `DATABASE_URL` or the DB container hasn't finished booting. `docker compose logs db` will show why.
- **GHSA collector reports `last_success: false`**: a token issue or upstream schema change. Run `python -m threat_intel.cli.collect_once github_advisories` to see the exception.
- **`/api/v1/admin/*` returns 401**: `ADMIN_API_KEY` is empty or the request is missing `X-Admin-Key`.
- **Rate limited locally**: lower `RATE_LIMIT_DEFAULT` is unlikely the culprit; check the proxy in front isn't reusing source IPs.
