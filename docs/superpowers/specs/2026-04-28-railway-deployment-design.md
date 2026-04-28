# Railway production deployment — design spec

**Date:** 2026-04-28
**Author:** Michel-Ange Doubogan
**Status:** Approved (brainstorming complete)
**Scope:** Production deployment of `threat-intel-api` on Railway, with managed Postgres, Sentry error tracking, hardened CI/CD gating, and full operational runbook.

---

## 1. Goals and non-goals

**Goals**
- Deploy the FastAPI service on Railway, accessible via the auto-generated `*.up.railway.app` URL.
- Provision a Railway-managed Postgres 16 instance for persistence.
- Run Alembic migrations *before* the new release receives traffic, with safe abort on failure.
- Capture unhandled exceptions in Sentry (errors only — no tracing or profiling).
- Split health endpoints into `/livez` (liveness, no DB), `/readyz` (readiness, DB probe), and keep the existing rich `/health` for monitoring.
- Tighten CI triggers so the security gate runs on PRs only (not on `push:dev`).
- Apply the same branch protection on `dev` as on `main`: PR required, security gate required, `enforce_admins=true`.
- Deliver an operator-facing `docs/DEPLOYMENT.md` that fully documents setup, deploy flow, rollback, and secrets rotation.

**Non-goals (explicitly deferred)**
- Custom domain (`threat-intel.dev` or other). Documented as an optional future step.
- Multi-replica deployments and Alembic advisory locks.
- Sentry tracing and profiling.
- Staging environment and a separate GitHub Actions deploy workflow.
- External backup tooling (litestream, S3) beyond what Railway managed Postgres provides.

---

## 2. Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                          GitHub                                     │
│                                                                     │
│   feat/* ──PR──▶ dev   ────PR──▶ main  (security gate REQUIRED)    │
│                                    │                                │
│                                    │ (push detected by Railway)     │
└────────────────────────────────────┼────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│                          Railway (project: threat-intel)            │
│                                                                     │
│   Service: api  ◀──────── env: DATABASE_URL ────────▶ Service: db   │
│   ──────────────                                       ───────────  │
│   Pre-deploy:                                          Postgres 16  │
│     alembic upgrade head                               (managed)    │
│   Start (Dockerfile CMD):                                           │
│     uvicorn threat_intel.main:app                                   │
│   Healthcheck path: /livez                                          │
│   Public URL: https://<service>.up.railway.app                      │
└────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼ (errors only)
                          ┌──────────────────┐
                          │  Sentry (free)   │
                          └──────────────────┘
```

A push on `main` (which only happens via PR with the security gate green, by branch-protection construction) triggers a Railway Docker build. Railway runs `alembic upgrade head` as a pre-deploy command on an ephemeral container, then starts the new release with `uvicorn` and probes `/livez` before routing traffic. Unhandled exceptions ship to Sentry. The DB probe lives in `/readyz`; Railway uses `/livez` for its liveness check, deliberately decoupling pod liveness from DB availability.

---

## 3. Decisions ledger (rationale)

| # | Decision | Rationale |
|---|---|---|
| 1 | Railway native GitHub auto-deploy on `main` push (option C hybrid) | Branch protection on `main` (`enforce_admins=true`) already guarantees no code reaches `main` without a green security gate. A separate GHA deploy workflow would duplicate work without adding security. |
| 2 | Railway managed Postgres add-on | Single provider, simpler narrative, no cross-provider latency. Data is reconstructible from the NVD collector if lost. |
| 3 | Split `/livez` (no DB) + `/readyz` (DB probe) + keep `/health` rich | Industry standard. A `/livez` that touches the DB cascades DB hiccups into pod restart loops. Readiness and liveness are different questions. |
| 4 | Migrations run as Railway pre-deploy command, not in `CMD` | Atomic, single-execution, fails the deploy without crash-looping if the migration is bad. Removes race condition for future scale-out. |
| 5 | Sentry errors-only, free tier | No tracing/profiling needed for this volume. `traces_sample_rate=0.0`, `send_default_pii=False`. |
| 6 | No custom domain initially | $13/yr deferral. Railway-generated URL has valid SSL; can add domain later without code changes. |
| 7 | Drop `push:dev` trigger from `security.yml` | Symmetry with `push:main` trigger already removed (commit `94761cb`). With branch protection on `dev` requiring the gate-on-PR, the `push:dev` run is redundant. |
| 8 | Branch protection on `dev` mirrors `main` (PR required, gate required, `enforce_admins=true`) | Removes the last path for unreviewed code to land on `dev`. Trades direct-push convenience for invariant-by-construction. |

---

## 4. Code changes

Seven changes, ~150 lines total.

### 4.1 `Dockerfile` — alembic moves out of CMD

```diff
- CMD ["sh", "-c", "alembic upgrade head && exec uvicorn threat_intel.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
+ CMD ["uvicorn", "threat_intel.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
```

Side benefit: dropping the `sh -c` wrapper means tini forwards signals directly to uvicorn, giving clean `SIGTERM` handling on `docker stop` and Railway redeploys.

### 4.2 `docker-compose.yml` — separate `migrate` service

To keep local parity with the Railway "migration before app" model:

```yaml
services:
  db: # unchanged
  migrate:
    build: .
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql+asyncpg://threat:threat@db:5432/threat_intel
    command: ["alembic", "upgrade", "head"]
    restart: "no"
  app:
    depends_on:
      migrate:
        condition: service_completed_successfully
      db:
        condition: service_healthy
    # ... rest unchanged
```

`docker compose up` runs `migrate` once, then `app`.

### 4.3 `src/threat_intel/api/health.py` — add `/livez` and `/readyz`

```python
@router.get("/livez", include_in_schema=False)
async def livez() -> dict[str, str]:
    return {"status": "ok"}  # process is up; no external dependency

@router.get("/readyz", include_in_schema=False)
async def readyz(session: Annotated[AsyncSession, Depends(get_db)]) -> Response:
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        logger.warning("readyz_db_unreachable")
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return JSONResponse({"status": "ready"}, status_code=200)
```

`include_in_schema=False` keeps the OpenAPI spec focused on the public API. The existing `/health` endpoint stays untouched.

### 4.4 `src/threat_intel/core/config.py` — Sentry fields + DATABASE_URL normalization

Two new fields:
```python
sentry_dsn: str | None = None
sentry_environment: str = "prod"
```
Both routed through the existing `_strip_optional_string` validator pattern.

A new normalization step on `database_url`: if the value starts with `postgresql://` (Railway's default), rewrite to `postgresql+asyncpg://`. This protects against Railway exposing the synchronous URL by default.

### 4.5 `src/threat_intel/main.py` — conditional Sentry init

```python
def _init_sentry(settings: Settings) -> None:
    if not settings.sentry_dsn:
        return
    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.starlette import StarletteIntegration

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment,
        release=__version__,
        send_default_pii=False,
        traces_sample_rate=0.0,
        integrations=[StarletteIntegration(), FastApiIntegration()],
    )
```
Called at the top of the FastAPI lifespan. Sentry is fully off in dev/test when `SENTRY_DSN` is empty.

### 4.6 Dependency: `sentry-sdk[fastapi]>=2.20`

Added to `pyproject.toml`, `requirements.lock` regenerated with `uv lock`.

### 4.7 `.env.example` — document new vars

```
# Sentry (errors only). Leave blank in dev/test to disable.
SENTRY_DSN=
SENTRY_ENVIRONMENT=prod
```

### 4.8 Tests

```
tests/api/test_health_probes.py
  - test_livez_returns_200_without_db
  - test_readyz_returns_200_when_db_ok
  - test_readyz_returns_503_when_db_fails
  - test_livez_excluded_from_openapi_schema
  - test_readyz_excluded_from_openapi_schema

tests/core/test_sentry_init.py
  - test_sentry_not_initialized_without_dsn
  - test_sentry_initialized_with_dsn (with mock to avoid network)
  - test_sentry_traces_sample_rate_is_zero

tests/core/test_config_database_url.py
  - test_database_url_postgresql_scheme_normalized_to_asyncpg
  - test_database_url_already_async_unchanged
  - test_database_url_other_drivers_unchanged
```

---

## 5. CI/CD changes

### 5.1 `.github/workflows/security.yml` trigger tightening

```diff
 on:
-  push:
-    branches: [dev]
   pull_request:
     branches: [main, dev]
   workflow_dispatch:
```

The gate now runs on PRs to either `main` or `dev`, plus manual dispatch. `push` triggers are gone entirely, mirroring the earlier `push:main` removal.

### 5.2 Branch protection on `dev`

To be applied via `gh api` after the trigger change is merged on `main`:

```bash
gh api -X PUT repos/Setounkpe7/threat-intel-api/branches/dev/protection \
  --input - <<'EOF'
{
  "required_status_checks": {"strict": true, "contexts": ["security gate"]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 0},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

This is a manual one-time step, recorded in `DEPLOYMENT.md`.

### 5.3 PR sequence

To avoid a "PR that tests its own rule" situation, the changes ship in two PRs:

- **PR 0** — `feat/ci-tighten-triggers`: only the `security.yml` change (5.1). Merged via `dev` → `main`.
- **PR 1** — `feat/m3-deployment-railway`: all code changes from §4 plus this spec and `DEPLOYMENT.md`. Merged via `dev` → `main`.

Branch protection on `dev` is applied between PR 0 merge and PR 1 work.

---

## 6. Railway configuration (manual, post-merge)

Source of truth lives in `DEPLOYMENT.md`. Summary here for the spec record.

**Project structure**
- 1 project: `threat-intel`
- 2 services: `api` (Dockerfile-built from `main`), `db` (Postgres 16 plugin)

**Service `api` settings**
- Source: GitHub `Setounkpe7/threat-intel-api`, branch `main`, Dockerfile
- Pre-Deploy Command: `alembic upgrade head`
- Healthcheck Path: `/livez`
- Replicas: 1
- Public Domain: auto-generated `*.up.railway.app`

**Environment variables on `api`**

| Variable | Source | Notes |
|---|---|---|
| `APP_ENV` | hardcoded `prod` | |
| `LOG_LEVEL` | hardcoded `INFO` | |
| `DATABASE_URL` | `${{<postgres-service>.DATABASE_URL}}` | Normalized to `postgresql+asyncpg://` by `core/config.py` (§4.4) |
| `CORS_ORIGINS` | empty | No frontend deployed yet |
| `NVD_BASE_URL` | hardcoded | NVD CVE 2.0 API |
| `NVD_API_KEY` | secret (optional) | Anonymous rate-limit acceptable initially |
| `NVD_FETCH_INTERVAL_MINUTES` | hardcoded `60` | |
| `PROFILES_PATH` | hardcoded `/app/profiles` | |
| `ADMIN_API_KEY` | secret | Generated locally with `secrets.token_urlsafe(32)` |
| `RATE_LIMIT_DEFAULT` | hardcoded `100/minute` | |
| `RATE_LIMIT_ENABLED` | hardcoded `true` | |
| `SENTRY_DSN` | secret | From Sentry project config |
| `SENTRY_ENVIRONMENT` | hardcoded `prod` | |

Three secrets total: `ADMIN_API_KEY`, `SENTRY_DSN`, optionally `NVD_API_KEY`.

---

## 7. Observability layers

| Layer | Question answered | Used by |
|---|---|---|
| `/livez` | Is the process alive? | Railway healthcheck |
| `/readyz` | Can the app serve traffic? | Manual deploy verification, future LB |
| `/health` | Is everything well (rich view)? | External monitoring, dashboards |
| Sentry | What broke and where? | Operator (you) |
| structlog JSON on stdout | What was the app doing at time T? | Railway Logs viewer |

---

## 8. Operational runbook (summary)

Full procedures live in `docs/DEPLOYMENT.md`. The runbook covers:

- **First-time setup**: PR 0 → branch protection on `dev` → PR 1 → Railway provisioning → smoke test.
- **Routine deploy**: branch → PR → gate → merge → Railway auto-deploy in 2-4 min.
- **Rollback**: 4 cases covered (failed healthcheck, code bug, urgent rollback, broken migration).
- **Secrets rotation**: `ADMIN_API_KEY`, `SENTRY_DSN`, `NVD_API_KEY` all routed through Railway variables.
- **Migration safety**: pre-deploy abort behavior, downgrade path, forward-fix preferred for non-trivially reversible migrations.

---

## 9. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Migration test passes on SQLite (CI) but fails on Postgres (prod) | Medium | High | Pre-deploy command aborts the deploy, old release stays live. Manual verification on first deploy. |
| Required check name mismatch (`security gate` vs `security-gate`) blocks all PRs | Low | High | Validate the exact context name before applying branch protection on `dev`. The existing `main` protection already uses `"security gate"` (with space). |
| Railway provisions `DATABASE_URL` with `postgresql://` scheme; asyncpg requires `postgresql+asyncpg://` | High | High | `core/config.py` validator normalizes the scheme (§4.4). Covered by unit test. |
| `_init_sentry` import-on-demand fails silently in prod | Low | Medium | Test exists for both DSN-set and DSN-empty paths. |
| Railway outage takes prod down | Low | High | Single-provider trade-off, accepted. Documented in `DEPLOYMENT.md` with optional UptimeRobot recommendation. |
| `enforce_admins=true` on `dev` prevents emergency push by repo owner | Low | Low | Open a PR even for emergencies; the gate runs in ~2 min. Trade-off accepted for invariant-by-construction. |

---

## 10. Acceptance criteria

The deployment work is complete when:

1. PR 0 is merged on `main` and `security.yml` no longer has `push:` triggers.
2. Branch protection on `dev` is applied with `enforce_admins=true` and `security gate` as a required context.
3. PR 1 is merged on `main` with all §4 code changes and tests passing.
4. Railway services `api` and `db` are provisioned with all env vars from §6.
5. `curl <railway-url>/livez` returns 200 `{"status":"ok"}`.
6. `curl <railway-url>/readyz` returns 200 `{"status":"ready"}`.
7. `curl <railway-url>/health` returns the rich JSON with `status:"ok"` and `database:"connected"`.
8. A test 5xx (e.g., forced 500) appears in Sentry with the correct release tag.
9. `docs/DEPLOYMENT.md` is published and accurate.
10. `README.md` references the live URL and the deployment doc.
