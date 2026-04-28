# Deployment

Production runbook for `threat-intel-api`. The target audience is the
operator: an engineer setting up a fresh environment, deploying a change,
or recovering from an incident.

## TL;DR

- Hosted on [Railway](https://railway.app), one project (`threat-intel`)
  with two services: `api` (built from this Dockerfile) and `db`
  (managed Postgres 16).
- A push on `main` triggers an auto-deploy. The only path to `main` is a
  PR with a green security gate, so no unsafe code can reach prod.
- Migrations run as a Railway pre-deploy command, before traffic is
  switched to the new release. A failed migration aborts the deploy and
  keeps the previous version live.
- Logs: Railway service `api` → Logs (structlog JSON, 7-day retention).
- Errors: Sentry, errors-only, release-tagged with the package version.

## Architecture

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

The two services share Railway's private network. `api` reaches `db` over
the internal hostname; the Postgres port is not exposed publicly. The
`api` service exposes a public domain provisioned by Railway (Let's
Encrypt certificate, auto-renewed).

## Prerequisites

- Railway account on the Hobby plan (~5 USD/month for compute, plus the
  Postgres add-on usage).
- Sentry account on the Developer (free) tier. The free quota
  (5k errors/month) is plenty here.
- Admin rights on the GitHub repo `Setounkpe7/threat-intel-api` (needed
  to apply branch protection on `dev`).
- `gh` CLI authenticated against the same account.
- Python 3.12 locally to generate the admin API key.

## CI/CD pipeline

```
1. Local development
   ├── Branch from dev
   ├── Code, run pytest / ruff / mypy
   └── Push the branch

2. PR into dev
   ├── GitHub triggers security.yml on the PR
   ├── 7 jobs: lint, sast, secrets, deps, test, docker-build, container-scan
   ├── Aggregating "security gate" job: green or red
   └── Merge once green

3. PR dev → main (release)
   ├── Branch protection requires "security gate" green
   ├── Merge once green
   └── Push detected on main by Railway

4. Railway build & deploy
   ├── Build the Docker image (layer cache)
   ├── Run pre-deploy command on an ephemeral container
   │   ├── Success → continue
   │   └── Failure → abort, keep previous release live
   ├── Start the new container with CMD = uvicorn
   ├── Probe /livez until healthy or until start-period elapses
   │   ├── 200 OK → switch traffic to the new release
   │   └── Timeout → roll back to previous release
   └── Public URL unchanged, zero downtime

5. Production
   ├── Sentry captures unhandled exceptions
   ├── /health is the rich monitoring view
   └── Railway → Logs streams structlog JSON
```

A typical commit-to-traffic time is 2–4 minutes; most of it is the
Docker build.

There is no GitHub Actions workflow that calls Railway. Two reasons:
the security gate is already enforced via branch protection on `main`,
so the deploy step adds no security; and Railway's native build cache
beats a hand-rolled CI build. If a staging environment is added later,
that calculus changes.

## First-time setup

These five steps are run once per environment.

### 1. PR 0 — tighten security workflow triggers

Drop `push:dev` from `.github/workflows/security.yml` so the gate runs
only on PRs (matching the earlier `push:main` removal). Open a PR from
`feat/ci-tighten-triggers` to `dev`, then `dev` to `main`. Both PRs need
the gate green; both go through the normal review flow.

### 2. Apply branch protection on `dev`

Run after PR 0 lands on `main`, so the required-status-check name is
already registered:

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

The same protection lives on `main` already. With `enforce_admins: true`
nobody (you included) can push directly to `dev` from now on. Every
change goes through a PR with the gate green.

The exact status check name is `security gate` (with a space). The job
ID in the workflow is `security-gate` (with a hyphen), but GitHub
registers the **name**, not the ID. The existing rule on `main` works
that way already.

### 3. PR 1 — deployment code changes

Branch `feat/m3-deployment-railway`. Ships:

- `/livez` and `/readyz` endpoints in `src/threat_intel/api/health.py`.
- `_init_sentry()` in `src/threat_intel/main.py`, called from
  `create_app()` after `configure_logging()`.
- `SENTRY_DSN` and `SENTRY_ENVIRONMENT` in `core/config.py`.
- `DATABASE_URL` scheme normalization (`postgresql://` →
  `postgresql+asyncpg://`).
- Dockerfile `CMD` slimmed to `uvicorn` only; HEALTHCHECK on `/livez`.
- `docker-compose.yml` adds a one-shot `migrate` service.
- `sentry-sdk[fastapi]` added to `pyproject.toml`.
- `.env.example` documents the new Sentry variables.
- This file.

Merge `dev` → `main` once the gate is green.

### 4. Provision Railway

In the Railway UI:

1. **New project from GitHub repo.** Pick `Setounkpe7/threat-intel-api`.
   Railway detects the Dockerfile automatically. Branch is `main`. Do
   not deploy yet.
2. **Add Postgres.** Project → New → Database → PostgreSQL. The plugin
   provisions a managed Postgres 16 with a persistent volume and
   exposes `DATABASE_URL`, `PGHOST`, `PGUSER`, etc. inside the project.
3. **Configure the `api` service.** Open the Variables tab and paste
   the table below.

   | Variable | Value | Notes |
   |---|---|---|
   | `APP_ENV` | `prod` | |
   | `LOG_LEVEL` | `INFO` | |
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` | Replace `Postgres` with the actual service name. The app's config validator rewrites `postgresql://` to `postgresql+asyncpg://`. |
   | `CORS_ORIGINS` | *(empty)* | No frontend yet. |
   | `NVD_BASE_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | |
   | `NVD_API_KEY` | *(empty initially)* | Anonymous rate limit is fine to start. |
   | `NVD_FETCH_INTERVAL_MINUTES` | `60` | |
   | `PROFILES_PATH` | `/app/profiles` | |
   | `ADMIN_API_KEY` | *(generated)* | See below. |
   | `RATE_LIMIT_DEFAULT` | `100/minute` | |
   | `RATE_LIMIT_ENABLED` | `true` | |
   | `SENTRY_DSN` | *(from Sentry)* | Project Settings → Client Keys. |
   | `SENTRY_ENVIRONMENT` | `prod` | |

   Generate `ADMIN_API_KEY` locally:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
   Save the output in a password manager. Railway hides it after save.

4. **Settings → Deploy:**
   - Pre-Deploy Command: `alembic upgrade head`
   - Healthcheck Path: `/livez`
   - Replicas: 1
5. **Settings → Networking:** click *Generate Domain*. Railway returns
   `<service>-production.up.railway.app` with a Let's Encrypt cert.
6. **Sentry:** create a project for `threat-intel-api` (Python /
   FastAPI), copy the DSN into the `SENTRY_DSN` variable above.
7. **Trigger the first deploy.** Settings → *Deploy Now* (or push an
   empty commit on `main`).

### 5. Smoke test

```bash
URL=https://<service>-production.up.railway.app

curl -f $URL/livez                   # → 200 {"status":"ok"}
curl -f $URL/readyz                  # → 200 {"status":"ready"}
curl -f $URL/health | jq             # → rich JSON, status=ok, database=connected
curl -f "$URL/api/v1/threats?limit=1"  # → 200, possibly empty array
```

In Railway → service `api` → Logs, confirm the boot logs are clean
(structlog JSON, no exceptions).

In Sentry → Issues, confirm the page is empty (or triage what's there).

## Environment variables

Same table as in the Railway provisioning step above. Three secrets:
`ADMIN_API_KEY`, `SENTRY_DSN`, and optionally `NVD_API_KEY`. Everything
else is hardcoded in Railway and committed in `.env.example`.

## Deploying a change

```
git checkout -b feat/<topic> dev
# code, tests, ruff, mypy
git push -u origin feat/<topic>
gh pr create --base dev          # gate runs, merge once green
gh pr create --base main --head dev   # gate runs again, merge once green
# Railway picks up the merge, builds, runs alembic, switches traffic
```

No manual step on Railway between merge and live traffic. If the change
contains a migration with surprising data effects, run the smoke test
again afterwards.

## Rollback

### Failed healthcheck during deploy

Nothing to do. Railway keeps the previous release live. Read the deploy
logs, fix the issue, merge a new PR.

### Code regression detected after deploy

```bash
git checkout main
git revert <bad-commit>
git push                    # opens a new PR via the normal flow
```

The revert lands like any other change: PR → gate → merge → Railway
redeploys the previous code. About 3 minutes from push to live.

### Urgent rollback (Sentry is on fire)

UI: Railway → service `api` → Deployments → click a known-good deploy →
*Redeploy*. Traffic switches in ~30 seconds. Then file the `git revert`
to keep the code and the live image in sync.

### Broken migration

A code revert does **not** revert a migration. Two options:

- **Downgrade explicitly** (only if the migration is reversible):
  ```bash
  railway run --service api -- alembic downgrade -1
  # then revert the offending code via the normal PR flow
  ```
- **Forward fix** (preferred for non-trivially reversible migrations,
  for example data migrations or column drops): write a new corrective
  migration, merge it via PR. Railway runs it as the next pre-deploy.

When you know a migration is risky, dump the database first:
```bash
railway run --service db -- pg_dump -Fc -f /tmp/backup.dump
```

## Secrets rotation

### `ADMIN_API_KEY`

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```
Paste into Railway → Variables → `ADMIN_API_KEY`. Railway redeploys
automatically (any variable change triggers a new release). Distribute
the new value to whoever calls the admin endpoints (you, future
frontend, scripts).

### `SENTRY_DSN`

In Sentry → Settings → Client Keys, revoke the old key, create a new
one, paste into the Railway variable. Auto-redeploy.

### `NVD_API_KEY`

If and when you obtain one, paste into Railway. Optional secret with no
revocation urgency.

### Postgres credentials

Managed by Railway. If they need to be reset, recreate the database
service. **Back up first.** The data is reconstructible from the NVD
collector, but a re-run takes time.

## Observability

| Endpoint / source | Question answered | Used by |
|---|---|---|
| `/livez` | Is the process alive? | Railway healthcheck |
| `/readyz` | Can the app serve traffic? | Manual deploy check, future LB |
| `/health` | Is everything well? (rich) | Public dashboard, external monitoring |
| Sentry | What broke and where? | Operator |
| structlog JSON on stdout | What was the app doing at time T? | Railway → Logs |

The split between `/livez` and `/readyz` is deliberate. A liveness probe
that touches the database would cascade DB hiccups into pod restart
loops. Liveness asks "is the process up"; readiness asks "is the app
ready to serve".

Sentry runs in errors-only mode: `traces_sample_rate=0.0`,
`send_default_pii=False`. The release tag uses the package
`__version__`, so the Issues view groups errors by app version. Bump
the version on each release to keep the grouping useful.

## Local development parity

`docker compose up --build` runs the same image with the same
release-time/runtime split:

- `db` boots, becomes healthy.
- `migrate` runs `alembic upgrade head`, exits 0.
- `app` starts only after `migrate` exits cleanly.

The only differences from production:

- No Sentry (`SENTRY_DSN` blank in dev).
- No Railway healthcheck. The in-image Docker `HEALTHCHECK` runs
  instead, targeting `/livez`.
- The Postgres password is the obvious dev-only string.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Healthcheck times out at deploy | `/livez` not responding within `start-period` | Check the Railway logs for an import-time failure (Sentry init, config validator). Fix and redeploy. |
| `503` on `/readyz` after a clean deploy | DB unreachable from the API | Check the Postgres service in Railway. Confirm `DATABASE_URL` references the correct service. |
| Sentry shows nothing after a known crash | DSN missing or wrong | Variables → confirm `SENTRY_DSN` is set on the `api` service, redeploy. |
| `asyncpg.InvalidCatalogNameError` at boot | `DATABASE_URL` not normalized to `postgresql+asyncpg://` | The validator should handle it. Confirm the variable is the whole URL, not a partial value. |
| Pre-deploy command times out | Migration is too long for Railway's pre-deploy budget | Split into smaller migrations or run the heavy step manually with `railway run`. |
| Container restart loop | `/livez` not returning `200` | Verify the `EXPOSE` port matches the `--port` flag (8000 in both places). |
| Sentry events missing the release tag | `__version__` not bumped, or older `release` cached | Bump `__version__` in `pyproject.toml` and `src/threat_intel/__init__.py`, redeploy. |

## Future improvements

- Custom domain (~13 USD/year). See below.
- Staging environment with Railway preview deploys, gated by a
  GitHub Actions workflow that runs smoke tests before promote.
- Multi-replica with an Alembic advisory lock to serialize migrations.
- Sentry tracing and profiling, once the per-endpoint latency picture
  becomes interesting.
- External backup (litestream → S3, or Railway pg_dump cron) once the
  data has independent value.
- UptimeRobot or BetterStack pinging `/livez` from outside Railway, to
  detect provider-level outages.

## Adding a custom domain (optional)

The default Railway domain (`*.up.railway.app`) is fine for a portfolio.
A custom domain costs ~13 USD/year and looks better on a CV.

1. **Buy the domain** at any registrar (Cloudflare and Porkbun are the
   cheapest; Namecheap and OVH are also fine). For example
   `threat-intel.dev` was 13 USD/year at the time of writing.
2. **In Railway:** service `api` → Settings → Networking → *Add Custom
   Domain* → enter the domain. Railway shows a CNAME target.
3. **At the registrar:** create a CNAME record from the domain (or
   subdomain `api.`) to the Railway target. If the domain is on
   Cloudflare DNS, set the proxy status to *DNS only* (gray cloud) for
   the certificate validation; you can flip to proxied later if you
   want Cloudflare in front.
4. **Wait** a few minutes for DNS propagation. Railway issues a Let's
   Encrypt cert automatically once the CNAME resolves.

`.dev` is on the HSTS preload list, so HTTPS is mandatory for that TLD.
Plain HTTP requests are blocked by the browser, regardless of server
config. That's fine because Railway provisions a valid cert
automatically.

After the domain is live, update the placeholders in this document and
in `README.md`. If a frontend ever lands on a different host, add it to
`CORS_ORIGINS`.
