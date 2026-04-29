# Railway Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the threat-intel-api to Railway production with managed Postgres, Sentry error tracking, split health probes, alembic-as-pre-deploy, and tightened CI gating.

**Architecture:** Two PRs to satisfy branch-protection-by-construction. PR 0 tightens `security.yml` triggers (drop `push:dev`) so the gate runs only on PRs. PR 1 ships the code changes (Sentry init, `/livez`/`/readyz`, `DATABASE_URL` async normalization, Dockerfile CMD slimming, compose `migrate` service) plus operator docs. Manual Railway/Sentry provisioning happens after PR 1 is merged on `main`.

**Tech Stack:** FastAPI, Pydantic v2, asyncpg, Alembic, structlog, sentry-sdk, Postgres 16, Railway, Docker (Alpine multi-stage), GitHub Actions, pytest-asyncio, httpx ASGI test client.

**Spec:** `docs/superpowers/specs/2026-04-28-railway-deployment-design.md`

---

## PR 0 — CI trigger tightening

Branch: `feat/ci-tighten-triggers` (off `dev`).

### Task A1: Drop `push:dev` from security.yml

**Files:**
- Modify: `.github/workflows/security.yml:1-12`

- [ ] **Step 1: Create branch and inspect current triggers**

```bash
cd /home/mdoub/Github/threat-intel-api
git fetch origin
git checkout dev
git pull origin dev
git checkout -b feat/ci-tighten-triggers
sed -n '1,12p' .github/workflows/security.yml
```

Expected (current):
```yaml
name: security

on:
  # main is protected — only PRs land there, so the pull_request trigger below
  # is enough. No push:main trigger to avoid double-runs on every merge commit.
  push:
    branches: [dev]
  pull_request:
    branches: [main, dev]
  workflow_dispatch:
```

- [ ] **Step 2: Edit triggers block**

Replace the `on:` block with:
```yaml
name: security

on:
  # Both main and dev are protected — only PRs land there, so the
  # pull_request trigger below is sufficient. No push triggers to avoid
  # double-runs on every merge commit.
  pull_request:
    branches: [main, dev]
  workflow_dispatch:
```

- [ ] **Step 3: Validate workflow YAML syntax locally**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"
```
Expected: no output (valid YAML).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "$(cat <<'EOF'
ci(security): drop push:dev trigger; PR-only gate

Mirrors the earlier push:main removal (94761cb). With branch protection
on dev requiring the gate-on-PR, the push:dev run is redundant and
introduces a double-run on every merge commit.

Branch protection on dev (PR required, security gate required,
enforce_admins=true) is applied via gh api after this PR merges.
EOF
)"
```

- [ ] **Step 5: Push and open PR to dev**

```bash
git push -u origin feat/ci-tighten-triggers
gh pr create --base dev --title "ci(security): drop push:dev trigger; PR-only gate" --body "$(cat <<'EOF'
## Summary
- Drop \`push:dev\` trigger from \`security.yml\`; the gate now runs only on PRs to \`main\` or \`dev\`, plus manual \`workflow_dispatch\`.
- Mirrors the earlier \`push:main\` removal (commit \`94761cb\`).

## Why
With branch protection on \`dev\` (to be applied via \`gh api\` after this PR merges) requiring the gate-on-PR, the \`push:dev\` run is redundant and produces a double-run on every merge commit.

## Test plan
- [x] YAML validates (\`python -c "import yaml; yaml.safe_load(...)"\`).
- [ ] CI security gate runs on this PR (and is the only run for the branch).
- [ ] After merge, no security workflow run is triggered by the merge commit on \`dev\`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 6: Note PR URL**

Print the PR URL. The user will merge after the gate is green. Once merged on `dev`, repeat for `dev` → `main` PR (same body, base `main`):

```bash
gh pr create --base main --head dev --title "ci(security): drop push:dev trigger; PR-only gate" --body "Merge feat/ci-tighten-triggers into main."
```

**Note:** Branch protection on `dev` is applied AFTER PR 0 lands on `main` (so the required-status-check is settled). This is a manual `gh api` step documented in `DEPLOYMENT.md`.

---

## PR 1 — Deployment code changes

Branch: `feat/m3-deployment-railway` (already created off `dev`, spec already committed).

### Task B1: Sentry config fields

**Files:**
- Modify: `src/threat_intel/core/config.py:30-90`
- Test: `tests/unit/test_config_sentry.py` (new)

- [ ] **Step 1: Write failing tests for Sentry config fields**

Create `tests/unit/test_config_sentry.py`:
```python
from threat_intel.core.config import Settings


def test_sentry_dsn_defaults_to_none(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    s = Settings()
    assert s.sentry_dsn is None


def test_sentry_dsn_loaded_from_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("SENTRY_DSN", "https://abc@sentry.io/123")
    s = Settings()
    assert s.sentry_dsn == "https://abc@sentry.io/123"


def test_sentry_dsn_blank_string_yields_none(monkeypatch):
    """Blank value is the standard 'feature off' signal in this codebase."""
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("SENTRY_DSN", "")
    s = Settings()
    assert s.sentry_dsn is None


def test_sentry_environment_defaults_to_prod(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.delenv("SENTRY_ENVIRONMENT", raising=False)
    s = Settings()
    assert s.sentry_environment == "prod"


def test_sentry_environment_overridable(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("SENTRY_ENVIRONMENT", "staging")
    s = Settings()
    assert s.sentry_environment == "staging"
```

- [ ] **Step 2: Run tests, expect failure**

```bash
uv run pytest tests/unit/test_config_sentry.py -v
```
Expected: 5 failures (`AttributeError: 'Settings' object has no attribute 'sentry_dsn'`).

- [ ] **Step 3: Add fields to Settings**

In `src/threat_intel/core/config.py`, after the `admin_api_key` field and before the rate-limit fields, add:
```python
    # Sentry (errors only). Leave SENTRY_DSN blank to disable.
    sentry_dsn: str | None = None
    sentry_environment: str = "prod"
```

In the same file, extend the validators to strip the new fields. Update the `_strip_optional_string` validator decorator:
```python
    @field_validator("nvd_api_key", "admin_api_key", "sentry_dsn", mode="before")
    @classmethod
    def _strip_optional_string(cls, v: object) -> object:
        ...  # body unchanged
```
And the `_strip_required_string` validator:
```python
    @field_validator(
        "app_name",
        "app_env",
        "log_level",
        "database_url",
        "nvd_base_url",
        "sentry_environment",
        mode="before",
    )
    @classmethod
    def _strip_required_string(cls, v: object) -> object:
        ...  # body unchanged
```

- [ ] **Step 4: Run tests, expect pass**

```bash
uv run pytest tests/unit/test_config_sentry.py -v
```
Expected: 5 passes.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/core/config.py tests/unit/test_config_sentry.py
git commit -m "feat(config): add SENTRY_DSN and SENTRY_ENVIRONMENT settings

Empty SENTRY_DSN disables Sentry init (the standard 'feature off'
signal in this codebase, consistent with NVD_API_KEY and ADMIN_API_KEY).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B2: DATABASE_URL async normalization

**Files:**
- Modify: `src/threat_intel/core/config.py` (validator block)
- Test: `tests/unit/test_config_database_url.py` (new)

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_config_database_url.py`:
```python
from threat_intel.core.config import Settings


def test_database_url_postgresql_scheme_normalized_to_asyncpg(monkeypatch):
    """Railway exposes DATABASE_URL with the synchronous 'postgresql://' scheme.
    The app uses asyncpg, which requires 'postgresql+asyncpg://'."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@host:5432/db")
    s = Settings()
    assert s.database_url == "postgresql+asyncpg://u:p@host:5432/db"


def test_database_url_already_async_unchanged(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@host:5432/db")
    s = Settings()
    assert s.database_url == "postgresql+asyncpg://u:p@host:5432/db"


def test_database_url_sqlite_unchanged(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    s = Settings()
    assert s.database_url == "sqlite+aiosqlite:///:memory:"


def test_database_url_other_postgres_drivers_unchanged(monkeypatch):
    """Don't rewrite if the user explicitly chose another async driver."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host:5432/db")
    s = Settings()
    assert s.database_url == "postgresql+psycopg://u:p@host:5432/db"


def test_database_url_with_inline_comment_normalized(monkeypatch):
    """Composes with the existing inline-comment stripping validator."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@host/db # railway managed")
    s = Settings()
    assert s.database_url == "postgresql+asyncpg://u:p@host/db"
```

- [ ] **Step 2: Run tests, expect failure**

```bash
uv run pytest tests/unit/test_config_database_url.py -v
```
Expected: `test_database_url_postgresql_scheme_normalized_to_asyncpg` fails (no normalization yet); the others may pass already because the values are already correct.

- [ ] **Step 3: Add normalization**

In `src/threat_intel/core/config.py`, add a new validator after `_strip_required_string`:
```python
    @field_validator("database_url", mode="after")
    @classmethod
    def _normalize_postgres_scheme(cls, v: str) -> str:
        """Rewrite synchronous 'postgresql://' → 'postgresql+asyncpg://'.

        Railway's managed Postgres exposes DATABASE_URL with the synchronous
        scheme by default. The runtime uses asyncpg and requires the
        '+asyncpg' driver suffix. Other schemes (sqlite+aiosqlite,
        postgresql+psycopg, postgresql+asyncpg) are left untouched.
        """
        if v.startswith("postgresql://"):
            return "postgresql+asyncpg://" + v.removeprefix("postgresql://")
        return v
```

- [ ] **Step 4: Run tests, expect pass**

```bash
uv run pytest tests/unit/test_config_database_url.py -v tests/unit/test_config.py tests/unit/test_config_inline_comments.py
```
Expected: all pass (5 new + existing config tests still green).

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/core/config.py tests/unit/test_config_database_url.py
git commit -m "feat(config): normalize postgresql:// to postgresql+asyncpg://

Railway's managed Postgres exposes DATABASE_URL with the synchronous
scheme. The app uses asyncpg, so we rewrite the scheme transparently.
Other drivers (psycopg, aiosqlite, already-async postgres) are left
untouched.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B3: `/livez` and `/readyz` endpoints

**Files:**
- Modify: `src/threat_intel/api/health.py`
- Test: `tests/integration/test_health_probes.py` (new)

- [ ] **Step 1: Write failing tests**

Create `tests/integration/test_health_probes.py`:
```python
from unittest.mock import patch

from sqlalchemy.exc import OperationalError


async def test_livez_returns_200_with_static_body(client):
    resp = await client.get("/livez")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_livez_does_not_query_database(client):
    """Liveness must not depend on DB. Patch session execute to confirm."""
    with patch(
        "threat_intel.api.health.AsyncSession.execute",
        side_effect=AssertionError("livez must not query DB"),
    ):
        resp = await client.get("/livez")
    assert resp.status_code == 200


async def test_readyz_returns_200_when_db_reachable(client):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


async def test_readyz_returns_503_when_db_unreachable(client):
    with patch(
        "threat_intel.api.health.AsyncSession.execute",
        side_effect=OperationalError("stmt", {}, Exception("db down")),
    ):
        resp = await client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json() == {"status": "not_ready"}


async def test_livez_excluded_from_openapi_schema(client):
    resp = await client.get("/openapi.json")
    schema = resp.json()
    assert "/livez" not in schema.get("paths", {})


async def test_readyz_excluded_from_openapi_schema(client):
    resp = await client.get("/openapi.json")
    schema = resp.json()
    assert "/readyz" not in schema.get("paths", {})
```

- [ ] **Step 2: Run tests, expect failure**

```bash
uv run pytest tests/integration/test_health_probes.py -v
```
Expected: 6 failures (404 on `/livez` and `/readyz`).

- [ ] **Step 3: Add the endpoints**

In `src/threat_intel/api/health.py`, add at the bottom of the file:
```python
@router.get("/livez", include_in_schema=False)
async def livez() -> dict[str, str]:
    """Liveness probe — process is alive. No external dependency.

    Used by Railway's healthcheck. Must remain trivially fast and
    must not depend on DB / network: a slow DB should not cascade
    into a pod restart loop.
    """
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz(
    session: Annotated[AsyncSession, Depends(get_db)],
) -> JSONResponse:
    """Readiness probe — app can serve traffic (DB reachable)."""
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        logger.warning("readyz_db_unreachable")
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return JSONResponse({"status": "ready"}, status_code=200)
```

Add the import for `JSONResponse` at the top:
```python
from fastapi.responses import JSONResponse
```

- [ ] **Step 4: Run tests, expect pass**

```bash
uv run pytest tests/integration/test_health_probes.py tests/integration/test_health.py -v
```
Expected: 8 passes (6 new + 2 existing).

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/api/health.py tests/integration/test_health_probes.py
git commit -m "feat(api): add /livez and /readyz health probes

- /livez: 200 if process is alive, no DB dependency. Used by Railway
  liveness check; cannot cascade DB hiccups into restart loops.
- /readyz: 200 if DB reachable, 503 otherwise. Used for deploy
  verification and future LBs.
- Both excluded from OpenAPI schema (infrastructure, not API surface).
- /health (rich) preserved unchanged for monitoring dashboards.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B4: Sentry init in main.py

**Files:**
- Modify: `src/threat_intel/main.py:63-72`
- Test: `tests/unit/test_sentry_init.py` (new)

- [ ] **Step 1: Add sentry-sdk dependency**

In `pyproject.toml`, locate the `dependencies = [` block and add:
```toml
    "sentry-sdk[fastapi]>=2.20",
```
(maintain alphabetical or insertion order matching the rest of the project — copy the surrounding style)

- [ ] **Step 2: Re-lock dependencies**

```bash
uv lock
uv sync --frozen
```
Expected: `requirements.lock` updated; sentry-sdk and its deps appear.

Regenerate `requirements.lock` to match the project's flow (the project tracks both `uv.lock` and `requirements.lock`):
```bash
uv export --no-dev --no-emit-project --frozen --format requirements-txt > requirements.lock
```

- [ ] **Step 3: Write failing tests**

Create `tests/unit/test_sentry_init.py`:
```python
from threat_intel.core.config import Settings
from threat_intel.main import _init_sentry


def _make_settings(monkeypatch, **overrides) -> Settings:
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    for k, v in overrides.items():
        monkeypatch.setenv(k, v)
    return Settings()


def test_init_sentry_noop_when_dsn_blank(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    settings = _make_settings(monkeypatch)
    # Should not raise, should not import sentry_sdk
    _init_sentry(settings)


def test_init_sentry_calls_sdk_when_dsn_set(monkeypatch):
    settings = _make_settings(monkeypatch, SENTRY_DSN="https://abc@sentry.io/1")

    captured: dict = {}

    def fake_init(**kwargs) -> None:
        captured.update(kwargs)

    import sentry_sdk

    monkeypatch.setattr(sentry_sdk, "init", fake_init)
    _init_sentry(settings)

    assert captured["dsn"] == "https://abc@sentry.io/1"
    assert captured["environment"] == "prod"
    assert captured["traces_sample_rate"] == 0.0
    assert captured["send_default_pii"] is False


def test_init_sentry_passes_release_tag(monkeypatch):
    settings = _make_settings(monkeypatch, SENTRY_DSN="https://abc@sentry.io/1")
    captured: dict = {}
    import sentry_sdk

    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: captured.update(kw))
    _init_sentry(settings)

    from threat_intel import __version__

    assert captured["release"] == __version__
```

- [ ] **Step 4: Run tests, expect failure**

```bash
uv run pytest tests/unit/test_sentry_init.py -v
```
Expected: ImportError on `_init_sentry` (not yet defined).

- [ ] **Step 5: Add `_init_sentry` to main.py**

In `src/threat_intel/main.py`, after the imports and before `_problem`, add:
```python
def _init_sentry(settings: Settings) -> None:
    """Initialize Sentry if SENTRY_DSN is set; no-op otherwise.

    Errors-only configuration: traces_sample_rate=0.0, no profiling,
    no PII. Release tag uses the package __version__ so Sentry can
    group issues by app version.
    """
    if not settings.sentry_dsn:
        return

    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.starlette import StarletteIntegration

    from threat_intel import __version__

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment,
        release=__version__,
        send_default_pii=False,
        traces_sample_rate=0.0,
        integrations=[StarletteIntegration(), FastApiIntegration()],
    )
```

In `create_app`, call it right after `configure_logging`:
```python
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(...)
    _init_sentry(settings)   # ← new line
    ...
```

- [ ] **Step 6: Run tests, expect pass**

```bash
uv run pytest tests/unit/test_sentry_init.py -v
```
Expected: 3 passes.

- [ ] **Step 7: Run full test suite to confirm no regression**

```bash
uv run pytest -x --timeout=60
```
Expected: all green (or at most pre-existing flakes — investigate any new failure).

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml uv.lock requirements.lock src/threat_intel/main.py tests/unit/test_sentry_init.py
git commit -m "feat(observability): conditional Sentry init (errors only)

Initialized at create_app() time, after logging configuration.
- No-op when SENTRY_DSN is empty (dev/test default).
- traces_sample_rate=0.0, send_default_pii=False (errors only,
  no PII shipped).
- Release tag = package __version__ for issue grouping by version.
- FastAPI + Starlette integrations auto-instrument middleware.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B5: Slim Dockerfile CMD

**Files:**
- Modify: `Dockerfile:101`

- [ ] **Step 1: Replace CMD line**

In `Dockerfile`, replace line 101:
```diff
-CMD ["sh", "-c", "alembic upgrade head && exec uvicorn threat_intel.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
+CMD ["uvicorn", "threat_intel.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
```

The migration now runs as a Railway pre-deploy command (configured in the Railway service settings). Local `docker-compose` runs migrations via the new `migrate` service (Task B6).

- [ ] **Step 2: Validate Dockerfile parses**

```bash
docker buildx build --check -f Dockerfile . 2>&1 | tail -20
```
If `buildx check` is unavailable, fall back to:
```bash
hadolint Dockerfile
```
Expected: no errors. Warnings are OK.

- [ ] **Step 3: Build the image locally**

```bash
docker build -t threat-intel-api:test --build-arg GIT_SHA=$(git rev-parse HEAD) .
```
Expected: build succeeds.

- [ ] **Step 4: Confirm CMD by inspecting the image**

```bash
docker inspect --format '{{json .Config.Cmd}}' threat-intel-api:test
```
Expected: `["uvicorn","threat_intel.main:app","--host","0.0.0.0","--port","8000","--proxy-headers","--forwarded-allow-ips=*"]`

- [ ] **Step 5: Commit**

```bash
git add Dockerfile
git commit -m "build(docker): drop alembic from CMD; uvicorn direct

Migrations now run as a Railway pre-deploy command (configured in
the service settings) and as a separate one-shot 'migrate' service
in docker-compose (next commit). The runtime container only runs
uvicorn.

Side benefit: no 'sh -c' wrapper means tini forwards signals
directly to uvicorn — clean SIGTERM on docker stop / Railway
redeploy.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B6: Compose `migrate` one-shot service

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Replace docker-compose.yml**

Replace the contents with:
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
    build: .
    depends_on:
      migrate:
        condition: service_completed_successfully
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

- [ ] **Step 2: Validate compose syntax**

```bash
docker compose config --quiet
```
Expected: no output (valid).

- [ ] **Step 3: Test bring-up locally (optional but recommended)**

```bash
docker compose down -v
docker compose up -d --build
docker compose logs migrate | tail -20
docker compose ps
curl -fs http://localhost:8000/livez
curl -fs http://localhost:8000/readyz
docker compose down -v
```
Expected: `migrate` exits 0, `app` reports healthy, `/livez` and `/readyz` both return 200.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml
git commit -m "build(compose): add migrate one-shot service

Local parity with the Railway 'migration before app' model:
- migrate: builds the same image, runs 'alembic upgrade head'
  once, exits.
- app: depends_on migrate (service_completed_successfully).
- 'docker compose up' now follows the same release-time vs
  runtime separation as production.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B7: Update `.env.example`

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Append Sentry block**

Add to the bottom of `.env.example`:
```
# Sentry error tracking (errors only, no tracing). Leave SENTRY_DSN
# blank to disable. The DSN is provided by your Sentry project
# settings → Client Keys.
SENTRY_DSN=
SENTRY_ENVIRONMENT=prod
```

- [ ] **Step 2: Validate that .env still loads cleanly**

```bash
uv run python -c "from threat_intel.core.config import Settings; print(Settings(_env_file='.env.example'))"
```
Expected: prints settings; no validation error. (Note: requires DATABASE_URL — if not set in `.env.example`, set a stub for the check.)

- [ ] **Step 3: Commit**

```bash
git add .env.example
git commit -m "docs(env): document SENTRY_DSN and SENTRY_ENVIRONMENT

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B8: Write `docs/DEPLOYMENT.md`

**Files:**
- Create: `docs/DEPLOYMENT.md`

- [ ] **Step 1: Create the file with the full operator runbook**

Write `docs/DEPLOYMENT.md` covering:

1. **TL;DR** (3-5 lines): Railway URL, "main push → auto-deploy", where to find logs.
2. **Architecture** (the diagram from the spec section 2 + 1 paragraph).
3. **Prerequisites**: Railway account (Hobby ~$5/mo), Sentry account (free), GitHub admin on the repo, `gh` CLI authenticated, Python 3.12 local.
4. **CI/CD pipeline** (diagram from spec §5 + 5-step flow + note on absence of GHA deploy workflow).
5. **First-time setup** — five subsections (PR 0, dev branch protection, PR 1, Railway provisioning, smoke test). Branch-protection-on-dev block:
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
6. **Environment variables** (table from spec §6).
7. **Deploying a change** (the routine 6-step flow).
8. **Rollback procedures** (4 cases: failed healthcheck, code revert, urgent UI rollback, broken migration with downgrade vs forward-fix).
9. **Secrets rotation** (`ADMIN_API_KEY`, `SENTRY_DSN`, `NVD_API_KEY`).
10. **Observability** (table: `/livez` vs `/readyz` vs `/health`; Sentry usage; logs).
11. **Local development parity** (1 paragraph: `docker compose up` mirrors prod's release-time/runtime split; Sentry off in dev).
12. **Troubleshooting** (5-7 entries: healthcheck timeout, 503 readyz, Sentry silent, asyncpg scheme error, pre-deploy timeout, restart loop).
13. **Future improvements** (custom domain, staging, multi-replica, traces, backups).
14. **Adding a custom domain (optional)** (3 steps: registrar buy, CNAME, Railway validation; note `.dev` HSTS preload).

The file should be ~250-350 lines, fully self-contained, technical (target = engineer reading later or recruiter peeking).

- [ ] **Step 2: Run humanizer skill on the result**

Per project memory ("Run humanizer before commit"), invoke:
```
Skill: humanizer
```
Apply it to `docs/DEPLOYMENT.md` to remove AI tells before committing. This is a tooling-aware step, not a manual edit pass.

- [ ] **Step 3: Commit**

```bash
git add docs/DEPLOYMENT.md
git commit -m "docs(deployment): operator runbook for Railway

Covers first-time setup (PR 0 → dev branch protection → PR 1 →
Railway provisioning → smoke test), env vars, routine deploys,
rollback (4 cases), secrets rotation, observability, troubleshooting,
local parity, and the deferred custom-domain procedure.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B9: Update README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Locate or create a Deployment section**

```bash
grep -n -i "deploy" README.md
```

- [ ] **Step 2: Add or update the section**

Insert after the Quickstart section (or near the top of the operations content):
```markdown
## Deployment

Production: deployed on [Railway](https://railway.app), auto-deploys on push to `main` (which only happens via PR with the security gate green).

Operator runbook: see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
```

(URL placeholder — the live URL is filled in once the Railway service is provisioned.)

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs(readme): link to deployment runbook

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B10: Final verification, push, open PR

- [ ] **Step 1: Run the full test suite**

```bash
uv run pytest --timeout=60
```
Expected: all green.

- [ ] **Step 2: Run lint and type-check**

```bash
uv run ruff check src/ tests/
uv run mypy src/
```
Expected: no errors.

- [ ] **Step 3: Confirm git log on the branch**

```bash
git log --oneline dev..HEAD
```
Expected: 1 spec commit + ~10 feature commits.

- [ ] **Step 4: Push branch**

```bash
git push -u origin feat/m3-deployment-railway
```

- [ ] **Step 5: Open PR to dev**

```bash
gh pr create --base dev --title "feat(m3): Railway production deployment" --body "$(cat <<'EOF'
## Summary
- Split health probes: \`/livez\` (no DB), \`/readyz\` (DB probe, 503 on failure), \`/health\` rich (preserved).
- Conditional Sentry init in \`create_app()\`: errors-only, no PII, \`traces_sample_rate=0.0\`.
- \`DATABASE_URL\` async normalization: rewrites Railway's \`postgresql://\` → \`postgresql+asyncpg://\`.
- Dockerfile \`CMD\` slimmed to \`uvicorn\` only — migrations run as Railway pre-deploy command.
- \`docker-compose.yml\` adds a one-shot \`migrate\` service for local parity with the prod release-time/runtime split.
- Operator runbook in \`docs/DEPLOYMENT.md\`.

## Spec
\`docs/superpowers/specs/2026-04-28-railway-deployment-design.md\`

## Test plan
- [x] Unit: SENTRY_DSN/SENTRY_ENVIRONMENT loading (5 tests).
- [x] Unit: DATABASE_URL scheme normalization (5 tests).
- [x] Unit: Sentry init no-op vs init with DSN (3 tests).
- [x] Integration: /livez, /readyz, OpenAPI exclusion (6 tests).
- [x] Existing /health and security suite still green.
- [x] \`docker compose up\` still works end-to-end with the new \`migrate\` service.
- [ ] Manual Railway provisioning (post-merge, documented).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 6: Print PR URLs and remaining manual steps**

After PR creation, print:
1. PR 0 URL (CI tightening) — ready for user merge.
2. Branch protection on `dev` — `gh api` command (run after PR 0 merges on `main`).
3. PR 1 URL (deployment) — ready for user merge after PR 0 + dev protection.
4. Railway provisioning steps (UI clicks): create project, add Postgres, set env vars, set Pre-Deploy Command, set Healthcheck Path, generate domain.
5. Sentry project creation + DSN copy.
6. Post-deploy smoke test commands.

---

## Self-review checklist

- [ ] All ten acceptance criteria from spec §10 mapped to a task above.
- [ ] No "TODO" / "TBD" / "fill in details" anywhere in the plan.
- [ ] Type names consistent across tasks (`Settings.sentry_dsn`, `_init_sentry`, `/livez`, `/readyz`).
- [ ] Each test has actual code, not a description.
- [ ] All commit messages use `Co-Authored-By` per repo convention.
- [ ] Manual Railway/Sentry steps documented in `DEPLOYMENT.md` (Task B8) and recapped in the final PR description (Task B10 step 6) — they are explicitly outside the code PRs.
