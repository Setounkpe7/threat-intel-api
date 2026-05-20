# Security controls

This document maps every control implemented in the API to the relevant
threat or compliance reference, so a reviewer can audit the surface
without reading the whole codebase. For the disclosure policy and
contact, see [SECURITY.md](../SECURITY.md) at the repository root.

## At a glance

| Control                         | Where                                                             |
|---------------------------------|-------------------------------------------------------------------|
| Auth on admin endpoints         | [`api/security.py`](../src/threat_intel/api/security.py)          |
| Rate limiting (slowapi)         | [`api/security.py`](../src/threat_intel/api/security.py), `main.py` |
| Security response headers       | [`api/middleware.py`](../src/threat_intel/api/middleware.py)      |
| Secret-scrubbing logger         | [`core/logging.py`](../src/threat_intel/core/logging.py)          |
| Pinned, hash-locked deps        | `requirements.lock`, `uv.lock`                                    |
| Multi-stage hardened image      | [`Dockerfile`](../Dockerfile)                                     |
| CI security gate (7 jobs)       | [`.github/workflows/security.yml`](../.github/workflows/security.yml) |
| Dependabot (pip + docker + GHA) | [`.github/dependabot.yml`](../.github/dependabot.yml)             |
| Pre-commit hooks                | [`.pre-commit-config.yaml`](../.pre-commit-config.yaml)           |

## Defense layers

### 1. Transport

The API is HTTP-only at the application layer. **TLS termination is the
operator's responsibility** (reverse proxy, load balancer, ingress).

`Strict-Transport-Security` (HSTS) is set to `max-age=63072000;
includeSubDomains` so any browser that visits `/docs` over HTTPS will
refuse to downgrade for two years.

### 2. Browser-level hardening

Every HTTP response carries:

- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`: ten dangerous features denied (`geolocation=()`,
  `camera=()`, `microphone=()`, `payment=()`, `usb=()`, `accelerometer=()`,
  `gyroscope=()`, `magnetometer=()`, `midi=()`, `interest-cohort=()`)
- `Content-Security-Policy`: a strict floor (`default-src 'none';
  frame-ancestors 'none'; base-uri 'none'; form-action 'none';
  object-src 'none'; script-src 'none'; style-src 'none'`) is set at the
  ASGI layer; only `/docs` and `/` opt into a relaxed CSP to keep Swagger
  UI and the index functional (B2 / audit pass 2).
- `Cross-Origin-Resource-Policy: same-origin` and
  `Cross-Origin-Opener-Policy: same-origin` on every response (B2).
- `Server` and seven other fingerprinting headers (`X-Powered-By`, `Via`,
  `X-Runtime`, `X-AspNet-Version`, `X-Process-Time`, `Sentry-Trace`,
  `Baggage`) are stripped at the ASGI layer; uvicorn is started with
  `--server-header=false` (B1).

Tested in [`tests/security/test_security_headers.py`](../tests/security/test_security_headers.py).

### 3. Authentication & authorization

There are two privilege levels:

- **Public**: anonymous, rate-limited, can only read public profiles
  and aggregated stats.
- **Admin**: must present a valid `X-Admin-Key` header. Used by
  `/api/v1/admin/*` and by `?visibility=all` on the sector list.

Admin key validation uses `secrets.compare_digest` to avoid string-comparison
timing leaks. If `ADMIN_API_KEY` is unset, every admin route returns **503**
instead of silently allowing access.

Private profiles (`visibility="private"`) return **404** for anonymous
callers — never 403 — to avoid confirming or denying their existence.

Admin endpoints additionally reject requests that carry a browser-style
`Origin` header via the `forbid_browser_origin` FastAPI dependency, neutralising
CSRF leverage that the previous `allow_headers=["*"]` CORS config
introduced (X2 / audit pass 2).

### 4. Input validation

All query and path parameters are validated by FastAPI/Pydantic. Enum-typed
fields (e.g. `severity`) reject anything outside the allowed set with a 422.
Database access goes through SQLAlchemy ORM with parameterised queries.
Injection attempts are exercised in
[`tests/security/test_injection.py`](../tests/security/test_injection.py)
against the standard SQLi payload corpus, plus log4shell, path traversal,
and an XSS string.

### 5. Rate limiting

Public endpoints carry `@limiter.limit("100/minute")` per source IP via
slowapi. The 429 response is returned as `application/problem+json` with an
integer-second `Retry-After` header so clients know exactly when to retry.
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` are
exposed on **every** response so well-behaved clients can budget their
requests without hitting the ceiling (B4 / audit pass 2). Verified in
[`tests/security/test_rate_limiting.py`](../tests/security/test_rate_limiting.py).

`HEAD` is enabled only on cheap probe endpoints (`/health`, `/`, `/docs`);
data-plane endpoints return **405** to prevent uptime-probe amplification
that would cause unexpected DB load (B3 / audit pass 2).

### 6. Logging & secret hygiene

The logger pipeline (structlog + stdlib `logging.Filter`) scrubs:

- any structured key matching one of: `password`, `passwd`, `secret`,
  `token`, `api_key`, `apikey`, `x-admin-key`, `admin_api_key`,
  `authorization`, `cookie`, `set-cookie`, `session`, `private_key`,
  `client_secret` (substring match on the lowered key);
- `Authorization: Bearer …` and `Cookie: …` lines in any free-form
  message;
- JWT-shaped tokens (`eyJ…\.…\.…`);
- `key=value` pairs where key is a sensitive token and value is ≥16 chars;
- bare 32+ char hex tokens (PAT / session id shape).

Logs are JSON in prod, console-rendered in dev. Optional
`RotatingFileHandler` (10 MB × 5) is enabled when `LOG_FILE` is set;
in containers we recommend leaving it off and letting the orchestrator
ship stdout.

Verified in [`tests/security/test_secret_leakage.py`](../tests/security/test_secret_leakage.py).

### 7. Dependencies

- `requirements.lock` is generated by `uv export` with hashes — the
  Docker build refuses any package that does not match.
- `pip-audit` runs in CI on every PR (strict mode, OSV) and locally via
  `make pip-audit`. The CI job fails on **any** vulnerability;
  `make security-audit` only blocks on HIGH/CRITICAL for fast local feedback.
- Dependabot opens grouped PRs weekly for runtime, dev, Docker, and
  GitHub Actions deps.

### 8. Container image

- Base: `python:3.12-alpine`, multi-stage build.
- Runs as a non-root system user (`uid:gid 1001:1001`, shell `/sbin/nologin`).
- No `pip`/`setuptools`/`wheel` left in the runtime venv; bundled package
  tests stripped.
- Runtime apt set is `libpq` + `curl` + `tini`.
- `tini` as PID 1 → clean signal handling on `docker stop`.
- HEALTHCHECK hits `/health` with a 3 s timeout.
- OCI labels populate `org.opencontainers.image.*` from build args.
- Hadolint must pass with zero warnings; Trivy fails the CI gate on any
  CRITICAL OS/library vulnerability with a known fix.

Final image size: **~195 MB** (under the 200 MB target).

## OWASP API Security Top 10 (2023) mapping

| Risk                                                | Status | Where it's handled                                                 |
|-----------------------------------------------------|--------|--------------------------------------------------------------------|
| **API1 — Broken Object Level Authorization**        | ✅     | Read-only public surface; admin routes gated; private profiles 404 |
| **API2 — Broken Authentication**                    | ✅     | `X-Admin-Key` constant-time compare; 503 if unconfigured; admin endpoints reject browser-origin requests via `forbid_browser_origin` dependency — neutralises CSRF leverage from `allow_headers=["*"]` (X2) |
| **API3 — Broken Object Property Level Authorization** | ✅   | Pydantic response models — fields are explicit, no ORM passthrough |
| **API4 — Unrestricted Resource Consumption**        | ✅     | `slowapi` 100/min per IP; pagination caps `limit`; `X-RateLimit-Limit`/`Remaining`/`Reset` on every response so clients can self-throttle (B4); 429 is `application/problem+json` with integer-second `Retry-After`; `HEAD` allowed only on cheap probes (`/health`, `/`, `/docs`) — data-plane endpoints return 405 to prevent DB-load amplification (B3) |
| **API5 — Broken Function Level Authorization**      | ✅     | Admin router wraps every route in `Depends(require_admin_key)`     |
| **API6 — Unrestricted Access to Sensitive Business Flows** | ⚠️ | `rescore-all` is admin-only and async; no quotas yet on admin path |
| **API7 — Server Side Request Forgery**              | ✅     | Only outbound URL is the configured `NVD_BASE_URL`                 |
| **API8 — Security Misconfiguration**                | ✅     | Hardened image; HSTS; strict CSP floor on every response — `/docs` and `/` opt into a relaxed CSP (B2); `Cross-Origin-Resource-Policy: same-origin` and `Cross-Origin-Opener-Policy: same-origin` on every response (B2); `Server` and 7 fingerprinting headers stripped at ASGI layer + `--server-header=false` (B1); catch-all `Exception` handler returns `application/problem+json` with fixed detail "Unexpected error" — no message or stack-trace leak, structlog never renders local variables (A1); `Cache-Control: no-store` + `Pragma: no-cache` on all `problem+json` responses so CDN/edge caches don't poison error responses (X1) |
| **API9 — Improper Inventory Management**            | ✅     | OpenAPI is the source of truth; OCI labels expose image metadata; `/health` and `/api/v1/sources` report the same collector-attestation count via a single canonical helper `source_attestations_24h` (B5) |
| **API10 — Unsafe Consumption of APIs**              | ✅     | NVD payload normalised through `BaseCollector.normalize`; never re-emitted raw |

## Known limitations

- **No mTLS / no JWT.** The admin gate is a static API key. Suitable for
  one-operator deployments behind a private network; not a replacement
  for SSO when team size grows.
- **No audit log persistence.** Admin actions are logged to stdout but
  not stored in an append-only table.
- **Rate limit storage is in-memory.** Two replicas have two independent
  buckets. Plug a Redis storage URL into slowapi when scaling out.
