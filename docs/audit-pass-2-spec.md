# Audit Pass 2 — Spec & Acceptance Criteria

**Source audit:** local sweep on `main` @ `be3ea92` (commit after PR #36 merge), executed 2026-05-20 via `docker compose up` against `localhost:8000`.

**Scope:** every finding from the post-PR-#36 audit, ordered by user-experience and contract impact. All fixes ship through one umbrella PR `dev → main` after a second-pass audit on `dev`.

**Out of scope (deferred):** STIX/TAXII export, webhook alerting, NLP indicator extraction (those live on the roadmap, M4–M6).

---

## Priority A — Must-fix before next `main` push

These two break a contract the README and `docs/SECURITY.md` advertise and a SIEM is allowed to rely on. They are the load-bearing follow-up of the PR #36 work.

### A1 · Catch-all `Exception` handler → RFC 7807 problem+json (no leak)

**Finding (BUG-3 in audit).** When an unhandled exception escapes a route, Starlette's default takes over and returns `500 text/plain "Internal Server Error"`. The PR #36 only registered handlers for `HTTPException` and `RequestValidationError`; bare `Exception` was missed. Confirmed locally with `GET /api/v1/threats?offset=99999…` (Python int overflow during query execution).

**Why it matters.**
- The README claims *"Errors served as RFC 7807 `application/problem+json` (no stack traces leaked)"* — false on 500.
- A SIEM parsing the documented contract crashes on first 500.
- Starlette's default also emits an unsanitised traceback when `debug=True`; in production we don't toggle that, but the absence of a catch-all means any future `debug=True` slip would leak straight to clients.

**Proposed design.**
- Register `@app.exception_handler(Exception)` last in `main.create_app()`.
- Body is `problem_response(request, 500, "Internal server error", "Unexpected error")` — fixed `detail`, **never echoes `str(exc)`**, to keep the no-leak promise.
- Log the actual exception at `error` level via `structlog.exception(...)` so Sentry + log pipeline still capture it.
- Sentry already wraps via `StarletteIntegration` + `FastApiIntegration` — Sentry instruments at the ASGI layer and captures *before* this handler runs. **Do NOT call `sentry_sdk.capture_exception(exc)` inside the handler** (it would double-fire).
- **⚠ Middleware ordering trap (BA review)**: `SecurityHeadersMiddleware` inherits `BaseHTTPMiddleware`, which converts downstream exceptions to a 500 internally before our `@exception_handler(Exception)` ever fires. Only Starlette's outermost `ServerErrorMiddleware` routes to handlers.
  - First step: write a probe test (raise `Exception("probe")` from a temp route, assert problem+json body). If the test fails, refactor `SecurityHeadersMiddleware` to a pure-ASGI `__call__`-style middleware that wraps `send` to mutate response start headers — same fix simultaneously cleans up B1's `headers.pop("server")` path.
- **Pre-routing failures** (malformed ASGI scope, body-size errors) bypass *all* FastAPI handlers and are emitted by Starlette's `ServerErrorMiddleware` as plain text. We can't intercept those without subclassing `ServerErrorMiddleware`; mitigation is **lock `debug=False`** in `create_app()` and add a startup assertion + regression test.
- **Scheduler / lifespan exceptions** (SE review): A1 does not cover APScheduler jobs. `run_daily_rescore` already wraps `Exception`; the ingestion job does not. Add equivalent `try/except + logger.exception` wrappers around every job runner in `lifespan`.
- **Logging surface (SE review)**: verify `structlog` does **not** have `pretty_exceptions_local_vars` enabled in prod (`src/threat_intel/core/logging.py`). Local var rendering would serialize DB rows, raw SQL params, and `Settings` (which holds API keys). Pin off; add regression test.

**Acceptance criteria.**
1. `GET /api/v1/threats?offset=99999…` returns `500` with `Content-Type: application/problem+json` and body `{"type":"about:blank","title":"Internal server error","status":500,"detail":"Unexpected error","instance":"/api/v1/threats"}`.
2. Response body **never contains** the underlying exception class, message, or stack frame.
3. A temp test route that raises `Exception("probe")` returns problem+json (proves middleware ordering is correct).
4. New unit + integration tests cover: (a) the body shape, (b) the log line carries the exception with `exc_info`, (c) Sentry receives the capture exactly **once** (mock; asserts dedupe).
5. Startup assertion: `assert app.debug is False` in production env (+ test).
6. Logging config test: structlog processor chain does NOT include local-var rendering.
7. Existing 291+ tests still pass.

---

### A2 · `instance` field on CORS-preflight problem+json

**Finding (REG-1).** All other problem+json bodies include `instance` (the request path, per RFC 7807 §3.1). My `ProblemCORSMiddleware.preflight_response` constructs the JSONResponse directly instead of routing through `problem_response(request, …)`, so `instance` is absent on the CORS 400.

**Proposed design.**
- Lift `problem_response` to accept `instance: str | None` (kwarg, additive) — clean separation, no Request coupling. Existing callers pass `request.url.path`; the CORS preflight passes `scope["path"]` directly.
- Update `ProblemCORSMiddleware.preflight_response` to extract `instance` from the ASGI scope and pass it through.

**Acceptance criteria.**
1. The CORS-preflight problem+json body contains `"instance": "/api/v1/threats"` (or whatever path was probed).
2. All other handlers continue to emit `instance` (regression-tested).
3. `tests/security/test_problem_json.py::test_cors_preflight_rejection_returns_problem_json` is extended to assert `instance`.

**Risk.** Touches a helper that 5 handlers import. Pure additive change to its signature (or kwargs) keeps it safe — call sites unchanged.

---

## Priority B — Hardening / fidelity to README claims

### B1 · Strip the `Server: uvicorn` header (info leak)

**Finding.** `Server: uvicorn` is sent on every response in the local stack. On Railway the edge overrides it with `server: railway-edge`, but local + any non-Railway deploy leaks the runtime. Minor by itself; aggregated with version-bump fingerprinting it accelerates CVE-targeted scans.

**Proposed design.** Two combinable layers (defence in depth — both agents endorsed):
- **App layer:** start uvicorn with `--server-header=false` (Dockerfile `CMD`) or `server_header=False` in `uvicorn.Config`.
- **Middleware deny-list:** in `SecurityHeadersMiddleware` (or its pure-ASGI rewrite per A1), pop a wider list of fingerprinting headers:
  - `Server`, `X-Powered-By`, `Via`, `X-Runtime`, `X-AspNet-Version`, `X-Process-Time`
  - `Sentry-Trace`, `Baggage` — Sentry's ASGI integration may emit these on responses if `propagate_traces=True` ever flips; explicit pop keeps it safe.

**Acceptance criteria.**
1. No `Server`, `X-Powered-By`, `Via`, `X-Runtime`, `X-AspNet-Version`, `X-Process-Time`, `Sentry-Trace`, or `Baggage` header on any 2xx/3xx/4xx/5xx response (parametrised test across status codes).
2. Hadolint / Dockerfile CI green after the `CMD` change.
3. Test in `tests/security/test_security_headers.py` asserts absence (deny-list parametrised).

---

### B2 · CSP per response content-type

**Finding.** A single CSP (built for Swagger UI: `script-src 'self' https://cdn.jsdelivr.net`, `style-src 'self' 'unsafe-inline' …`) is applied to JSON and RSS responses. Those content-types render no scripts and no styles — the relaxed directives are dead weight that erode the "hardened by default" claim.

**Proposed design (revised — BA + SE feedback).** Invert the default: strict CSP is the floor, relaxed CSP is opt-in by route.
- `SecurityHeadersConfig.content_security_policy` defaults to the **strict floor**:
  ```
  default-src 'none'; frame-ancestors 'none'; base-uri 'none';
  form-action 'none'; object-src 'none'; script-src 'none'; style-src 'none'
  ```
  Note: `form-action` and `frame-ancestors` are NOT covered by `default-src` (CSP3 §6.1), must be listed explicitly.
- `/docs` and `/redoc` routes explicitly set the Swagger-UI-compatible CSP via `response.headers["Content-Security-Policy"] = build_csp(nonce)`.
- `/` (landing) keeps `build_landing_csp()`.
- No content-type sniffing in the middleware — removes coupling to response inspection, makes per-route control testable.
- **NEW headers added simultaneously**: `Cross-Origin-Resource-Policy: same-origin` and `Cross-Origin-Opener-Policy: same-origin` on all responses. Blocks Spectre-style cross-origin reads; safe for an API consumed by SIEMs (not browsers).

**Acceptance criteria.**
1. `GET /api/v1/threats?limit=1` CSP equals the strict floor; `Cross-Origin-Resource-Policy: same-origin` present.
2. `GET /api/v1/sectors/finance/feed.rss` same as #1.
3. `GET /api/v1/cve/CVE-9999-0000` (404 problem+json) same as #1 — strict CSP applies to errors too.
4. `GET /docs` CSP includes `cdn.jsdelivr.net` + `nonce-…` for script-src.
5. `GET /` (landing) CSP unchanged.
6. Parametrised test in `tests/security/test_security_headers.py`.

**Risk.** Browsers following CSP strictly might block third-party tooling that fetches our JSON via `<script>` (none today). Curl/HTTP libraries ignore CSP. Low risk.

---

### B3 · `HEAD` support on `/health`, `/docs`, `/api/v1/threats` (currently 405)

**Finding.** Cloud probes (Kubernetes liveness, uptime monitors like UptimeRobot/Pingdom) often default to `HEAD`. Today they get 405 with `Allow: GET`. Forcing GET wastes upstream bandwidth on `/api/v1/threats` (returns a paginated list per probe).

**Proposed design (revised — both agents flagged ASGI rewrite as DoS amplifier).**
- ASGI HEAD→GET rewrite is rejected: a `HEAD /api/v1/threats` would run the full DB query then discard the body, amplifying load on every uptime probe.
- **Use explicit `methods=["GET", "HEAD"]` on cheap endpoints only:** `/health`, `/docs`, `/redoc`, `/openapi.json`, `/`. These are constant-cost (or near-constant) responses; HEAD is safe.
- **Do NOT enable HEAD on `/api/v1/threats`** or any other paginated/DB-backed endpoint — uptime probes should use `/health`, not the data plane.

**Acceptance criteria.**
1. `HEAD /health` → `200`, body empty, headers identical to GET.
2. `HEAD /docs` → `200`, headers, no body.
3. `HEAD /` → `200`, headers, no body.
4. `HEAD /api/v1/threats` → `405` (intentional, per design — documented in OpenAPI).
5. `GET` behaviour unchanged on all routes (regression).

**Risk.** None significant; explicit-method approach is idiomatic in FastAPI.

---

### B4 · `X-RateLimit-*` and `Retry-After` headers on rate-limited responses

**Finding.** SlowAPI is wired but emits no rate-limit headers by default. Clients have no way to discover the budget or when they can retry. `docs/SECURITY.md` itself notes the in-memory storage caveat; missing headers compound it.

**Proposed design.**
- Pass `headers_enabled=True` to `Limiter(...)` in `src/threat_intel/api/security.py`. SlowAPI then emits `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` on 429.
- **Replace** the registered SlowAPI handler. The current line in `main.py`:
  ```python
  app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
  ```
  becomes a custom handler that returns `problem_response(request, 429, "Too Many Requests", "Rate limit exceeded", **{"Retry-After": seconds})`. Keeps the RFC 7807 contract on 429.
- `Retry-After` must be **integer seconds** (HTTP/1.1 §7.1.3 accepts both integer-seconds and HTTP-date; SIEMs handle integer reliably).

**Acceptance criteria.**
1. `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` present on any 200 from a rate-limited route.
2. Burst beyond limit → 429 with `Content-Type: application/problem+json`, body `{type, title:"Too Many Requests", status:429, detail, instance}`, `Retry-After: <integer>`.
3. New parametrised tests in `tests/security/test_rate_limiting.py`.

**Risk.** SlowAPI's in-memory storage means rate-limit numbers lie under multi-worker uvicorn; documented in `docs/SECURITY.md` already, keep the note.

---

### B5 · Collector counter coherence: `/health` vs `/sources`

**Finding.** `/health.collectors[*].threats_collected_24h` and `/api/v1/sources[*].events_24h` differ by 2–4 per source in steady state (and were wildly off — 0 vs 6368 — on Railway pre-fix). Two different queries against the same data, two different semantics, no docs.

**Investigation.** Both functions live in `src/threat_intel/services/threats.py` and `…/services/sources.py` (approx). Need to:
1. Identify the exact SQL difference (window calculation, source-row filter, threat vs event count).
2. Decide a single canonical semantic ("new threats from this source in last 24h" — counts distinct `threat_id` joined to `threat_source` filtered by `source_id` and `first_seen_at >= now-24h`).
3. Refactor both to call one helper.

**Proposed design (revised — BA reframed the semantic).**
- The right metric for both endpoints is **collector attestations in last 24h**: count of `threat_source` rows for this `source_id` with `first_seen_at >= now - 24h` (or `created_at` if first_seen is back-filled). NOT `count(distinct threat_id)` — a collector re-asserting an existing CVE is real activity a SIEM wants to see.
- Extract `source_attestations_24h(session, source_id) -> int` in `services.threats` (or `services.sources`).
- Both endpoints call the helper.
- Document the chosen semantic in `docs/COLLECTORS.md` ("Collector heartbeat = attestations in window, not unique threats discovered").

**Acceptance criteria.**
1. For every source, `/health.collectors[name].threats_collected_24h == /sources[name].events_24h` **when called inside the same session/transaction** (race-resilient).
2. The helper's SQL is unit-tested (in-memory sqlite fixture, multiple seeds — re-attestation produces +N, not +1).
3. `docs/COLLECTORS.md` updated.
4. **Field name change considered**: `threats_collected_24h` is misleading post-fix. Rename in `/health` schema to `attestations_24h` and bump the schema OR leave the name and document the semantic in OpenAPI description. **Decision: leave the name, document in OpenAPI description** — avoid breaking SIEM dashboards that scrape the field name; the *value* is what changes (and it changes for the better — was wrong before).

**Risk.** Dashboards pinned to the old (wrong) value see a one-time correction. Acceptable; release notes will call it out.

---

## Priority C — Cleanup

### C1 · Replace or delete `scripts/demo_seed.py` (pre-M3a, crashes)

**Finding (FND-1).** The script uses `Threat(external_id=…)` which the M3a schema migration removed. Running `python scripts/demo_seed.py` against current code raises `TypeError: 'external_id' is an invalid keyword argument for Threat`. Any new contributor following the README will hit this.

**Proposed design.** Two paths:
- **Delete** the script and replace with a one-shot CLI command (`python -m threat_intel.scripts.demo_seed`) that uses the current models. Cleaner.
- **Rewrite** in place to be M3a-compatible.

**Decision: rewrite in place** to keep the path `scripts/demo_seed.py` stable for anyone with bookmarks. The local audit produced a working post-M3a seed (`/tmp/seed_audit.py`) that can be adapted.

**Safety guardrail (SE review):** the script MUST refuse to run if `DATABASE_URL` points to anything other than a local dev host. Check: hostname is one of `localhost`, `127.0.0.1`, `db` (compose default), `postgres` (common compose alias). Any other host → fail with a clear message. Prevents an analyst from seeding fake threats into production.

**Acceptance criteria.**
1. `python scripts/demo_seed.py` runs to completion against a fresh `docker compose up` stack.
2. Produces ≥ 5 distinct threats across NVD/KEV/GHSA sources, scored against all 6 public sector profiles.
3. Aborts with non-zero exit + clear error when `DATABASE_URL` host is not in the allow-list above.
4. README's quick-start adds a note: *"Optionally seed demo data: `python scripts/demo_seed.py`."*
5. Smoke test in CI: a job that runs the seed against the compose stack and asserts non-zero threats.

---

### C2 · Trailing-slash discrepancy investigation

**Finding (FND-2).** Live pre-fix returned `307` on `/api/v1/threats/`; local post-fix returns `200`. Likely Railway proxy difference or FastAPI/Starlette default change with the 3.14-alpine bump. Worth verifying on the next deploy.

**Proposed design.** No code change unless the post-deploy audit re-surfaces the 307. Just a checklist item in the post-deploy audit:
- Probe `/api/v1/threats` with and without slash on Railway live.
- If 307, decide whether to set `app = FastAPI(redirect_slashes=False)` (returns 404 instead) or to add explicit no-slash routes.

**Acceptance criteria.** Documented behaviour post-deploy. No code change at this stage.

---

---

## Cross-cutting hardening (folded into the relevant branches above)

These came out of the agent reviews and don't deserve their own branch — they ride along with A1/A2/B1/B2 work.

### X1 · `Cache-Control: no-store` on every `problem_response`

**Why (SE review):** Cloudflare / Railway-edge / browser caches happily cache 4xx and 5xx by default. A poisoned 429 or 500 cached at edge becomes a free DoS amplifier — every subsequent client sees the error until TTL expires. RFC 7234 §4.2.2 makes 404 implicitly cacheable.

**Fix.** In `problem_response()`, set `headers={"Cache-Control": "no-store", "Pragma": "no-cache"}` on the JSONResponse. Folded into A2 (same helper change).

**AC.** All problem+json responses carry `Cache-Control: no-store`. Parametrised test.

### X2 · Strict CORS on admin endpoints

**Why (SE review):** Current CORS allows `allow_headers=["*", "X-Admin-Key"]`. Combined with admin routes mounted under the same `/api/v1` prefix, a CSRF-able SPA could in theory send `X-Admin-Key` from a browser if `CORS_ORIGINS` allows it.

**Fix.** Either (a) move admin routes to a separate router with no CORS, or (b) keep one router but reject any request whose `Origin` is non-empty on admin routes. Lean toward (b) — simpler, achieves the same goal. Add a dependency `forbid_browser_origin` on the admin router.

**AC.** A request to `/api/v1/admin/*` with `Origin: https://anything` is rejected with 403 problem+json regardless of `X-Admin-Key` presence. Folded into B1 work (same security headers cluster).

### X3 · OWASP API Top 10 mapping update in `docs/SECURITY.md`

**Why (SE review):** API8:2023 (Security Misconfiguration) and API9:2023 (Improper Inventory Management) mappings reference behaviours that change with B1 (Server header) and B2 (CSP per content-type). Drift would erase the compliance argument.

**Fix.** Update `docs/SECURITY.md` mapping table at the end of the umbrella PR cycle (NOT inside individual branches — keep doc edits cohesive).

**AC.** `docs/SECURITY.md` mentions every new control (server header strip, COOP/CORP, strict CSP floor, 429 problem+json, Cache-Control no-store).

---

## Sequencing / branches

One branch per finding, all targeting `dev`, then bundled into a single umbrella PR `dev → main`:

| # | Branch | Item | Effort |
|---|---|---|---|
| 1 | `fix/exception-handler-problem-json` | A1 | S |
| 2 | `fix/cors-preflight-instance-field` | A2 | XS |
| 3 | `fix/strip-server-header` | B1 | XS |
| 4 | `fix/csp-per-content-type` | B2 | S |
| 5 | `fix/head-method-support` | B3 | M |
| 6 | `fix/rate-limit-headers` | B4 | S |
| 7 | `fix/collector-counter-coherence` | B5 | M |
| 8 | `chore/demo-seed-m3a` | C1 | S |
| 9 | `docs/security-mapping-refresh` | X3 | XS — last, after all code branches merged |

C2 is investigation-only — no branch. X1 and X2 are folded into branches 2 and 3 respectively.

After every branch lands on `dev`, the second-pass audit re-runs against `localhost:8000`. The umbrella PR `dev → main` is opened only when:
- All 8 branches merged + CI green on `dev`
- Local audit (same script set as the first audit) re-validates A1–B5
- README updated where claims changed (e.g., test count)

---

## Testing strategy

- Unit tests live next to the handler they cover.
- Each item that affects HTTP shape adds to `tests/security/test_problem_json.py` or `tests/security/test_security_headers.py`.
- The umbrella PR keeps the coverage gate ≥ 80 %.
- A new file `tests/security/test_no_info_leak.py` covers: no fingerprinting headers (parametrised deny-list), no exception messages in 500 problem+json, no stack traces in any error path (parametrised over every endpoint that can produce 4xx/5xx).
- A new file `tests/security/test_middleware_ordering.py` proves: catch-all `Exception` handler fires for non-HTTPException raises from routes (the A1 trap).

## Definition of done for the umbrella PR

Before opening `dev → main`:
1. All 9 branches merged into `dev`, CI green on each.
2. Local audit (same probe script as audit pass 1) re-validates every AC.
3. Coverage gate ≥ 80 %; ideally ≥ 88 % (current).
4. `docs/SECURITY.md` mapping refreshed (X3).
5. README test count bumped to the new total.
6. CHANGELOG entry summarising user-visible changes (new `Cache-Control: no-store` on errors, strict CSP on JSON/RSS, etc.).
7. PR description includes the live before/after of one example per fix.
