# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Portfolio-oriented `README.md` rewrite with project metrics, action links and sector-aware scoring example.
- SVG banner `docs/assets/banner-rich.svg`.
- Animated hero GIF (`docs/assets/screenshots/hero-demo.gif`, 1.1 MB, 32 s) rendered from `docs/assets/hero-demo.tape` using [charmbracelet/vhs](https://github.com/charmbracelet/vhs). Reproducible with `docs/assets/hero-demo.Dockerfile`, which adds `curl` and `jq` to the upstream VHS image.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`.
- `docs/INSTALLATION.md` and `docs/API_USAGE.md` as authoritative install and API references.
- GitHub issue templates (bug report, feature request) and a pull request template.

### Changed
- README structure split into a portfolio-facing surface (this `README.md`) and audience-specific docs under `docs/`.

## [0.1.0] — 2026-04-30

First public release. The API is reachable at <https://threat-intel-api-production.up.railway.app/>.

### Added
- **Ingestion**
  - NVD collector (REST/JSON, hourly).
  - CISA KEV collector (REST/JSON, every 6 hours).
  - GitHub Advisories collector (GraphQL, every 2 hours).
  - `IngestService` with cross-source deduplication and field-level priority.
  - `BaseCollector` contract — `fetch(since)` + `to_event(raw)`.
- **Scoring**
  - `SectorScoringService` and `SectorProfileLoader`.
  - 6 public sector profiles: e-commerce, finance, government, healthcare, ICS, SaaS.
  - Hot-reload of profiles via `POST /api/v1/admin/reload-profiles`.
  - Per-criterion auditable score breakdown.
- **API surface** (`/api/v1/`)
  - `/threats`, `/cve/{id}`, `/threats/{id}/sources`.
  - `/sectors`, `/sectors/{id}`, `/sectors/{id}/threats`, `/sectors/{id}/dashboard`, `/sectors/{id}/feed.rss`.
  - `/sources` (collector health), `/indicators` (reverse IOC lookup), `/stats/global`.
  - `/health` with DB state and per-collector last-run.
  - Admin: `/admin/reload-profiles`, `/admin/rescore-all`.
  - Swagger UI at `/docs`, OpenAPI at `/openapi.json`.
- **Security**
  - Hardened multi-stage Alpine container (~195 MB, non-root uid 1001).
  - 7-job CI security gate: ruff, mypy, pytest with coverage, bandit, semgrep, pip-audit, trivy, hadolint, gitleaks.
  - Security headers middleware, per-IP rate limiter, RFC 7807 error responses.
  - Coordinated disclosure policy in `SECURITY.md`.
  - OWASP API Top 10 mapping in `docs/SECURITY.md`.
- **Operations**
  - Production deploy on Railway with managed Postgres.
  - Branch-protected `main`, PR-only path, security gate required.
  - Sentry error capture, structlog JSON logs with PII scrubbing.

### Known issues
- The GitHub Advisories collector is currently failing in production; tracked for stabilization in M3b. NVD and CISA KEV are unaffected.

[Unreleased]: https://github.com/Setounkpe7/threat-intel-api/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Setounkpe7/threat-intel-api/releases/tag/v0.1.0
