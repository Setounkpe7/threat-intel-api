# CyberThreat Intelligence API — Milestone 3a Design

**Date:** 2026-04-29
**Status:** approved
**Scope:** Add CISA KEV and GitHub Security Advisories collectors. Refactor the collector hierarchy and the data model to support cross-source deduplication. Out of scope: RSS, URLhaus, OTX (M3b), webhooks, STIX/TAXII, NLP indicator extraction, manual Threat-merge workflows.

---

## 1. Goal

Move the platform from one source (NVD) to three (NVD + CISA KEV + GitHub Security Advisories) while preparing the architecture for further heterogeneous collectors (RSS, IOC feeds). A single CVE that appears in multiple sources must produce **one** `Threat` record with multiple `ThreatSource` rows attached to it. The sectoral scoring engine introduced in M2 must consume the new signals (KEV exploitation, multi-source confirmation, package-level matches).

## 2. Stack changes

| Item | Decision |
|---|---|
| New runtime dependency | `bleach` (sanitization of GitHub markdown/HTML before storage) |
| Existing dependency to verify | `httpx[http2]` (already used by NVD collector — confirm presence) |
| Auth secrets | `GITHUB_TOKEN` env var, optional. Absence ⇒ collector disabled at startup with a warning, no crash. |

No other stack changes. Logging stays on `structlog`, scheduler stays on `AsyncIOScheduler`, DB stays on async SQLAlchemy + Alembic.

## 3. Collector hierarchy

```
BaseCollector (ABC)
├── APIRestCollector       (NVD, CISA KEV, future RSS adapters)
└── APIGraphQLCollector    (GitHub Advisories, future GraphQL APIs)
```

### `BaseCollector`

```python
class BaseCollector(ABC):
    source_name: ClassVar[str]              # "nvd", "cisa_kev", "github_advisories"
    source_kind: ClassVar[SourceKind]
    base_interval_minutes: ClassVar[int]    # 60 (NVD), 360 (KEV), 120 (GHSA)

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None: ...

    @abstractmethod
    def fetch(self, since: datetime) -> AsyncIterator[RawEvent]: ...

    @abstractmethod
    def to_event(self, raw: RawEvent) -> CollectedEvent: ...
```

`extract_indicators` is **not** a separate method. The list of indicators is part of the `CollectedEvent` produced by `to_event()`. One fixture in, one DTO out — easier to test.

### `APIRestCollector`

Adds:
- `base_url: ClassVar[str]`
- `auth_method: ClassVar[Literal["none", "api_key", "bearer"]]`
- `rate_limit_per_minute: ClassVar[int]`
- `_rate_limited_get(url, **kwargs)` — wraps `self.http.get` with a token-bucket limiter (in-memory, per-collector instance).

The existing NVD collector is migrated to this class with **no behavioral change**. All M1 tests must still pass.

### `APIGraphQLCollector`

Adds:
- `endpoint_url: ClassVar[str]` (e.g. `"https://api.github.com/graphql"`)
- `auth_token_env: ClassVar[str]` (e.g. `"GITHUB_TOKEN"`)
- `_execute_query(query: str, variables: dict)` — wraps the GraphQL POST, raises on `errors`, surfaces rate-limit headers.

If the env var is absent at construction time, `enabled` is forced to `False` and a warning is logged via `structlog`. The scheduler skips it.

### Output DTO `CollectedEvent`

```python
class CollectedIndicator(BaseModel):
    type: Literal["cve", "ghsa", "cpe", "package", "ip", "domain", "url", "md5", "sha1", "sha256"]
    value: str

class CollectedEvent(BaseModel):
    source_name: str
    external_id: str

    # canonical-candidate fields (priority resolution lives in the service)
    title: str
    summary: str | None = None
    severity: Severity | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe_ids: list[str] = []

    # per-source metadata
    tags: list[str] = []
    indicators: list[CollectedIndicator] = []

    published_at: datetime
    last_modified_at: datetime
    raw_data: dict[str, Any]
```

## 4. Data model

### 4.1 `threats` (refactored)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | unchanged |
| `threat_type` | str | `"cve"`, `"advisory"` (extensible) |
| `title` | text | canonical, recomputed |
| `summary` | text nullable | canonical, recomputed |
| `severity` | enum | canonical, recomputed |
| `cvss_score`, `cvss_vector`, `cvss_version` | float / text | canonical, recomputed (NVD wins, falls back to GHSA, then KEV) |
| `cwe_ids` | JSON list | union across sources |
| `tags` | JSON list | union across sources, recomputed |
| `published_at` | datetime | `min(threat_sources.first_seen_at)` |
| `last_modified_at` | datetime | `max(threat_sources.last_seen_at)` |
| `created_at`, `updated_at` | from `TimestampMixin` | |

**Removed columns** (moved to `threat_sources`): `source_id`, `external_id`, `affected_products`, `references`, `raw_data`.

`affected_products` and `references` move to `threat_sources` because they are intrinsically per-source data — different sources document different package ranges and different reference URLs.

### 4.2 `threat_sources` (new)

| Column | Type | Notes |
|---|---|---|
| `threat_id` | UUID FK ON DELETE CASCADE | part of PK |
| `source_id` | int FK | part of PK |
| `external_id` | str(128) | `CVE-…`, `GHSA-…` |
| `first_seen_at` | datetime | first ingestion of this `(threat, source)` |
| `last_seen_at` | datetime | refreshed on each re-ingestion |
| `tags` | JSON list | tags applied **by this source** |
| `affected_products` | JSON list | per-source |
| `references` | JSON list | per-source |
| `raw_data` | JSONB | full original payload |

PK: `(threat_id, source_id)`. INDEX on `(source_id, external_id)` to support same-source upserts.

### 4.3 `threat_indicators` (new)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `threat_id` | UUID FK ON DELETE CASCADE | |
| `indicator_type` | enum | `cve`, `ghsa`, `cpe`, `package`, `ip`, `domain`, `url`, `md5`, `sha1`, `sha256` |
| `value` | str(512) | |
| `first_seen` | datetime | |
| `confidence` | int | 0–100, default 100 for official APIs |

UNIQUE `(threat_id, indicator_type, value)` — no duplicate indicator per Threat.
INDEX on `(indicator_type, value)` — supports IOC reverse lookup and dedup.

### 4.4 `source` (extended)

Existing columns kept (`name`, `kind`, `url`, `enabled`, `last_run_at`, `last_success_at`, `last_error`). Added:

| Column | Type | Default |
|---|---|---|
| `consecutive_failures` | int | 0 |
| `current_interval_minutes` | int | seeded equal to `base_interval_minutes` by the migration; not a SQL default |
| `base_interval_minutes` | int | seeded per source by the migration (NVD: 60, KEV: 360, GHSA: 120) |
| `next_run_at` | datetime nullable | NULL (NULL means "due now") |

### 4.5 `collector_runs` (new)

| Column | Type |
|---|---|
| `id` | int PK |
| `source_id` | int FK |
| `started_at` | datetime |
| `finished_at` | datetime nullable |
| `status` | enum (`running`, `success`, `failure`, `partial`). `partial` = at least one event ingested AND at least one event failed before the run terminated (e.g. paginated fetch errored after page 3 of 4) |
| `events_fetched` | int |
| `events_new` | int |
| `events_updated` | int |
| `events_failed` | int |
| `error_message` | text nullable |
| `duration_ms` | int nullable |

INDEX on `(source_id, started_at DESC)` for the `/sources/{id}/runs` endpoint.

### 4.6 Migration `0003_m3a_cross_source_schema.py`

The migration runs in this order in `upgrade()`:

1. Create `threat_sources`, `threat_indicators`, `collector_runs`. Add new columns to `source` and `threats`.
2. **Data migration** (raw SQL or `op.execute` with SQLAlchemy core):
   - For each existing `threat` row (NVD-only): `INSERT INTO threat_sources (threat_id, source_id, external_id, first_seen_at, last_seen_at, tags, affected_products, references, raw_data) SELECT ...`.
   - Extract indicators from each row's `raw_data`:
     - one `(cve, external_id)` indicator per Threat,
     - one `(cpe, value)` indicator per CPE found in `raw_data.configurations` (best-effort, skip if absent).
   - UPDATE the existing Source row (NVD) with `base_interval_minutes=60`, `current_interval_minutes=60`.
   - INSERT the two new sources: `cisa_kev` (base_interval=360) and `github_advisories` (base_interval=120).
3. DROP from `threats`: `source_id`, `external_id`, `affected_products`, `references`, `raw_data`.
4. ADD to `threats`: `threat_type` (default `"cve"` for the backfill), `summary`, `tags` (default `[]`).

`downgrade()` reverses the schema strictly. The data migration is **not reversed** — `downgrade` is a schema-only path used for local development. This is documented in the migration docstring.

## 5. Ingestion service

### 5.1 `IngestService.process(event: CollectedEvent) -> tuple[Literal["created","updated"], UUID]`

Steps:

1. **Dedup lookup** — for each indicator in `event.indicators` whose type is `cve` or `ghsa`, query `threat_indicators` for a matching `(type, value)`. Collect the set of matching `threat_id`s.
2. **Resolve target Threat:**
   - 0 matches → **create** new `Threat` (default `threat_type` = `"cve"` if any CVE indicator, else `"advisory"`).
   - 1 match → reuse it.
   - 2+ matches → **gnarly case A**: log a structured `merge_candidate` warning (`level=warning`, `event="merge_candidate"`, `winner_threat_id=...`, `other_threat_ids=[...]`, `triggered_by=<external_id>`). Pick the oldest by `created_at`. Append `cross_references=[...]` into the `ThreatSource.raw_data` we are about to write.
3. **Upsert ThreatSource** — `INSERT ... ON CONFLICT (threat_id, source_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, raw_data = EXCLUDED.raw_data, tags = EXCLUDED.tags, affected_products = EXCLUDED.affected_products, references = EXCLUDED.references`. Result decides `created` vs `updated`.
4. **Upsert indicators** — `INSERT ... ON CONFLICT (threat_id, indicator_type, value) DO NOTHING`.
5. **`recompute_canonical(threat_id)`** — see 5.2.
6. Return `("created"|"updated", threat_id)`.

### 5.2 `recompute_canonical(threat_id)`

Pure function (no I/O beyond the single DB read + write it performs). Reads all `ThreatSource` rows for the Threat and applies field-level priority:

| Field | Resolution rule |
|---|---|
| `cvss_score`, `cvss_vector`, `cvss_version` | NVD if present; else first non-null in source order (NVD → GHSA → KEV) |
| `cwe_ids` | union of all sources |
| `severity` | NVD if present; else GHSA; else KEV; bumped to `critical` if tag `kev` is in the union |
| `title` | NVD if present; else GHSA; else KEV |
| `summary` | NVD if present; else GHSA; else KEV |
| `tags` | union of all `ThreatSource.tags` |
| `published_at` | min of `ThreatSource.first_seen_at` |
| `last_modified_at` | max of `ThreatSource.last_seen_at` |

The function is idempotent and rejouable: replaying it after a settings change in the priority rules will repair canonical fields without re-ingesting raw data.

### 5.3 Sanitization

`bleach.clean(text, tags=[], strip=True)` is applied inside each collector's `to_event()` on `title`, `summary`, and any other free-text field that comes from an external API. The unsanitized markdown/HTML stays in `raw_data` for downstream re-rendering if ever needed.

## 6. Collectors

### 6.1 CISA KEV

- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Auth: none. `auth_method = "none"`.
- Frequency: 360 min (every 6 h).
- `fetch()`: download the full JSON dump, yield one `RawEvent` per `vulnerabilities[]` item. No incremental — dedup happens DB-side.
- `to_event()` mapping:
  - `cveID` → `external_id`, plus `(cve, cveID)` indicator
  - `vulnerabilityName` → `title`
  - `shortDescription` → `summary`
  - `dateAdded` → first `RawEvent.fetched_at` proxy (used as `first_seen_at` if Threat is new)
  - `dueDate`, `requiredAction`, `notes` → kept inside `raw_data`
  - `knownRansomwareCampaignUse == "Known"` → tag `ransomware`
- Tags applied by this source: `["kev", "actively-exploited"]` always, plus `["ransomware"]` conditionally.
- Severity: not exposed by KEV. Leave `severity = None`; canonical resolution will pick another source's severity, then bump to `critical` because of the `kev` tag.

### 6.2 GitHub Security Advisories

- Endpoint: `https://api.github.com/graphql`.
- Auth: bearer `GITHUB_TOKEN`. Missing token → `enabled = False`, warning logged once at startup, scheduler skips.
- Frequency: 120 min.
- Pagination: cursor on `securityAdvisories.pageInfo.endCursor`. Loop `while page_info.hasNextPage`.
- Page size: `first: 50` for advisories, `first: 20` for nested `vulnerabilities`, `first: 10` for `cwes`.
- Query (final form):

  ```graphql
  query SecurityAdvisories($since: DateTime!, $cursor: String) {
    securityAdvisories(first: 50, publishedSince: $since, orderBy: { field: PUBLISHED_AT, direction: ASC }, after: $cursor) {
      pageInfo { hasNextPage, endCursor }
      nodes {
        ghsaId
        summary
        description
        severity
        publishedAt
        updatedAt
        identifiers { type, value }
        vulnerabilities(first: 20) { nodes { package { ecosystem, name }, vulnerableVersionRange } }
        references { url }
        cwes(first: 10) { nodes { cweId } }
      }
    }
  }
  ```

- `to_event()` mapping:
  - `ghsaId` → `external_id`, plus `(ghsa, ghsaId)` indicator
  - Each `identifiers[]` of type `CVE` → `(cve, value)` indicator (this is the dedup key with NVD/KEV)
  - `summary` → `title` (after `bleach.clean`)
  - `description` → DTO `summary` (after `bleach.clean`)
  - `severity` → `Severity` (mapping `CRITICAL → critical`, `HIGH → high`, `MODERATE → medium`, `LOW → low`)
  - `publishedAt` → `published_at`; `updatedAt` → `last_modified_at`
  - Each `vulnerabilities.nodes[].package` → indicator `(package, "{ecosystem}:{name}")` (lowercased ecosystem)
  - Each `cwes.nodes[].cweId` → appended to `cwe_ids`
  - All `references[].url` → kept under `references` in `raw_data` — they go into `ThreatSource.references` via the service
- Tags applied by this source: `["github-advisory"]` plus one tag per affected ecosystem (e.g. `npm`, `pypi`, `maven`).

### 6.3 NVD (refactored, no behavior change)

Migrate the existing NVD collector to inherit from `APIRestCollector`. Replace its `normalize()` with `to_event()`. The DTO already carries `cwe_ids`, `cvss_*`, etc. — same data, new envelope. Tags applied by this source: `["nvd"]`. M1 tests must keep passing without modification beyond constructor signatures and DTO type names.

## 7. Scheduler & resilience

- Tick interval: 60 s.
- Each tick: `SELECT * FROM source WHERE enabled = TRUE AND (next_run_at IS NULL OR next_run_at <= NOW())`.
- For each eligible source: insert `CollectorRun(status="running")`, dispatch the collector via `asyncio.create_task`. Exceptions are caught at the task boundary — they update the run row to `status="failure"` and never propagate to the scheduler.
- After each run:
  - On success: `Source.last_success_at = NOW()`, `consecutive_failures = 0`, `current_interval_minutes = base_interval_minutes`, `next_run_at = NOW() + current_interval_minutes`.
  - On failure: `Source.last_error = <message>`, `consecutive_failures += 1`. If `consecutive_failures >= 3`: `current_interval_minutes = min(current_interval_minutes * 2, 1440)`. `next_run_at = NOW() + current_interval_minutes`.
- `events_new` counts `("created", _)` returns from `IngestService.process`. `events_updated` counts `("updated", _)`.
- Manual trigger via the admin endpoint creates a `CollectorRun` and dispatches the coroutine **without modifying** `next_run_at` (manual runs do not displace the schedule).

## 8. Scoring (extension of M2)

Additions to `score_breakdown`:

| Criterion | Points |
|---|---|
| Threat has tag `kev` | +25 |
| Threat has tag `actively-exploited` | +15 |
| Threat has tag `ransomware` | +15 |
| Threat is documented by 2 sources | +5 |
| Threat is documented by 3+ sources | +10 (replaces the +5) |
| At least one indicator of type `package` matches a profile `technology` (case-insensitive comparison against the package name part, e.g. `npm:react` matches `React`) | +20 |

Each criterion adds a labelled entry to `score_breakdown` (e.g. `{"label": "actively-exploited", "points": 15}`).

## 9. API endpoints

All under `/api/v1`. Read endpoints public; admin endpoints behind `X-Admin-Key`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/sources` | Dashboard view: per-source `name`, `enabled`, `last_run_at`, `last_success_at`, `consecutive_failures`, `next_run_at`, count of events ingested in the last 24 h |
| GET | `/sources/{id}/runs` | Last 50 `CollectorRun` for that source, newest first |
| GET | `/threats/{id}/sources` | All `ThreatSource` for the Threat with `external_id`, `first_seen_at`, `last_seen_at`, source name |
| GET | `/indicators?type=&value=` | Returns `[Threat]` whose indicators match. Required query params; 400 if either is missing |
| POST | `/admin/collectors/{name}/trigger` | Inserts a `CollectorRun` and dispatches |
| POST | `/admin/collectors/{name}/enable` | Sets `Source.enabled=True`, resets `consecutive_failures`, sets `next_run_at=NOW()` |
| POST | `/admin/collectors/{name}/disable` | Sets `Source.enabled=False` |

Response schemas live in `schemas/api/sources.py`, `schemas/api/indicators.py`, `schemas/api/admin.py`.

## 10. Repository changes

```
src/threat_intel/
├── collectors/
│   ├── base.py                     # BaseCollector + APIRestCollector + APIGraphQLCollector
│   ├── nvd.py                      # adapted to APIRestCollector, no behavior change
│   ├── cisa_kev.py                 # NEW
│   └── github_advisories.py        # NEW
├── models/
│   ├── threat.py                   # refactored
│   ├── threat_source.py            # NEW
│   ├── threat_indicator.py         # NEW
│   ├── collector_run.py            # NEW
│   └── source.py                   # extended
├── schemas/
│   ├── ingest.py                   # NEW (CollectedEvent, CollectedIndicator)
│   └── api/
│       ├── sources.py              # NEW
│       ├── indicators.py           # NEW
│       └── admin.py                # NEW
├── services/
│   ├── ingest.py                   # IngestService.process + recompute_canonical
│   └── scheduler.py                # adapted for backoff + parallel isolation
├── api/v1/
│   ├── sources.py                  # NEW
│   ├── indicators.py               # NEW
│   ├── threats.py                  # add /threats/{id}/sources
│   └── admin.py                    # NEW
└── core/
    └── config.py                   # add GITHUB_TOKEN (optional)

alembic/versions/
└── 0003_m3a_cross_source_schema.py # NEW

tests/
├── unit/collectors/
│   ├── test_cisa_kev.py
│   └── test_github_advisories.py
├── unit/services/
│   ├── test_ingest_dedup.py
│   └── test_recompute_canonical.py
├── integration/
│   ├── test_dedup_cross_source.py
│   ├── test_collector_resilience.py
│   └── api/
│       ├── test_sources_endpoint.py
│       ├── test_indicators_endpoint.py
│       └── test_admin_endpoints.py
└── fixtures/
    ├── cisa_kev_sample.json
    └── ghsa_sample.json
```

## 11. Tests

Coverage target: **85% on new code** (collectors + services + API additions). M1 + M2 tests must remain green.

Critical test cases:

- **Dedup cross-source happy path:** ingest CVE-2021-44228 (Log4Shell) via NVD → KEV → GHSA in that order. Assert: 1 Threat, 3 ThreatSource rows, indicators include `(cve, CVE-2021-44228)`, `(ghsa, GHSA-...)`, multiple `(cpe, ...)`, multiple `(package, ...)`. Tags union includes `nvd`, `kev`, `actively-exploited`, `github-advisory`, plus the matching ecosystem tags.
- **Out-of-order ingestion:** same CVE via KEV first, then NVD. After NVD ingestion, canonical `cvss_score` and `title` come from NVD (priority A), `severity` is bumped to `critical` due to KEV tag.
- **Multi-match warning:** GHSA referencing two CVEs that already exist as separate Threats. Assert: ThreatSource attached to oldest Threat, structured warning emitted, no merge.
- **Idempotency:** ingest the same KEV dump twice; expect zero new events on the second pass, `events_updated == events_fetched`.
- **GHSA without token:** instantiate `GitHubAdvisoriesCollector` with `GITHUB_TOKEN` unset. Assert `enabled is False`, warning logged, scheduler skips.
- **Resilience:** simulate a 500 from GitHub via `respx`. Assert NVD and KEV runs in the same scheduler tick complete normally; the GHSA `CollectorRun` is `status="failure"` with the error message; `consecutive_failures = 1`; backoff rule applies after the 3rd consecutive failure.
- **Scoring:** Threat with tags `["kev", "actively-exploited"]` against a profile listing `React` and a `(package, "npm:react")` indicator yields `25 + 15 + 20` from the new criteria.
- **API:** the 6 new endpoints, including 400 on missing `type/value` for `/indicators`, 401 without `X-Admin-Key` for admin routes, 404 for unknown collector name on `trigger`.

Fixtures: real-shape JSON from CISA and a recorded GHSA payload, both stored in `tests/fixtures/`. No live network calls in CI — `respx` mocks for HTTP, file reads for fixtures.

## 12. Documentation

- **README** updates:
  - "Sources" section with a table (name, type, frequency, auth required, link to public docs).
  - Mermaid pipeline diagram updated to show three sources fanning into a single ingestion service.
  - Quick-start: mention `GITHUB_TOKEN` (optional).
  - Project stats updated (1 → 3 sources).
- **`docs/COLLECTORS.md`** (new) — guide for adding a new collector, with a checklist (subclass choice, settings, fixture, mapping table, tags, indicators, tests, registration in `Source` table via Alembic).
- **`docs/INDICATORS.md`** (new) — list of indicator types, sample queries against `/indicators`, examples of dedup behavior.
- **`.env.example`** — `GITHUB_TOKEN=` with a comment linking to `https://github.com/settings/tokens` and noting that no scope is required for public advisories.

## 13. DevSecOps continuity

- `GITHUB_TOKEN` validated by `Settings` (Pydantic), never logged, never written to `raw_data`.
- Strict Pydantic schemas for the GHSA GraphQL response and the CISA KEV JSON. A breaking change in either feed surfaces as a validation error in a `CollectorRun`, not a silent corruption.
- All free-text from external feeds is sanitized via `bleach.clean(text, tags=[], strip=True)` before storage. Raw payloads stay in `raw_data` for audit only — they are never rendered as HTML by the API.
- `structlog` log lines for every run carry `source_name`, `run_id`, `events_*` counters, and the truncated error message on failure. Tokens never appear.
- Existing CI (lint, mypy --strict, pytest, SBOM) gates the PR. Pipeline must stay green.

## 14. Acceptance criteria

- The 3 collectors run side by side without interference; a forced 500 on one does not affect the others.
- A single CVE ingested by all 3 sources yields 1 `Threat`, 3 `ThreatSource`, indicators merged, tags unioned.
- `/api/v1/threats/{id}/sources` exposes the cross-source correlation in one call.
- `/api/v1/sources` is usable as a live health dashboard.
- `/api/v1/indicators?type=cve&value=CVE-...` returns the matching Threat(s).
- Sectoral score for a KEV-tagged Threat affecting a profiled technology is materially higher than the same Threat without those signals.
- All M1 + M2 + M3a tests pass; coverage on new code ≥ 85 %.
- CI/CD pipeline passes on the PR that ships M3a.

## 15. Out of scope (explicit)

- RSS feeds, URLhaus, OTX (M3b).
- Webhooks, STIX/TAXII (M4).
- NLP indicator extraction.
- Automatic merge of two existing Threats (only logged as `merge_candidate`).
- Automatic purge of the `kev` tag when a CVE is removed from the KEV catalog (limitation acknowledged for M3b).
- Zero-downtime migration. The Alembic migration runs in a single Railway deploy window; the data migration is small enough (~1k–10k rows) to complete in seconds.
