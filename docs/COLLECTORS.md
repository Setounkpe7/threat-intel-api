# Adding a new collector

This is a step-by-step guide for adding a new threat-intelligence source to the platform.

## Architecture

Collectors live in `src/threat_intel/collectors/` and form a two-level hierarchy:

```
BaseCollector (abstract)
├── APIRestCollector       # NVD, CISA KEV
└── APIGraphQLCollector    # GitHub Advisories
```

`BaseCollector` defines two abstract methods:
- `fetch(since: datetime) -> AsyncIterator[RawEvent]` — yields raw payloads from the upstream feed
- `to_event(raw: RawEvent) -> CollectedEvent` — translates a raw payload to the platform's canonical event schema

`APIRestCollector` provides `_get(url, params, headers)` with retries (`tenacity`, exponential backoff) and rate-limit awareness. `APIGraphQLCollector` provides `_execute_query(query, variables)` with bearer auth and a check on the GraphQL `errors` field. Both subclasses also handle the `enabled` flag — set to `False` automatically when an auth token is missing.

## The CollectedEvent contract

Every collector emits a `CollectedEvent` (see `src/threat_intel/schemas/ingest.py`) with:

- `source_name`, `external_id`, `title` — required identity fields
- `summary`, `severity`, `cvss_*`, `cwe_ids` — optional canonical-candidate fields
- `tags` — per-source tags (e.g. `["kev", "actively-exploited"]`)
- `indicators` — list of `(type, value)` pairs (e.g. `[("cve", "CVE-2021-44228"), ("package", "maven:org.apache.logging.log4j:log4j-core")]`)
- `published_at`, `last_modified_at` — timestamps
- `raw_data` — the original payload, plus the canonical fields restated under known keys (`title`, `summary`, `severity`, `cvss_score`, `cvss_vector`, `cvss_version`, `cwe_ids`, `references`, `affected_products`); the unmodified upstream payload lives under `_payload`

The `raw_data` redundancy is intentional: `recompute_canonical()` (in `services/ingest.py`) reads canonical fields directly from `raw_data` to apply field-level priority rules across sources without reparsing each upstream format.

## Field-level priority order

When multiple sources document the same Common Vulnerabilities and Exposures identifier (CVE), the canonical Threat fields are resolved in this order:

```python
_PRIORITY_ORDER = ("nvd", "github_advisories", "cisa_kev")
```

For each field (CVSS, severity, title, summary), the first source in the list that has a non-empty value wins. Tags and Common Weakness Enumeration (CWE) identifiers are unioned across all sources. Severity is then bumped to `critical` if the union of tags contains `kev` (KEV-listed vulnerabilities are critical by definition, since active exploitation is confirmed).

## Concurrency model

`IngestService.process()` runs the dedup lookup and the create/upsert sequence inside a single session/transaction. This is **single-task safe** — within one coroutine, no race can produce a duplicate Threat.

When two collectors processing the same CVE-ID land in the same scheduler tick (e.g. NVD and KEV both ingesting `CVE-2024-X`), both coroutines may pass the dedup lookup with zero matches and both may try to create the Threat. The `UNIQUE` constraint on `threat_indicators(threat_id, indicator_type, value)` fails one of the two transactions; the failure is captured in `IngestionService` as an event-level error and counted in `CollectorRun.events_failed`. The next ingestion of the same CVE-ID will dedup correctly against the surviving Threat.

This is acceptable for the platform's once-per-tick cadence. Stronger guarantees (advisory locks per CVE-ID, or `SERIALIZABLE` transactions) are out of scope for M3a.

## Checklist for adding a new collector

1. **Pick a base class** — REST/JSON → `APIRestCollector`, GraphQL → `APIGraphQLCollector`.
2. **Create the file** at `src/threat_intel/collectors/<name>.py`. Define class-level constants:
   - `source_name` (snake_case)
   - `source_kind` (`SourceKind.cve_feed`, `SourceKind.advisory`, `SourceKind.rss`)
   - `base_interval_minutes`
   - For REST: `base_url`, `auth_method`, `rate_limit_per_minute`
   - For GraphQL: `endpoint_url`, `auth_token_env`
3. **Implement `fetch`** — async generator yielding `RawEvent(external_id, payload, fetched_at)`. For paginated sources, loop until the upstream signals end-of-data.
4. **Implement `to_event`** — wrap parsing errors in `CollectorParseError`. Populate `CollectedEvent.indicators` with at least a `(cve, value)` indicator if the source publishes CVE identifiers (this is the dedup key with NVD/KEV/GHSA).
5. **Tags**: list every tag your source contributes in `CollectedEvent.tags`. The canonical Threat tags are the union of all per-source tags.
6. **Sanitize** any free-text fields with `bleach.clean(text, tags=[], strip=True)` before storage. The original markup stays in `raw_data["_payload"]`.
7. **Register the source** by adding a row to the `source` table in a new Alembic migration:

   ```python
   op.execute(
       "INSERT INTO source (name, kind, url, enabled, base_interval_minutes, "
       "current_interval_minutes, consecutive_failures, created_at, updated_at) "
       "VALUES ('mysource', 'cve_feed', 'https://...', 1, 120, 120, 0, "
       "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
       "ON CONFLICT (name) DO NOTHING"
   )
   ```

8. **Wire it in `main.py`** alongside the other collectors:

   ```python
   collectors = [NVDCollector(...), CISAKEVCollector(...), GitHubAdvisoriesCollector(...), MyCollector(...)]
   ```

9. **Tests**:
   - Real-shape JSON fixture under `tests/fixtures/<name>_sample.json`
   - Unit test `tests/unit/collectors/test_<name>.py`: `fetch` happy path with `respx`, `to_event` mapping table

## Reference implementations

- **NVD** (`src/threat_intel/collectors/nvd.py`) — REST with pagination via `startIndex`/`totalResults`, retry on 5xx
- **CISA KEV** (`src/threat_intel/collectors/cisa_kev.py`) — single-shot full-dump REST, no auth, conditional ransomware tag
- **GitHub Advisories** (`src/threat_intel/collectors/github_advisories.py`) — GraphQL cursor pagination, bearer auth, HTML sanitization

## Collector heartbeat

`/health.collectors[name].threats_collected_24h` and
`/api/v1/sources[name].events_24h` both report **collector attestations**
in the last 24 hours: the number of times a collector produced a
threat_source row for any threat. Re-assertions of an existing CVE count
as activity. This is intentionally NOT a count of distinct threats
discovered (which would mask a collector that is healthy but processing
a deduplicated stream).

Both fields are computed by `source_attestations_24h(session, source_name)`
in `src/threat_intel/services/threats.py`, which counts `threat_source`
rows where `first_seen_at >= now - 24h` for the named source. Field names
are left unchanged to avoid breaking SIEM dashboards; only the value
computation was unified (audit-pass-2, B5).
