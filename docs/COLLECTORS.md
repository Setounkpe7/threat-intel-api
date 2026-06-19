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

---

## RSS feeds subsystem (M3b)

### Overview

RSS/Atom feeds are ingested by `RSSCollector` (`src/threat_intel/collectors/rss.py`), a
config-driven collector instantiated once per feed from `feeds/feeds.yaml`. One
`RSSFeedLoader` (`src/threat_intel/services/rss_feed_loader.py`) reads that file on
startup and builds the collector list; the collectors are then registered alongside NVD,
KEV and GHSA in `main.py`.

### Configured feeds

All four feeds are enabled in `feeds/feeds.yaml`. **Each URL must be verified with a
real GET before enabling in production** (the comment in the YAML file states this
explicitly).

| `source_name`      | `threat_type` | `indicator_confidence` | Tier     | Interval |
|--------------------|---------------|------------------------|----------|----------|
| `cisa_advisories`  | `advisory`    | 80                     | gov      | 120 min  |
| `cisa_ics`         | `advisory`    | 80                     | gov      | 120 min  |
| `cisco_psirt`      | `advisory`    | 70                     | vendor   | 240 min  |
| `dfir_report`      | `report`      | 50                     | research | 240 min  |

URLs (from `feeds.yaml`):

- `cisa_advisories` → `https://www.cisa.gov/cybersecurity-advisories/all.xml`
- `cisa_ics` → `https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml`
- `cisco_psirt` → `https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml`
- `dfir_report` → `https://thedfirreport.com/feed/`

### Two-path ingestion mechanism

Every `CollectedEvent` emitted by an `RSSCollector` has `enrichment_mode=True`.
`IngestService.process()` dispatches on this flag into `_process_enrichment()`, which
applies one of two paths:

**Path A — CVE/GHSA match (enrichment):**
If any indicator in the event (`cve` or `ghsa` type) matches an existing `Threat`,
the RSS source row and its indicators are attached to **each** matched threat (fan-out).
Every matched threat is recomputed via `recompute_canonical()`. No merge_candidate
logic fires; no new autonomous threat is created. This is the multi-source enrichment
path for items that cite a known vulnerability.

**Path B — no CVE/GHSA match (autonomous threat):**
If no existing threat matches, an autonomous `Threat` is created with
`threat_type = event.threat_type` (`"advisory"` or `"report"`). Subsequent ingestion
of the same RSS item deduplicates idempotently on `(source_id, external_id)` via
`_get_or_create_autonomous()`, which looks up an existing `ThreatSource` row before
creating a new `Threat`. This dedup key is stable because `external_id` is computed
deterministically from the RSS item's `<guid>` / `<link>` / title / published date by
`stable_external_id()` in `_extract.py`.

### `enrichment_mode` flag

`CollectedEvent.enrichment_mode` (defined in `src/threat_intel/schemas/ingest.py`,
default `False`) signals to `IngestService` that an event was produced by an RSS
collector and must follow the enrichment regime rather than the canonical CVE dedup
regime. Setting `severity=None` and `cvss_score=None` in `RSSCollector.to_event()` is
the collector-side convention; the `recompute_canonical()` exclusion (see below) is the
enforcement-side guarantee.

### Confidence tiers

`indicator_confidence` controls the weight given to IOCs extracted from an RSS item
when stored in `ThreatSource`. Three tiers are in use:

| Tier       | Value | Sources                       |
|------------|-------|-------------------------------|
| government | 80    | `cisa_advisories`, `cisa_ics` |
| vendor     | 70    | `cisco_psirt`                 |
| research   | 50    | `dfir_report`                 |

### `unverified-ioc` quarantine tag

When `RSSCollector.to_event()` extracts IOCs of type `ip`, `domain`, `url`, `md5`,
`sha1`, or `sha256` from the item text, it appends the tag `"unverified-ioc"` to the
event's tag list. This signals downstream consumers that those indicators come from an
unstructured free-text source and have not been validated by a structured feed.

### Rule: RSS sources NEVER set canonical CVSS / severity

`RSSCollector.to_event()` always sets `severity=None` and `cvss_score=None` on the
emitted `CollectedEvent`. In `recompute_canonical()` (`src/threat_intel/services/ingest.py`),
RSS sources are identified by `source.kind == SourceKind.rss` and collected into
`rss_names`. The `canonical_order` list used for CVSS and severity resolution is
built by **excluding** every name in `rss_names`:

```python
canonical_order = [n for n in effective_order if n not in rss_names]
```

RSS sources are still included in `effective_order` for title/summary resolution
(where `_first_str` iterates all sources), but they can never influence the
`cvss_score`, `cvss_vector`, `cvss_version`, or `severity` fields of any threat.

### Security controls

| Control | Implementation |
|---------|---------------|
| **XXE / entity-expansion** | `defusedxml` safety gate in `_feedparse.py`: every feed is parsed once with `DefusedET.fromstring(forbid_dtd=True, forbid_entities=True, forbid_external=True)` before `feedparser` processes it. Any `DefusedXmlException` raises `CollectorParseError` and aborts ingestion of that feed. |
| **SSRF** | `assert_fetchable_url()` in `_net.py`: scheme must be `https`; the feed hostname is DNS-resolved and every returned IP is checked — private, loopback, link-local, reserved, multicast, unspecified, and RFC 6598 CGNAT (`100.64.0.0/10`) addresses are all blocked. |
| **Size cap** | Streaming download in `RSSCollector.fetch()` accumulates chunks and raises `CollectorHTTPError` if the total exceeds **5 MiB** (`MAX_FEED_BYTES = 5 * 1024 * 1024`). |
| **HTML sanitization** | `clean_text()` in `_sanitize.py` first strips `<script>…</script>` blocks (regex), then runs `bleach.clean(tags=[], strip=True)` to remove all remaining tags. Applied to `title` and `summary` before storing in `CollectedEvent`. |

### Persona decision — advisory/report threats excluded from sector feeds (Plan 2)

Items that become autonomous `advisory`/`report` threats (Path B above) are **not yet
filtered out of sector feeds**. The validated design decision is that such threats
should be excluded from sector-scored feeds and threat lists by default, with an
opt-in parameter (`?include_advisories=true`). This read-side filter is intentionally
deferred to **Plan 2** (a separate implementation plan). Until Plan 2 ships,
`advisory` and `report` threats surface in sector feeds alongside `cve` threats.

### Adding or modifying a feed

Edit `feeds/feeds.yaml`. The schema is validated at startup by `RSSFeedSchema`
(`src/threat_intel/schemas/rss_feed.py`) — invalid entries are skipped with a warning
log rather than crashing the process. Fields:

| Field | Type | Constraints | Description |
|-------|------|------------|-------------|
| `source_name` | `str` | 1–64 chars, unique | Used as the `Source.name` DB key |
| `url` | `str` | — | Must be `https`; verified by SSRF guard at fetch time |
| `threat_type` | `"advisory"` \| `"report"` | — | Determines `Threat.threat_type` for no-CVE items |
| `interval_minutes` | `int` | 15–1440 | Polling cadence |
| `indicator_confidence` | `int` | 0–100 | Per-IOC confidence weight |
| `default_tags` | `list[str]` | — | Tags always attached (e.g. `source:cisa_advisories`) |

---

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
