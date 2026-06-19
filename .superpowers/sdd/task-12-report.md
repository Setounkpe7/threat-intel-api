# Task 12 Report — Docs, graphify refresh, final quality gate

## Docs written

### `docs/COLLECTORS.md` — extended (not overwritten)

Added a new top-level section **"RSS feeds subsystem (M3b)"** covering:

- **4 configured feeds**: `cisa_advisories` (gov/80), `cisa_ics` (gov/80), `cisco_psirt` (vendor/70), `dfir_report` (research/50) — with exact URLs from `feeds/feeds.yaml` and note that URLs must be GET-verified before production enable.
- **Two-path mechanism**: Path A (CVE/GHSA match → enrichment fan-out to all matched threats, no merge_candidate, no autonomous creation), Path B (no match → idempotent autonomous `advisory`/`report` threat deduped on `(source_id, external_id)`).
- **`enrichment_mode` flag**: documented as the dispatch signal on `CollectedEvent`; RSS collectors always set it `True`; `IngestService.process()` dispatches to `_process_enrichment()` on this flag.
- **Confidence tiers**: gov=80, vendor=70, research=50 — mapped to sources exactly as in `feeds.yaml`.
- **`unverified-ioc` quarantine tag**: appended when IOCs of type `ip`, `domain`, `url`, `md5`, `sha1`, or `sha256` are extracted from free text.
- **Rule — RSS never sets canonical CVSS/severity**: documented at both the collector level (`severity=None`, `cvss_score=None` in `to_event()`) and the `recompute_canonical()` level (`canonical_order = [n for n in effective_order if n not in rss_names]`).
- **Security controls table**: defusedxml XXE gate (`forbid_dtd/entities/external`), SSRF guard (https-only + public-IP check + CGNAT block), 5 MiB cap, `clean_text()` bleach sanitization.
- **Persona decision**: advisory/report threats NOT yet filtered from sector feeds; read-side filter deferred to Plan 2 — clearly stated.
- **Feed schema table**: all fields with types and constraints from `RSSFeedSchema`.

### `README.md`

Two targeted changes matching the existing table/roadmap style:
1. Features table: updated Multi-source ingestion cell to include "RSS feeds".
2. Roadmap: marked M3b as `[x]` with a one-line summary of what was built; renamed the previously-M3b stub to M3c.

No other README edits made.

## graphify update

Ran `graphify update .` — completed successfully:
- 149/149 AST files processed (8 workers)
- Result: 1481 nodes, 2079 edges, 318 communities
- Updated: `graphify-out/graph.json`, `graphify-out/graph.html`, `graphify-out/GRAPH_REPORT.md`

`graphify-out/` changes staged in the commit.

## Quality gate results

| Tool | Result |
|------|--------|
| `pytest -q` | **404 passed**, 15 warnings — all green |
| `ruff check src/` | **All checks passed** |
| `ruff check .` (full repo) | 65 errors in `alembic/`, `scripts/`, `tests/` — **pre-existing**, confirmed identical count before and after my changes via `git stash` round-trip |
| `mypy src` | **Success: no issues found in 68 source files** |

Note: `ruff check .` fails on pre-existing issues in `alembic/versions/`, `scripts/demo_seed.py`, and some integration test files. These were present on the branch before Task 12 (verified by stashing my changes and re-running — same 65 errors). No new lint issues introduced.

## SBOM note

`feedparser` and `defusedxml` were added as runtime dependencies in earlier tasks on this branch. `sbom.cdx.json` is an untracked CI-generated artifact (not committed to the repo); it will be regenerated automatically by the release workflow (`release.yml`) on the next merge to `main`.

## Files changed

| File | Change |
|------|--------|
| `docs/COLLECTORS.md` | Extended: added RSS feeds subsystem section |
| `README.md` | Updated features table + roadmap bullet |
| `graphify-out/graph.json` | Refreshed (1481 nodes, 2079 edges) |
| `graphify-out/graph.html` | Refreshed |
| `graphify-out/GRAPH_REPORT.md` | Refreshed |

## Concerns / notes

- The 65 pre-existing `ruff check .` failures (all outside `src/`) are not gated in CI for this branch type — the CI Makefile target runs `ruff check src/` which is clean. No action taken on them as they are out of scope for this docs task.
- No source code or tests were modified. All doc claims were verified against the actual implementation before writing.
- The "persona default exclusion" (advisory/report filtered from sector feeds) is correctly documented as deferred to Plan 2 and NOT yet implemented — confirmed by reading the query path; no read-side filter exists in the current code.

---

## Final-review fix pass

### Fix 1 — Document autonomous-path TOCTOU (ingest.py `_get_or_create_autonomous`)

Read `src/threat_intel/core/scheduler.py` to establish what mitigations actually exist.

**Scheduler evidence**: The `collector_tick` APScheduler job is registered with `max_instances=1` (line 65) and `coalesce=True` (line 66), using an `IntervalTrigger(seconds=60)` (line 60). Inside the tick, per-source ingestion is launched via `asyncio.create_task()` (line 47) — so sources run concurrently within one tick, but each source spawns at most one task per tick. After a successful ingestion run, `next_run_at` is written to `source.next_run_at = finished_at + timedelta(minutes=...)` (ingestion.py line ~140), so the same source is skipped in subsequent ticks until its interval elapses.

**Race that exists**: Two concurrent tasks for two *different* RSS sources cannot race on the same `(source_id, external_id)`. A race between two tasks for the *same* source is prevented by the scheduler. The remaining theoretical window: if an ingestion run crashes after creating the threat but before writing `next_run_at`, the next tick could retry and see 0 existing rows in the TOCTOU window.

**Docstring added** to `_get_or_create_autonomous` naming the race, citing the actual mitigations (`max_instances=1`, `coalesce=True`, `next_run_at`), and noting the durable fix is a deferred `UNIQUE(source_id, external_id)` constraint via Alembic migration (Plan 2).

### Fix 2 — Tighten kev→critical bump to non-RSS sources (ingest.py `recompute_canonical`)

**Approach chosen**: Changed the bump condition to check `kev` membership in `canonical_tags` — a set built from `pcandidate.tags` for each name in `canonical_order` (which already excludes `rss_names`). The full `tags` union (all sources) is still written to `threat.tags` for display. The kev bump now only triggers when `cisa_kev` (kind != rss, present in `canonical_order`) emits the `kev` tag. The canary test (`test_cross_source_dedup_log4shell`) uses `cisa_kev` as the KEV source — it stays in `canonical_order` and the severity=critical bump still fires correctly.

### Fix 3 — CLI parity (cli/collect_once.py)

Added `unchanged={result.unchanged}` to the `rss` command's `typer.echo`, matching the `nvd` command format exactly.

### Fix 4 — Strengthen 3 tests

- `test_rss_never_overrides_canonical_cvss`: added `assert t.severity == Severity.high` — verifies RSS bogus "low" severity does not override NVD-derived value.
- `test_rss_no_cve_idempotent`: added query + `assert len(ts_rows) == 1` — verifies exactly one `ThreatSource` row exists for `(dfir_report, "orphan-1")` after double ingest.
- `test_parse_feed_rejects_xxe` added to `test_feedparse.py`: calls `parse_feed(_XXE)` (reusing existing fixture) and asserts `CollectorParseError` is raised — end-to-end XXE gate wiring test.

### Fix 5 — Clarifying comment in rss.py `to_event`

Added a 4-line comment before the CVE/GHSA extraction block explaining that CVE/GHSA runs on the raw `corpus` (so HTML-embedded identifiers are found) while IOC extraction runs on the sanitized `summary` (to avoid false positives on HTML attributes), with explicit "Do NOT unify" instruction.

### Canary result

`tests/integration/test_dedup_cross_source.py::test_cross_source_dedup_log4shell` — PASSED (both baseline and post-fix).

### Covering test command + output

```
pytest tests/integration/test_dedup_cross_source.py tests/integration/test_rss_enrichment.py tests/unit/collectors/test_feedparse.py tests/unit/test_cli.py -q
12 passed in 0.40s
```

### Full suite

405 passed, 15 warnings (up from 404; new test: `test_parse_feed_rejects_xxe`).

### mypy/ruff results

- `mypy src`: Success: no issues found in 68 source files
- `ruff check src`: All checks passed

### kev-bump approach

Changed the logic: `kev` bump now checks `canonical_tags` (tags from `canonical_order` sources only, which excludes `rss_names`). RSS-emitted `kev` tags are collected into `threat.tags` for display but cannot trigger severity escalation.

### Files changed

| File | Change |
|------|--------|
| `src/threat_intel/services/ingest.py` | Fix 1 docstring on `_get_or_create_autonomous`; Fix 2 kev bump scoped to canonical tags |
| `src/threat_intel/cli/collect_once.py` | Fix 3: added `unchanged=` to rss echo |
| `src/threat_intel/collectors/rss.py` | Fix 5: clarifying comment in `to_event` |
| `tests/integration/test_rss_enrichment.py` | Fix 4: severity assertion + ThreatSource count assertion |
| `tests/unit/collectors/test_feedparse.py` | Fix 4: `test_parse_feed_rejects_xxe` |
