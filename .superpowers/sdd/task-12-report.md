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
