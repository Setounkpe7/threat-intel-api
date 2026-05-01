# API usage

Working examples against the live deployment. Replace the host with `http://localhost:8000` for local runs.

```
BASE=https://threat-intel-api-production.up.railway.app
```

The interactive Swagger UI is at [`$BASE/docs`](https://threat-intel-api-production.up.railway.app/docs); the machine-readable schema is at `$BASE/openapi.json`.

## Conventions

- All times are UTC, ISO 8601 (`2026-05-01T16:10:36Z`).
- Errors are returned as `application/problem+json` (RFC 7807) with `type`, `title`, `status`, `detail`.
- Public endpoints are rate-limited to 100 requests/minute per source IP. The response carries `Retry-After` on 429.
- Pagination uses `limit` (default 50, max 200) and `offset`.
- Admin endpoints require `X-Admin-Key: <ADMIN_API_KEY>`.

## Health

```bash
curl -s "$BASE/health" | jq
```

```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime_seconds": 1640,
  "database": "connected",
  "collectors": {
    "nvd":         { "last_run": "2026-05-01T16:10:36Z", "last_success": true,  "threats_collected_24h": 26113 },
    "cisa_kev":    { "last_run": "2026-05-01T14:55:03Z", "last_success": true,  "threats_collected_24h": 1586 },
    "github_advisories": { "last_run": null,             "last_success": false, "threats_collected_24h": 0 }
  },
  "stats": { "total_threats": 27695, "threats_last_24h": 273 }
}
```

Use this endpoint as a probe for orchestration and as an ingestion-pipeline status board.

## Threats

### List, filterable

```bash
curl -s "$BASE/api/v1/threats?severity=critical&since=2026-04-25T00:00:00Z&limit=20" | jq '.items[].external_id'
```

| Filter | Effect |
|---|---|
| `severity` | one of `low`, `medium`, `high`, `critical` |
| `since` | ISO 8601 — only threats published or modified after this instant |
| `source` | `nvd`, `cisa_kev`, `github_advisories` |
| `limit`, `offset` | pagination |

### Single CVE detail

```bash
curl -s "$BASE/api/v1/cve/CVE-2021-44228" | jq
```

Response includes `raw_data` (per-source original payload), the merged record, and a list of source attributions.

### Sources that document a Threat

```bash
THREAT_ID=$(curl -s "$BASE/api/v1/cve/CVE-2021-44228" | jq -r .id)
curl -s "$BASE/api/v1/threats/$THREAT_ID/sources" | jq
```

Useful when you want to show "this CVE was reported by NVD on X, then added to CISA KEV on Y."

## Sectors

### List public profiles

```bash
curl -s "$BASE/api/v1/sectors" | jq '.items[] | {id, name, sector}'
```

```json
{ "id": "finance",    "name": "Finance & Banking",          "sector": "financial-services" }
{ "id": "healthcare", "name": "Healthcare & Life Sciences", "sector": "healthcare" }
{ "id": "ics",        "name": "Industrial Control Systems / OT", "sector": "industrial" }
{ "id": "saas",       "name": "SaaS / B2B Cloud",           "sector": "software" }
{ "id": "ecommerce",  "name": "E-commerce & Retail",        "sector": "retail" }
{ "id": "government", "name": "Government & Public Sector", "sector": "government" }
```

### Threats scored against a sector

```bash
curl -s "$BASE/api/v1/sectors/finance/threats?min_score=70&limit=10" | jq '.items[] | {cve: .external_id, score, kev: .score_breakdown.kev.hit}'
```

### Sector dashboard

```bash
curl -s "$BASE/api/v1/sectors/finance/dashboard" | jq '{
  top_24h: (.top_24h | length),
  top_7d:  (.top_7d  | length),
  stats: .stats
}'
```

The dashboard returns the top-scoring threats over 24 h and 7 d, plus aggregate counts. Each threat ships with a full `score_breakdown` so the score is auditable per criterion.

### RSS feed (for SIEM ingestion or analyst RSS readers)

```bash
curl "$BASE/api/v1/sectors/finance/feed.rss?min_score=70" \
  -H 'Accept: application/rss+xml'
```

Default `min_score` is 70. Lower it for noisier feeds, raise it for stricter ones.

## Indicators

Reverse IOC lookup — given an indicator, find every Threat that references it.

```bash
curl -s "$BASE/api/v1/indicators?type=cve&value=CVE-2021-44228" | jq
```

| `type` values | Examples |
|---|---|
| `cve` | `CVE-2021-44228` |
| `package` | `pypi:requests`, `npm:lodash`, `maven:org.apache.logging.log4j:log4j-core` |
| `cwe` | `CWE-79`, `CWE-89` |

Schema and matching rules: [`docs/INDICATORS.md`](INDICATORS.md).

## Source health

```bash
curl -s "$BASE/api/v1/sources" | jq
```

Returns the same `last_run` / `last_success` / `failure_count` data as `/health.collectors`, plus the enabled/disabled flag and the configured base interval. Use this when wiring up a collector dashboard.

## Global stats

```bash
curl -s "$BASE/api/v1/stats/global" | jq
```

Aggregated counters intended for a public landing page or status banner.

## Admin

Both admin endpoints require `X-Admin-Key`. Without it (or with a wrong key) the API returns `401`.

### Reload sector profiles

```bash
curl -X POST "$BASE/api/v1/admin/reload-profiles" \
     -H "X-Admin-Key: $ADMIN_API_KEY" | jq
```

Re-scans `profiles/public/` and `profiles/private/`, then upserts. Returns `{added, updated, removed, errors}`.

### Rescore everything

```bash
curl -X POST "$BASE/api/v1/admin/rescore-all" \
     -H "X-Admin-Key: $ADMIN_API_KEY" -i
```

Returns `202 Accepted` and queues the work in the background. Useful after editing scoring weights.

## Errors

```http
HTTP/1.1 404 Not Found
Content-Type: application/problem+json

{
  "type":   "https://threat-intel-api-production.up.railway.app/problems/not-found",
  "title":  "Not Found",
  "status": 404,
  "detail": "No CVE matches the identifier 'CVE-9999-0000'."
}
```

Common statuses:

| Code | When |
|---|---|
| `400` | Validation error on a query parameter |
| `401` | Admin endpoint hit without (or with a wrong) `X-Admin-Key` |
| `404` | Unknown CVE, sector or threat ID |
| `429` | Rate limit exceeded — see `Retry-After` header |
| `503` | Database unreachable, collector disabled by config |
