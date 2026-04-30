# Indicator types and queries

The platform extracts and stores **indicators of compromise (IOCs)** for every Threat. Indicators provide the dedup key for cross-source merging and a reverse-lookup capability for hunting.

## Supported indicator types

| Type | Description | Example value |
|---|---|---|
| `cve` | Common Vulnerabilities and Exposures identifier | `CVE-2021-44228` |
| `ghsa` | GitHub Security Advisory identifier | `GHSA-jfh8-c2jp-5v3q` |
| `cpe` | Common Platform Enumeration name (used by NVD to identify affected products) | `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` |
| `package` | Ecosystem-prefixed package name | `npm:lodash`, `pypi:requests`, `maven:org.apache.logging.log4j:log4j-core` |
| `ip`, `domain`, `url` | Network IOC | reserved for future feeds (RSS, URLhaus) |
| `md5`, `sha1`, `sha256` | File hash IOC | reserved for future feeds (binary intelligence) |

Indicators are stored in the `threat_indicators` table with the unique constraint `(threat_id, indicator_type, value)` — the same indicator value is recorded once per Threat regardless of how many sources extract it. A reverse lookup uses the index on `(indicator_type, value)`.

## Lookup endpoint

```
GET /api/v1/indicators?type=<type>&value=<value>
```

Returns the list of `Threat` records that have at least one matching indicator.

### Examples

```bash
# Find every Threat that documents CVE-2021-44228
curl 'http://localhost:8000/api/v1/indicators?type=cve&value=CVE-2021-44228'

# Find every Threat affecting npm:lodash
curl 'http://localhost:8000/api/v1/indicators?type=package&value=npm:lodash'

# Find every Threat associated with a specific CPE
curl 'http://localhost:8000/api/v1/indicators?type=cpe&value=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'
```

The response is a JSON list of Threat objects (same shape as `/api/v1/threats/{id}`).

### Error responses

- `400` — `type` is not one of the supported indicator types
- `422` — `type` or `value` query parameter is missing
- `200 []` — no Threat matches the indicator (empty list, not 404)

## Cross-source dedup behavior

When a Threat is documented by multiple sources, looking up any of its indicators returns the single Threat record. For example, if NVD ingests `CVE-2021-44228`, then CISA KEV adds it to its catalog, then GitHub Advisories publishes a related advisory, the database holds:

- 1 Threat row
- 3 ThreatSource rows (one per feed)
- ~10 ThreatIndicator rows: one `(cve, CVE-2021-44228)`, one `(ghsa, GHSA-jfh8-c2jp-5v3q)`, one or more `(cpe, ...)` from NVD, one or more `(package, maven:...)` from GitHub Advisories

A query for any of those indicators returns the same Threat. Use `/api/v1/threats/{id}/sources` to see all sources documenting it, and `/api/v1/sources` for a global health view of the ingestion pipeline.
