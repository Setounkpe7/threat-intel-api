# Sector scoring algorithm

The API scores every `Threat` against every active `SectorProfile`. The result is a single number (`0-100`) plus a JSON `breakdown` that shows exactly how the score was reached. Both are persisted in the `threat_sector_score` table and surfaced verbatim by the API.

## Inputs

| From the threat | From the profile |
|---|---|
| `title`, `description`, `affected_products` (joined as the matching corpus) | `keywords`, `technologies`, `excluded_keywords`, `priority_boost_keywords` |
| `cwes` (the M2M-loaded list of CWE rows) | `cwe_priorities` |
| `cvss_score` | `cvss_threshold` |

`references` (URLs) are intentionally **not** matched — URLs contain too much incidental noise (CDN paths, tracking ids).

## Rules

| # | Condition | Points |
|---|---|---|
| 1 | At least one `technology` appears in the corpus | `+30` |
| 2 | At least one `keyword` appears in the corpus | `+25` |
| 3 | At least one threat CWE is listed in `cwe_priorities` | `+20` |
| 4 | `cvss_score >= cvss_threshold` | `+15` |
| 5 | At least one `priority_boost_keyword` appears in the corpus (bonus) | `+20` |
| 6 | At least one `excluded_keyword` appears in the corpus (penalty) | `-30` |

The raw total is then **clamped to `[0, 100]`**.

## Matching rules

- Case-insensitive: `Tomcat`, `tomcat`, `TOMCAT` all match.
- **Whole-word only**: the regex `\b{re.escape(term)}\b` is applied to the lower-cased corpus, so `java` will not match `javascript`.
- Empty / whitespace-only terms in the profile are silently skipped — no error.
- A duplicate hit on the same term inside the corpus does not count twice; each rule is "did at least one match happen?".

## Worked example

**Threat** (real-ish NVD CVE):

```
title              : Apache Tomcat RCE via crafted request
description        : Apache Tomcat 9.x is vulnerable to remote code execution
                     when handling malformed payment processing requests.
affected_products  : ["cpe:2.3:a:apache:tomcat:9.0.65"]
cvss_score         : 9.8
cwes               : ["CWE-79"]
```

**Profile** `finance`:

```yaml
keywords:                [payment, swift]
technologies:            [Tomcat, Java]
cwe_priorities:          [CWE-79, CWE-89]
priority_boost_keywords: [wire transfer]
excluded_keywords:       [minecraft]
cvss_threshold:          7.0
```

**Evaluation**:

| Rule | Match? | Points |
|---|---|---|
| technology_match | yes (`Tomcat` in description and CPE) | **+30** |
| keyword_match | yes (`payment`) | **+25** |
| cwe_match | yes (`CWE-79`) | **+20** |
| cvss_threshold | `9.8 >= 7.0` | **+15** |
| priority_boost | no (`wire transfer` not present) | 0 |
| excluded | no (`minecraft` not present) | 0 |
| **raw_total** | | **90** |
| **final_score** (clamped) | | **90** |

The API returns this as:

```json
{
  "score": 90.0,
  "score_breakdown": {
    "technology_match": {"hit": true, "matched": ["Tomcat"], "points": 30},
    "keyword_match":    {"hit": true, "matched": ["payment"], "points": 25},
    "cwe_match":        {"hit": true, "matched": ["CWE-79"], "points": 20},
    "cvss_threshold":   {"hit": true, "threshold": 7.0, "cvss_score": 9.8, "points": 15},
    "priority_boost":   {"hit": false, "matched": [], "points": 0},
    "excluded":         {"hit": false, "matched": [], "points": 0},
    "raw_total": 90,
    "final_score": 90.0
  }
}
```

## When does scoring run?

| Trigger | Scope |
|---|---|
| Each ingestion run, after the final commit | Threats inserted or updated during this run |
| APScheduler daily job (02:00 UTC) | All threats modified in the last 7 days |
| `POST /api/v1/admin/rescore-all` | Every threat in the database (background task) |
| `POST /api/v1/admin/reload-profiles` | Implicit: future ingestions; explicit re-score is the next step in the runbook |

## Tuning a profile

The `breakdown` field is meant for tuning. When a known-relevant threat scores too low, look at it:

- `technology_match.hit == false` → add the vendor/product names you actually care about to `technologies`.
- `keyword_match.hit == false` → enrich `keywords` with the domain terms your team uses.
- `cvss_threshold.points == 0` while the CVSS is high → lower the threshold; remember `+15` is a **floor signal**, not the main driver.

When an irrelevant threat scores high:

- Check which rule pushed it up. Often a shared word like `payment` matches an unrelated SaaS CVE.
- Add discriminating terms to `excluded_keywords` (`-30` is large enough to push noise back down to ~0).
