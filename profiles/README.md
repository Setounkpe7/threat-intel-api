# Sector profiles

Each YAML file under `profiles/public/` or `profiles/private/` declares one
sector profile. The API loads them at startup and re-scores recent threats
against every profile, so adding a profile is the only step needed to expose
a new dashboard, threats endpoint and RSS feed.

`public/` profiles are reachable by anyone. `private/` profiles require the
`X-Admin-Key` header and never appear in unauthenticated `GET /api/v1/sectors`
responses.

## Schema

```yaml
id:                       <slug>            # required, [a-z0-9_-]{2,64}
name:                     <human readable>  # required
sector:                   <category>        # required
description:              <1-2 lignes>      # optional
visibility:               public|private    # optional; if set, must match folder

keywords:                 [<string>, ...]   # whole-word, case-insensitive
technologies:             [<string>, ...]   # matched against affected_products too
cwe_priorities:           [CWE-NNN, ...]    # exact CWE ids
excluded_keywords:        [<string>, ...]   # subtract 30 points if matched
compliance:               [<string>, ...]   # informational, surfaced in /sectors/{id}
priority_boost_keywords:  [<string>, ...]   # add 20 points on top of regular keywords

cvss_threshold:           7.0               # 0-10; threats >= threshold gain 15 points
```

See [docs/SCORING.md](../docs/SCORING.md) for the scoring algorithm and a
worked example.

## Hot reload

```bash
curl -X POST http://localhost:8000/api/v1/admin/reload-profiles \
     -H "X-Admin-Key: $ADMIN_API_KEY"
```

The response lists profiles added, updated, removed (no longer on disk), and
errors (with file path and reason). Removing a profile from disk and reloading
deletes its row only if `source_file` was set when it was loaded — manually
inserted profiles are preserved.

## Example: minimal valid profile

```yaml
id: my-org
name: My Organisation
sector: software
keywords: [my-product]
technologies: [Node.js]
cwe_priorities: [CWE-79]
cvss_threshold: 7.0
```
