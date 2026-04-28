# Security Policy

## Supported versions

This project is in active development. Only the **`main`** branch is supported
for security fixes. Older tags or development branches will not receive
backports.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | ✅                 |
| `dev`   | best-effort        |
| `< 0.1` | ❌                 |

## Reporting a vulnerability

**Do not file public GitHub issues for security problems.**

Please email **[Mdoubogan@yahoo.fr](mailto:Mdoubogan@yahoo.fr)** with:

- a clear description of the issue and the impact you observed,
- step-by-step reproduction (smallest payload that triggers it),
- the commit hash / Docker image tag where you reproduced,
- any logs or screenshots that help triage.

You should expect:

- an acknowledgement within **3 business days**,
- a triage and severity assessment within **7 business days** (CVSS v3.1),
- a fix or mitigation plan within **30 days** for High/Critical issues,
  and a longer window for Medium/Low,
- public credit in the release notes once a fix ships, unless you ask
  to remain anonymous.

We follow **coordinated disclosure**. Please give us a reasonable window
to ship a fix before publishing details. If you do not get a reply within
the timelines above, feel free to escalate by replying to your original
email — that's not noise.

## In scope

- The API code under [`src/threat_intel/`](src/threat_intel/), including
  HTTP handlers, middleware, scoring services, ingestion pipeline, and
  database models.
- The Dockerfile and the resulting container image.
- The locked dependency manifest (`requirements.lock`, `uv.lock`) and any
  CVE that affects a runtime dependency we ship.
- The CI/CD workflows under `.github/workflows/`.

## Out of scope

- Issues that require a privileged role on the host running the container
  (root inside the container, host-volume tampering).
- Vulnerabilities that depend on a misconfigured deployment (e.g. running
  the container as `root`, exposing it without TLS termination, leaving the
  default `ADMIN_API_KEY`).
- Rate-limit bypass via raw IP rotation when no upstream proxy is enforcing
  source identity. The API trusts `X-Forwarded-For` only when configured to.
- Findings against demo seed data or sample profiles in `profiles/public/`.
- Denial of service requiring more than 1 req/s of plain GET traffic (use
  the rate limiter and a CDN in production).

## Hardening you should expect from operators

- Run behind TLS — never expose the bare HTTP port to the internet.
- Set `ADMIN_API_KEY` to a 32-byte random value
  (`python -c "import secrets; print(secrets.token_urlsafe(32))"`).
- Restrict admin endpoints at the network layer (private network, VPN, or
  firewall rule) on top of the API key.
- Rotate `ADMIN_API_KEY` and `NVD_API_KEY` periodically, and on staff change.
- Watch the CI security workflow — it gates merges on bandit, semgrep,
  pip-audit (CVE), gitleaks (secrets), Trivy (image), and ≥ 80% test cover.
