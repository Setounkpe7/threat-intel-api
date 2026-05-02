# Contributing

Thanks for considering a contribution. This guide covers the dev loop, the conventions the repo enforces, and what a green PR looks like.

## Dev setup

```bash
git clone https://github.com/Setounkpe7/threat-intel-api.git
cd threat-intel-api

python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

cp .env.example .env
alembic upgrade head
uvicorn threat_intel.main:app --reload
```

For the Docker route and Postgres setup, see [`docs/INSTALLATION.md`](docs/INSTALLATION.md).

## Branches

- `main` is production. Protected, PR-only, must pass the security gate.
- `dev` is integration. Default base for feature branches.
- `feat/<short-slug>` for feature branches, opened against `dev`.
- `fix/<short-slug>` for bug fixes.
- `chore/<short-slug>` for tooling, CI, docs, refactors with no behavior change.

Open PRs against `dev`. The path to `main` is a separate PR from `dev` once a milestone is ready, gated by the same CI.

## Commits

Conventional Commits, kept terse:

```
feat(api): add /api/v1/sectors/{id}/feed.atom
fix(scheduler): handle aware vs naive datetimes in NVD payloads
chore(deps): bump httpx to 0.28.x
docs(readme): refresh project metrics
```

Common prefixes: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `perf`, `ci`, `build`, `security`.

## Local checks (the same ones CI runs)

```bash
make lint            # ruff check + ruff format
make typecheck       # mypy strict on src/
make test            # pytest, coverage gate ≥ 80%
make security-audit  # bandit + pip-audit + semgrep
make docker-build    # build the hardened image
make docker-scan     # hadolint + trivy
```

`pre-commit run --all-files` runs the lint, type, SAST and secret-scan combo on the whole tree.

## Adding a collector

The whole point of `BaseCollector` is that a new source costs one file plus a registration. The walkthrough lives in [`docs/COLLECTORS.md`](docs/COLLECTORS.md). The contract is `fetch(since)` plus `to_event(raw)`; everything else (dedup, persistence, `/health` reporting, scoring) is wired from there.

## Adding a sector profile

```bash
$EDITOR profiles/public/<your-sector>.yaml
curl -X POST http://localhost:8000/api/v1/admin/reload-profiles \
     -H "X-Admin-Key: $ADMIN_API_KEY"
```

Schema and validation rules: [`profiles/README.md`](profiles/README.md).

## Pull requests

A PR is ready when:

- [ ] CI is green (lint, types, tests, SAST, SCA, container scan, gitleaks).
- [ ] New code has tests. Unit for pure logic, integration for anything that touches the DB or HTTP.
- [ ] Public API changes are reflected in `docs/API_USAGE.md`.
- [ ] User-visible behavior changes are added to `CHANGELOG.md` under `[Unreleased]`.
- [ ] No secrets, no `.env`, no large binaries committed.

Squash-merge is the default. Keep the squashed message Conventional-Commit shaped.

## Regenerating the README hero GIF

The animated hero in the README is rendered from `docs/assets/hero-demo.tape` using [charmbracelet/vhs](https://github.com/charmbracelet/vhs). The upstream VHS image does not include `curl` or `jq`, so a one-line Dockerfile in the same folder adds them.

```bash
docker build -t threat-intel-vhs -f docs/assets/hero-demo.Dockerfile docs/assets/
docker run --rm --shm-size=1g --cap-add=SYS_ADMIN \
  -v "$PWD":/vhs -w /vhs threat-intel-vhs \
  docs/assets/hero-demo.tape
docker run --rm -v "$PWD":/vhs alpine \
  chown $(id -u):$(id -g) /vhs/docs/assets/screenshots/hero-demo.gif
```

`--shm-size` and `--cap-add=SYS_ADMIN` are needed for VHS's bundled headless Chromium to start. The `chown` step is needed because VHS runs as root inside the container.

## Reporting a security issue

Do not open a public issue. Email the address listed in [`SECURITY.md`](SECURITY.md).

## Code of conduct

By participating you agree to the [Contributor Covenant](CODE_OF_CONDUCT.md).
