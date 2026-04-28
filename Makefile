# threat-intel-api — common dev / security workflows
# `make help` lists targets.

PY ?= .venv/bin/python
UV ?= uv

.DEFAULT_GOAL := help

.PHONY: help
help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install:  ## install runtime + dev + security extras (uv)
	$(UV) sync --all-extras

.PHONY: lock
lock:  ## refresh uv.lock + requirements.lock
	$(UV) lock
	$(UV) export --no-dev --no-emit-project --format requirements-txt > requirements.lock

.PHONY: lint
lint:  ## ruff check + ruff format --check
	$(UV) run ruff check src tests
	$(UV) run ruff format --check src tests

.PHONY: typecheck
typecheck:  ## mypy strict on src/
	$(UV) run mypy src

.PHONY: test
test:  ## pytest with coverage gate (80%)
	$(UV) run pytest --cov=src/threat_intel --cov-report=term-missing --cov-fail-under=80

.PHONY: bandit
bandit:  ## SAST on src/ (skip B101 assert_used)
	$(UV) run --extra security bandit -r src -x src/threat_intel/cli --skip B101

.PHONY: pip-audit
pip-audit:  ## CVE scan on locked deps; fail on HIGH/CRITICAL only
	$(UV) run --extra security pip-audit \
		--requirement requirements.lock \
		--strict \
		--vulnerability-service osv

.PHONY: semgrep
semgrep:  ## semgrep with auto config (community rules)
	$(UV) run --extra security semgrep --config auto --error src

.PHONY: security-audit
security-audit: bandit pip-audit semgrep  ## full local security gate (bandit + pip-audit + semgrep)

.PHONY: docker-build
docker-build:  ## build the hardened image
	docker build -t threat-intel-api:dev .

.PHONY: docker-scan
docker-scan: docker-build  ## hadolint + trivy on the local image (need both on PATH)
	hadolint Dockerfile
	trivy image --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed threat-intel-api:dev

.PHONY: clean
clean:  ## remove caches and build artefacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist build *.egg-info
