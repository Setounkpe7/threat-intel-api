# syntax=docker/dockerfile:1.7
# ---------- Stage 1: builder ----------
# Builds the venv against the pinned requirements.lock so the runtime image
# never sees a compiler, source tree, or pip cache.
FROM python:3.14-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

# Toolchain only needed in case any dep falls back to a sdist on musl
# (most ship musllinux wheels: asyncpg, lxml, pydantic-core, uvloop, …).
# hadolint ignore=DL3018
RUN apk add --no-cache \
      build-base \
      libffi-dev \
      postgresql-dev

# Install pinned runtime deps first (best layer cache hit on source-only edits).
COPY requirements.lock ./requirements.lock
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.lock

# Then install the project itself (no deps — already locked above).
COPY pyproject.toml README.md ./
COPY src ./src
COPY alembic.ini ./
COPY alembic ./alembic
RUN /opt/venv/bin/pip install --no-deps .

# Slim the venv: pip/setuptools/wheel are useless at runtime, and bundled
# package tests are dead weight on the runtime image.
RUN /opt/venv/bin/pip uninstall -y pip setuptools wheel || true \
 && find /opt/venv -depth -type d \( -name "__pycache__" -o -name "tests" -o -name "test" \) -exec rm -rf {} + \
 && find /opt/venv -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete


# ---------- Stage 2: runtime ----------
FROM python:3.14-alpine AS runtime

ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.1.0

LABEL org.opencontainers.image.title="threat-intel-api" \
      org.opencontainers.image.description="CyberThreat Intelligence REST API — OSINT CVE aggregator with sector scoring" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Michel-Ange Doubogan <Mdoubogan@yahoo.fr>" \
      org.opencontainers.image.source="https://github.com/Setounkpe7/threat-intel-api" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12-alpine"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=prod

# Runtime libs only: libpq for asyncpg, curl for HEALTHCHECK, tini for PID 1.
# hadolint ignore=DL3018
RUN apk add --no-cache \
      libpq \
      curl \
      tini

# Non-root user (uid 1001) with a system home for explicit ownership.
RUN addgroup -S -g 1001 app \
 && adduser -S -u 1001 -G app -h /app -s /sbin/nologin app

WORKDIR /app
RUN chown app:app /app

# Copy the prebuilt venv with explicit ownership — no chown -R later.
COPY --from=builder --chown=app:app /opt/venv /opt/venv

# Copy app artefacts needed at runtime (alembic for migrations on boot).
COPY --chown=app:app alembic.ini ./
COPY --chown=app:app alembic ./alembic
COPY --chown=app:app profiles ./profiles

USER app:app

EXPOSE 8000

# tini reaps zombies and forwards signals to uvicorn (clean SIGTERM on `docker stop`).
ENTRYPOINT ["/sbin/tini", "--"]

# Migrations no longer run in CMD: in production they run as a Railway
# pre-deploy command, in local docker-compose they run via the dedicated
# 'migrate' one-shot service. So the start period can be shorter.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8000/livez || exit 1

CMD ["uvicorn", "threat_intel.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*", "--no-server-header"]
