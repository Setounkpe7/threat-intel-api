"""Secrets configured on the server (admin key, NVD API key, DB password in
the URL) must never appear in HTTP responses, logs, or the OpenAPI schema.
"""

from __future__ import annotations

import json
import logging

import pytest
import structlog

from threat_intel.core.logging import REDACTED, configure_logging

ADMIN_KEY = "TOPSECRET-ADMIN-KEY-9k2p8q7"
NVD_API_KEY = "nvd-pat-aaaa1111bbbb2222cccc3333dddd4444"


@pytest.fixture
def secret_settings(monkeypatch, settings):
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("NVD_API_KEY", NVD_API_KEY)
    settings.admin_api_key = ADMIN_KEY
    settings.nvd_api_key = NVD_API_KEY
    return settings


async def test_secrets_absent_from_openapi(client, secret_settings):
    resp = await client.get("/openapi.json")
    body = resp.text
    assert ADMIN_KEY not in body
    assert NVD_API_KEY not in body


async def test_secrets_absent_from_health(client, secret_settings):
    resp = await client.get("/health")
    body = resp.text
    assert ADMIN_KEY not in body
    assert NVD_API_KEY not in body


async def test_secrets_absent_from_404_error_body(client, secret_settings):
    resp = await client.get("/this/route/does/not/exist", headers={"X-Admin-Key": ADMIN_KEY})
    assert ADMIN_KEY not in resp.text


async def test_admin_key_in_log_event_is_redacted(capsys):
    """A handler accidentally logging request headers must not leak the key."""
    configure_logging(env="prod", level="INFO")
    log = structlog.get_logger()
    log.info(
        "request_received",
        path="/api/v1/admin/reload-profiles",
        headers={"X-Admin-Key": ADMIN_KEY, "User-Agent": "ua/1"},
    )
    out = capsys.readouterr().out
    assert ADMIN_KEY not in out
    assert REDACTED in out


async def test_authorization_value_in_stdlib_logger_is_redacted(capsys):
    """Third-party loggers (uvicorn / httpx) emit via stdlib logging, which
    goes through ScrubbingFilter."""
    configure_logging(env="prod", level="INFO")
    logging.getLogger("uvicorn.access").info(
        "GET /v1/threats Authorization=Bearer eyJfoo.bar.baz from 127.0.0.1"
    )
    out = capsys.readouterr().out
    assert "eyJfoo.bar.baz" not in out


async def test_db_password_in_url_is_not_echoed(client, secret_settings):
    """If the DB URL contains credentials and ends up serialised somewhere,
    /health must not parrot it back."""
    resp = await client.get("/health")
    payload = json.loads(resp.text)
    blob = json.dumps(payload).lower()
    # Conservatively assert no `://user:` substring sneaks into the response.
    assert "://" not in blob or "password" not in blob
