"""Sensitive values must never reach the log sink — verifies the structlog
scrubber processor for both key-based redaction and regex-based redaction
on free-form messages."""

import json

import pytest
import structlog

from threat_intel.core.logging import REDACTED, configure_logging


@pytest.fixture(autouse=True)
def _reset_logging():
    configure_logging(env="prod", level="INFO")
    yield


def _last_json_line(out: str) -> dict:
    lines = [ln for ln in out.strip().splitlines() if ln.startswith("{")]
    return json.loads(lines[-1])


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "client_secret",
        "authorization",
        "cookie",
        "x-admin-key",
        "x_admin_key",
    ],
)
def test_sensitive_keys_are_redacted(capsys, key):
    log = structlog.get_logger()
    log.info("auth_attempt", **{key: "supersecretvalue123"})
    payload = _last_json_line(capsys.readouterr().out)
    assert payload[key.lower()] == REDACTED
    assert "supersecretvalue123" not in capsys.readouterr().out


def test_sensitive_keys_redacted_in_nested_dict(capsys):
    log = structlog.get_logger()
    log.info(
        "request_received",
        headers={"Authorization": "Bearer abc.def.ghi", "User-Agent": "ua/1"},
        user={"password": "p4ssw0rd!"},
    )
    payload = _last_json_line(capsys.readouterr().out)
    assert payload["headers"]["authorization"] == REDACTED
    assert payload["headers"]["user-agent"] == "ua/1"
    assert payload["user"]["password"] == REDACTED


def test_authorization_header_value_in_message_is_redacted(capsys):
    log = structlog.get_logger()
    log.info("upstream_call: Authorization=Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
    out = capsys.readouterr().out
    assert "eyJhbGciOiJIUzI1NiJ9.payload.sig" not in out
    assert REDACTED in out


def test_long_high_entropy_token_in_message_is_redacted(capsys):
    log = structlog.get_logger()
    # 40-char hex token (typical PAT / session id shape)
    token = "deadbeefcafebabe0123456789abcdef01234567"
    log.info(f"validate token={token} for user=alice")
    out = capsys.readouterr().out
    assert token not in out
    assert "alice" in out  # non-secret context preserved
