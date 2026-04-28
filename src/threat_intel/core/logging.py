"""Structured logging with secret-scrubbing.

`configure_logging` wires structlog and stdlib logging in one go:

- dev  → ConsoleRenderer (colorised, human-readable)
- prod → JSONRenderer    (one event per line, ready for log aggregation)

Every record passes through `_scrub_processor` first: keys whose name matches
a sensitive pattern are replaced by `REDACTED`, and free-form messages are
sanitised against a regex catalogue (Authorization headers, JWT-like blobs,
high-entropy tokens). The same scrubber is mirrored as a stdlib `logging.Filter`
so events from third-party libraries (uvicorn, sqlalchemy, httpx) are scrubbed
too.

Optional rotation: pass `log_file=...` to also tee logs to a
`RotatingFileHandler` (10 MB × 5).
"""

from __future__ import annotations

import logging
import logging.handlers
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import structlog

REDACTED = "***REDACTED***"

# Substring match against the lowered key name. Keep the list narrow — the
# false-positive cost of redacting a real field is much lower than leaking
# a token, but redacting "user_password_hash_strength" because it contains
# "password" is fine.
_SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "x-admin-key",
    "x_admin_key",
    "admin_api_key",
    "authorization",
    "cookie",
    "set-cookie",
    "session",
    "private_key",
    "client_secret",
)

# Regex catalogue applied to free-form string values that survived key-based
# redaction. Order matters — bearer tokens first so the broad hex/base64
# rule does not chop them in half.
_AUTHZ_INLINE = re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?\S+")
_COOKIE_INLINE = re.compile(r"(?i)(set-?cookie\s*[:=]\s*)\S+")
_JWT_BLOB = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")
_KV_SECRET = re.compile(
    r"(?i)\b(token|secret|api[_-]?key|password)=([A-Za-z0-9+/_=\-\.]{16,})"
)
_BARE_HEX = re.compile(r"\b[a-fA-F0-9]{32,}\b")


def _is_sensitive_key(key: str) -> bool:
    lower = key.lower().replace(" ", "")
    return any(token in lower for token in _SENSITIVE_KEY_TOKENS)


def _scrub_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _scrub_mapping(value)
    if isinstance(value, list):
        return [_scrub_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(v) for v in value)
    if isinstance(value, str):
        return _scrub_string(value)
    return value


def _scrub_mapping(d: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = str(k).lower()  # canonicalise — eases matching downstream
        if _is_sensitive_key(key):
            out[key] = REDACTED
        else:
            out[key] = _scrub_value(v)
    return out


def _scrub_string(s: str) -> str:
    result = s
    result = _AUTHZ_INLINE.sub(lambda m: f"{m.group(1)}{REDACTED}", result)
    result = _COOKIE_INLINE.sub(lambda m: f"{m.group(1)}{REDACTED}", result)
    result = _JWT_BLOB.sub(REDACTED, result)
    result = _KV_SECRET.sub(lambda m: f"{m.group(1)}={REDACTED}", result)
    result = _BARE_HEX.sub(REDACTED, result)
    return result


def _scrub_processor(
    _logger: object, _method: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor — runs on every event before rendering."""
    return _scrub_mapping(event_dict)


class ScrubbingFilter(logging.Filter):
    """stdlib `logging` filter — catches third-party loggers (uvicorn, httpx, …)."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        if isinstance(record.msg, str):
            record.msg = _scrub_string(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(_scrub_value(a) for a in record.args)
            elif isinstance(record.args, dict):
                record.args = _scrub_mapping(record.args)
        return True


def configure_logging(
    env: Literal["dev", "prod"],
    level: str = "INFO",
    *,
    log_file: str | Path | None = None,
    log_file_max_bytes: int = 10 * 1024 * 1024,
    log_file_backup_count: int = 5,
) -> None:
    """Configure structlog + stdlib logging.

    `log_file` (when given) enables a `RotatingFileHandler` alongside stdout:
    handy for VMs where the orchestrator is not the log shipper. In containers,
    leave it None and let the runtime collect stdout.
    """
    level_int = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _scrub_processor,
    ]

    renderer: structlog.types.Processor = (
        structlog.dev.ConsoleRenderer() if env == "dev" else structlog.processors.JSONRenderer()
    )

    # Resolve sys.stdout at write time (not config time) so that pytest's
    # capsys / temporary stream replacement does not leave the cached logger
    # pointing at a closed file.
    def _stdout_factory(*_: object) -> structlog.PrintLogger:
        return structlog.PrintLogger(file=sys.stdout)

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level_int),
        logger_factory=_stdout_factory,
        cache_logger_on_first_use=False,
    )

    handlers: list[logging.Handler] = [logging.StreamHandler(stream=sys.stdout)]
    if log_file is not None:
        handlers.append(
            logging.handlers.RotatingFileHandler(
                filename=str(log_file),
                maxBytes=log_file_max_bytes,
                backupCount=log_file_backup_count,
                encoding="utf-8",
            )
        )

    scrub = ScrubbingFilter()
    for h in handlers:
        h.addFilter(scrub)
        h.setFormatter(logging.Formatter("%(message)s"))

    root = logging.getLogger()
    root.handlers = handlers
    root.setLevel(level_int)
