import json

import structlog

from threat_intel.core.logging import configure_logging


def test_configure_logging_dev_emits_console(capsys):
    configure_logging(env="dev", level="INFO")
    log = structlog.get_logger()
    log.info("hello", user="me")
    out = capsys.readouterr().out
    assert "hello" in out
    assert "user" in out


def test_configure_logging_prod_emits_json(capsys):
    configure_logging(env="prod", level="INFO")
    log = structlog.get_logger()
    log.info("hello", user="me")
    out = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(out)
    assert payload["event"] == "hello"
    assert payload["user"] == "me"
    assert payload["level"] == "info"


def test_configure_logging_respects_level(capsys):
    configure_logging(env="prod", level="WARNING")
    log = structlog.get_logger()
    log.info("nope")
    log.warning("yep")
    lines = [ln for ln in capsys.readouterr().out.strip().splitlines() if ln]
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "yep"
