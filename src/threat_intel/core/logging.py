import logging
import sys
from typing import Literal

import structlog


def configure_logging(env: Literal["dev", "prod"], level: str = "INFO") -> None:
    """Configure structlog + stdlib logging.

    dev  -> ConsoleRenderer (colorized, human-readable).
    prod -> JSONRenderer    (one event per line).
    """
    level_int = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
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

    logging.basicConfig(
        format="%(message)s",
        level=level_int,
        stream=sys.stdout,
        force=True,
    )
