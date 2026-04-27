from collections.abc import Awaitable, Callable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-untyped]
from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import-untyped]

from threat_intel.core.config import Settings

logger = structlog.get_logger(__name__)


def build_scheduler(
    settings: Settings,
    nvd_runner: Callable[[], Awaitable[None]],
) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        nvd_runner,
        trigger=IntervalTrigger(minutes=settings.nvd_fetch_interval_minutes),
        id="ingest_nvd",
        name="NVD ingestion",
        max_instances=1,
        coalesce=True,
    )
    logger.info(
        "scheduler.job_registered",
        job_id="ingest_nvd",
        interval_minutes=settings.nvd_fetch_interval_minutes,
    )
    return scheduler
