from collections.abc import Awaitable, Callable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-untyped]
from apscheduler.triggers.cron import CronTrigger  # type: ignore[import-untyped]
from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import-untyped]

from threat_intel.core.config import Settings

logger = structlog.get_logger(__name__)


def build_scheduler(
    settings: Settings,
    nvd_runner: Callable[[], Awaitable[None]],
    daily_rescore_runner: Callable[[], Awaitable[None]] | None = None,
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
    if daily_rescore_runner is not None:
        scheduler.add_job(
            daily_rescore_runner,
            trigger=CronTrigger(hour=2, minute=0),  # 02:00 UTC daily
            id="rescore_recent",
            name="Rescore last-7-days threats",
            max_instances=1,
            coalesce=True,
        )
        logger.info("scheduler.job_registered", job_id="rescore_recent")
    return scheduler
