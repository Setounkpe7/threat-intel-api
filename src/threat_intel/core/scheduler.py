import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-untyped]
from apscheduler.triggers.cron import CronTrigger  # type: ignore[import-untyped]
from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import-untyped]
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.core.config import Settings
from threat_intel.models.source import Source
from threat_intel.services.ingestion import IngestionService

logger = structlog.get_logger(__name__)

SCHEDULER_TICK_SECONDS = 60

_SessionFactory = async_sessionmaker[AsyncSession]


async def _run_safe(ingestion: IngestionService, source_name: str) -> None:
    try:
        await ingestion.run(source_name)
    except Exception:  # noqa: BLE001  # isolation boundary
        logger.exception("scheduler.run_failed", source=source_name)


async def _scheduler_tick(ingestion: IngestionService, session_factory: _SessionFactory) -> None:
    try:
        now = datetime.now(UTC)
        async with session_factory() as session:
            rows = (
                (
                    await session.execute(
                        select(Source).where(
                            Source.enabled == True,  # noqa: E712
                            or_(Source.next_run_at.is_(None), Source.next_run_at <= now),
                        )
                    )
                )
                .scalars()
                .all()
            )
        for src in rows:
            asyncio.create_task(_run_safe(ingestion, src.name))
    except Exception:  # noqa: BLE001
        logger.exception("scheduler.tick_failed")


def build_scheduler(
    settings: Settings,
    ingestion: IngestionService,
    session_factory: _SessionFactory,
    daily_rescore_runner: Callable[[], Awaitable[None]] | None = None,
) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        _scheduler_tick,
        kwargs={"ingestion": ingestion, "session_factory": session_factory},
        trigger=IntervalTrigger(seconds=SCHEDULER_TICK_SECONDS),
        id="collector_tick",
        name="Multi-collector tick",
        max_instances=1,
        coalesce=True,
    )
    logger.info(
        "scheduler.tick_registered",
        interval_seconds=SCHEDULER_TICK_SECONDS,
    )
    if daily_rescore_runner is not None:
        scheduler.add_job(
            daily_rescore_runner,
            trigger=CronTrigger(hour=2, minute=0),
            id="rescore_recent",
            name="Rescore last-7-days threats",
            max_instances=1,
            coalesce=True,
        )
        logger.info("scheduler.job_registered", job_id="rescore_recent")
    return scheduler
