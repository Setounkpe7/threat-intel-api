from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.analyzers.dedup import upsert_threat
from threat_intel.collectors.base import BaseCollector
from threat_intel.core.exceptions import ConfigurationError
from threat_intel.models.source import Source

logger = structlog.get_logger(__name__)


@dataclass
class IngestionResult:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0


class IngestionService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        collectors: list[BaseCollector],
        batch_size: int = 100,
    ) -> None:
        self._sf = session_factory
        self._collectors = {c.source_name: c for c in collectors}
        self._batch_size = batch_size

    async def run(self, source_name: str) -> IngestionResult:
        collector = self._collectors.get(source_name)
        if collector is None:
            raise ConfigurationError(f"No collector registered for source '{source_name}'")

        log = logger.bind(source=source_name)

        async with self._sf() as session:
            src = (
                await session.execute(select(Source).where(Source.name == source_name))
            ).scalar_one_or_none()
            if src is None:
                raise ConfigurationError(f"Source row missing in DB: {source_name}")
            since = src.last_success_at or datetime.now(UTC) - timedelta(hours=24)

        log.info("ingestion.start", since=since.isoformat())

        result = IngestionResult()
        try:
            async with self._sf() as session:
                src = (
                    await session.execute(select(Source).where(Source.name == source_name))
                ).scalar_one()
                src.last_run_at = datetime.now(UTC)
                await session.commit()

                count = 0
                async for raw in collector.fetch(since):
                    draft = collector.normalize(raw)
                    outcome = await upsert_threat(session, src, draft)
                    if outcome == "inserted":
                        result.inserted += 1
                    elif outcome == "updated":
                        result.updated += 1
                    else:
                        result.unchanged += 1
                    count += 1
                    if count % self._batch_size == 0:
                        await session.commit()
                await session.commit()

                src.last_success_at = datetime.now(UTC)
                src.last_error = None
                await session.commit()
            log.info(
                "ingestion.done",
                inserted=result.inserted,
                updated=result.updated,
                unchanged=result.unchanged,
            )
            return result
        except Exception as e:
            log.exception("ingestion.failed", error=str(e))
            async with self._sf() as session:
                src = (
                    await session.execute(select(Source).where(Source.name == source_name))
                ).scalar_one()
                src.last_error = f"{type(e).__name__}: {e}"[:1000]
                await session.commit()
            raise
