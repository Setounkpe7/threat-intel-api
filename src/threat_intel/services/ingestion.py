from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.analyzers.dedup import upsert_threat
from threat_intel.collectors.base import BaseCollector
from threat_intel.core.exceptions import ConfigurationError
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.services.scoring_job import ThreatScoringJob

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
        scoring_job: ThreatScoringJob | None = None,
    ) -> None:
        self._sf = session_factory
        self._collectors = {c.source_name: c for c in collectors}
        self._batch_size = batch_size
        self._scoring_job = scoring_job

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

        # Capture a slightly earlier timestamp so SQLite's second-precision
        # CURRENT_TIMESTAMP does not race with newly-inserted rows.
        run_started = datetime.now(UTC) - timedelta(seconds=1)
        result = IngestionResult()
        try:
            async with self._sf() as session:
                src = (
                    await session.execute(select(Source).where(Source.name == source_name))
                ).scalar_one()
                src.last_run_at = datetime.now(UTC)
                src_id = src.id
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

            if self._scoring_job is not None and (result.inserted + result.updated) > 0:
                async with self._sf() as session:
                    affected_ids = (
                        (
                            await session.execute(
                                select(Threat.id).where(
                                    Threat.source_id == src_id,
                                    Threat.updated_at >= run_started,
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                if affected_ids:
                    score_result = await self._scoring_job.score_threat_ids(
                        list(affected_ids)
                    )
                    log.info(
                        "ingestion.scoring_done",
                        threats=score_result.threats_scored,
                        profiles=score_result.profiles_count,
                        rows_written=score_result.rows_written,
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
