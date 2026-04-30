from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.collectors.base import BaseCollector
from threat_intel.core.exceptions import ConfigurationError
from threat_intel.models.base import CollectorRunStatus
from threat_intel.models.collector_run import CollectorRun
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.services.ingest import IngestService
from threat_intel.services.scoring_job import ThreatScoringJob

logger = structlog.get_logger(__name__)


@dataclass
class IngestionResult:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    events_failed: int = 0


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
        self._ingest = IngestService(session_factory)

    async def run(self, source_name: str) -> IngestionResult:
        collector = self._collectors.get(source_name)
        if collector is None:
            raise ConfigurationError(f"No collector registered for source '{source_name}'")

        log = logger.bind(source=source_name)

        # --- Read source row, determine `since` window ---
        async with self._sf() as session:
            src = (
                await session.execute(select(Source).where(Source.name == source_name))
            ).scalar_one_or_none()
            if src is None:
                raise ConfigurationError(f"Source row missing in DB: {source_name}")
            since = src.last_success_at or datetime.now(UTC) - timedelta(hours=24)
            src_id = src.id

        log.info("ingestion.start", since=since.isoformat())

        # Capture a slightly earlier timestamp so SQLite's second-precision
        # CURRENT_TIMESTAMP does not race with newly-inserted rows.
        run_started_dt = datetime.now(UTC) - timedelta(seconds=1)

        # --- INSERT CollectorRun (status=running) ---
        async with self._sf() as session:
            run_row = CollectorRun(
                source_id=src_id,
                started_at=run_started_dt,
                status=CollectorRunStatus.running,
            )
            session.add(run_row)
            await session.flush()
            run_id = run_row.id
            await session.commit()

        result = IngestionResult()
        fetched = 0
        new_count = 0
        updated_count = 0
        failed_count = 0

        try:
            async for raw in collector.fetch(since):
                fetched += 1
                try:
                    event = collector.to_event(raw)
                    outcome, _ = await self._ingest.process(event, src_id)
                    if outcome == "created":
                        new_count += 1
                    elif outcome == "updated":
                        updated_count += 1
                except Exception as event_exc:  # noqa: BLE001
                    failed_count += 1
                    log.warning(
                        "ingestion.event_failed",
                        external_id=getattr(raw, "external_id", "unknown"),
                        error=str(event_exc),
                    )
                    # Continue processing remaining events

            result.inserted = new_count
            result.updated = updated_count
            result.events_failed = failed_count

            # --- Determine final status ---
            if failed_count == 0:
                final_status = CollectorRunStatus.success
            elif (new_count + updated_count) > 0:
                final_status = CollectorRunStatus.partial
            else:
                final_status = CollectorRunStatus.failure

            finished_at = datetime.now(UTC)
            duration_ms = int((finished_at - run_started_dt).total_seconds() * 1000)

            # --- Update CollectorRun row ---
            async with self._sf() as session:
                run_row = (
                    await session.execute(
                        select(CollectorRun).where(CollectorRun.id == run_id)
                    )
                ).scalar_one()
                run_row.finished_at = finished_at
                run_row.status = final_status
                run_row.events_fetched = fetched
                run_row.events_new = new_count
                run_row.events_updated = updated_count
                run_row.events_failed = failed_count
                run_row.duration_ms = duration_ms
                await session.commit()

            # --- Reset Source backoff on clean exit ---
            async with self._sf() as session:
                src = (
                    await session.execute(select(Source).where(Source.name == source_name))
                ).scalar_one()
                src.consecutive_failures = 0
                src.current_interval_minutes = src.base_interval_minutes
                src.last_success_at = finished_at
                src.last_error = None
                src.next_run_at = finished_at + timedelta(minutes=src.current_interval_minutes)
                src.last_run_at = finished_at
                await session.commit()

            log.info(
                "ingestion.done",
                inserted=result.inserted,
                updated=result.updated,
                unchanged=result.unchanged,
                failed=result.events_failed,
                status=final_status,
            )

            # --- Score newly affected threats ---
            if self._scoring_job is not None and (result.inserted + result.updated) > 0:
                async with self._sf() as session:
                    affected_ids = (
                        (
                            await session.execute(
                                select(Threat.id).where(
                                    Threat.updated_at >= run_started_dt,
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                if affected_ids:
                    score_result = await self._scoring_job.score_threat_ids(list(affected_ids))
                    log.info(
                        "ingestion.scoring_done",
                        threats=score_result.threats_scored,
                        profiles=score_result.profiles_count,
                        rows_written=score_result.rows_written,
                    )

            return result

        except Exception as e:
            log.exception("ingestion.failed", error=str(e))

            failed_at = datetime.now(UTC)
            duration_ms = int((failed_at - run_started_dt).total_seconds() * 1000)
            error_msg = f"{type(e).__name__}: {e}"[:1000]

            # --- Update CollectorRun row with failure ---
            async with self._sf() as session:
                run_row = (
                    await session.execute(
                        select(CollectorRun).where(CollectorRun.id == run_id)
                    )
                ).scalar_one()
                run_row.finished_at = failed_at
                run_row.status = CollectorRunStatus.failure
                run_row.events_fetched = fetched
                run_row.events_new = new_count
                run_row.events_updated = updated_count
                run_row.events_failed = failed_count
                run_row.error_message = error_msg
                run_row.duration_ms = duration_ms
                await session.commit()

            # --- Apply Source backoff ---
            async with self._sf() as session:
                src = (
                    await session.execute(select(Source).where(Source.name == source_name))
                ).scalar_one()
                src.consecutive_failures += 1
                if src.consecutive_failures >= 3:
                    src.current_interval_minutes = min(
                        src.current_interval_minutes * 2, 1440
                    )
                src.last_error = error_msg
                src.next_run_at = failed_at + timedelta(minutes=src.current_interval_minutes)
                src.last_run_at = failed_at
                await session.commit()

            raise
