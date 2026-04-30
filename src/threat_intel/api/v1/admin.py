"""Admin endpoints — protected by X-Admin-Key (M2 phase 7)."""

from datetime import UTC
from datetime import datetime as _dt
from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from sqlalchemy import select

from threat_intel.api.security import AdminAuth
from threat_intel.models.source import Source as _Source
from threat_intel.schemas.api.admin import CollectorActionResult
from threat_intel.schemas.sector import ReloadProfilesResult, RescoreAllAcknowledged
from threat_intel.services.profile_loader import SectorProfileLoader
from threat_intel.services.scoring_job import ThreatScoringJob

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[AdminAuth])


@router.post("/reload-profiles", response_model=ReloadProfilesResult)
async def reload_profiles(request: Request) -> ReloadProfilesResult:
    loader: SectorProfileLoader = request.app.state.profile_loader
    result = await loader.load_all(remove_missing=True)
    return ReloadProfilesResult(
        public_count=result.public_count,
        private_count=result.private_count,
        added=result.added,
        updated=result.updated,
        removed=result.removed,
        errors=[{"file": p, "message": m} for p, m in result.errors],
    )


async def _rescore_all_in_background(scoring_job: ThreatScoringJob) -> None:
    try:
        result = await scoring_job.rescore_all()
        logger.info(
            "admin.rescore_all.done",
            threats=result.threats_scored,
            rows_written=result.rows_written,
        )
    except Exception:  # noqa: BLE001
        logger.exception("admin.rescore_all.failed")


@router.post(
    "/rescore-all",
    response_model=RescoreAllAcknowledged,
    status_code=202,
)
async def rescore_all(
    request: Request, background: Annotated[BackgroundTasks, BackgroundTasks]
) -> RescoreAllAcknowledged:
    scoring_job: ThreatScoringJob = request.app.state.scoring_job
    background.add_task(_rescore_all_in_background, scoring_job)
    return RescoreAllAcknowledged(detail="Rescoring queued in background")


# ---------------------------------------------------------------------------
# Collector controls
# ---------------------------------------------------------------------------


async def _run_collector_in_background(ingestion: object, source_name: str) -> None:
    try:
        from threat_intel.services.ingestion import IngestionService

        assert isinstance(ingestion, IngestionService)
        await ingestion.run(source_name)
    except Exception:  # noqa: BLE001
        logger.exception("admin.trigger.failed", source=source_name)


@router.post("/collectors/{name}/trigger", response_model=CollectorActionResult)
async def trigger_collector(
    name: str, request: Request, background: BackgroundTasks
) -> CollectorActionResult:
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (
            await session.execute(select(_Source).where(_Source.name == name))
        ).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail=f"Unknown collector: {name}")
        enabled = src.enabled
    background.add_task(_run_collector_in_background, request.app.state.ingestion, name)
    return CollectorActionResult(
        name=name, enabled=enabled, next_run_at=None, detail="Run dispatched"
    )


@router.post("/collectors/{name}/enable", response_model=CollectorActionResult)
async def enable_collector(name: str, request: Request) -> CollectorActionResult:
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (
            await session.execute(select(_Source).where(_Source.name == name))
        ).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail=f"Unknown collector: {name}")
        src.enabled = True
        src.consecutive_failures = 0
        src.current_interval_minutes = src.base_interval_minutes
        src.next_run_at = _dt.now(UTC)
        await session.commit()
        next_run = src.next_run_at
    return CollectorActionResult(name=name, enabled=True, next_run_at=next_run, detail="Enabled")


@router.post("/collectors/{name}/disable", response_model=CollectorActionResult)
async def disable_collector(name: str, request: Request) -> CollectorActionResult:
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (
            await session.execute(select(_Source).where(_Source.name == name))
        ).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail=f"Unknown collector: {name}")
        src.enabled = False
        await session.commit()
    return CollectorActionResult(name=name, enabled=False, next_run_at=None, detail="Disabled")
