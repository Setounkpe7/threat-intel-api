"""Admin endpoints — protected by X-Admin-Key (M2 phase 7)."""

from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, Request

from threat_intel.api.security import AdminAuth
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
