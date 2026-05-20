"""Aggregated stats endpoint for a future public dashboard (M2 phase 10)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.api.security import limiter
from threat_intel.schemas.sector import GlobalStats
from threat_intel.services import sectors as sector_svc

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/global", response_model=GlobalStats)
@limiter.limit("100/minute")
async def global_stats(
    request: Request,
    response: Response,  # injected by SlowAPI for X-RateLimit-* header population
    session: Annotated[AsyncSession, Depends(get_db)],
) -> GlobalStats:
    payload = await sector_svc.global_stats_payload(session)
    return GlobalStats(**payload)
