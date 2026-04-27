from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel import __version__
from threat_intel.api.deps import get_db
from threat_intel.schemas.health import CollectorHealth, HealthResponse, Stats
from threat_intel.services.threats import collector_health, stats

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request, session: AsyncSession = Depends(get_db)) -> HealthResponse:
    start_time: datetime = request.app.state.start_time
    uptime = int((datetime.now(UTC) - start_time).total_seconds())

    db_status = "connected"
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    collectors_state: dict[str, CollectorHealth] = {}
    overall_status: str = "ok"

    for source_name in request.app.state.collector_names:
        src, count_24h = await collector_health(session, source_name)
        if src is None:
            continue
        collectors_state[source_name] = CollectorHealth(
            last_run=src.last_run_at,
            last_success=src.last_error is None and src.last_success_at is not None,
            threats_collected_24h=count_24h,
        )

    if db_status != "connected":
        overall_status = "degraded"

    total, last_24h = (0, 0) if db_status != "connected" else await stats(session)

    return HealthResponse(
        status="ok" if overall_status == "ok" else "degraded",
        version=__version__,
        uptime_seconds=uptime,
        database=db_status,
        collectors=collectors_state,
        stats=Stats(total_threats=total, threats_last_24h=last_24h),
    )
