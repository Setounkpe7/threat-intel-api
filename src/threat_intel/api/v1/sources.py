from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from threat_intel.models.collector_run import CollectorRun
from threat_intel.models.source import Source
from threat_intel.schemas.api.sources import CollectorRunOut, SourceHealth
from threat_intel.services.threats import source_attestations_24h

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("", response_model=list[SourceHealth])
async def list_sources(request: Request) -> list[SourceHealth]:
    sf = request.app.state.session_factory
    out: list[SourceHealth] = []
    async with sf() as session:
        rows = (await session.execute(select(Source).order_by(Source.name))).scalars().all()
        for src in rows:
            # Use the canonical attestation metric: threat_source rows with
            # first_seen_at in the last 24h. This matches /health exactly.
            count = await source_attestations_24h(session, src.name)
            out.append(
                SourceHealth(
                    name=src.name,
                    enabled=src.enabled,
                    last_run_at=src.last_run_at,
                    last_success_at=src.last_success_at,
                    consecutive_failures=src.consecutive_failures,
                    current_interval_minutes=src.current_interval_minutes,
                    next_run_at=src.next_run_at,
                    events_24h=count,
                )
            )
    return out


@router.get("/{source_id}/runs", response_model=list[CollectorRunOut])
async def list_source_runs(source_id: int, request: Request) -> list[CollectorRunOut]:
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (
            await session.execute(select(Source).where(Source.id == source_id))
        ).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail="Source not found")
        runs = (
            (
                await session.execute(
                    select(CollectorRun)
                    .where(CollectorRun.source_id == source_id)
                    .order_by(CollectorRun.started_at.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
    return [
        CollectorRunOut(
            id=r.id,
            started_at=r.started_at,
            finished_at=r.finished_at,
            status=r.status.value,
            events_fetched=r.events_fetched,
            events_new=r.events_new,
            events_updated=r.events_updated,
            events_failed=r.events_failed,
            error_message=r.error_message,
            duration_ms=r.duration_ms,
        )
        for r in runs
    ]
