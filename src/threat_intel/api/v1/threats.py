import uuid as _uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.models.base import Severity
from threat_intel.models.source import Source as _Source
from threat_intel.models.threat_source import ThreatSource as _ThreatSource
from threat_intel.schemas.api.sources import ThreatSourceOut
from threat_intel.schemas.threat import ThreatList
from threat_intel.services.threats import list_threats

router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("", response_model=ThreatList)
async def get_threats(
    session: Annotated[AsyncSession, Depends(get_db)],
    severity: Annotated[list[Severity] | None, Query()] = None,
    since: datetime | None = None,
    source: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ThreatList:
    page = await list_threats(
        session,
        severity=severity or None,
        since=since,
        source=source,
        limit=limit,
        offset=offset,
    )
    return ThreatList(
        items=page.items,  # already ThreatRead instances from service layer
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{threat_id}/sources", response_model=list[ThreatSourceOut])
async def list_threat_sources(
    threat_id: _uuid.UUID, request: Request
) -> list[ThreatSourceOut]:
    sf = request.app.state.session_factory
    async with sf() as session:
        rows = (
            await session.execute(
                select(_ThreatSource, _Source.name)
                .join(_Source, _ThreatSource.source_id == _Source.id)
                .where(_ThreatSource.threat_id == threat_id)
            )
        ).all()
    return [
        ThreatSourceOut(
            source_name=name,
            external_id=ts.external_id,
            first_seen_at=ts.first_seen_at,
            last_seen_at=ts.last_seen_at,
            tags=ts.tags,
        )
        for ts, name in rows
    ]
