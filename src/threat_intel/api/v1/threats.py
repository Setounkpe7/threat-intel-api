from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.models.base import Severity
from threat_intel.schemas.threat import ThreatList, ThreatRead
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
        items=[ThreatRead.model_validate(t) for t in page.items],
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )
