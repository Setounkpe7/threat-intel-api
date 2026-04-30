"""Sector profile endpoints — listing, details, scored threats, dashboard, RSS."""

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from feedgen.feed import FeedGenerator  # type: ignore[import-untyped]
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.api.security import HasAdminKey, limiter
from threat_intel.schemas.sector import (
    DashboardStats,
    ScoredThreatList,
    ScoredThreatRead,
    SectorDashboard,
    SectorList,
    SectorProfileRead,
    SectorProfileSummary,
)
from threat_intel.services import sectors as sector_svc
from threat_intel.services.threats import _to_read

router = APIRouter(prefix="/sectors", tags=["sectors"])


@router.get("", response_model=SectorList)
@limiter.limit("100/minute")
async def list_sectors(
    request: Request,
    is_admin: HasAdminKey,
    session: Annotated[AsyncSession, Depends(get_db)],
    visibility: Annotated[Literal["public", "all"], Query()] = "public",
) -> SectorList:
    if visibility == "all" and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="visibility=all requires X-Admin-Key",
        )
    profiles = await sector_svc.list_profiles(session, include_private=(visibility == "all"))
    return SectorList(
        items=[SectorProfileSummary.model_validate(p) for p in profiles],
        total=len(profiles),
    )


@router.get("/{sector_id}", response_model=SectorProfileRead)
@limiter.limit("100/minute")
async def get_sector(
    request: Request,
    is_admin: HasAdminKey,
    sector_id: str,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> SectorProfileRead:
    profile = await sector_svc.get_profile(session, sector_id, include_private=is_admin)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sector not found")
    return SectorProfileRead.model_validate(profile)


@router.get("/{sector_id}/threats", response_model=ScoredThreatList)
@limiter.limit("100/minute")
async def get_sector_threats(
    request: Request,
    is_admin: HasAdminKey,
    sector_id: str,
    session: Annotated[AsyncSession, Depends(get_db)],
    min_score: Annotated[float, Query(ge=0, le=100)] = 0.0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    since: datetime | None = None,
) -> ScoredThreatList:
    profile = await sector_svc.get_profile(session, sector_id, include_private=is_admin)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sector not found")
    rows = await sector_svc.list_scored_threats(
        session,
        sector_id=sector_id,
        min_score=min_score,
        since=since,
        limit=limit,
    )
    items = [
        ScoredThreatRead(
            **_to_read(r.threat).model_dump(),
            score=r.score,
            score_breakdown=r.score_breakdown,
            calculated_at=r.calculated_at,
        )
        for r in rows
    ]
    return ScoredThreatList(items=items, total=len(items), limit=limit)


@router.get("/{sector_id}/dashboard", response_model=SectorDashboard)
@limiter.limit("100/minute")
async def get_sector_dashboard(
    request: Request,
    is_admin: HasAdminKey,
    sector_id: str,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> SectorDashboard:
    profile = await sector_svc.get_profile(session, sector_id, include_private=is_admin)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sector not found")
    top_24h, top_7d, stats = await sector_svc.sector_dashboard_payload(session, sector_id=sector_id)

    def _to_scored(rows: list[Any]) -> list[ScoredThreatRead]:
        return [
            ScoredThreatRead(
                **_to_read(r.threat).model_dump(),
                score=r.score,
                score_breakdown=r.score_breakdown,
                calculated_at=r.calculated_at,
            )
            for r in rows
        ]

    return SectorDashboard(
        sector=SectorProfileSummary.model_validate(profile),
        top_24h=_to_scored(top_24h),
        top_7d=_to_scored(top_7d),
        stats=DashboardStats(**stats),
    )


@router.get("/{sector_id}/feed.rss", response_class=Response)
@limiter.limit("100/minute")
async def get_sector_feed(
    request: Request,
    is_admin: HasAdminKey,
    sector_id: str,
    session: Annotated[AsyncSession, Depends(get_db)],
    min_score: Annotated[float, Query(ge=0, le=100)] = 70.0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Response:
    profile = await sector_svc.get_profile(session, sector_id, include_private=is_admin)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sector not found")

    rows = await sector_svc.list_scored_threats(
        session, sector_id=sector_id, min_score=min_score, limit=limit
    )

    fg = FeedGenerator()
    base = str(request.base_url).rstrip("/")
    feed_url = f"{base}/api/v1/sectors/{sector_id}/feed.rss"
    fg.id(feed_url)
    fg.title(f"Threat Intelligence Feed — {profile.name}")
    fg.link(href=feed_url, rel="self")
    fg.link(href=f"{base}/api/v1/sectors/{sector_id}", rel="alternate")
    fg.description(f"Threats scored >= {min_score:.0f} for sector profile '{profile.name}'.")
    fg.language("en")

    for r in rows:
        fe = fg.add_entry()
        tr = _to_read(r.threat)
        ext_id = tr.external_id or r.threat.title
        fe.id(f"{base}/api/v1/cve/{ext_id}")
        fe.title(f"[score={r.score:.0f}] {r.threat.title}")
        fe.link(href=f"{base}/api/v1/cve/{ext_id}")
        fe.published(r.threat.published_at)
        fe.description((tr.description or r.threat.summary or "")[:500])

    rss_bytes = fg.rss_str(pretty=True)
    return Response(content=rss_bytes, media_type="application/rss+xml")
