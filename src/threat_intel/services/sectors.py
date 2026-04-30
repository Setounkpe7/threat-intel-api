"""Read-side helpers for sector endpoints (M2)."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from threat_intel.models.base import Severity
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource


@dataclass
class ScoredThreatRow:
    threat: Threat
    score: float
    score_breakdown: dict[str, Any]
    calculated_at: datetime


async def list_profiles(session: AsyncSession, *, include_private: bool) -> list[SectorProfile]:
    stmt = select(SectorProfile).order_by(SectorProfile.id)
    if not include_private:
        stmt = stmt.where(SectorProfile.visibility == "public")
    return list((await session.execute(stmt)).scalars().all())


async def get_profile(
    session: AsyncSession, sector_id: str, *, include_private: bool
) -> SectorProfile | None:
    row = await session.get(SectorProfile, sector_id)
    if row is None:
        return None
    if row.visibility == "private" and not include_private:
        return None
    return row


async def list_scored_threats(
    session: AsyncSession,
    *,
    sector_id: str,
    min_score: float = 0.0,
    since: datetime | None = None,
    limit: int = 50,
) -> list[ScoredThreatRow]:
    limit = max(1, min(limit, 200))
    stmt = (
        select(Threat, ThreatSectorScore)
        .join(ThreatSectorScore, Threat.id == ThreatSectorScore.threat_id)
        .options(
            selectinload(Threat.cwes),
            selectinload(Threat.sources).selectinload(ThreatSource.source),
        )
        .where(
            ThreatSectorScore.sector_id == sector_id,
            ThreatSectorScore.score >= min_score,
        )
        .order_by(ThreatSectorScore.score.desc(), Threat.published_at.desc())
        .limit(limit)
    )
    if since is not None:
        stmt = stmt.where(Threat.published_at >= since)
    rows = (await session.execute(stmt)).all()
    return [
        ScoredThreatRow(
            threat=t,
            score=tss.score,
            score_breakdown=tss.score_breakdown,
            calculated_at=tss.calculated_at,
        )
        for t, tss in rows
    ]


async def sector_dashboard_payload(
    session: AsyncSession, *, sector_id: str
) -> tuple[list[ScoredThreatRow], list[ScoredThreatRow], dict[str, Any]]:
    now = datetime.now(UTC)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    top_24 = await list_scored_threats(session, sector_id=sector_id, since=last_24h, limit=10)
    top_7 = await list_scored_threats(session, sector_id=sector_id, since=last_7d, limit=10)

    total = (
        await session.execute(
            select(func.count())
            .select_from(ThreatSectorScore)
            .where(ThreatSectorScore.sector_id == sector_id)
        )
    ).scalar_one()

    sev_counts = (
        await session.execute(
            select(Threat.severity, func.count())
            .join(ThreatSectorScore, Threat.id == ThreatSectorScore.threat_id)
            .where(
                ThreatSectorScore.sector_id == sector_id,
                ThreatSectorScore.score >= 70.0,
            )
            .group_by(Threat.severity)
        )
    ).all()
    crit = sum(c for s, c in sev_counts if s == Severity.critical)
    high = sum(c for s, c in sev_counts if s == Severity.high)

    avg_score = (
        await session.execute(
            select(func.avg(ThreatSectorScore.score)).where(
                ThreatSectorScore.sector_id == sector_id
            )
        )
    ).scalar() or 0.0

    sources = (
        (
            await session.execute(
                select(Source.name)
                .join(ThreatSource, ThreatSource.source_id == Source.id)
                .join(ThreatSectorScore, ThreatSource.threat_id == ThreatSectorScore.threat_id)
                .where(ThreatSectorScore.sector_id == sector_id)
                .distinct()
            )
        )
        .scalars()
        .all()
    )

    stats = {
        "total_threats": int(total),
        "critical_count": int(crit),
        "high_count": int(high),
        "average_score": round(float(avg_score), 2),
        "sources_active": list(sources),
    }
    return top_24, top_7, stats


async def global_stats_payload(session: AsyncSession) -> dict[str, Any]:
    total = (await session.execute(select(func.count(Threat.id)))).scalar_one()
    last_24h = (
        await session.execute(
            select(func.count(Threat.id)).where(
                Threat.published_at >= datetime.now(UTC) - timedelta(hours=24)
            )
        )
    ).scalar_one()
    sev_counts = (
        await session.execute(select(Threat.severity, func.count()).group_by(Threat.severity))
    ).all()
    by_severity = {str(s.value): int(c) for s, c in sev_counts}
    high_score_per_sector = (
        await session.execute(
            select(ThreatSectorScore.sector_id, func.count())
            .where(ThreatSectorScore.score >= 70.0)
            .group_by(ThreatSectorScore.sector_id)
            .order_by(func.count().desc())
            .limit(20)
        )
    ).all()
    by_sector_top_score = [
        {"sector_id": sid, "count_score_ge_70": int(c)} for sid, c in high_score_per_sector
    ]
    sources = (
        (await session.execute(select(Source.name).where(Source.enabled.is_(True)))).scalars().all()
    )
    return {
        "total_threats": int(total),
        "last_24h": int(last_24h),
        "by_severity": by_severity,
        "by_sector_top_score": by_sector_top_score,
        "sources_active": list(sources),
    }
