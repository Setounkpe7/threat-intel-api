from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.models.base import Severity
from threat_intel.models.cve import CVE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat


@dataclass
class ThreatPage:
    items: list[Threat]
    total: int
    limit: int
    offset: int


async def list_threats(
    session: AsyncSession,
    *,
    severity: list[Severity] | None = None,
    since: datetime | None = None,
    source: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> ThreatPage:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    base = select(Threat)
    count_base = select(func.count(Threat.id))

    conditions: list[Any] = []
    if severity:
        conditions.append(Threat.severity.in_(severity))
    if since:
        conditions.append(Threat.published_at >= since)
    if source:
        base = base.join(Source, Threat.source_id == Source.id)
        count_base = count_base.join(Source, Threat.source_id == Source.id)
        conditions.append(Source.name == source)

    if conditions:
        base = base.where(*conditions)
        count_base = count_base.where(*conditions)

    total = (await session.execute(count_base)).scalar_one()
    rows = (
        (
            await session.execute(
                base.order_by(Threat.published_at.desc(), Threat.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ThreatPage(items=list(rows), total=total, limit=limit, offset=offset)


async def get_threat_by_cve(session: AsyncSession, cve_id: str) -> Threat | None:
    row = (
        await session.execute(select(CVE).where(CVE.cve_id == cve_id))
    ).scalar_one_or_none()
    return row.threat if row else None


async def collector_health(
    session: AsyncSession, source_name: str
) -> tuple[Source | None, int]:
    src = (
        await session.execute(select(Source).where(Source.name == source_name))
    ).scalar_one_or_none()
    if src is None:
        return None, 0
    yesterday = datetime.now(UTC) - timedelta(hours=24)
    count = (
        await session.execute(
            select(func.count(Threat.id)).where(
                Threat.source_id == src.id, Threat.created_at >= yesterday
            )
        )
    ).scalar_one()
    return src, int(count)


async def stats(session: AsyncSession) -> tuple[int, int]:
    yesterday = datetime.now(UTC) - timedelta(hours=24)
    total = (await session.execute(select(func.count(Threat.id)))).scalar_one()
    last_24h = (
        await session.execute(
            select(func.count(Threat.id)).where(Threat.created_at >= yesterday)
        )
    ).scalar_one()
    return int(total), int(last_24h)
