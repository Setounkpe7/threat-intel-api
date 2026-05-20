from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from threat_intel.models.base import Severity
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource
from threat_intel.schemas.threat import ThreatRead


@dataclass
class ThreatPage:
    items: list[ThreatRead]
    total: int
    limit: int
    offset: int


def _to_read(threat: Threat) -> ThreatRead:
    """Assemble a ThreatRead from an eagerly-loaded Threat + ThreatSource[*]."""
    sources = list(threat.sources or [])

    # Pick external_id: prefer the NVD ThreatSource, else first available
    nvd_source = next((s for s in sources if s.source and s.source.name == "nvd"), None)
    representative = nvd_source or (sources[0] if sources else None)
    external_id_value = representative.external_id if representative else None

    products: list[str] = []
    refs: list[str] = []
    for s in sources:
        for p in s.affected_products or []:
            if p not in products:
                products.append(p)
        for r in s.references or []:
            if r not in refs:
                refs.append(r)

    source_names: list[str] = []
    for s in sources:
        if s.source and s.source.name not in source_names:
            source_names.append(s.source.name)

    return ThreatRead(
        id=threat.id,
        threat_type=threat.threat_type,
        title=threat.title,
        summary=threat.summary,
        severity=threat.severity,
        cvss_score=threat.cvss_score,
        cvss_vector=threat.cvss_vector,
        cvss_version=threat.cvss_version,
        tags=list(threat.tags or []),
        published_at=threat.published_at,
        last_modified_at=threat.last_modified_at,
        external_id=external_id_value,
        description=threat.summary,
        affected_products=products,
        references=refs,
        sources=source_names,
    )


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
    base = select(Threat).options(selectinload(Threat.sources).selectinload(ThreatSource.source))
    count_base = select(func.count(Threat.id))

    conditions: list[Any] = []
    if severity:
        conditions.append(Threat.severity.in_(severity))
    if since:
        conditions.append(Threat.published_at >= since)
    if source:
        subq = (
            select(ThreatSource.threat_id)
            .join(Source, ThreatSource.source_id == Source.id)
            .where(Source.name == source)
        )
        conditions.append(Threat.id.in_(subq))

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
    return ThreatPage(
        items=[_to_read(t) for t in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


async def get_threat_by_external_id(session: AsyncSession, external_id: str) -> Threat | None:
    # M3a moved canonical CVE/GHSA storage to threat_source.external_id; the legacy
    # cve table is no longer written to. Look up via ThreatSource so drill-down from
    # sector dashboards (which surface CVE-* and GHSA-* alike) resolves.
    row = (
        await session.execute(
            select(ThreatSource)
            .options(
                selectinload(ThreatSource.threat)
                .selectinload(Threat.sources)
                .selectinload(ThreatSource.source)
            )
            .where(ThreatSource.external_id == external_id)
            .limit(1)
        )
    ).scalar_one_or_none()
    return row.threat if row else None


async def collector_health(session: AsyncSession, source_name: str) -> tuple[Source | None, int]:
    src = (
        await session.execute(select(Source).where(Source.name == source_name))
    ).scalar_one_or_none()
    if src is None:
        return None, 0
    yesterday = datetime.now(UTC) - timedelta(hours=24)
    # Count threats that have a ThreatSource from this source created in the last 24h
    count = (
        await session.execute(
            select(func.count(ThreatSource.threat_id)).where(
                ThreatSource.source_id == src.id,
                ThreatSource.created_at >= yesterday,
            )
        )
    ).scalar_one()
    return src, int(count)


async def stats(session: AsyncSession) -> tuple[int, int]:
    yesterday = datetime.now(UTC) - timedelta(hours=24)
    total = (await session.execute(select(func.count(Threat.id)))).scalar_one()
    last_24h = (
        await session.execute(select(func.count(Threat.id)).where(Threat.published_at >= yesterday))
    ).scalar_one()
    return int(total), int(last_24h)
