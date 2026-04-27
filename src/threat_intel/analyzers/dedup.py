import uuid
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from threat_intel.collectors.base import ThreatDraft
from threat_intel.models.cve import CVE
from threat_intel.models.cwe import CWE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat

UpsertResult = Literal["inserted", "updated", "unchanged"]


async def _get_or_create_cwes(session: AsyncSession, cwe_ids: list[str]) -> list[CWE]:
    if not cwe_ids:
        return []
    existing = (
        (await session.execute(select(CWE).where(CWE.id.in_(cwe_ids)))).scalars().all()
    )
    found = {c.id for c in existing}
    new_rows = [CWE(id=cid) for cid in cwe_ids if cid not in found]
    for row in new_rows:
        session.add(row)
    if new_rows:
        await session.flush()
    return [*existing, *new_rows]


async def upsert_threat(
    session: AsyncSession, source: Source, draft: ThreatDraft
) -> UpsertResult:
    """Insert or update a Threat row keyed by (source_id, external_id).

    Returns one of "inserted", "updated", or "unchanged".
    """
    stmt = (
        select(Threat)
        .options(selectinload(Threat.cwes))
        .where(Threat.source_id == source.id, Threat.external_id == draft.external_id)
    )
    existing = (await session.execute(stmt)).scalar_one_or_none()

    cwes = await _get_or_create_cwes(session, draft.cwe_ids)

    if existing is None:
        threat = Threat(
            id=uuid.uuid4(),
            source_id=source.id,
            external_id=draft.external_id,
            title=draft.title,
            description=draft.description,
            severity=draft.severity,
            cvss_score=draft.cvss_score,
            cvss_vector=draft.cvss_vector,
            cvss_version=draft.cvss_version,
            affected_products=draft.affected_products,
            references=draft.references,
            published_at=draft.published_at,
            last_modified_at=draft.last_modified_at,
            raw_data=draft.raw_data,
            cwes=cwes,
        )
        session.add(threat)
        await session.flush()
        session.add(CVE(cve_id=draft.external_id, threat_id=threat.id))
        return "inserted"

    if existing.last_modified_at == draft.last_modified_at:
        return "unchanged"

    existing.title = draft.title
    existing.description = draft.description
    existing.severity = draft.severity
    existing.cvss_score = draft.cvss_score
    existing.cvss_vector = draft.cvss_vector
    existing.cvss_version = draft.cvss_version
    existing.affected_products = draft.affected_products
    existing.references = draft.references
    existing.published_at = draft.published_at
    existing.last_modified_at = draft.last_modified_at
    existing.raw_data = draft.raw_data
    existing.cwes = cwes
    return "updated"
