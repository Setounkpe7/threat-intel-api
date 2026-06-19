import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from sqlalchemy import Executable, select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.models.base import IndicatorType, Severity, SourceKind
from threat_intel.models.cwe import CWE
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.models.threat_source import ThreatSource
from threat_intel.schemas.ingest import CollectedEvent

logger = structlog.get_logger(__name__)

_SEVERITY_RANK = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.none: 1,
    Severity.unknown: 0,
}

_PRIORITY_ORDER = ("nvd", "github_advisories", "cisa_kev")


def _is_postgres(session: AsyncSession) -> bool:
    bind = session.get_bind()
    return bind.dialect.name == "postgresql"


def _upsert_indicator_stmt(session: AsyncSession, values: dict[str, Any]) -> Executable:
    """ON CONFLICT DO NOTHING upsert for ThreatIndicator; works on both PG and SQLite."""
    if _is_postgres(session):
        pg_stmt = pg_insert(ThreatIndicator.__table__).values(**values)  # type: ignore[arg-type]
        return pg_stmt.on_conflict_do_nothing(
            index_elements=["threat_id", "indicator_type", "value"]
        )
    sq_stmt = sqlite_insert(ThreatIndicator.__table__).values(**values)  # type: ignore[arg-type]
    return sq_stmt.on_conflict_do_nothing(index_elements=["threat_id", "indicator_type", "value"])


async def _lookup_threat_ids_by_indicators(
    session: AsyncSession, indicators: list[Any]
) -> list[uuid.UUID]:
    keys = [(IndicatorType[i.type], i.value) for i in indicators if i.type in ("cve", "ghsa")]
    if not keys:
        return []
    rows = (
        (
            await session.execute(
                select(ThreatIndicator.threat_id).where(
                    tuple_(ThreatIndicator.indicator_type, ThreatIndicator.value).in_(keys)
                )
            )
        )
        .scalars()
        .all()
    )
    seen: list[uuid.UUID] = []
    for r in rows:
        if r not in seen:
            seen.append(r)
    return seen


class IngestService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def process(
        self, event: CollectedEvent, source_id: int
    ) -> tuple[Literal["created", "updated"], uuid.UUID]:
        """Ingest one CollectedEvent — dispatches to canonical or enrichment regime.

        enrichment_mode=False (CVE collectors: NVD, KEV, GHSA):
            → _process_canonical: the original dedup/merge/create behavior.

        enrichment_mode=True (RSS feeds):
            → _process_enrichment: fan-out to matched CVE threats; idempotent
              autonomous threat for no-CVE items.
        """
        if event.enrichment_mode:
            return await self._process_enrichment(event, source_id)
        return await self._process_canonical(event, source_id)

    async def _process_canonical(
        self, event: CollectedEvent, source_id: int
    ) -> tuple[Literal["created", "updated"], uuid.UUID]:
        """Original dedup logic for canonical CVE/advisory collectors.

        Single-task safe: the entire sequence (lookup → create/upsert → recompute)
        runs inside one session/transaction, so within a single coroutine no
        TOCTOU race can produce duplicate Threats.

        Multi-task safety: NOT guaranteed. If two collectors process the same CVE
        in parallel coroutines (e.g. NVD and KEV both ingesting CVE-2024-X in the
        same scheduler tick), both may pass the dedup lookup with 0 matches and
        both may create a Threat. On Postgres the UNIQUE constraint on
        threat_indicators(threat_id, indicator_type, value) will fail one of the
        two transactions and the IngestionService event-level except block will
        record it as events_failed. On SQLite (tests) the constraint behaves the
        same way at INSERT time. The merge_candidate path then handles future
        ingestions of the same CVE.

        Acceptable for M3a given the once-per-tick cadence and small per-collector
        fan-out. A stronger guarantee (advisory locks per CVE-ID, or a
        SERIALIZABLE transaction) is M3b/M4 work.
        """
        async with self._sf() as session:
            matches = await _lookup_threat_ids_by_indicators(session, event.indicators)

            created_threat = False
            if len(matches) == 0:
                threat_id = await self._create_threat(session, event)
                created_threat = True
            elif len(matches) > 1:
                threat_id = await self._pick_oldest(session, matches)
                others = [m for m in matches if m != threat_id]
                logger.warning(
                    "merge_candidate",
                    winner_threat_id=str(threat_id),
                    other_threat_ids=[str(o) for o in others],
                    triggered_by=event.external_id,
                    source=event.source_name,
                )
                event.raw_data = {
                    **event.raw_data,
                    "cross_references": [str(o) for o in others],
                }
            else:
                threat_id = matches[0]

            await self._upsert_threat_source(session, threat_id, source_id, event)
            await self._upsert_indicators(session, threat_id, event)
            await session.flush()
            await recompute_canonical(session, threat_id)
            await session.commit()

            outcome: Literal["created", "updated"] = "created" if created_threat else "updated"
            return outcome, threat_id

    async def _process_enrichment(
        self, event: CollectedEvent, source_id: int
    ) -> tuple[Literal["created", "updated"], uuid.UUID]:
        """Enrichment regime for RSS feeds.

        If the event's indicators match ≥1 existing threat (via CVE/GHSA lookup):
          - attach the RSS source + indicators to EACH matched threat
          - recompute each matched threat
          - NO merge_candidate, NO autonomous threat creation
          - returns ("updated", matches[0])

        If 0 matches: create/fetch an autonomous threat keyed on
        (source_id, external_id) via _get_or_create_autonomous, then
        upsert indicators and recompute.
        """
        async with self._sf() as session:
            matches = await _lookup_threat_ids_by_indicators(session, event.indicators)
            if matches:
                for threat_id in matches:
                    await self._upsert_threat_source(session, threat_id, source_id, event)
                    await self._upsert_indicators(session, threat_id, event)
                await session.flush()
                for threat_id in matches:
                    await recompute_canonical(session, threat_id)
                await session.commit()
                return "updated", matches[0]

            threat_id, created = await self._get_or_create_autonomous(session, event, source_id)
            await self._upsert_threat_source(session, threat_id, source_id, event)
            await self._upsert_indicators(session, threat_id, event)
            await session.flush()
            await recompute_canonical(session, threat_id)
            await session.commit()
            return ("created" if created else "updated"), threat_id

    async def _get_or_create_autonomous(
        self, session: AsyncSession, event: CollectedEvent, source_id: int
    ) -> tuple[uuid.UUID, bool]:
        """Return (threat_id, created) for an RSS item with no CVE/GHSA matches.

        Idempotent within a single coroutine: looks up an existing ThreatSource row
        for (source_id, external_id) before creating a new Threat, so repeated
        ingestion of the same RSS post returns the same threat_id without duplicates.

        Concurrency caveat (TOCTOU race):
          Two concurrent scheduler ticks for the SAME RSS source can both execute
          the SELECT above and see 0 rows for the same (source_id, external_id),
          then both proceed to _create_threat — producing duplicate autonomous
          threats for the same item.  No-CVE items carry no CVE/GHSA indicators,
          so the UNIQUE constraint on threat_indicators never fires to block one of
          the two inserts.

          Actual mitigations present in the scheduler (scheduler.py):
            - max_instances=1 on the "collector_tick" APScheduler job prevents a
              second _scheduler_tick coroutine from starting while one is still
              running.
            - coalesce=True collapses missed fires into a single execution,
              preventing bursts of catch-up ticks.
          Together these make it unlikely for two ticks to race in practice, but
          they are NOT a hard guarantee: asyncio.create_task() inside the tick
          spawns per-source tasks that run concurrently within the same tick, so
          two different RSS sources cannot race with each other on the same
          (source_id, external_id).  Within a single source the tasks are spawned
          serially; a second task for the same source would only appear in the
          NEXT tick, by which point next_run_at has been written (ingestion.py
          line ~140) and the source is skipped.

          Durable fix: add a UNIQUE(source_id, external_id) constraint to the
          threat_source table via an Alembic migration (Plan 2 follow-up).  Until
          then the window is narrow but non-zero on slow/failed ingestion runs.
        """
        existing = (
            await session.execute(
                select(ThreatSource.threat_id).where(
                    ThreatSource.source_id == source_id,
                    ThreatSource.external_id == event.external_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False
        threat_id = await self._create_threat(session, event)
        return threat_id, True

    async def _create_threat(self, session: AsyncSession, event: CollectedEvent) -> uuid.UUID:
        if event.threat_type is not None:
            threat_type = event.threat_type
        elif any(i.type == "cve" for i in event.indicators):
            threat_type = "cve"
        elif any(i.type == "ghsa" for i in event.indicators):
            threat_type = "advisory"
        else:
            threat_type = "advisory"

        threat = Threat(
            id=uuid.uuid4(),
            threat_type=threat_type,
            title=event.title,
            summary=event.summary,
            severity=event.severity or Severity.unknown,
            cvss_score=event.cvss_score,
            cvss_vector=event.cvss_vector,
            cvss_version=event.cvss_version,
            tags=list(event.tags),
            published_at=event.published_at,
            last_modified_at=event.last_modified_at,
        )
        session.add(threat)
        await session.flush()
        return threat.id

    async def _pick_oldest(self, session: AsyncSession, ids: list[uuid.UUID]) -> uuid.UUID:
        rows = (
            await session.execute(select(Threat.id, Threat.created_at).where(Threat.id.in_(ids)))
        ).all()
        rows_sorted = sorted(rows, key=lambda r: r[1])
        return uuid.UUID(str(rows_sorted[0][0]))

    async def _upsert_threat_source(
        self,
        session: AsyncSession,
        threat_id: uuid.UUID,
        source_id: int,
        event: CollectedEvent,
    ) -> None:
        affected = (
            event.raw_data.get("affected_products") if isinstance(event.raw_data, dict) else None
        ) or []
        references = (
            event.raw_data.get("references") if isinstance(event.raw_data, dict) else None
        ) or []
        existing = (
            await session.execute(
                select(ThreatSource).where(
                    ThreatSource.threat_id == threat_id,
                    ThreatSource.source_id == source_id,
                )
            )
        ).scalar_one_or_none()
        now = datetime.now(UTC)
        if existing is None:
            session.add(
                ThreatSource(
                    threat_id=threat_id,
                    source_id=source_id,
                    external_id=event.external_id,
                    first_seen_at=event.published_at,
                    last_seen_at=now,
                    tags=list(event.tags),
                    affected_products=list(affected),
                    references=list(references),
                    raw_data=dict(event.raw_data),
                )
            )
        else:
            existing.last_seen_at = now
            existing.tags = list(event.tags)
            existing.affected_products = list(affected)
            existing.references = list(references)
            existing.raw_data = dict(event.raw_data)

    async def _upsert_indicators(
        self,
        session: AsyncSession,
        threat_id: uuid.UUID,
        event: CollectedEvent,
    ) -> None:
        if not event.indicators:
            return
        now = datetime.now(UTC)
        for ind in event.indicators:
            stmt = _upsert_indicator_stmt(
                session,
                {
                    "threat_id": threat_id,
                    "indicator_type": IndicatorType[ind.type],
                    "value": ind.value,
                    "first_seen": now,
                    "confidence": event.indicator_confidence,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            await session.execute(stmt)


async def recompute_canonical(session: AsyncSession, threat_id: uuid.UUID) -> None:
    threat = (
        await session.execute(select(Threat).where(Threat.id == threat_id))
    ).scalar_one_or_none()
    if threat is None:
        return

    sources = (
        (await session.execute(select(ThreatSource).where(ThreatSource.threat_id == threat_id)))
        .scalars()
        .all()
    )
    if not sources:
        return

    by_name: dict[str, ThreatSource] = {}
    for src_ts in sources:
        await session.refresh(src_ts, ["source"])
        by_name[src_ts.source.name] = src_ts

    rss_names = {n for n, ts in by_name.items() if ts.source.kind == SourceKind.rss}
    extra_names = [n for n in by_name if n not in _PRIORITY_ORDER]
    effective_order = list(_PRIORITY_ORDER) + sorted(extra_names)
    canonical_order = [n for n in effective_order if n not in rss_names]

    def _first_str(field: str) -> str | None:
        for name in effective_order:
            candidate = by_name.get(name)
            if candidate is None:
                continue
            v = (candidate.raw_data or {}).get(field)
            if isinstance(v, str) and v:
                return v
        return None

    title = _first_str("title") or threat.title
    summary = _first_str("summary")

    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    for pname in canonical_order:
        pcandidate = by_name.get(pname)
        if pcandidate is None:
            continue
        s = (pcandidate.raw_data or {}).get("cvss_score")
        if s is not None:
            cvss_score = float(s)
            cvss_vector_val = (pcandidate.raw_data or {}).get("cvss_vector")
            cvss_version_val = (pcandidate.raw_data or {}).get("cvss_version")
            cvss_vector = cvss_vector_val if isinstance(cvss_vector_val, str) else None
            cvss_version = cvss_version_val if isinstance(cvss_version_val, str) else None
            break

    severity: Severity = Severity.unknown
    for pname in canonical_order:
        pcandidate = by_name.get(pname)
        if pcandidate is None:
            continue
        sv = (pcandidate.raw_data or {}).get("severity")
        if sv:
            try:
                severity = Severity(sv) if isinstance(sv, str) else Severity(str(sv))
                break
            except ValueError:
                continue

    tags: list[str] = []
    for src_ts in sources:
        for tag in src_ts.tags or []:
            if tag not in tags:
                tags.append(tag)
    # Only bump severity to critical when the `kev` tag comes from a canonical
    # (non-RSS) source.  RSS feeds must not emit `kev` themselves; if one does it
    # should not be trusted to drive a severity escalation.
    canonical_tags: set[str] = set()
    for pname in canonical_order:
        pcandidate = by_name.get(pname)
        if pcandidate is not None:
            canonical_tags.update(pcandidate.tags or [])
    kev_from_canonical = "kev" in canonical_tags
    if kev_from_canonical and _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK[Severity.critical]:
        severity = Severity.critical

    cwe_ids: list[str] = []
    for src_ts in sources:
        for c in (src_ts.raw_data or {}).get("cwe_ids") or []:
            if c not in cwe_ids:
                cwe_ids.append(c)

    threat.title = title if isinstance(title, str) and title else threat.title
    threat.summary = summary if isinstance(summary, str) else threat.summary
    threat.severity = severity
    threat.cvss_score = cvss_score
    threat.cvss_vector = cvss_vector
    threat.cvss_version = cvss_version
    threat.tags = tags
    threat.published_at = min(
        (src_ts.first_seen_at for src_ts in sources), default=threat.published_at
    )
    threat.last_modified_at = max(
        (src_ts.last_seen_at for src_ts in sources), default=threat.last_modified_at
    )

    if cwe_ids:
        existing_cwes = (
            (await session.execute(select(CWE).where(CWE.id.in_(cwe_ids)))).scalars().all()
        )
        found = {c.id for c in existing_cwes}
        new_cwes = [CWE(id=cid) for cid in cwe_ids if cid not in found]
        for c in new_cwes:
            session.add(c)
        if new_cwes:
            await session.flush()
        threat.cwes = list(existing_cwes) + new_cwes
