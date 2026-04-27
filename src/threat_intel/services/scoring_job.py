"""ThreatScoringJob — orchestrates SectorScoringService over the DB (M2).

Scoping:
- `score_threat_ids` is the workhorse: load fully hydrated threats, load every
  sector profile, compute scores, upsert one ThreatSectorScore per (threat, profile).
- `score_threats_since` is used by the daily APScheduler tick.
- `rescore_all` is used by /admin/rescore-all.
"""

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.threat import Threat
from threat_intel.services.sector_scoring import SectorScoringService

logger = structlog.get_logger(__name__)


@dataclass
class ScoringRunResult:
    threats_scored: int = 0
    profiles_count: int = 0
    rows_written: int = 0


class ThreatScoringJob:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        chunk_size: int = 200,
    ) -> None:
        self._sf = session_factory
        self._chunk = chunk_size

    async def score_threat_ids(
        self, threat_ids: Sequence[uuid.UUID]
    ) -> ScoringRunResult:
        result = ScoringRunResult()
        if not threat_ids:
            return result
        async with self._sf() as session:
            profiles = await self._load_profiles(session)
            result.profiles_count = len(profiles)
            if not profiles:
                return result
            for chunk in _chunked(threat_ids, self._chunk):
                threats = await self._load_threats(session, chunk)
                for threat in threats:
                    written = await self._score_one(session, threat, profiles)
                    if written > 0:
                        result.threats_scored += 1
                        result.rows_written += written
                await session.commit()
        logger.info(
            "scoring_job.score_threat_ids.done",
            requested=len(threat_ids),
            scored=result.threats_scored,
            profiles=result.profiles_count,
            rows_written=result.rows_written,
        )
        return result

    async def score_threats_since(self, since: datetime) -> ScoringRunResult:
        async with self._sf() as session:
            ids = (
                await session.execute(
                    select(Threat.id).where(Threat.last_modified_at >= since)
                )
            ).scalars().all()
        return await self.score_threat_ids(list(ids))

    async def rescore_all(self) -> ScoringRunResult:
        async with self._sf() as session:
            ids = (await session.execute(select(Threat.id))).scalars().all()
        return await self.score_threat_ids(list(ids))

    async def _load_profiles(self, session: AsyncSession) -> list[SectorProfile]:
        return list((await session.execute(select(SectorProfile))).scalars().all())

    async def _load_threats(
        self, session: AsyncSession, ids: Sequence[uuid.UUID]
    ) -> list[Threat]:
        if not ids:
            return []
        rows = await session.execute(
            select(Threat).options(selectinload(Threat.cwes)).where(Threat.id.in_(ids))
        )
        return list(rows.scalars().all())

    async def _score_one(
        self,
        session: AsyncSession,
        threat: Threat,
        profiles: list[SectorProfile],
    ) -> int:
        now = datetime.now(UTC)
        existing = (
            await session.execute(
                select(ThreatSectorScore).where(
                    ThreatSectorScore.threat_id == threat.id,
                    ThreatSectorScore.sector_id.in_([p.id for p in profiles]),
                )
            )
        ).scalars().all()
        existing_by_sid = {row.sector_id: row for row in existing}

        written = 0
        for profile in profiles:
            res = SectorScoringService.calculate_score(threat, profile)
            row = existing_by_sid.get(profile.id)
            if row is None:
                session.add(
                    ThreatSectorScore(
                        threat_id=threat.id,
                        sector_id=profile.id,
                        score=res.score,
                        score_breakdown=res.breakdown,
                        calculated_at=now,
                    )
                )
            else:
                row.score = res.score
                row.score_breakdown = res.breakdown
                row.calculated_at = now
            written += 1
        return written


def _chunked(seq: Sequence[uuid.UUID], n: int) -> Iterable[Sequence[uuid.UUID]]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


__all__ = ["ThreatScoringJob", "ScoringRunResult"]


def daily_recent_window() -> datetime:
    return datetime.now(UTC) - timedelta(days=7)
