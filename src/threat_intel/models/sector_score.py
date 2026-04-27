"""ThreatSectorScore ORM model — per-(threat, profile) scoring result (M2)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import GUID, Base, UtcDateTime


class ThreatSectorScore(Base):
    __tablename__ = "threat_sector_score"
    __table_args__ = (
        Index("ix_tss_sector_score", "sector_id", "score"),
        Index("ix_tss_calculated_at", "calculated_at"),
    )

    threat_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat.id", ondelete="CASCADE"), primary_key=True
    )
    sector_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("sector_profile.id", ondelete="CASCADE"), primary_key=True
    )
    score: Mapped[float] = mapped_column(Float)
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    calculated_at: Mapped[datetime] = mapped_column(UtcDateTime())
