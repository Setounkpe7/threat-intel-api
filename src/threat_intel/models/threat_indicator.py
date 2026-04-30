import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import GUID, Base, IndicatorType, TimestampMixin, UtcDateTime


class ThreatIndicator(Base, TimestampMixin):
    __tablename__ = "threat_indicator"
    __table_args__ = (
        UniqueConstraint("threat_id", "indicator_type", "value", name="uq_threat_indicator"),
        Index("ix_threat_indicator_lookup", "indicator_type", "value"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    threat_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat.id", ondelete="CASCADE"), index=True
    )
    indicator_type: Mapped[IndicatorType]
    value: Mapped[str] = mapped_column(String(512))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime())
    confidence: Mapped[int] = mapped_column(Integer, default=100)
