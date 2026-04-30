import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.models.base import GUID, Base, TimestampMixin, UtcDateTime

if TYPE_CHECKING:
    from threat_intel.models.source import Source
    from threat_intel.models.threat import Threat


class ThreatSource(Base, TimestampMixin):
    __tablename__ = "threat_source"
    __table_args__ = (
        Index("ix_threat_source_source_external", "source_id", "external_id"),
    )

    threat_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat.id", ondelete="CASCADE"), primary_key=True
    )
    source_id: Mapped[int] = mapped_column(
        ForeignKey("source.id", ondelete="CASCADE"), primary_key=True
    )
    external_id: Mapped[str] = mapped_column(String(128))

    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime())
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime())

    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column("references_json", JSON, default=list)
    raw_data: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        default=dict,
    )

    threat: Mapped["Threat"] = relationship(back_populates="sources")
    source: Mapped["Source"] = relationship()
