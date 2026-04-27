import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.models.base import GUID, Base, Severity, TimestampMixin, UtcDateTime
from threat_intel.models.cwe import threat_cwe

if TYPE_CHECKING:
    from threat_intel.models.cwe import CWE


class Threat(Base, TimestampMixin):
    __tablename__ = "threat"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_threat_source_external"),
        Index("ix_threat_published_at", "published_at"),
        Index("ix_threat_severity", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(128))

    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(default=Severity.unknown)

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)

    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    # 'references' is reserved in PostgreSQL — keep the physical column 'references_json'.
    references: Mapped[list[str]] = mapped_column("references_json", JSON, default=list)

    published_at: Mapped[datetime] = mapped_column(UtcDateTime())
    last_modified_at: Mapped[datetime] = mapped_column(UtcDateTime())

    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    cwes: Mapped[list["CWE"]] = relationship(secondary=threat_cwe, lazy="selectin")
