import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.models.base import GUID, Base, Severity, TimestampMixin, UtcDateTime
from threat_intel.models.cwe import threat_cwe

if TYPE_CHECKING:
    from threat_intel.models.cwe import CWE
    from threat_intel.models.threat_source import ThreatSource


class Threat(Base, TimestampMixin):
    __tablename__ = "threat"
    __table_args__ = (
        Index("ix_threat_published_at", "published_at"),
        Index("ix_threat_severity", "severity"),
        Index("ix_threat_threat_type", "threat_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    threat_type: Mapped[str] = mapped_column(String(32), default="cve")

    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(default=Severity.unknown)

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)

    tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    published_at: Mapped[datetime] = mapped_column(UtcDateTime())
    last_modified_at: Mapped[datetime] = mapped_column(UtcDateTime())

    cwes: Mapped[list["CWE"]] = relationship(secondary=threat_cwe, lazy="selectin")
    sources: Mapped[list["ThreatSource"]] = relationship(back_populates="threat", lazy="selectin")
