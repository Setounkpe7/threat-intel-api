"""SectorProfile ORM model — sector-specific scoring profile (M2)."""

from datetime import datetime
from typing import Literal

from sqlalchemy import JSON, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import Base, TimestampMixin, UtcDateTime

Visibility = Literal["public", "private"]


class SectorProfile(Base, TimestampMixin):
    __tablename__ = "sector_profile"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    sector: Mapped[str] = mapped_column(String(100), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    keywords: Mapped[list[str]] = mapped_column(JSON, default=list)
    technologies: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwe_priorities: Mapped[list[str]] = mapped_column(JSON, default=list)
    excluded_keywords: Mapped[list[str]] = mapped_column(JSON, default=list)
    compliance: Mapped[list[str]] = mapped_column(JSON, default=list)
    priority_boost_keywords: Mapped[list[str]] = mapped_column(JSON, default=list)

    cvss_threshold: Mapped[float] = mapped_column(Float, default=7.0)

    visibility: Mapped[Visibility] = mapped_column(String(16), default="public", index=True)
    source_file: Mapped[str | None] = mapped_column(String(512), nullable=True)
    loaded_at: Mapped[datetime] = mapped_column(UtcDateTime())
