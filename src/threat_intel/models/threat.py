import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Dialect, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import CHAR, TypeDecorator, TypeEngine

from threat_intel.models.base import Base, Severity, TimestampMixin, UtcDateTime
from threat_intel.models.cwe import threat_cwe

if TYPE_CHECKING:
    from threat_intel.models.cwe import CWE


class GUID(TypeDecorator[uuid.UUID]):
    """Cross-DB UUID: native UUID on Postgres, CHAR(36) elsewhere."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(
        self, value: uuid.UUID | str | None, dialect: Dialect
    ) -> uuid.UUID | str | None:
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value
        return str(value)

    def process_result_value(
        self, value: uuid.UUID | str | None, dialect: Dialect
    ) -> uuid.UUID | None:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


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
    severity: Mapped[Severity] = mapped_column(String(16), default=Severity.unknown)

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)

    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column("references_json", JSON, default=list)

    published_at: Mapped[datetime] = mapped_column(UtcDateTime())
    last_modified_at: Mapped[datetime] = mapped_column(UtcDateTime())

    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)  # type: ignore[type-arg]

    cwes: Mapped[list["CWE"]] = relationship(secondary=threat_cwe, lazy="selectin")
