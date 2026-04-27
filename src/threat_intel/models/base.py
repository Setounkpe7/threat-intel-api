from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Dialect, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator[datetime]):
    """DateTime that always round-trips as tz-aware UTC.

    Backends like SQLite drop tzinfo on read; this decorator re-attaches
    UTC so the application layer can rely on aware datetimes everywhere.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self, value: datetime | None, dialect: Dialect
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(
        self, value: datetime | None, dialect: Dialect
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime(), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime(),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"
    unknown = "unknown"


class SourceKind(StrEnum):
    cve_feed = "cve_feed"
    rss = "rss"
    advisory = "advisory"


__all__ = [
    "Base",
    "Severity",
    "SourceKind",
    "TimestampMixin",
    "UtcDateTime",
]
