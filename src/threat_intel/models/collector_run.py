from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import Base, CollectorRunStatus, TimestampMixin, UtcDateTime


class CollectorRun(Base, TimestampMixin):
    __tablename__ = "collector_run"
    __table_args__ = (Index("ix_collector_run_source_started", "source_id", "started_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id", ondelete="CASCADE"))
    started_at: Mapped[datetime] = mapped_column(UtcDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    status: Mapped[CollectorRunStatus] = mapped_column(default=CollectorRunStatus.running)
    events_fetched: Mapped[int] = mapped_column(Integer, default=0)
    events_new: Mapped[int] = mapped_column(Integer, default=0)
    events_updated: Mapped[int] = mapped_column(Integer, default=0)
    events_failed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
