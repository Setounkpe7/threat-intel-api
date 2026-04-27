from datetime import datetime

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import Base, SourceKind, TimestampMixin, UtcDateTime


class Source(Base, TimestampMixin):
    __tablename__ = "source"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    kind: Mapped[SourceKind]
    url: Mapped[str] = mapped_column(String(512))
    enabled: Mapped[bool] = mapped_column(default=True)

    last_run_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
