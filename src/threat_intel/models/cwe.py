from sqlalchemy import Column, ForeignKey, String, Table
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import Base

threat_cwe = Table(
    "threat_cwe",
    Base.metadata,
    Column("threat_id", ForeignKey("threat.id", ondelete="CASCADE"), primary_key=True),
    Column("cwe_id", ForeignKey("cwe.id", ondelete="CASCADE"), primary_key=True),
)


class CWE(Base):
    __tablename__ = "cwe"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
