import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.models.base import Base
from threat_intel.models.threat import GUID, Threat


class CVE(Base):
    __tablename__ = "cve"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    threat_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat.id", ondelete="CASCADE"), unique=True
    )

    threat: Mapped["Threat"] = relationship(lazy="selectin")
