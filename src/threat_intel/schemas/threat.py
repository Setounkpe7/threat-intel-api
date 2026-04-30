import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from threat_intel.models.base import Severity


class ThreatBase(BaseModel):
    """Public API representation of a Threat — derived from the M3a model.

    External-facing fields are populated from ThreatSource[*] by the service
    layer (_to_read helper), preserving backward compatibility with M1/M2 callers.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    threat_type: str
    title: str
    summary: str | None
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    tags: list[str]
    published_at: datetime
    last_modified_at: datetime

    # Backward-compatibility derived fields (populated by service layer)
    external_id: str | None = None
    description: str | None = None
    affected_products: list[str] = []
    references: list[str] = []
    sources: list[str] = []


class ThreatRead(ThreatBase):
    """List representation."""


class ThreatList(BaseModel):
    items: list[ThreatRead]
    total: int
    limit: int
    offset: int


class ThreatFilters(BaseModel):
    severity: list[Severity] = Field(default_factory=list)
    since: datetime | None = None
    source: str | None = None
    limit: Annotated[int, Field(ge=1, le=200)] = 50
    offset: Annotated[int, Field(ge=0)] = 0
