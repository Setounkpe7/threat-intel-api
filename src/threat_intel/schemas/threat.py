import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from threat_intel.models.base import Severity


class ThreatBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    external_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    affected_products: list[str]
    references: list[str]
    published_at: datetime
    last_modified_at: datetime


class ThreatRead(ThreatBase):
    """List representation. Excludes raw_data."""


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
