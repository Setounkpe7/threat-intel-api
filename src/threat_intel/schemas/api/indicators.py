import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from threat_intel.models.base import Severity


class ThreatOut(BaseModel):
    """Response shape for /indicators — mirrors the actual Threat model columns."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    threat_type: str
    title: str
    summary: str | None = None
    severity: Severity
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    tags: list[str]
    published_at: datetime
    last_modified_at: datetime
