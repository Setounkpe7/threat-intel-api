from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from threat_intel.models.base import Severity

IndicatorTypeLiteral = Literal[
    "cve", "ghsa", "cpe", "package", "ip", "domain", "url", "md5", "sha1", "sha256"
]


class CollectedIndicator(BaseModel):
    model_config = ConfigDict(frozen=True)
    type: IndicatorTypeLiteral
    value: str


class CollectedEvent(BaseModel):
    model_config = ConfigDict(frozen=False)

    source_name: str
    external_id: str

    title: str
    summary: str | None = None
    severity: Severity | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe_ids: list[str] = []

    tags: list[str] = []
    indicators: list[CollectedIndicator] = []

    published_at: datetime
    last_modified_at: datetime
    raw_data: dict[str, Any] = {}
