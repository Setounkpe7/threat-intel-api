from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel

from threat_intel.core.config import Settings
from threat_intel.models.base import Severity, SourceKind


@dataclass(frozen=True)
class RawEvent:
    external_id: str
    payload: dict[str, Any]
    fetched_at: datetime


class ThreatDraft(BaseModel):
    source_name: str
    external_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    cwe_ids: list[str]
    affected_products: list[str]
    references: list[str]
    published_at: datetime
    last_modified_at: datetime
    raw_data: dict[str, Any]


class BaseCollector(ABC):
    source_name: ClassVar[str]
    source_kind: ClassVar[SourceKind]

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None:
        self.http = http_client
        self.settings = settings

    @abstractmethod
    def fetch(self, since: datetime) -> AsyncIterator[RawEvent]: ...

    @abstractmethod
    def normalize(self, raw: RawEvent) -> ThreatDraft: ...
