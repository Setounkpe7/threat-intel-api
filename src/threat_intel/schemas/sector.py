"""API schemas for sector profiles, scored threats, dashboard, stats (M2)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from threat_intel.schemas.threat import ThreatRead

Visibility = Literal["public", "private"]


class SectorProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    sector: str
    description: str | None
    keywords: list[str]
    technologies: list[str]
    cwe_priorities: list[str]
    excluded_keywords: list[str]
    compliance: list[str]
    priority_boost_keywords: list[str]
    cvss_threshold: float
    visibility: Visibility
    loaded_at: datetime


class SectorProfileSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    sector: str
    description: str | None
    visibility: Visibility


class SectorList(BaseModel):
    items: list[SectorProfileSummary]
    total: int


class ScoredThreatRead(ThreatRead):
    """Threat fields plus its score and breakdown for a given sector."""

    score: float
    score_breakdown: dict[str, Any]
    calculated_at: datetime


class ScoredThreatList(BaseModel):
    items: list[ScoredThreatRead]
    total: int
    limit: int


class DashboardStats(BaseModel):
    total_threats: int
    critical_count: int
    high_count: int
    average_score: float
    sources_active: list[str]


class SectorDashboard(BaseModel):
    sector: SectorProfileSummary
    top_24h: list[ScoredThreatRead]
    top_7d: list[ScoredThreatRead]
    stats: DashboardStats


class GlobalStats(BaseModel):
    total_threats: int
    last_24h: int
    by_severity: dict[str, int]
    by_sector_top_score: list[dict[str, Any]] = Field(
        description="One entry per sector with count of threats scored >= 70"
    )
    sources_active: list[str]


class ReloadProfilesResult(BaseModel):
    public_count: int
    private_count: int
    added: list[str]
    updated: list[str]
    removed: list[str]
    errors: list[dict[str, str]]


class RescoreAllAcknowledged(BaseModel):
    status: Literal["accepted"] = "accepted"
    detail: str
