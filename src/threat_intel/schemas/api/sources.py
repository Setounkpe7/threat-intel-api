from datetime import datetime

from pydantic import BaseModel


class SourceHealth(BaseModel):
    name: str
    enabled: bool
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    consecutive_failures: int = 0
    current_interval_minutes: int
    next_run_at: datetime | None = None
    events_24h: int = 0


class CollectorRunOut(BaseModel):
    id: int
    started_at: datetime
    finished_at: datetime | None = None
    status: str
    events_fetched: int
    events_new: int
    events_updated: int
    events_failed: int
    error_message: str | None = None
    duration_ms: int | None = None


class ThreatSourceOut(BaseModel):
    source_name: str
    external_id: str
    first_seen_at: datetime
    last_seen_at: datetime
    tags: list[str]
