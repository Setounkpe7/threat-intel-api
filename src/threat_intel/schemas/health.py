from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class CollectorHealth(BaseModel):
    last_run: datetime | None
    last_success: bool
    threats_collected_24h: int


class Stats(BaseModel):
    total_threats: int
    threats_last_24h: int


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    uptime_seconds: int
    database: Literal["connected", "disconnected"]
    collectors: dict[str, CollectorHealth]
    stats: Stats
