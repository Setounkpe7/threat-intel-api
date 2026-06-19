from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RSSFeedSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_name: str = Field(min_length=1, max_length=64)
    url: str
    threat_type: Literal["advisory", "report"]
    interval_minutes: int = Field(ge=15, le=1440)
    indicator_confidence: int = Field(ge=0, le=100)
    default_tags: list[str] = []
