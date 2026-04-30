from datetime import datetime

from pydantic import BaseModel


class CollectorActionResult(BaseModel):
    name: str
    enabled: bool
    next_run_at: datetime | None = None
    detail: str
