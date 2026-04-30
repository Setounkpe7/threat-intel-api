import os
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar, Literal

import httpx
import structlog
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorHTTPError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent

logger = structlog.get_logger(__name__)

_RETRY_STATUSES = (429, 500, 502, 503, 504)


class _RetryableHTTPError(Exception):
    def __init__(self, status_code: int, url: str) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"retryable HTTP {status_code} on {url}")


@dataclass(frozen=True)
class RawEvent:
    external_id: str
    payload: dict[str, Any]
    fetched_at: datetime


class BaseCollector(ABC):
    source_name: ClassVar[str]
    source_kind: ClassVar[SourceKind]
    base_interval_minutes: ClassVar[int]

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None:
        self.http = http_client
        self.settings = settings
        self.enabled = True

    @abstractmethod
    def fetch(self, since: datetime) -> AsyncIterator[RawEvent]: ...

    @abstractmethod
    def to_event(self, raw: RawEvent) -> CollectedEvent: ...


class APIRestCollector(BaseCollector):
    base_url: ClassVar[str]
    auth_method: ClassVar[Literal["none", "api_key", "bearer"]]
    rate_limit_per_minute: ClassVar[int]

    async def _get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(4),
                wait=wait_exponential(multiplier=1, min=1, max=4),
                retry=retry_if_exception_type((httpx.TransportError, _RetryableHTTPError)),
                reraise=True,
            ):
                with attempt:
                    resp = await self.http.get(url, params=params, headers=headers, timeout=30.0)
                    if resp.status_code in _RETRY_STATUSES:
                        raise _RetryableHTTPError(resp.status_code, str(resp.url))
                    if resp.status_code >= 400:
                        raise CollectorHTTPError(
                            status_code=resp.status_code,
                            url=str(resp.url),
                            message=resp.text[:200],
                        )
                    data: dict[str, Any] = resp.json()
                    return data
        except _RetryableHTTPError as e:
            raise CollectorHTTPError(
                status_code=e.status_code, url=e.url, message="retry attempts exhausted"
            ) from e
        except httpx.TransportError as e:
            raise CollectorHTTPError(status_code=0, url=url, message=f"transport error: {e}") from e
        raise CollectorHTTPError(status_code=0, url=url, message="retry loop exhausted")


class APIGraphQLCollector(BaseCollector):
    endpoint_url: ClassVar[str]
    auth_token_env: ClassVar[str]

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None:
        super().__init__(http_client, settings)
        token = os.environ.get(self.auth_token_env)
        if not token:
            self.enabled = False
            self._token: str | None = None
            logger.warning(
                "collector.graphql.disabled",
                source=self.source_name,
                reason=f"{self.auth_token_env} not set",
            )
        else:
            self._token = token

    async def _execute_query(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        if not self._token:
            raise CollectorHTTPError(
                status_code=0,
                url=self.endpoint_url,
                message=f"{self.auth_token_env} not configured",
            )
        headers = {
            "authorization": f"Bearer {self._token}",
            "content-type": "application/json",
        }
        resp = await self.http.post(
            self.endpoint_url,
            headers=headers,
            json={"query": query, "variables": variables},
            timeout=30.0,
        )
        if resp.status_code >= 400:
            raise CollectorHTTPError(
                status_code=resp.status_code,
                url=self.endpoint_url,
                message=resp.text[:200],
            )
        data: dict[str, Any] = resp.json()
        if data.get("errors"):
            raise CollectorHTTPError(
                status_code=200,
                url=self.endpoint_url,
                message=str(data["errors"])[:500],
            )
        return data
