from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from threat_intel.collectors.base import BaseCollector, RawEvent, ThreatDraft
from threat_intel.core.exceptions import CollectorHTTPError, CollectorParseError
from threat_intel.models.base import Severity, SourceKind

_SEVERITY_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "NONE": Severity.none,
}


class _RetryableHTTPError(Exception):
    def __init__(self, status_code: int, url: str) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"retryable HTTP {status_code} on {url}")


def _parse_dt(value: str) -> datetime:
    # NVD timestamps look like "2026-04-26T08:00:00.000" — naive, UTC by spec.
    if value.endswith("Z"):
        value = value[:-1]
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


class NVDCollector(BaseCollector):
    source_name: ClassVar[str] = "nvd"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed

    _PAGE_SIZE: ClassVar[int] = 2000
    _RETRY_STATUSES: ClassVar[tuple[int, ...]] = (429, 500, 502, 503, 504)

    def normalize(self, raw: RawEvent) -> ThreatDraft:
        try:
            cve = raw.payload["cve"]
            cve_id: str = cve["id"]
            descriptions = cve.get("descriptions") or []
            en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            description = en or (descriptions[0]["value"] if descriptions else "")
            title = description[:150] if description else cve_id

            metrics = cve.get("metrics") or {}
            cvss_score: float | None = None
            cvss_vector: str | None = None
            cvss_version: str | None = None
            severity = Severity.unknown

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                items = metrics.get(key) or []
                if items:
                    data = items[0].get("cvssData", {})
                    score = data.get("baseScore")
                    cvss_score = float(score) if score is not None else None
                    cvss_vector = data.get("vectorString")
                    cvss_version = data.get("version")
                    sev_label = (
                        items[0].get("baseSeverity") or data.get("baseSeverity") or ""
                    ).upper()
                    severity = _SEVERITY_MAP.get(sev_label, Severity.unknown)
                    break

            cwe_ids: list[str] = []
            for w in cve.get("weaknesses") or []:
                for d in w.get("description") or []:
                    val = d.get("value", "")
                    if val.startswith("CWE-") and val not in cwe_ids:
                        cwe_ids.append(val)

            products: list[str] = []
            for cfg in cve.get("configurations") or []:
                for node in cfg.get("nodes") or []:
                    for match in node.get("cpeMatch") or []:
                        c = match.get("criteria")
                        if c and c not in products:
                            products.append(c)

            refs = [r["url"] for r in (cve.get("references") or []) if r.get("url")]

            return ThreatDraft(
                source_name=self.source_name,
                external_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                cwe_ids=cwe_ids,
                affected_products=products,
                references=refs,
                published_at=_parse_dt(cve["published"]),
                last_modified_at=_parse_dt(cve["lastModified"]),
                raw_data=raw.payload,
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"NVD payload malformed for {raw.external_id}: {e}") from e

    async def _request_page(self, params: dict[str, Any]) -> dict[str, Any]:
        url = self.settings.nvd_base_url
        headers: dict[str, str] = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(4),
                wait=wait_exponential(multiplier=1, min=1, max=4),
                retry=retry_if_exception_type((httpx.TransportError, _RetryableHTTPError)),
                reraise=True,
            ):
                with attempt:
                    resp = await self.http.get(url, params=params, headers=headers, timeout=30.0)
                    if resp.status_code in self._RETRY_STATUSES:
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
                status_code=e.status_code,
                url=e.url,
                message="retry attempts exhausted",
            ) from e
        except httpx.TransportError as e:
            raise CollectorHTTPError(
                status_code=0,
                url=url,
                message=f"transport error: {e}",
            ) from e
        raise CollectorHTTPError(status_code=0, url=url, message="retry loop exhausted")

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:
        start_index = 0
        while True:
            params: dict[str, Any] = {
                "lastModStartDate": since.isoformat(),
                "lastModEndDate": datetime.now(UTC).isoformat(),
                "resultsPerPage": self._PAGE_SIZE,
                "startIndex": start_index,
            }
            page = await self._request_page(params)
            items = page.get("vulnerabilities") or []
            for item in items:
                cve_id = item.get("cve", {}).get("id", "")
                yield RawEvent(
                    external_id=cve_id,
                    payload=item,
                    fetched_at=datetime.now(UTC),
                )
            total = int(page.get("totalResults", 0))
            returned = int(page.get("resultsPerPage", self._PAGE_SIZE))
            if returned <= 0 or not items:
                break  # defensive: server inconsistency, stop rather than loop forever
            start_index += returned
            if start_index >= total:
                break
