from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar, Literal

from threat_intel.collectors.base import APIRestCollector, RawEvent
from threat_intel.core.exceptions import CollectorParseError
from threat_intel.models.base import Severity, SourceKind
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator

_SEVERITY_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "NONE": Severity.none,
}


def _parse_dt(value: str) -> datetime:
    # NVD timestamps look like "2026-04-26T08:00:00.000" — naive, UTC by spec.
    if value.endswith("Z"):
        value = value[:-1]
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


class NVDCollector(APIRestCollector):
    source_name: ClassVar[str] = "nvd"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed
    base_interval_minutes: ClassVar[int] = 60
    base_url: ClassVar[str] = ""  # set from settings.nvd_base_url at runtime via _request_page
    auth_method: ClassVar[Literal["none", "api_key", "bearer"]] = "api_key"
    rate_limit_per_minute: ClassVar[int] = 50

    _PAGE_SIZE: ClassVar[int] = 2000

    def to_event(self, raw: RawEvent) -> CollectedEvent:
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
            indicators: list[CollectedIndicator] = [
                CollectedIndicator(type="cve", value=cve_id),
            ]
            for cfg in cve.get("configurations") or []:
                for node in cfg.get("nodes") or []:
                    for match in node.get("cpeMatch") or []:
                        c = match.get("criteria")
                        if c:
                            if c not in products:
                                products.append(c)
                            indicators.append(CollectedIndicator(type="cpe", value=c[:512]))

            refs = [r["url"] for r in (cve.get("references") or []) if r.get("url")]

            return CollectedEvent(
                source_name=self.source_name,
                external_id=cve_id,
                title=title,
                summary=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                cwe_ids=cwe_ids,
                tags=["nvd"],
                indicators=indicators,
                published_at=_parse_dt(cve["published"]),
                last_modified_at=_parse_dt(cve["lastModified"]),
                raw_data={
                    "title": title,
                    "summary": description,
                    "severity": severity.value,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cvss_version": cvss_version,
                    "cwe_ids": cwe_ids,
                    "affected_products": products,
                    "references": refs,
                    "_payload": raw.payload,
                },
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"NVD payload malformed for {raw.external_id}: {e}") from e

    async def _request_page(self, params: dict[str, Any]) -> dict[str, Any]:
        url = self.settings.nvd_base_url
        headers: dict[str, str] = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key
        return await self._get(url, params=params, headers=headers)

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
