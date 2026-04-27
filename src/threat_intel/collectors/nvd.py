from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any, ClassVar

import httpx

from threat_intel.collectors.base import BaseCollector, RawEvent, ThreatDraft
from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorParseError
from threat_intel.models.base import Severity, SourceKind

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
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class NVDCollector(BaseCollector):
    source_name: ClassVar[str] = "nvd"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed

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
                    cvss_score = data.get("baseScore")
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

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:  # implemented in next task
        raise NotImplementedError
        yield  # pragma: no cover
