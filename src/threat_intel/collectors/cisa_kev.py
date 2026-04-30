from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import ClassVar, Literal

from threat_intel.collectors._sanitize import clean_text
from threat_intel.collectors.base import APIRestCollector, RawEvent
from threat_intel.core.exceptions import CollectorParseError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVCollector(APIRestCollector):
    source_name: ClassVar[str] = "cisa_kev"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed
    base_interval_minutes: ClassVar[int] = 360
    base_url: ClassVar[str] = CISA_KEV_URL
    auth_method: ClassVar[Literal["none", "api_key", "bearer"]] = "none"
    rate_limit_per_minute: ClassVar[int] = 60

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:
        data = await self._get(self.base_url)
        for vuln in data.get("vulnerabilities") or []:
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
            yield RawEvent(
                external_id=cve_id,
                payload=vuln,
                fetched_at=datetime.now(UTC),
            )

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        try:
            v = raw.payload
            cve_id = v["cveID"]
            title = clean_text(v.get("vulnerabilityName")) or cve_id
            summary = clean_text(v.get("shortDescription") or "")

            tags = ["kev", "actively-exploited"]
            if (v.get("knownRansomwareCampaignUse") or "").lower() == "known":
                tags.append("ransomware")

            date_added = v.get("dateAdded")
            published_at = (
                datetime.fromisoformat(date_added).replace(tzinfo=UTC)
                if date_added
                else datetime.now(UTC)
            )

            return CollectedEvent(
                source_name=self.source_name,
                external_id=cve_id,
                title=title,
                summary=summary,
                severity=None,
                cvss_score=None,
                tags=tags,
                indicators=[CollectedIndicator(type="cve", value=cve_id)],
                published_at=published_at,
                last_modified_at=datetime.now(UTC),
                raw_data={
                    "title": title,
                    "summary": summary,
                    "cwe_ids": [],
                    "_payload": v,
                },
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"CISA KEV malformed for {raw.external_id}: {e}") from e
