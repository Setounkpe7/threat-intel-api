"""Generic, config-driven RSS/Atom collector (M3b).

One instance per feed. Items that cite a CVE/GHSA become enrichment events
(enrichment_mode=True) that the ingestion layer fans out across matched
threats; items without a CVE become autonomous advisory/report threats.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import ClassVar, Literal

import httpx
import structlog

from threat_intel.collectors._extract import (
    extract_cves,
    extract_ghsa,
    extract_iocs,
    stable_external_id,
)
from threat_intel.collectors._feedparse import parse_feed
from threat_intel.collectors._net import assert_fetchable_url
from threat_intel.collectors._sanitize import clean_text
from threat_intel.collectors.base import BaseCollector, RawEvent
from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorHTTPError, CollectorParseError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator

logger = structlog.get_logger(__name__)

MAX_FEED_BYTES = 5 * 1024 * 1024
_ACCEPT = "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.1"
_SUMMARY_MAX = 2000


class RSSCollector(BaseCollector):
    source_kind: ClassVar[SourceKind] = SourceKind.rss

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        settings: Settings,
        *,
        source_name: str,
        url: str,
        threat_type: Literal["advisory", "report"],
        interval_minutes: int,
        indicator_confidence: int,
        default_tags: list[str],
    ) -> None:
        super().__init__(http_client, settings)
        self.source_name = source_name  # type: ignore[misc]  # instance attr shadows ClassVar
        self.url = url
        self.threat_type = threat_type
        self.base_interval_minutes = interval_minutes  # type: ignore[misc]  # instance attr shadows ClassVar
        self.indicator_confidence = indicator_confidence
        self.default_tags = list(default_tags)

    def _assert_fetchable(self, url: str) -> None:
        assert_fetchable_url(url)

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:
        # `since` is intentionally unused: like the CISA KEV collector, we yield all
        # current feed items and rely on downstream dedup (external_id idempotency /
        # CVE-merge) rather than client-side date filtering.
        self._assert_fetchable(self.url)
        total = 0
        chunks: list[bytes] = []
        async with self.http.stream(
            "GET",
            self.url,
            headers={"accept": _ACCEPT},
            timeout=30.0,
            follow_redirects=False,
        ) as resp:
            if resp.status_code >= 400:
                raise CollectorHTTPError(
                    status_code=resp.status_code, url=self.url, message="rss fetch failed"
                )
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_FEED_BYTES:
                    raise CollectorHTTPError(
                        status_code=0, url=self.url, message="feed exceeds size cap"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        for entry in parse_feed(raw):
            ext_id = stable_external_id(
                guid=entry.guid,
                link=entry.link,
                source_name=self.source_name,
                title=entry.title,
                published=entry.published,
            )
            yield RawEvent(
                external_id=ext_id,
                payload={
                    "guid": entry.guid,
                    "link": entry.link,
                    "title": entry.title,
                    "summary": entry.summary,
                    "published": entry.published,
                    "tags": entry.tags,
                },
                fetched_at=datetime.now(UTC),
            )

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        try:
            p = raw.payload
            title = clean_text(p.get("title")) or raw.external_id
            summary = clean_text(p.get("summary"))[:_SUMMARY_MAX]
            corpus = f"{p.get('title') or ''} {p.get('summary') or ''}"

            indicators: list[CollectedIndicator] = []
            for cve in extract_cves(corpus):
                indicators.append(CollectedIndicator(type="cve", value=cve))
            for ghsa in extract_ghsa(corpus):
                indicators.append(CollectedIndicator(type="ghsa", value=ghsa))
            iocs = extract_iocs(summary)
            for kind, value in iocs:
                indicators.append(CollectedIndicator(type=kind, value=value[:512]))

            tags = list(self.default_tags)
            lower = corpus.lower()
            if "exploited in the wild" in lower or "actively exploited" in lower:
                tags.append("actively-exploited")
            if "ransomware" in lower:
                tags.append("ransomware")
            if any(k in ("ip", "domain", "url", "md5", "sha1", "sha256") for k, _ in iocs):
                tags.append("unverified-ioc")

            published_at = self._parse_dt(p.get("published")) or raw.fetched_at
            link = p.get("link")
            return CollectedEvent(
                source_name=self.source_name,
                external_id=raw.external_id,
                title=title,
                summary=summary or None,
                severity=None,
                cvss_score=None,
                tags=tags,
                indicators=indicators,
                published_at=published_at,
                last_modified_at=raw.fetched_at,
                raw_data={
                    "title": title,
                    "summary": summary,
                    "references": [link] if isinstance(link, str) else [],
                    "cwe_ids": [],
                },
                enrichment_mode=True,
                threat_type=self.threat_type,
                indicator_confidence=self.indicator_confidence,
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"RSS malformed for {raw.external_id}: {e}") from e

    @staticmethod
    def _parse_dt(value: object) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            dt = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            try:
                dt = datetime.fromisoformat(value)
            except ValueError:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
