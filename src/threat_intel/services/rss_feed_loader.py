"""RSSFeedLoader — read feeds/feeds.yaml and build one RSSCollector per feed."""

from pathlib import Path

import httpx
import structlog
import yaml
from pydantic import ValidationError

from threat_intel.collectors.rss import RSSCollector
from threat_intel.core.config import Settings
from threat_intel.schemas.rss_feed import RSSFeedSchema

logger = structlog.get_logger(__name__)


class RSSFeedLoader:
    FILENAME = "feeds.yaml"

    def __init__(
        self, http_client: httpx.AsyncClient, settings: Settings, feeds_root: Path
    ) -> None:
        self._http = http_client
        self._settings = settings
        self._root = feeds_root

    def build_collectors(self) -> list[RSSCollector]:
        path = self._root / self.FILENAME
        if not path.is_file():
            logger.info("rss_feeds_file_missing", path=str(path))
            return []
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError) as e:
            logger.warning("rss_feeds_yaml_invalid", path=str(path), error=str(e))
            return []
        entries = raw.get("feeds") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            logger.warning("rss_feeds_no_feeds_list", path=str(path))
            return []

        collectors: list[RSSCollector] = []
        seen: set[str] = set()
        for item in entries:
            try:
                feed = RSSFeedSchema.model_validate(item)
            except ValidationError as e:
                logger.warning("rss_feed_invalid", entry=item, errors=e.errors())
                continue
            if feed.source_name in seen:
                logger.warning("rss_feed_duplicate", source_name=feed.source_name)
                continue
            seen.add(feed.source_name)
            collectors.append(
                RSSCollector(
                    http_client=self._http,
                    settings=self._settings,
                    source_name=feed.source_name,
                    url=feed.url,
                    threat_type=feed.threat_type,
                    interval_minutes=feed.interval_minutes,
                    indicator_confidence=feed.indicator_confidence,
                    default_tags=feed.default_tags,
                )
            )
        logger.info("rss_feeds_loaded", count=len(collectors))
        return collectors
