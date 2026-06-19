from pathlib import Path

import httpx
import pytest

from threat_intel.core.config import Settings
from threat_intel.services.rss_feed_loader import RSSFeedLoader


def _settings() -> Settings:
    return Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_loader_builds_one_collector_per_feed(tmp_path: Path):
    (tmp_path / "feeds.yaml").write_text(
        """
feeds:
  - source_name: cisa_advisories
    url: https://www.cisa.gov/a.xml
    threat_type: advisory
    interval_minutes: 120
    indicator_confidence: 80
  - source_name: dfir_report
    url: https://thedfirreport.com/feed/
    threat_type: report
    interval_minutes: 240
    indicator_confidence: 50
""",
        encoding="utf-8",
    )
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, _settings(), feeds_root=tmp_path)
        collectors = loader.build_collectors()
    names = {c.source_name for c in collectors}
    assert names == {"cisa_advisories", "dfir_report"}
    dfir = next(c for c in collectors if c.source_name == "dfir_report")
    assert dfir.threat_type == "report"
    assert dfir.base_interval_minutes == 240
    assert dfir.indicator_confidence == 50


@pytest.mark.asyncio
async def test_loader_skips_invalid_entry(tmp_path: Path):
    (tmp_path / "feeds.yaml").write_text(
        """
feeds:
  - source_name: good
    url: https://x/a.xml
    threat_type: advisory
    interval_minutes: 120
    indicator_confidence: 80
  - source_name: bad
    url: https://y/b.xml
    threat_type: not_a_type
    interval_minutes: 120
    indicator_confidence: 80
""",
        encoding="utf-8",
    )
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, _settings(), feeds_root=tmp_path)
        collectors = loader.build_collectors()
    assert {c.source_name for c in collectors} == {"good"}


@pytest.mark.asyncio
async def test_loader_missing_file_returns_empty(tmp_path: Path):
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, _settings(), feeds_root=tmp_path)
        assert loader.build_collectors() == []
