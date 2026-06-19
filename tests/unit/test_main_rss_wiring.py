from pathlib import Path

import pytest

from threat_intel.core.config import Settings
from threat_intel.services.rss_feed_loader import RSSFeedLoader


@pytest.mark.asyncio
async def test_feeds_yaml_in_repo_builds_four_collectors():
    import httpx

    settings = Settings(database_url="sqlite+aiosqlite:///:memory:", feeds_path=Path("feeds"))  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, settings, feeds_root=settings.feeds_path)
        collectors = loader.build_collectors()
    assert {c.source_name for c in collectors} == {
        "cisa_advisories", "cisa_ics", "cisco_psirt", "dfir_report",
    }
