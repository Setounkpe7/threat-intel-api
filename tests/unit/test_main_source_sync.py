from dataclasses import dataclass

import pytest
from sqlalchemy import select

from threat_intel.main import _sync_source_enabled_state
from threat_intel.models.base import SourceKind
from threat_intel.models.source import Source


@dataclass
class _FakeCollector:
    source_name: str
    enabled: bool


async def _seed_source(factory, name: str, *, enabled: bool) -> None:
    async with factory() as s:
        s.add(Source(name=name, kind=SourceKind.advisory, url="https://x", enabled=enabled))
        await s.commit()


async def _read_enabled(factory, name: str) -> bool:
    async with factory() as s:
        row = (await s.execute(select(Source).where(Source.name == name))).scalar_one()
        return row.enabled


@pytest.mark.asyncio
async def test_sync_disables_source_when_collector_disabled(factory):
    await _seed_source(factory, "github_advisories", enabled=True)

    async with factory() as session:
        await _sync_source_enabled_state(
            session, [_FakeCollector("github_advisories", enabled=False)]
        )

    assert await _read_enabled(factory, "github_advisories") is False


@pytest.mark.asyncio
async def test_sync_reenables_source_when_collector_becomes_enabled(factory):
    """Regression: token-less startup once disabled the row; later token + redeploy
    must flip it back, otherwise the scheduler skips the source forever."""
    await _seed_source(factory, "github_advisories", enabled=False)

    async with factory() as session:
        await _sync_source_enabled_state(
            session, [_FakeCollector("github_advisories", enabled=True)]
        )

    assert await _read_enabled(factory, "github_advisories") is True


@pytest.mark.asyncio
async def test_sync_noop_when_states_match(factory):
    await _seed_source(factory, "nvd", enabled=True)

    async with factory() as session:
        await _sync_source_enabled_state(session, [_FakeCollector("nvd", enabled=True)])

    assert await _read_enabled(factory, "nvd") is True


@pytest.mark.asyncio
async def test_sync_skips_unknown_source(factory):
    async with factory() as session:
        await _sync_source_enabled_state(session, [_FakeCollector("does_not_exist", enabled=True)])
