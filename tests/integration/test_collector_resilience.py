"""Integration test: scheduler tick isolation.

Three collectors are registered — two succeed, one raises an unhandled exception.
Verifies:
- All three CollectorRun rows are written.
- The two working collectors have status=success.
- The broken one has status=failure with error_message populated.
- Source.consecutive_failures is 1 only for the broken collector.
- The scheduler tick does not propagate exceptions from individual collectors.
"""

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest_asyncio
from sqlalchemy import select

from threat_intel.collectors.base import BaseCollector, RawEvent
from threat_intel.core.db import build_engine
from threat_intel.core.db import session_factory as make_factory
from threat_intel.core.exceptions import CollectorHTTPError
from threat_intel.core.scheduler import _scheduler_tick
from threat_intel.models.base import Base, CollectorRunStatus, SourceKind
from threat_intel.models.collector_run import CollectorRun
from threat_intel.models.source import Source
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator
from threat_intel.services.ingestion import IngestionService

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def factory():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = make_factory(engine)
    yield sf
    await engine.dispose()


async def _insert_source(factory, name: str) -> Source:
    async with factory() as s:
        src = Source(
            name=name,
            kind=SourceKind.cve_feed,
            url=f"https://test.example/{name}",
            enabled=True,
            base_interval_minutes=60,
            current_interval_minutes=60,
            consecutive_failures=0,
            next_run_at=None,  # due immediately
        )
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


# ---------------------------------------------------------------------------
# Collector stubs
# ---------------------------------------------------------------------------


def _make_event(source_name: str, ext_id: str) -> CollectedEvent:
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name=source_name,
        external_id=ext_id,
        title=f"Title {ext_id}",
        summary=None,
        severity=None,
        cvss_score=None,
        tags=[],
        indicators=[CollectedIndicator(type="cve", value=ext_id)],
        published_at=now,
        last_modified_at=now,
        raw_data={
            "title": f"Title {ext_id}",
            "summary": None,
            "severity": None,
            "cvss_score": None,
            "cvss_vector": None,
            "cvss_version": None,
            "cwe_ids": [],
        },
    )


class _GoodCollector(BaseCollector):
    """Yields one event successfully."""

    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60

    def __init__(self, name: str) -> None:
        # Bypass BaseCollector.__init__ — no HTTP client needed in tests.
        self._name = name
        self.enabled = True

    @property
    def source_name(self) -> str:  # type: ignore[override]
        return self._name

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:  # type: ignore[override]
        yield RawEvent(
            external_id=f"CVE-2026-9{self._name[-1]}01",
            payload={},
            fetched_at=datetime.now(UTC),
        )

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        return _make_event(self._name, raw.external_id)


class _BrokenCollector(BaseCollector):
    """fetch() always raises CollectorHTTPError."""

    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60

    def __init__(self, name: str) -> None:
        self._name = name
        self.enabled = True

    @property
    def source_name(self) -> str:  # type: ignore[override]
        return self._name

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:  # type: ignore[override]
        raise CollectorHTTPError(status_code=500, url="https://broken.example/feed")
        yield  # type: ignore[misc]

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        return _make_event(self._name, raw.external_id)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


async def test_scheduler_tick_isolates_broken_collector(factory):
    """Tick dispatches 3 sources; broken one fails without killing the others."""
    good1_src = await _insert_source(factory, "good_one")
    good2_src = await _insert_source(factory, "good_two")
    broken_src = await _insert_source(factory, "broken_col")

    good1 = _GoodCollector("good_one")
    good2 = _GoodCollector("good_two")
    broken = _BrokenCollector("broken_col")

    ingestion = IngestionService(
        session_factory=factory,
        collectors=[good1, good2, broken],
    )

    # Run the scheduler tick — it creates tasks but returns immediately.
    # We must yield control so the tasks can run.
    await _scheduler_tick(ingestion=ingestion, session_factory=factory)

    # Drain all pending tasks so the asyncio.create_task calls complete.
    # gather with return_exceptions=True so we don't re-raise.
    tasks = [t for t in asyncio.all_tasks() if not t.done() and t != asyncio.current_task()]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # --- Assertions ---
    async with factory() as s:
        runs = (await s.execute(select(CollectorRun))).scalars().all()
        assert len(runs) == 3, f"Expected 3 CollectorRun rows, got {len(runs)}"

        by_source_id = {r.source_id: r for r in runs}

        # good_one and good_two: success
        for src in (good1_src, good2_src):
            run = by_source_id.get(src.id)
            assert run is not None, f"Missing run for source id {src.id}"
            assert run.status == CollectorRunStatus.success, (
                f"Expected success for {src.name}, got {run.status}"
            )

        # broken_col: failure with error_message
        broken_run = by_source_id.get(broken_src.id)
        assert broken_run is not None, "Missing run for broken_col"
        assert broken_run.status == CollectorRunStatus.failure
        assert broken_run.error_message is not None
        assert "CollectorHTTPError" in broken_run.error_message

    # Source state: consecutive_failures incremented only for broken
    async with factory() as s:
        for src_name, expected_failures in [
            ("good_one", 0),
            ("good_two", 0),
            ("broken_col", 1),
        ]:
            src_row = (await s.execute(select(Source).where(Source.name == src_name))).scalar_one()
            assert src_row.consecutive_failures == expected_failures, (
                f"{src_name}: expected consecutive_failures={expected_failures}, "
                f"got {src_row.consecutive_failures}"
            )
