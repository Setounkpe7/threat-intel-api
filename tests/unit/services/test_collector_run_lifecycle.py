"""Unit tests for CollectorRun lifecycle in IngestionService.run.

Covers:
- Successful run writes CollectorRun(status=success) with correct counters.
- Failure increments consecutive_failures on Source and writes status=failure.
- Third consecutive failure triggers interval doubling (backoff).
- Success after failures resets backoff.
- Per-event failure (CollectorParseError) yields status=partial with correct counters.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import select

from threat_intel.collectors.base import BaseCollector, RawEvent
from threat_intel.core.db import build_engine
from threat_intel.core.db import session_factory as make_factory
from threat_intel.core.exceptions import CollectorHTTPError, CollectorParseError
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


@pytest_asyncio.fixture
async def source(factory):
    """A single enabled Source row with default intervals."""
    async with factory() as s:
        src = Source(
            name="test_collector",
            kind=SourceKind.cve_feed,
            url="https://test.example/feed",
            enabled=True,
            base_interval_minutes=60,
            current_interval_minutes=60,
            consecutive_failures=0,
        )
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


# ---------------------------------------------------------------------------
# Helper: build a minimal CollectedEvent
# ---------------------------------------------------------------------------


def _make_event(ext_id: str) -> CollectedEvent:
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name="test_collector",
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


# ---------------------------------------------------------------------------
# Collector stubs
# ---------------------------------------------------------------------------


class _SuccessCollector(BaseCollector):
    """Yields N raw events; to_event always succeeds."""

    source_name = "test_collector"
    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60

    def __init__(self, n_events: int = 3) -> None:
        # Bypass BaseCollector.__init__ — no HTTP client needed in tests.
        self._n = n_events
        self.enabled = True

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:  # type: ignore[override]
        for i in range(self._n):
            yield RawEvent(
                external_id=f"CVE-2026-{1000 + i}",
                payload={},
                fetched_at=datetime.now(UTC),
            )

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        return _make_event(raw.external_id)


class _FailFetchCollector(BaseCollector):
    """fetch() raises CollectorHTTPError immediately."""

    source_name = "test_collector"
    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60

    def __init__(self) -> None:
        self.enabled = True

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:  # type: ignore[override]
        raise CollectorHTTPError(status_code=500, url="https://test.example/feed")
        # make mypy happy — never reached
        yield  # type: ignore[misc]

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        return _make_event(raw.external_id)


class _PartialFailCollector(BaseCollector):
    """Yields 3 events; to_event raises CollectorParseError for the middle one."""

    source_name = "test_collector"
    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60

    def __init__(self) -> None:
        self.enabled = True

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:  # type: ignore[override]
        for i in range(3):
            yield RawEvent(
                external_id=f"CVE-2026-{2000 + i}",
                payload={},
                fetched_at=datetime.now(UTC),
            )

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        if raw.external_id == "CVE-2026-2001":
            raise CollectorParseError(f"cannot parse {raw.external_id}")
        return _make_event(raw.external_id)


# ---------------------------------------------------------------------------
# Test 1: Successful run writes CollectorRun(status=success)
# ---------------------------------------------------------------------------


async def test_successful_run_writes_collector_run(factory, source):
    """status=success, correct counters, Source backoff reset."""
    collector = _SuccessCollector(n_events=3)
    svc = IngestionService(session_factory=factory, collectors=[collector])

    result = await svc.run("test_collector")

    assert result.inserted == 3
    assert result.updated == 0
    assert result.events_failed == 0

    async with factory() as s:
        run_row = (await s.execute(select(CollectorRun))).scalars().first()
        assert run_row is not None
        assert run_row.status == CollectorRunStatus.success
        assert run_row.events_fetched == 3
        assert run_row.events_new == 3
        assert run_row.events_updated == 0
        assert run_row.events_failed == 0
        assert run_row.finished_at is not None
        assert run_row.duration_ms is not None
        assert run_row.duration_ms >= 0

        src = (await s.execute(select(Source).where(Source.name == "test_collector"))).scalar_one()
        assert src.consecutive_failures == 0
        assert src.last_success_at is not None
        assert src.last_error is None
        assert src.next_run_at is not None


# ---------------------------------------------------------------------------
# Test 2: Failure increments consecutive_failures
# ---------------------------------------------------------------------------


async def test_failure_increments_consecutive_failures(factory, source):
    """fetch() raises → CollectorRun status=failure, consecutive_failures incremented."""
    collector = _FailFetchCollector()
    svc = IngestionService(session_factory=factory, collectors=[collector])

    with pytest.raises(CollectorHTTPError):
        await svc.run("test_collector")

    async with factory() as s:
        run_row = (await s.execute(select(CollectorRun))).scalars().first()
        assert run_row is not None
        assert run_row.status == CollectorRunStatus.failure
        assert run_row.error_message is not None
        assert "CollectorHTTPError" in run_row.error_message

        src = (await s.execute(select(Source).where(Source.name == "test_collector"))).scalar_one()
        assert src.consecutive_failures == 1
        assert src.last_error is not None
        assert src.next_run_at is not None


# ---------------------------------------------------------------------------
# Test 3: Third consecutive failure doubles current_interval_minutes
# ---------------------------------------------------------------------------


async def test_third_failure_doubles_interval(factory, source):
    """After 3 sequential failures, current_interval_minutes doubles (capped at 1440)."""
    collector = _FailFetchCollector()
    svc = IngestionService(session_factory=factory, collectors=[collector])

    original_interval = source.base_interval_minutes  # 60

    for _ in range(3):
        with pytest.raises(CollectorHTTPError):
            await svc.run("test_collector")

    async with factory() as s:
        src = (await s.execute(select(Source).where(Source.name == "test_collector"))).scalar_one()
        assert src.consecutive_failures == 3
        # After exactly 3 failures: doubling happens on the 3rd, so doubled once
        assert src.current_interval_minutes == min(original_interval * 2, 1440)
        assert src.current_interval_minutes <= 1440


# ---------------------------------------------------------------------------
# Test 4: Success resets backoff
# ---------------------------------------------------------------------------


async def test_success_resets_backoff(factory, source):
    """Success after failures resets consecutive_failures=0 and interval to base."""
    fail_collector = _FailFetchCollector()
    success_collector = _SuccessCollector(n_events=1)
    svc = IngestionService(session_factory=factory, collectors=[fail_collector])

    # Two failures first
    for _ in range(2):
        with pytest.raises(CollectorHTTPError):
            await svc.run("test_collector")

    # Now succeed
    svc._collectors["test_collector"] = success_collector
    result = await svc.run("test_collector")

    assert result.inserted == 1

    async with factory() as s:
        src = (await s.execute(select(Source).where(Source.name == "test_collector"))).scalar_one()
        assert src.consecutive_failures == 0
        assert src.current_interval_minutes == src.base_interval_minutes
        assert src.last_success_at is not None


# ---------------------------------------------------------------------------
# Test 5: Per-event failure → status=partial
# ---------------------------------------------------------------------------


async def test_per_event_failure_yields_partial_status(factory, source):
    """1 of 3 events raises CollectorParseError → status=partial, counters correct."""
    collector = _PartialFailCollector()
    svc = IngestionService(session_factory=factory, collectors=[collector])

    result = await svc.run("test_collector")

    # 2 succeed, 1 fails
    assert result.inserted == 2
    assert result.events_failed == 1

    async with factory() as s:
        run_row = (await s.execute(select(CollectorRun))).scalars().first()
        assert run_row is not None
        assert run_row.status == CollectorRunStatus.partial
        assert run_row.events_fetched == 3
        assert run_row.events_new == 2
        assert run_row.events_failed == 1
