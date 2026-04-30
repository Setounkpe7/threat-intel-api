"""Integration tests for /api/v1/sources and /api/v1/sources/{id}/runs."""

from datetime import UTC, datetime, timedelta

import pytest_asyncio

from threat_intel.models.base import CollectorRunStatus, SourceKind
from threat_intel.models.collector_run import CollectorRun
from threat_intel.models.source import Source

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def three_sources(factory):
    """Seed NVD, KEV, and GHSA source rows."""
    now = datetime.now(UTC)
    async with factory() as s:
        nvd = Source(
            name="nvd",
            kind=SourceKind.cve_feed,
            url="https://nvd.test",
            enabled=True,
            last_run_at=now,
            last_success_at=now,
            current_interval_minutes=60,
        )
        kev = Source(
            name="cisa_kev",
            kind=SourceKind.advisory,
            url="https://cisa.test",
            enabled=True,
            current_interval_minutes=360,
        )
        ghsa = Source(
            name="github_advisories",
            kind=SourceKind.advisory,
            url="https://ghsa.test",
            enabled=True,
            current_interval_minutes=120,
        )
        s.add_all([nvd, kev, ghsa])
        await s.commit()
        await s.refresh(nvd)
        await s.refresh(kev)
        await s.refresh(ghsa)
    return {"nvd": nvd, "kev": kev, "ghsa": ghsa}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_list_sources_returns_three_sources(client, three_sources):
    resp = await client.get("/api/v1/sources")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 3
    names = {s["name"] for s in body}
    assert names == {"nvd", "cisa_kev", "github_advisories"}
    # Verify shape — all required keys present
    for entry in body:
        assert "name" in entry
        assert "enabled" in entry
        assert "current_interval_minutes" in entry
        assert "events_24h" in entry


async def test_list_sources_includes_events_24h(client, factory, three_sources):
    nvd = three_sources["nvd"]
    now = datetime.now(UTC)

    async with factory() as s:
        # This run is within 24h — should be counted
        recent_run = CollectorRun(
            source_id=nvd.id,
            started_at=now - timedelta(hours=1),
            finished_at=now - timedelta(hours=1, minutes=-5),
            status=CollectorRunStatus.success,
            events_fetched=3,
            events_new=2,
            events_updated=1,
            events_failed=0,
        )
        # This run is older than 24h — should NOT be counted
        old_run = CollectorRun(
            source_id=nvd.id,
            started_at=now - timedelta(hours=26),
            finished_at=now - timedelta(hours=26, minutes=-5),
            status=CollectorRunStatus.success,
            events_fetched=10,
            events_new=5,
            events_updated=5,
            events_failed=0,
        )
        s.add_all([recent_run, old_run])
        await s.commit()

    resp = await client.get("/api/v1/sources")
    assert resp.status_code == 200
    body = resp.json()
    nvd_row = next(s for s in body if s["name"] == "nvd")
    # events_24h = events_new + events_updated from recent run only = 2 + 1 = 3
    assert nvd_row["events_24h"] == 3


async def test_list_source_runs_returns_50_most_recent_desc(client, factory, three_sources):
    nvd = three_sources["nvd"]
    now = datetime.now(UTC)

    async with factory() as s:
        runs = [
            CollectorRun(
                source_id=nvd.id,
                started_at=now - timedelta(hours=i),
                status=CollectorRunStatus.success,
                events_fetched=0,
                events_new=0,
                events_updated=0,
                events_failed=0,
            )
            for i in range(60)
        ]
        s.add_all(runs)
        await s.commit()
        # Refresh to get IDs
        for r in runs:
            await s.refresh(r)
        nvd_id = nvd.id

    resp = await client.get(f"/api/v1/sources/{nvd_id}/runs")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 50

    # Verify DESC order by started_at
    started_ats = [entry["started_at"] for entry in body]
    assert started_ats == sorted(started_ats, reverse=True)


async def test_list_source_runs_404_on_unknown_id(client):
    resp = await client.get("/api/v1/sources/9999/runs")
    assert resp.status_code == 404
