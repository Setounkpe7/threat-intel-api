"""Integration tests for sector endpoints (M2 phase 8)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from threat_intel.models.base import Severity, SourceKind
from threat_intel.models.cwe import CWE
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource

ADMIN_KEY = "test-admin-key-please-rotate"


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("CORS_ORIGINS", "")
    monkeypatch.setenv("NVD_BASE_URL", "https://nvd.test/cves/2.0")
    monkeypatch.setenv("NVD_FETCH_INTERVAL_MINUTES", "60")
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    from threat_intel.core.config import Settings

    return Settings()  # type: ignore[call-arg]


@pytest_asyncio.fixture
async def seeded_sectors(factory):
    """Seed: 2 public profiles, 1 private profile, 3 scored threats."""
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x", enabled=True)
        s.add(src)
        await s.flush()
        cwe = CWE(id="CWE-79", name="XSS")
        s.add(cwe)

        threats: list[Threat] = []
        for i, (sev, _score_finance, age_h) in enumerate(
            [
                (Severity.critical, 90.0, 1),
                (Severity.high, 50.0, 5),
                (Severity.medium, 20.0, 30),
            ]
        ):
            tid = uuid.uuid4()
            pub_at = now - timedelta(hours=age_h)
            t = Threat(
                id=tid,
                threat_type="cve",
                title=f"Apache Tomcat issue {i}",
                summary=f"Payment processing flaw {i}",
                severity=sev,
                cvss_score=8.0 if sev != Severity.medium else 4.0,
                cvss_vector="CVSS:3.1/X",
                cvss_version="3.1",
                tags=[],
                published_at=pub_at,
                last_modified_at=pub_at,
                cwes=[cwe] if i == 0 else [],
            )
            s.add(t)
            await s.flush()
            ts = ThreatSource(
                threat_id=tid,
                source_id=src.id,
                external_id=f"CVE-2026-{1000 + i}",
                first_seen_at=pub_at,
                last_seen_at=pub_at,
                tags=["nvd"],
                affected_products=[f"cpe:2.3:a:apache:tomcat:{i}"],
                references=[f"https://x/{i}"],
                raw_data={},
            )
            s.add(ts)
            threats.append(t)

        s.add(
            SectorProfile(
                id="finance",
                name="Finance",
                sector="banking",
                description="Retail banking",
                keywords=["payment"],
                technologies=["Tomcat"],
                cwe_priorities=["CWE-79"],
                cvss_threshold=7.0,
                visibility="public",
                source_file="profiles/public/finance.yaml",
                loaded_at=now,
            )
        )
        s.add(
            SectorProfile(
                id="saas",
                name="SaaS",
                sector="software",
                keywords=[],
                technologies=[],
                cwe_priorities=[],
                cvss_threshold=7.0,
                visibility="public",
                source_file="profiles/public/saas.yaml",
                loaded_at=now,
            )
        )
        s.add(
            SectorProfile(
                id="corp",
                name="Internal",
                sector="enterprise",
                visibility="private",
                source_file="profiles/private/corp.yaml",
                loaded_at=now,
            )
        )
        await s.flush()

        # Pre-computed scores against the finance profile
        for t, score in zip(threats, [90.0, 50.0, 20.0], strict=True):
            s.add(
                ThreatSectorScore(
                    threat_id=t.id,
                    sector_id="finance",
                    score=score,
                    score_breakdown={"final_score": score},
                    calculated_at=now,
                )
            )
        # corp gets one score too
        s.add(
            ThreatSectorScore(
                threat_id=threats[0].id,
                sector_id="corp",
                score=42.0,
                score_breakdown={"final_score": 42.0},
                calculated_at=now,
            )
        )
        await s.commit()
    return threats


# ---------- listing ----------


async def test_list_sectors_public_only_by_default(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors")
    assert resp.status_code == 200
    body = resp.json()
    ids = sorted(p["id"] for p in body["items"])
    assert ids == ["finance", "saas"]
    assert body["total"] == 2


async def test_list_sectors_visibility_all_requires_admin(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors?visibility=all")
    assert resp.status_code == 403


async def test_list_sectors_visibility_all_with_admin(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors?visibility=all", headers={"X-Admin-Key": ADMIN_KEY})
    assert resp.status_code == 200
    ids = sorted(p["id"] for p in resp.json()["items"])
    assert ids == ["corp", "finance", "saas"]


async def test_list_sectors_wrong_admin_key_is_403(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors?visibility=all", headers={"X-Admin-Key": "wrong"})
    assert resp.status_code == 403


# ---------- detail ----------


async def test_get_sector_public(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/finance")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "finance"
    assert "Tomcat" in body["technologies"]


async def test_get_private_sector_returns_404_without_key(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/corp")
    assert resp.status_code == 404


async def test_get_private_sector_visible_to_admin(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/corp", headers={"X-Admin-Key": ADMIN_KEY})
    assert resp.status_code == 200
    assert resp.json()["id"] == "corp"


async def test_get_unknown_sector_404(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/does-not-exist")
    assert resp.status_code == 404


# ---------- threats ----------


async def test_get_sector_threats_sorted_by_score_desc(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/finance/threats")
    assert resp.status_code == 200
    items = resp.json()["items"]
    scores = [i["score"] for i in items]
    assert scores == sorted(scores, reverse=True)
    assert scores == [90.0, 50.0, 20.0]


async def test_get_sector_threats_min_score_filter(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/finance/threats?min_score=70")
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["score"] == 90.0


async def test_get_sector_threats_since_filter(client, seeded_sectors):
    cutoff = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
    resp = await client.get("/api/v1/sectors/finance/threats", params={"since": cutoff})
    items = resp.json()["items"]
    # Only the threat at age_h=1 and age_h=5 are within the last 10 hours
    assert len(items) == 2


async def test_get_threats_for_private_sector_404_without_key(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/corp/threats")
    assert resp.status_code == 404


# ---------- dashboard ----------


async def test_dashboard_structure(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/finance/dashboard")
    assert resp.status_code == 200
    body = resp.json()
    assert body["sector"]["id"] == "finance"
    assert "top_24h" in body and isinstance(body["top_24h"], list)
    assert "top_7d" in body
    stats = body["stats"]
    assert stats["total_threats"] == 3
    assert stats["critical_count"] == 1  # only the score=90 critical threat is >= 70
    assert "nvd" in stats["sources_active"]
    assert isinstance(stats["average_score"], float)


# ---------- RSS feed ----------


async def test_rss_feed_serves_xml(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/finance/feed.rss?min_score=0")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/rss+xml")
    body = resp.text
    assert "<rss" in body and "<item>" in body
    assert "Apache Tomcat issue 0" in body


async def test_rss_feed_default_threshold_filters(client, seeded_sectors):
    resp = await client.get("/api/v1/sectors/finance/feed.rss")  # default min_score=70
    body = resp.text
    assert "Apache Tomcat issue 0" in body
    assert "Apache Tomcat issue 2" not in body  # score=20 below 70


# ---------- admin endpoints ----------


async def test_admin_endpoints_require_key(client, seeded_sectors):
    r1 = await client.post("/api/v1/admin/reload-profiles")
    assert r1.status_code == 403

    r2 = await client.post("/api/v1/admin/rescore-all")
    assert r2.status_code == 403


async def test_admin_rescore_all_returns_202(client, app, seeded_sectors):
    # The route reads scoring_job from app.state — install one for the test.
    from threat_intel.services.scoring_job import ThreatScoringJob

    app.state.scoring_job = ThreatScoringJob(app.state.session_factory)
    resp = await client.post("/api/v1/admin/rescore-all", headers={"X-Admin-Key": ADMIN_KEY})
    assert resp.status_code == 202
    assert resp.json()["status"] == "accepted"


async def test_admin_reload_profiles_returns_summary(
    client, app, factory, seeded_sectors, tmp_path
):
    # Wire a loader pointed at an empty tmp dir; reload should remove the
    # disk-sourced profiles (finance, saas, corp) and report them.
    from threat_intel.services.profile_loader import SectorProfileLoader

    app.state.profile_loader = SectorProfileLoader(factory, tmp_path)
    resp = await client.post("/api/v1/admin/reload-profiles", headers={"X-Admin-Key": ADMIN_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert sorted(body["removed"]) == ["corp", "finance", "saas"]
    assert body["public_count"] == 0
