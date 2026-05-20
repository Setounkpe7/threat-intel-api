import uuid
from datetime import UTC, datetime

from threat_intel.models.base import Severity, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource


async def test_get_cve_returns_detail(client, seeded_db):
    resp = await client.get("/api/v1/cve/CVE-2026-1000")
    assert resp.status_code == 200
    body = resp.json()
    assert body["external_id"] == "CVE-2026-1000"
    assert "raw_data" in body
    assert body["cwe_ids"] == ["CWE-79"]


async def test_get_cve_404_problem_json(client):
    resp = await client.get("/api/v1/cve/CVE-2026-9999")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["title"] == "Threat not found"
    assert body["status"] == 404


async def test_get_cve_invalid_format_returns_422(client):
    resp = await client.get("/api/v1/cve/NOT-A-CVE")
    assert resp.status_code == 422


async def test_get_cve_resolves_ghsa_id(client, factory):
    """GHSA-prefixed advisories surfaced by the dashboard must resolve via /cve/{id}."""
    ghsa_id = "GHSA-7xpr-hc2w-34m9"
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(
            name="github_advisories",
            kind=SourceKind.cve_feed,
            url="https://x",
            enabled=True,
        )
        s.add(src)
        await s.flush()
        tid = uuid.uuid4()
        s.add(
            Threat(
                id=tid,
                threat_type="cve",
                title="GHSA-only advisory",
                summary="Desc",
                severity=Severity.high,
                cvss_score=7.5,
                published_at=now,
                last_modified_at=now,
            )
        )
        await s.flush()
        s.add(
            ThreatSource(
                threat_id=tid,
                source_id=src.id,
                external_id=ghsa_id,
                first_seen_at=now,
                last_seen_at=now,
                tags=[],
                affected_products=[],
                references=[],
                raw_data={},
            )
        )
        await s.commit()

    resp = await client.get(f"/api/v1/cve/{ghsa_id}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["external_id"] == ghsa_id


async def test_get_cve_rejects_garbage_ghsa(client):
    resp = await client.get("/api/v1/cve/GHSA-too-short")
    assert resp.status_code == 422
