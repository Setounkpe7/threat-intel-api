"""Server-rendered landing page at `/` (M5).

The root path used to redirect to `/docs`. It now serves an editorial
landing page that consumes the project's own services for live numbers,
so visitors hitting the bare domain see a recruiter-friendly entry
point rather than an empty Swagger UI.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest_asyncio

from threat_intel.models.base import Severity, SourceKind
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat

PUBLIC_SECTOR_IDS = ("ecommerce", "finance", "government", "healthcare", "ics", "saas")


@pytest_asyncio.fixture
async def seeded_landing(factory):
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(
            name="nvd",
            kind=SourceKind.cve_feed,
            url="https://nvd.test",
            enabled=True,
            last_run_at=now - timedelta(minutes=4),
            last_success_at=now - timedelta(minutes=4),
        )
        s.add(src)
        await s.flush()

        for sector_id in PUBLIC_SECTOR_IDS:
            s.add(
                SectorProfile(
                    id=sector_id,
                    name=sector_id.capitalize(),
                    sector=sector_id,
                    description=None,
                    keywords=[],
                    technologies=[],
                    cwe_priorities=[],
                    cvss_threshold=7.0,
                    visibility="public",
                    source_file=f"profiles/public/{sector_id}.yaml",
                    loaded_at=now,
                )
            )
        # one private profile that must NOT appear on the landing.
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

        for i, sev in enumerate(
            [Severity.critical, Severity.critical, Severity.high, Severity.medium, Severity.low]
        ):
            tid = uuid.uuid4()
            pub_at = now - timedelta(hours=i)
            s.add(
                Threat(
                    id=tid,
                    threat_type="cve",
                    title=f"Threat {i}",
                    summary=f"desc {i}",
                    severity=sev,
                    cvss_score=8.0 if sev != Severity.low else 3.0,
                    cvss_vector="CVSS:3.1/AV:N",
                    cvss_version="3.1",
                    tags=[],
                    published_at=pub_at,
                    last_modified_at=pub_at,
                )
            )
        await s.commit()


async def test_root_serves_html_landing_not_redirect(client, seeded_landing):
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"].lower()


async def test_landing_contains_project_title_and_total_threats(client, seeded_landing):
    resp = await client.get("/")
    body = resp.text
    assert "CyberThreat Intelligence" in body
    # 5 threats seeded → total must render verbatim.
    assert ">5<" in body or " 5 " in body, "total_threats=5 not rendered"


async def test_landing_lists_all_six_public_sector_slugs(client, seeded_landing):
    resp = await client.get("/")
    body = resp.text
    for slug in PUBLIC_SECTOR_IDS:
        assert slug in body, f"sector slug {slug!r} missing from landing"


async def test_landing_does_not_expose_private_sector_or_admin_endpoints(client, seeded_landing):
    resp = await client.get("/")
    body = resp.text
    # Private sector profiles must not leak — the loader excludes them on the
    # public visibility filter, but a regression that drops the filter would
    # silently surface them in the linked sector list.
    assert "/api/v1/sectors/corp" not in body
    # Admin namespace must not be advertised on the public page.
    assert "/api/v1/admin" not in body
    assert "X-Admin-Key" not in body


async def test_landing_advertises_public_endpoints(client, seeded_landing):
    resp = await client.get("/")
    body = resp.text
    for endpoint in (
        "/api/v1/threats",
        "/api/v1/cve/",
        "/api/v1/sectors",
        "/api/v1/stats/global",
    ):
        assert endpoint in body, f"public endpoint {endpoint!r} not linked on landing"


async def test_landing_csp_permits_google_fonts(client, seeded_landing):
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    # Stylesheets and fonts come from Google Fonts on the editorial design.
    assert "https://fonts.googleapis.com" in csp
    assert "https://fonts.gstatic.com" in csp
    # Hardening guarantees from the global middleware must still hold.
    assert "frame-ancestors 'none'" in csp
    assert "'unsafe-eval'" not in csp


async def test_landing_renders_when_database_is_empty(client):
    """No seed → service queries return 0; landing must still render, not 500."""
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"].lower()
