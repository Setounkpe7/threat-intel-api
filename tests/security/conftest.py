"""Fixtures shared by tests/security/. Mirrors the seeded_sectors fixture
from test_sectors.py so the security suite is self-contained."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest_asyncio

from threat_intel.models.base import Severity, SourceKind
from threat_intel.models.cwe import CWE
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat


@pytest_asyncio.fixture
async def security_seed(factory):
    """Two threats, one public profile, one private profile, scored."""
    now = datetime.now(UTC)
    async with factory() as s:
        src = Source(name="nvd", kind=SourceKind.cve_feed, url="https://x", enabled=True)
        s.add(src)
        await s.flush()
        cwe = CWE(id="CWE-79", name="XSS")
        s.add(cwe)

        threats: list[Threat] = []
        for i, sev in enumerate([Severity.critical, Severity.high]):
            t = Threat(
                id=uuid.uuid4(),
                source_id=src.id,
                external_id=f"CVE-2026-{2000 + i}",
                title=f"Sample threat {i}",
                description="payment processing flaw",
                severity=sev,
                cvss_score=8.5,
                cvss_vector="CVSS:3.1/X",
                cvss_version="3.1",
                affected_products=["cpe:2.3:a:apache:tomcat"],
                references=[],
                published_at=now - timedelta(hours=2),
                last_modified_at=now - timedelta(hours=2),
                raw_data={},
                cwes=[cwe] if i == 0 else [],
            )
            s.add(t)
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
                id="corp-secret",
                name="Internal Corp",
                sector="enterprise",
                description="Internal stack — must not leak through public API",
                keywords=["confidential-internal-keyword"],
                technologies=["MySecretInternalTool"],
                visibility="private",
                source_file="profiles/private/corp-secret.yaml",
                loaded_at=now,
            )
        )
        await s.flush()

        for t, score in zip(threats, [85.0, 60.0], strict=True):
            s.add(
                ThreatSectorScore(
                    threat_id=t.id,
                    sector_id="finance",
                    score=score,
                    score_breakdown={"final_score": score},
                    calculated_at=now,
                )
            )
            s.add(
                ThreatSectorScore(
                    threat_id=t.id,
                    sector_id="corp-secret",
                    score=score,
                    score_breakdown={"final_score": score},
                    calculated_at=now,
                )
            )
        await s.commit()
    return {"threat_ids": [t.id for t in threats]}
