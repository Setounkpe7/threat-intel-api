"""Seed the demo DB with realistic threats and trigger scoring against all profiles."""

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Severity, SourceKind
from threat_intel.models.cwe import CWE
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.services.profile_loader import SectorProfileLoader
from threat_intel.services.scoring_job import ThreatScoringJob


THREATS = [
    {
        "external_id": "CVE-2026-0001",
        "title": "Apache Tomcat RCE via crafted request",
        "description": "Apache Tomcat 9.x is vulnerable to remote code execution when handling malformed payment processing requests. Attackers can execute arbitrary code on the underlying server via a crafted HTTP request.",
        "severity": Severity.critical,
        "cvss_score": 9.8,
        "affected_products": ["cpe:2.3:a:apache:tomcat:9.0.65"],
        "cwes": ["CWE-79"],
        "age_h": 2,
    },
    {
        "external_id": "CVE-2026-0002",
        "title": "Magento checkout coupon abuse",
        "description": "Magento 2.4.x allows authenticated users to bypass the checkout flow by replaying expired coupons against the storefront API.",
        "severity": Severity.high,
        "cvss_score": 7.5,
        "affected_products": ["cpe:2.3:a:magento:magento:2.4.5"],
        "cwes": ["CWE-639"],
        "age_h": 5,
    },
    {
        "external_id": "CVE-2026-0003",
        "title": "Siemens SCADA PLC firmware backdoor",
        "description": "An undocumented authentication bypass exists in Siemens SIMATIC S7-1500 PLC firmware enabling remote code execution on industrial control systems via the OPC-UA interface.",
        "severity": Severity.critical,
        "cvss_score": 9.5,
        "affected_products": ["cpe:2.3:o:siemens:simatic_s7-1500:2.9"],
        "cwes": ["CWE-798"],
        "age_h": 8,
    },
    {
        "external_id": "CVE-2026-0004",
        "title": "Epic EHR information exposure",
        "description": "Epic EHR exposes patient phi (protected health information) via the patient portal API when an attacker forges the tenant header. This affects hospital deployments.",
        "severity": Severity.high,
        "cvss_score": 8.2,
        "affected_products": ["cpe:2.3:a:epic:hyperspace:8.0"],
        "cwes": ["CWE-200"],
        "age_h": 14,
    },
    {
        "external_id": "CVE-2026-0005",
        "title": "Cisco ASA SSL VPN auth bypass actively exploited",
        "description": "A zero-day in Cisco ASA SSL VPN allows authentication bypass. cisa advisory issued. Reportedly exploited by apt actors against government and defense contractors.",
        "severity": Severity.critical,
        "cvss_score": 9.9,
        "affected_products": ["cpe:2.3:o:cisco:adaptive_security_appliance:9.18"],
        "cwes": ["CWE-287"],
        "age_h": 1,
    },
    {
        "external_id": "CVE-2026-0006",
        "title": "Minecraft forge mod arbitrary file write",
        "description": "A Minecraft Forge mod loader vulnerability allows a malicious mod to write arbitrary files outside the game directory.",
        "severity": Severity.medium,
        "cvss_score": 5.5,
        "affected_products": ["cpe:2.3:a:minecraftforge:forge:47.0"],
        "cwes": ["CWE-22"],
        "age_h": 36,
    },
    {
        "external_id": "CVE-2026-0007",
        "title": "Auth0 JWT signature bypass in tenant isolation",
        "description": "Auth0 JWT validation flaw enables tenant boundary crossing in multi-tenant SaaS deployments. Affects oauth and oidc flows on Node.js SDKs.",
        "severity": Severity.high,
        "cvss_score": 8.8,
        "affected_products": ["cpe:2.3:a:auth0:auth0-js:9.20"],
        "cwes": ["CWE-287"],
        "age_h": 20,
    },
]


async def main() -> None:
    db_url = os.environ["DATABASE_URL"]
    engine = build_engine(db_url)
    factory = session_factory(engine)

    loader = SectorProfileLoader(factory, Path("profiles"))
    res = await loader.load_all()
    print(f"Loaded profiles: public={res.public_count} added={len(res.added)}")

    now = datetime.now(UTC)
    async with factory() as s:
        s.add(
            Source(
                name="nvd",
                kind=SourceKind.cve_feed,
                url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                enabled=True,
                last_run_at=now,
                last_success_at=now,
            )
        )
        await s.flush()
        src_id = (await s.execute(__import__("sqlalchemy").select(Source.id))).scalar_one()

        cwe_ids: set[str] = set()
        for t in THREATS:
            for c in t["cwes"]:
                cwe_ids.add(c)
        for cid in cwe_ids:
            s.add(CWE(id=cid))
        await s.flush()

        from sqlalchemy import select as _select

        cwes_by_id = {
            c.id: c
            for c in (
                await s.execute(_select(CWE).where(CWE.id.in_(list(cwe_ids))))
            ).scalars().all()
        }

        for t in THREATS:
            published = now - timedelta(hours=t["age_h"])
            s.add(
                Threat(
                    id=uuid.uuid4(),
                    source_id=src_id,
                    external_id=t["external_id"],
                    title=t["title"],
                    description=t["description"],
                    severity=t["severity"],
                    cvss_score=t["cvss_score"],
                    cvss_vector="CVSS:3.1/AV:N",
                    cvss_version="3.1",
                    affected_products=t["affected_products"],
                    references=[f"https://nvd.nist.gov/vuln/detail/{t['external_id']}"],
                    published_at=published,
                    last_modified_at=published,
                    raw_data={"source": "demo"},
                    cwes=[cwes_by_id[c] for c in t["cwes"]],
                )
            )
        await s.commit()
    print(f"Inserted {len(THREATS)} demo threats")

    job = ThreatScoringJob(factory)
    score_res = await job.rescore_all()
    print(
        f"Scored: threats={score_res.threats_scored} "
        f"profiles={score_res.profiles_count} rows_written={score_res.rows_written}"
    )

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
