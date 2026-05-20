"""Seed the local DB with realistic post-M3a threats and score them.

Refuses to run against any DATABASE_URL whose host is not in the
documented dev allow-list (localhost / 127.0.0.1 / db / postgres).
This is a safety guardrail: an analyst pointing the script at staging
or prod by mistake should fail fast, not contaminate the data.
"""

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse


SAFE_HOSTS = {"localhost", "127.0.0.1", "db", "postgres"}


def assert_safe_database_url() -> None:
    """Abort if DATABASE_URL points to a non-dev host."""
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("DATABASE_URL not set", file=sys.stderr)
        sys.exit(2)
    # SQLAlchemy URLs look like "postgresql+asyncpg://user:pass@host:port/db".
    # urlparse needs the +asyncpg stripped to parse the netloc correctly.
    parsed = urlparse(url.replace("+asyncpg", "").replace("+aiosqlite", ""))
    host = parsed.hostname or ""
    if host not in SAFE_HOSTS and not url.startswith("sqlite"):
        print(
            f"Refusing to seed: DATABASE_URL host {host!r} is not in the "
            f"dev allow-list {sorted(SAFE_HOSTS)}. Set DATABASE_URL to a "
            f"local stack before running this script.",
            file=sys.stderr,
        )
        sys.exit(1)


# 5 realistic threats covering finance, ICS, and cloud-native sectors.
# External IDs live on ThreatSource (post-M3a schema); Threat stores only
# the deduplicated record.
THREATS = [
    {
        "ext_id": "CVE-2026-0001",
        "source": "nvd",
        "title": "Apache Tomcat RCE in payment-processing module",
        "summary": (
            "RCE in Apache Tomcat 9.x via crafted POST to /payment endpoint."
            " Attackers can execute arbitrary code on the underlying server."
        ),
        "severity": "critical",
        "cvss": 9.8,
        "products": ["cpe:2.3:a:apache:tomcat:9.0.65"],
        "cwes": ["CWE-79"],
        "age_h": 2,
    },
    {
        "ext_id": "CVE-2026-0002",
        "source": "cisa_kev",
        "title": "Hard-coded admin credentials in banking gateway",
        "summary": (
            "Hard-coded credentials allowing auth bypass on payment-rail gateway."
            " Actively exploited per CISA KEV."
        ),
        "severity": "critical",
        "cvss": 9.4,
        "products": ["cpe:2.3:a:bank:payment-rail:1.0"],
        "cwes": ["CWE-798"],
        "age_h": 6,
    },
    {
        "ext_id": "GHSA-aaaa-bbbb-cccc",
        "source": "github_advisories",
        "title": "square/wire SQL injection in protobuf parser",
        "summary": "SQLi via crafted wire payload in the square/wire library.",
        "severity": "high",
        "cvss": 7.5,
        "products": [],
        "cwes": ["CWE-89"],
        "age_h": 4,
    },
    {
        "ext_id": "CVE-2026-0003",
        "source": "nvd",
        "title": "Kubernetes API server XSS in audit logs",
        "summary": "XSS via crafted audit log entries on the K8s API server.",
        "severity": "high",
        "cvss": 7.2,
        "products": ["cpe:2.3:a:kubernetes:kubernetes:1.28"],
        "cwes": ["CWE-79"],
        "age_h": 12,
    },
    {
        "ext_id": "CVE-2026-0004",
        "source": "nvd",
        "title": "Siemens PLC firmware buffer overflow",
        "summary": (
            "Buffer overflow in Siemens SIMATIC S7 PLC firmware reachable"
            " via Modbus on industrial control networks."
        ),
        "severity": "high",
        "cvss": 8.0,
        "products": ["cpe:2.3:o:siemens:simatic_s7:6"],
        "cwes": [],
        "age_h": 18,
    },
]


async def main() -> None:
    assert_safe_database_url()

    from sqlalchemy import select

    from threat_intel.core.db import build_engine, session_factory
    from threat_intel.models.base import Severity, SourceKind
    from threat_intel.models.cwe import CWE
    from threat_intel.models.source import Source
    from threat_intel.models.threat import Threat
    from threat_intel.models.threat_source import ThreatSource
    from threat_intel.services.profile_loader import SectorProfileLoader
    from threat_intel.services.scoring_job import ThreatScoringJob

    eng = build_engine(os.environ["DATABASE_URL"])
    factory = session_factory(eng)
    now = datetime.now(UTC)

    async with factory() as s:
        # Ensure the three demo sources exist (upsert-style: skip if present).
        for src_name, src_kind in [
            ("nvd", SourceKind.cve_feed),
            ("cisa_kev", SourceKind.cve_feed),
            ("github_advisories", SourceKind.advisory),
        ]:
            existing = (
                await s.execute(select(Source).where(Source.name == src_name))
            ).scalar_one_or_none()
            if existing is None:
                s.add(
                    Source(
                        name=src_name,
                        kind=src_kind,
                        url=f"https://{src_name}.test",
                        enabled=True,
                    )
                )
        await s.flush()

        sources = {
            n: (await s.execute(select(Source).where(Source.name == n))).scalar_one()
            for n in ("nvd", "cisa_kev", "github_advisories")
        }

        # Ensure CWEs exist.
        for cid, cname in [
            ("CWE-79", "Cross-Site Scripting"),
            ("CWE-89", "SQL Injection"),
            ("CWE-798", "Use of Hard-coded Credentials"),
        ]:
            existing_cwe = (
                await s.execute(select(CWE).where(CWE.id == cid))
            ).scalar_one_or_none()
            if existing_cwe is None:
                s.add(CWE(id=cid, name=cname))
        await s.flush()

        cwes = {
            cid: (await s.execute(select(CWE).where(CWE.id == cid))).scalar_one()
            for cid in ("CWE-79", "CWE-89", "CWE-798")
        }

        for t in THREATS:
            pub = now - timedelta(hours=t["age_h"])
            tid = uuid.uuid4()
            # Post-M3a: external_id + affected_products + raw_data live on
            # ThreatSource, not on Threat.
            s.add(
                Threat(
                    id=tid,
                    threat_type="cve",
                    title=t["title"],
                    summary=t["summary"],
                    severity=Severity[t["severity"]],
                    cvss_score=t["cvss"],
                    cvss_vector="CVSS:3.1/AV:N",
                    cvss_version="3.1",
                    tags=["kev"] if t["source"] == "cisa_kev" else [],
                    published_at=pub,
                    last_modified_at=pub,
                    cwes=[cwes[c] for c in t["cwes"]],
                )
            )
            await s.flush()
            s.add(
                ThreatSource(
                    threat_id=tid,
                    source_id=sources[t["source"]].id,
                    external_id=t["ext_id"],
                    first_seen_at=pub,
                    last_seen_at=pub,
                    tags=[t["source"]],
                    affected_products=t["products"],
                    references=[],
                    raw_data={"id": t["ext_id"], "source": "demo"},
                )
            )

        await s.commit()
        print(f"Inserted {len(THREATS)} demo threats")

    loader = SectorProfileLoader(
        session_factory=factory,
        profiles_root=Path("profiles"),
    )
    await loader.load_all()

    job = ThreatScoringJob(factory)
    res = await job.rescore_all()
    print(
        f"Scored: threats={res.threats_scored} "
        f"profiles={res.profiles_count} rows_written={res.rows_written}"
    )

    await eng.dispose()


if __name__ == "__main__":
    asyncio.run(main())
