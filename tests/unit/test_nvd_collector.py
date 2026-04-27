import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from threat_intel.collectors.base import RawEvent
from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings
from threat_intel.models.base import Severity

FIXTURE = json.loads(Path("tests/fixtures/nvd_sample.json").read_text())


def _make_collector() -> NVDCollector:
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    return NVDCollector(http_client=httpx.AsyncClient(), settings=settings)


def test_normalize_full_record():
    item = FIXTURE["vulnerabilities"][0]
    raw = RawEvent(
        external_id=item["cve"]["id"],
        payload=item,
        fetched_at=datetime.now(timezone.utc),
    )
    draft = _make_collector().normalize(raw)

    assert draft.source_name == "nvd"
    assert draft.external_id == "CVE-2026-0001"
    assert draft.severity is Severity.critical
    assert draft.cvss_score == 9.8
    assert draft.cvss_version == "3.1"
    assert draft.cvss_vector.startswith("CVSS:3.1/")
    assert draft.cwe_ids == ["CWE-79"]
    assert draft.affected_products == ["cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"]
    assert draft.references == ["https://example.test/advisory/1"]
    assert draft.published_at.tzinfo is not None
    assert draft.title.startswith("Remote code execution")


def test_normalize_minimal_record_falls_back_to_unknown():
    item = FIXTURE["vulnerabilities"][1]
    raw = RawEvent(
        external_id=item["cve"]["id"],
        payload=item,
        fetched_at=datetime.now(timezone.utc),
    )
    draft = _make_collector().normalize(raw)

    assert draft.severity is Severity.unknown
    assert draft.cvss_score is None
    assert draft.cwe_ids == []
    assert draft.affected_products == []
    assert draft.references == []


def test_normalize_picks_english_description():
    item = FIXTURE["vulnerabilities"][0]
    raw = RawEvent(external_id=item["cve"]["id"], payload=item, fetched_at=datetime.now(timezone.utc))
    draft = _make_collector().normalize(raw)
    assert "código" not in draft.description.lower()
    assert "ExampleProduct" in draft.description
