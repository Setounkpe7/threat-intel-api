from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from threat_intel.models.base import Severity
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator


def test_collected_indicator_rejects_unknown_type():
    with pytest.raises(ValidationError):
        CollectedIndicator(type="unknown", value="x")


def test_collected_event_minimum_fields():
    ev = CollectedEvent(
        source_name="nvd",
        external_id="CVE-2024-1",
        title="Foo",
        published_at=datetime.now(UTC),
        last_modified_at=datetime.now(UTC),
        raw_data={},
    )
    assert ev.tags == []
    assert ev.indicators == []
    assert ev.severity is None


def test_collected_event_round_trip():
    payload = {
        "source_name": "github_advisories",
        "external_id": "GHSA-1234-5678-90ab",
        "title": "Foo",
        "summary": "bar",
        "severity": "high",
        "cvss_score": 7.5,
        "tags": ["github-advisory", "npm"],
        "indicators": [
            {"type": "cve", "value": "CVE-2024-9"},
            {"type": "package", "value": "npm:lodash"},
        ],
        "published_at": "2026-04-01T00:00:00+00:00",
        "last_modified_at": "2026-04-02T00:00:00+00:00",
        "raw_data": {"k": "v"},
    }
    ev = CollectedEvent.model_validate(payload)
    assert ev.severity == Severity.high
    assert ev.indicators[0].type == "cve"
