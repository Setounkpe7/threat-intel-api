from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from threat_intel.schemas.cve import ThreatDetail
from threat_intel.schemas.health import CollectorHealth, HealthResponse, Stats
from threat_intel.schemas.threat import ThreatFilters, ThreatRead


def test_threat_filters_rejects_limit_too_large():
    with pytest.raises(ValidationError):
        ThreatFilters(limit=500)


def test_threat_filters_defaults():
    f = ThreatFilters()
    assert f.limit == 50
    assert f.offset == 0
    assert f.severity == []


def test_threat_read_excludes_raw_data_attribute():
    fields = ThreatRead.model_fields
    assert "raw_data" not in fields


def test_threat_detail_includes_raw_data_attribute():
    fields = ThreatDetail.model_fields
    assert "raw_data" in fields


def test_health_response_shape():
    hr = HealthResponse(
        status="ok",
        version="0.1.0",
        uptime_seconds=10,
        database="connected",
        collectors={
            "nvd": CollectorHealth(
                last_run=datetime.now(UTC),
                last_success=True,
                threats_collected_24h=5,
            )
        },
        stats=Stats(total_threats=100, threats_last_24h=5),
    )
    assert hr.status == "ok"


def test_collected_event_enrichment_defaults():
    from threat_intel.schemas.ingest import CollectedEvent

    now = datetime.now(UTC)
    ev = CollectedEvent(source_name="s", external_id="x", title="t",
                        published_at=now, last_modified_at=now)
    assert ev.enrichment_mode is False
    assert ev.threat_type is None
    assert ev.indicator_confidence == 100


def test_collected_event_enrichment_set():
    from threat_intel.schemas.ingest import CollectedEvent

    now = datetime.now(UTC)
    ev = CollectedEvent(source_name="s", external_id="x", title="t",
                        published_at=now, last_modified_at=now,
                        enrichment_mode=True, threat_type="report",
                        indicator_confidence=50)
    assert ev.enrichment_mode is True
    assert ev.threat_type == "report"
    assert ev.indicator_confidence == 50
