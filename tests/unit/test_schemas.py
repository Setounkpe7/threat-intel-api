from datetime import datetime, timezone

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
                last_run=datetime.now(timezone.utc),
                last_success=True,
                threats_collected_24h=5,
            )
        },
        stats=Stats(total_threats=100, threats_last_24h=5),
    )
    assert hr.status == "ok"
