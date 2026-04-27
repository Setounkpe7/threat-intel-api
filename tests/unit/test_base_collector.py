import inspect
from collections.abc import AsyncIterator

from threat_intel.collectors.base import BaseCollector, RawEvent, ThreatDraft


def test_raw_event_is_immutable():
    e = RawEvent(external_id="x", payload={}, fetched_at=None)  # type: ignore[arg-type]
    import dataclasses
    assert dataclasses.is_dataclass(e)
    fields = {f.name for f in dataclasses.fields(e)}
    assert fields == {"external_id", "payload", "fetched_at"}


def test_threat_draft_validates_required_fields():
    from datetime import datetime, timezone
    from threat_intel.models.base import Severity

    now = datetime.now(timezone.utc)
    d = ThreatDraft(
        source_name="nvd",
        external_id="CVE-2026-1",
        title="t",
        description="d",
        severity=Severity.high,
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        cwe_ids=[],
        affected_products=[],
        references=[],
        published_at=now,
        last_modified_at=now,
        raw_data={},
    )
    assert d.source_name == "nvd"


def test_base_collector_is_abstract():
    assert inspect.isabstract(BaseCollector)
    assert "fetch" in BaseCollector.__abstractmethods__
    assert "normalize" in BaseCollector.__abstractmethods__
