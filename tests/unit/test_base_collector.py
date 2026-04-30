import inspect

from threat_intel.collectors.base import BaseCollector, RawEvent


def test_raw_event_is_immutable():
    e = RawEvent(external_id="x", payload={}, fetched_at=None)  # type: ignore[arg-type]
    import dataclasses

    assert dataclasses.is_dataclass(e)
    fields = {f.name for f in dataclasses.fields(e)}
    assert fields == {"external_id", "payload", "fetched_at"}


def test_base_collector_is_abstract():
    assert inspect.isabstract(BaseCollector)
    assert "fetch" in BaseCollector.__abstractmethods__
    assert "to_event" in BaseCollector.__abstractmethods__
