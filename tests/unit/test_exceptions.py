from threat_intel.core.exceptions import (
    CollectorError,
    CollectorHTTPError,
    CollectorParseError,
    ConfigurationError,
    PersistenceError,
    ThreatIntelException,
    ThreatNotFoundException,
)


def test_all_descend_from_base():
    for cls in (
        ConfigurationError,
        CollectorError,
        CollectorHTTPError,
        CollectorParseError,
        PersistenceError,
        ThreatNotFoundException,
    ):
        assert issubclass(cls, ThreatIntelException)


def test_collector_http_and_parse_descend_from_collector_error():
    assert issubclass(CollectorHTTPError, CollectorError)
    assert issubclass(CollectorParseError, CollectorError)


def test_threat_not_found_carries_cve_id():
    err = ThreatNotFoundException(cve_id="CVE-2026-9999")
    assert err.cve_id == "CVE-2026-9999"
    assert "CVE-2026-9999" in str(err)


def test_collector_http_error_carries_status_and_url():
    err = CollectorHTTPError(status_code=502, url="https://x", message="bad gateway")
    assert err.status_code == 502
    assert err.url == "https://x"
    assert "502" in str(err)
