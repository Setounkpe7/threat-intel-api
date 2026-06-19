import socket

import pytest

from threat_intel.collectors._net import assert_fetchable_url
from threat_intel.core.exceptions import CollectorError


def _resolver_to(ip: str):
    def _r(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    return _r


def test_rejects_non_https():
    with pytest.raises(CollectorError):
        assert_fetchable_url("http://example.test/feed", resolver=_resolver_to("8.8.8.8"))


def test_rejects_file_scheme():
    with pytest.raises(CollectorError):
        assert_fetchable_url("file:///etc/passwd", resolver=_resolver_to("8.8.8.8"))


def test_rejects_loopback():
    with pytest.raises(CollectorError):
        assert_fetchable_url("https://localhost/feed", resolver=_resolver_to("127.0.0.1"))


def test_rejects_link_local_metadata():
    with pytest.raises(CollectorError):
        assert_fetchable_url("https://meta.test/feed", resolver=_resolver_to("169.254.169.254"))


def test_rejects_rfc1918():
    with pytest.raises(CollectorError):
        assert_fetchable_url("https://int.test/feed", resolver=_resolver_to("10.1.2.3"))


def test_rejects_cgnat():
    with pytest.raises(CollectorError):
        assert_fetchable_url("https://cgnat.test/feed", resolver=_resolver_to("100.64.1.1"))


def test_accepts_public_https():
    assert_fetchable_url("https://www.cisa.gov/x.xml", resolver=_resolver_to("23.1.2.3"))
