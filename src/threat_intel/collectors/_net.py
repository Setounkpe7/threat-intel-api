"""SSRF guard: only https to publicly-routable hosts may be fetched."""

import ipaddress
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from threat_intel.core.exceptions import CollectorError

Resolver = Callable[..., list[Any]]

# RFC 6598 CGNAT shared space (100.64.0.0/10) is not flagged by any ipaddress
# built-in flag (is_private, is_loopback, etc.), so we block it explicitly.
_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 CGNAT shared space
]


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    return any(ip in net for net in _BLOCKED_NETWORKS)


def assert_fetchable_url(url: str, *, resolver: Resolver = socket.getaddrinfo) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise CollectorError(f"refusing non-https feed url: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise CollectorError("feed url has no host")
    try:
        # NOTE: a DNS-rebinding window exists between this check and the actual
        # httpx request; binding a custom transport at connect time is deferred (MVP).
        infos = resolver(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise CollectorError(f"dns resolution failed for {host}: {e}") from e
    if not infos:
        raise CollectorError(f"no addresses resolved for {host}")
    for info in infos:
        addr = info[4][0]
        ip = ipaddress.ip_address(addr)
        if _is_blocked(ip):
            raise CollectorError(f"feed host {host} resolves to non-public ip {addr}")
