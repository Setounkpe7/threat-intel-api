"""SSRF guard: only https to publicly-routable hosts may be fetched."""

import ipaddress
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from threat_intel.core.exceptions import CollectorError

Resolver = Callable[..., list[Any]]


def assert_fetchable_url(url: str, *, resolver: Resolver = socket.getaddrinfo) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise CollectorError(f"refusing non-https feed url: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise CollectorError("feed url has no host")
    try:
        infos = resolver(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise CollectorError(f"dns resolution failed for {host}: {e}") from e
    if not infos:
        raise CollectorError(f"no addresses resolved for {host}")
    for info in infos:
        addr = info[4][0]
        ip = ipaddress.ip_address(addr)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise CollectorError(f"feed host {host} resolves to non-public ip {addr}")
