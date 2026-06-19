"""SSRF guard for collector outbound HTTP requests.

Rejects URLs that resolve to private/loopback/link-local addresses to prevent
server-side request forgery attacks when collector URLs come from config files.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from threat_intel.core.exceptions import CollectorError


def assert_fetchable_url(url: str) -> None:
    """Raise CollectorError if *url* must not be fetched (SSRF guard).

    Checks:
    - Scheme must be https or http.
    - Hostname must resolve to a public routable IP (not private, loopback,
      link-local, reserved, or multicast).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise CollectorError(f"URL scheme not allowed: {parsed.scheme!r} in {url!r}")
    host = parsed.hostname
    if not host:
        raise CollectorError(f"URL has no hostname: {url!r}")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise CollectorError(f"DNS resolution failed for {host!r}: {exc}") from exc
    for _family, _type, _proto, _canonname, sockaddr in infos:
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise CollectorError(
                f"URL resolves to non-public IP {ip!s} — blocked by SSRF guard: {url!r}"
            )
