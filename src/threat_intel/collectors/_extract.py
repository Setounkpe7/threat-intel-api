"""Pure extractors for RSS collector: CVE/GHSA ids, IOCs, stable external ids."""

import hashlib
import ipaddress
import re

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.IGNORECASE)


def _refang(text: str) -> str:
    return (
        text.replace("hxxp", "http")
        .replace("hXXp", "http")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("[at]", "@")
    )


def _dedup_preserve(items: list[str]) -> list[str]:
    seen: list[str] = []
    for it in items:
        if it not in seen:
            seen.append(it)
    return seen


def extract_cves(text: str) -> list[str]:
    if not text:
        return []
    return _dedup_preserve([m.group(0).upper() for m in _CVE_RE.finditer(text)])


def extract_ghsa(text: str) -> list[str]:
    if not text:
        return []
    return _dedup_preserve([m.group(0).lower() for m in _GHSA_RE.finditer(text)])


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def extract_iocs(text: str, *, max_each: int = 25) -> list[tuple[str, str]]:
    if not text:
        return []
    t = _refang(text)
    out: list[tuple[str, str]] = []

    def _add(kind: str, values: list[str]) -> None:
        for v in _dedup_preserve(values)[:max_each]:
            out.append((kind, v))

    _add("sha256", _SHA256_RE.findall(t))
    # sha1/md5 exclude substrings already captured as sha256
    sha256_set = {v for k, v in out if k == "sha256"}
    _add("sha1", [h for h in _SHA1_RE.findall(t) if h not in sha256_set])
    _add("md5", [h for h in _MD5_RE.findall(t) if h not in sha256_set])
    _add("url", [u.rstrip(".,);") for u in _URL_RE.findall(t)])
    _add("ip", [ip for ip in _IPV4_RE.findall(t) if _public_ip(ip)])
    domains = [
        d.lower()
        for d in _DOMAIN_RE.findall(t)
        if not _IPV4_RE.fullmatch(d) and d.lower() not in {"example.com", "example.org"}
    ]
    _add("domain", domains)
    return out


def stable_external_id(
    *, guid: str | None, link: str | None, source_name: str, title: str, published: str
) -> str:
    if guid:
        return guid[:128]
    if link:
        return ("link:" + hashlib.sha256(link.encode("utf-8")).hexdigest())[:128]
    composite = f"{source_name}|{title}|{published}".encode()
    return ("h:" + hashlib.sha256(composite).hexdigest())[:128]
