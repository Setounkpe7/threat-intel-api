# RSS Feeds Ingestion (MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest 4 curated threat-intel RSS/Atom feeds (CISA Advisories, CISA ICS Advisories, Cisco PSIRT, The DFIR Report) as new data sources — items that cite a CVE enrich the existing CVE threat (multi-source), items without a CVE become standalone `advisory`/`report` threats, deduped idempotently — with hardened XML parsing and SSRF protection.

**Architecture:** One generic, config-driven `RSSCollector(BaseCollector)` is instantiated once per feed from a YAML catalog (`feeds/feeds.yaml`), loaded at lifespan exactly like `SectorProfileLoader`. The collector fetches over the shared `httpx` client (no redirects, size-capped), runs a `defusedxml` safety pre-check, parses with `feedparser`, sanitizes via the existing `clean_text`, extracts CVE/GHSA/IOC indicators from the text, and emits a `CollectedEvent` flagged `enrichment_mode=True`. The ingestion layer gains an enrichment regime that fans out CVE matches across distinct threats (never merges them) and is idempotent on `(source_id, external_id)` for no-CVE items. The data-driven scheduler picks up the new `Source` rows with no change.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, httpx, `feedparser` (RSS/Atom), `defusedxml` (XML hardening), `bleach`/`clean_text` (sanitization), PyYAML, pytest + respx, structlog, mypy --strict, ruff (with `ANN`/`S` rules).

**Spec:** This conversation's multi-agent convergence (Threat Detection Engineer, Security Engineer, Backend Architect, Product Manager — Tours 1 & 2) plus the user's validated decisions. No separate spec file.

## Global Constraints

- **Branch:** `feat/rss-feeds-ingestion`, cut from `dev`. Flow `feat/* → dev → main`, every merge via PR (CONTRIBUTING.md). Never commit on `dev`/`main`.
- **Python:** `>=3.12`. **mypy `--strict`** must stay green (`pydantic.mypy` plugin on). **ruff** rules include `ANN` (annotations) and `S` (bandit-style security); `tests/**` ignore `ANN`/`S105`/`S106`.
- **Tests:** `pytest-asyncio` `asyncio_mode = "auto"`; HTTP mocked with `respx`; DB is in-memory SQLite via `build_engine("sqlite+aiosqlite:///:memory:")` + `Base.metadata.create_all`; construct `Settings(database_url=...)  # type: ignore[call-arg]`.
- **NON-REGRESSION CANARY:** `pytest tests/integration/test_dedup_cross_source.py` (Log4Shell cross-source merge) MUST pass after **every** task touching `ingest.py`. Run it as the first check each time.
- **Sanitization:** every text field a collector emits (`title`, `summary`) goes through `threat_intel.collectors._sanitize.clean_text`.
- **No Alembic migration** is required for this plan (verified: `ThreatIndicator.confidence` exists; `Threat.threat_type` is free `String(32)`; `SourceKind.rss` exists; `ix_threat_source_source_external` index exists; all IOC `IndicatorType`s exist).
- **The 4 feeds (MVP):**
  | source_name | URL (verify with a real GET before enabling) | kind | threat_type | interval (min) | indicator_confidence |
  |---|---|---|---|---|---|
  | `cisa_advisories` | `https://www.cisa.gov/cybersecurity-advisories/all.xml` | rss | advisory | 120 | 80 |
  | `cisa_ics` | `https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml` | rss | advisory | 120 | 80 |
  | `cisco_psirt` | `https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml` | rss | advisory | 240 | 70 |
  | `dfir_report` | `https://thedfirreport.com/feed/` | rss | report | 240 | 50 |
- **Persona decision (validated):** no-CVE `advisory`/`report` threats are EXCLUDED from sector feeds by default, surfaced via a future `?include_advisories=true` flag. **That read-side filter is OUT of scope of this plan** — see "Follow-up: Plan 2" at the end. This plan only produces correctly-typed data.
- **Security posture (Security Engineer, mandatory):** `https://` only; `follow_redirects=False`; response size cap (5 MiB); `defusedxml` pre-check (`forbid_dtd/forbid_entities/forbid_external`) before any parse; SSRF guard rejecting loopback/RFC1918/link-local/`169.254.169.254`/reserved/multicast IPs; IOCs persisted as candidates (`confidence < 100`) and tagged `unverified-ioc`; `raw_data` bounded.

---

## Sequencing rules

- TDD throughout: failing test → run it red → minimal implementation → green → commit. One behavior per step.
- After each task: run `pytest -q` and confirm green; run the **canary** first for any `ingest.py` task.
- Commit at the granularity shown. No batch commits.
- **Gating checkpoint:** validate with the user after **Task 9** (full ingestion layer done, before wiring real feeds in Task 11).
- After code changes: run `graphify update .` (CLAUDE.md rule) — folded into the final task.
- Task order: deps/config → pure extractors → secure parse → SSRF guard → collector → ingestion-layer (6 sub-tasks) → YAML loader → wiring/CLI → docs.

---

## Task 1: Dependencies + `feeds_path` setting

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/threat_intel/core/config.py`
- Modify: `.env.example`
- Test: `tests/unit/test_config.py`

**Interfaces:**
- Produces: `Settings.feeds_path: Path` (default `Path("feeds")`); deps `feedparser`, `defusedxml` importable.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_config.py`:

```python
from pathlib import Path


def test_feeds_path_defaults_to_feeds_dir(monkeypatch):
    monkeypatch.delenv("FEEDS_PATH", raising=False)
    from threat_intel.core.config import Settings

    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    assert settings.feeds_path == Path("feeds")


def test_dependencies_importable():
    import defusedxml.ElementTree  # noqa: F401
    import feedparser  # noqa: F401
```

- [ ] **Step 2: Run it, verify it fails**

Run: `pytest tests/unit/test_config.py::test_feeds_path_defaults_to_feeds_dir tests/unit/test_config.py::test_dependencies_importable -q`
Expected: FAIL (`AttributeError: feeds_path` and/or `ModuleNotFoundError: feedparser`).

- [ ] **Step 3: Add dependencies**

In `pyproject.toml`, add to `dependencies` (after `"feedgen>=1.0",`):

```toml
  "feedparser>=6.0.11",
  "defusedxml>=0.7.1",
```

Add to `[project.optional-dependencies].dev` (after `"types-PyYAML",`):

```toml
  "types-feedparser",
```

Then install: `uv pip install -e ".[dev]"` (or `pip install -e ".[dev]"`).

- [ ] **Step 4: Add the setting**

In `src/threat_intel/core/config.py`, after the `profiles_path: Path = Path("profiles")` line (config.py:58):

```python
    feeds_path: Path = Path("feeds")
```

In `.env.example`, add:

```dotenv
# Directory holding the RSS feed catalog (feeds/feeds.yaml).
FEEDS_PATH=feeds
```

- [ ] **Step 5: Run tests, verify they pass**

Run: `pytest tests/unit/test_config.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/threat_intel/core/config.py .env.example tests/unit/test_config.py
git commit -m "chore(rss): add feedparser/defusedxml deps and feeds_path setting"
```

---

## Task 2: CVE / GHSA / IOC / external-id extractors (pure functions)

**Files:**
- Create: `src/threat_intel/collectors/_extract.py`
- Test: `tests/unit/collectors/test_extract.py`

**Interfaces:**
- Produces:
  - `extract_cves(text: str) -> list[str]` — uppercased, de-duplicated, order-preserving.
  - `extract_ghsa(text: str) -> list[str]` — lowercased GHSA ids, de-duped.
  - `extract_iocs(text: str, *, max_each: int = 25) -> list[tuple[str, str]]` — list of `(indicator_type, value)` for `ip`/`domain`/`url`/`md5`/`sha1`/`sha256`, defanged input refanged, validated, capped.
  - `stable_external_id(*, guid: str | None, link: str | None, source_name: str, title: str, published: str) -> str` — returns `guid` if present, else `sha256(link)`, else `sha256(source_name|title|published)`; always ≤128 chars.

- [ ] **Step 1: Write the failing tests**

`tests/unit/collectors/test_extract.py`:

```python
from threat_intel.collectors._extract import (
    extract_cves,
    extract_ghsa,
    extract_iocs,
    stable_external_id,
)


def test_extract_cves_basic_and_dedup():
    text = "Affects CVE-2021-44228 and cve-2021-44228 plus CVE-2024-3094."
    assert extract_cves(text) == ["CVE-2021-44228", "CVE-2024-3094"]


def test_extract_cves_ignores_garbage():
    assert extract_cves("version 2021-4 and CVE-XXXX-1") == []


def test_extract_ghsa():
    assert extract_ghsa("see GHSA-jfh8-c2jp-5v3q here") == ["ghsa-jfh8-c2jp-5v3q"]


def test_extract_iocs_refangs_and_validates():
    text = "C2 at hxxp://evil[.]example[.]com/path and ip 10.0.0.1 and 8.8.8.8"
    iocs = extract_iocs(text)
    assert ("url", "http://evil.example.com/path") in iocs
    # private IP must be dropped
    assert ("ip", "10.0.0.1") not in iocs
    assert ("ip", "8.8.8.8") in iocs


def test_extract_iocs_hashes():
    sha256 = "a" * 64
    md5 = "b" * 32
    iocs = extract_iocs(f"hash {sha256} and {md5}")
    assert ("sha256", sha256) in iocs
    assert ("md5", md5) in iocs


def test_extract_iocs_capped():
    text = " ".join(f"{i}.{i}.{i}.{i}" for i in range(1, 60))  # many invalid/garbage
    assert len(extract_iocs(text, max_each=5)) <= 5 * 6  # 6 types max


def test_stable_external_id_prefers_guid():
    assert stable_external_id(
        guid="urn:guid:abc", link="https://x/y", source_name="s", title="t", published="p"
    ) == "urn:guid:abc"


def test_stable_external_id_hashes_link_when_no_guid():
    eid = stable_external_id(
        guid=None, link="https://x/y", source_name="s", title="t", published="p"
    )
    assert eid.startswith("link:") and len(eid) <= 128


def test_stable_external_id_falls_back_to_composite():
    eid = stable_external_id(guid=None, link=None, source_name="s", title="t", published="p")
    assert eid.startswith("h:") and len(eid) <= 128
```

- [ ] **Step 2: Run, verify fail**

Run: `pytest tests/unit/collectors/test_extract.py -q`
Expected: FAIL (`ModuleNotFoundError: _extract`).

- [ ] **Step 3: Implement**

`src/threat_intel/collectors/_extract.py`:

```python
"""Pure extractors for RSS collector: CVE/GHSA ids, IOCs, stable external ids."""

import hashlib
import ipaddress
import re
from urllib.parse import urlparse

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
```

- [ ] **Step 4: Run, verify pass**

Run: `pytest tests/unit/collectors/test_extract.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `ruff check src/threat_intel/collectors/_extract.py && mypy src/threat_intel/collectors/_extract.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/collectors/_extract.py tests/unit/collectors/test_extract.py
git commit -m "feat(rss): add CVE/GHSA/IOC extractors and stable external-id"
```

---

## Task 3: Hardened XML pre-check + feed parse helper

**Files:**
- Create: `src/threat_intel/collectors/_feedparse.py`
- Test: `tests/unit/collectors/test_feedparse.py`

**Interfaces:**
- Consumes: `feedparser`, `defusedxml`.
- Produces:
  - `assert_safe_xml(raw: bytes) -> None` — raises `CollectorParseError` on DTD/entities/external refs.
  - `parse_feed(raw: bytes) -> list[ParsedEntry]` where `ParsedEntry` is a frozen dataclass with `guid: str | None, link: str | None, title: str, summary: str, published: str, tags: list[str]`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/collectors/test_feedparse.py`:

```python
import pytest

from threat_intel.collectors._feedparse import ParsedEntry, assert_safe_xml, parse_feed
from threat_intel.core.exceptions import CollectorParseError

_RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Feed</title>
<item>
  <title>CVE-2021-44228 exploited</title>
  <link>https://example.test/a</link>
  <guid isPermaLink="false">guid-1</guid>
  <description>Log4Shell &lt;b&gt;active&lt;/b&gt;</description>
  <pubDate>Mon, 13 Dec 2021 00:00:00 GMT</pubDate>
  <category>advisory</category>
</item></channel></rss>"""

_XXE = b"""<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<rss version="2.0"><channel><item><title>&xxe;</title></item></channel></rss>"""

_BILLION = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [ <!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;"> ]>
<rss><channel><item><title>&lol2;</title></item></channel></rss>"""


def test_assert_safe_xml_accepts_clean():
    assert_safe_xml(_RSS)  # no raise


def test_assert_safe_xml_rejects_xxe():
    with pytest.raises(CollectorParseError):
        assert_safe_xml(_XXE)


def test_assert_safe_xml_rejects_entity_bomb():
    with pytest.raises(CollectorParseError):
        assert_safe_xml(_BILLION)


def test_parse_feed_maps_fields():
    entries = parse_feed(_RSS)
    assert len(entries) == 1
    e = entries[0]
    assert isinstance(e, ParsedEntry)
    assert e.guid == "guid-1"
    assert e.link == "https://example.test/a"
    assert "CVE-2021-44228" in e.title
    assert "advisory" in e.tags
    assert e.published.startswith("Mon, 13 Dec 2021")
```

- [ ] **Step 2: Run, verify fail**

Run: `pytest tests/unit/collectors/test_feedparse.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement**

`src/threat_intel/collectors/_feedparse.py`:

```python
"""Hardened RSS/Atom parsing: defusedxml safety gate, then feedparser mapping."""

from dataclasses import dataclass
from typing import Any

import defusedxml.ElementTree as DefusedET
import feedparser
from defusedxml.common import DefusedXmlException

from threat_intel.core.exceptions import CollectorParseError


@dataclass(frozen=True)
class ParsedEntry:
    guid: str | None
    link: str | None
    title: str
    summary: str
    published: str
    tags: list[str]


def assert_safe_xml(raw: bytes) -> None:
    """Reject DTDs, internal/external entities (XXE, entity expansion bombs).

    We parse once with defusedxml purely as a safety gate; the result is
    discarded. feedparser then does the real mapping on the same bytes.
    """
    try:
        DefusedET.fromstring(
            raw, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except DefusedXmlException as e:
        raise CollectorParseError(f"unsafe XML rejected: {type(e).__name__}") from e
    except Exception:  # noqa: BLE001 - malformed XML is fine here; feedparser is tolerant
        return


def _entry_tags(entry: Any) -> list[str]:
    tags = []
    for t in getattr(entry, "tags", []) or []:
        term = getattr(t, "term", None)
        if isinstance(term, str) and term:
            tags.append(term)
    return tags


def parse_feed(raw: bytes) -> list[ParsedEntry]:
    assert_safe_xml(raw)
    parsed = feedparser.parse(raw, resolve_relative_uris=False, sanitize_html=True)
    entries: list[ParsedEntry] = []
    for e in parsed.entries:
        entries.append(
            ParsedEntry(
                guid=getattr(e, "id", None) or getattr(e, "guid", None),
                link=getattr(e, "link", None),
                title=getattr(e, "title", "") or "",
                summary=getattr(e, "summary", "") or getattr(e, "description", "") or "",
                published=getattr(e, "published", "") or getattr(e, "updated", "") or "",
                tags=_entry_tags(e),
            )
        )
    return entries
```

> Note: `feedparser.parse` accepts `resolve_relative_uris` / `sanitize_html` kwargs. If a `feedparser` version rejects a kwarg under mypy/runtime, drop the kwarg and keep the `assert_safe_xml` gate + downstream `clean_text` (Task 5) as the protection.

- [ ] **Step 4: Run, verify pass**

Run: `pytest tests/unit/collectors/test_feedparse.py -q`
Expected: PASS.

- [ ] **Step 5: Type/lint** — `mypy src/threat_intel/collectors/_feedparse.py && ruff check src/threat_intel/collectors/_feedparse.py`. (If `defusedxml` lacks type stubs under `--strict`, add `[[tool.mypy.overrides]]` with `module = "defusedxml.*"`, `ignore_missing_imports = true` to `pyproject.toml`.)

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/collectors/_feedparse.py tests/unit/collectors/test_feedparse.py pyproject.toml
git commit -m "feat(rss): hardened defusedxml gate + feedparser mapping"
```

---

## Task 4: SSRF guard for feed URLs

**Files:**
- Create: `src/threat_intel/collectors/_net.py`
- Test: `tests/unit/collectors/test_net.py`

**Interfaces:**
- Produces: `assert_fetchable_url(url: str, *, resolver=socket.getaddrinfo) -> None` — raises `CollectorError` unless `https` scheme and all resolved IPs are public. `resolver` injectable for tests.

- [ ] **Step 1: Write the failing tests**

`tests/unit/collectors/test_net.py`:

```python
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


def test_accepts_public_https():
    assert_fetchable_url("https://www.cisa.gov/x.xml", resolver=_resolver_to("23.1.2.3"))
```

- [ ] **Step 2: Run, verify fail** — `pytest tests/unit/collectors/test_net.py -q` → FAIL.

- [ ] **Step 3: Implement**

`src/threat_intel/collectors/_net.py`:

```python
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
```

> `CollectorError` already exists in `core/exceptions.py` (base for collector failures) and is mapped to a 502 by `main.py`.

- [ ] **Step 4: Run, verify pass** — `pytest tests/unit/collectors/test_net.py -q` → PASS.

- [ ] **Step 5: Type/lint** — `mypy src/threat_intel/collectors/_net.py && ruff check src/threat_intel/collectors/_net.py`.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/collectors/_net.py tests/unit/collectors/test_net.py
git commit -m "feat(rss): SSRF guard rejecting non-https and non-public hosts"
```

---

## Task 5: `RSSCollector` (config-driven, multi-feed)

**Files:**
- Create: `src/threat_intel/collectors/rss.py`
- Create: `tests/fixtures/rss_sample.xml`
- Test: `tests/unit/collectors/test_rss_collector.py`

**Interfaces:**
- Consumes: `_extract`, `_feedparse`, `_net`, `clean_text`, `BaseCollector`/`RawEvent`, `CollectedEvent`/`CollectedIndicator`.
- Produces: `RSSCollector(BaseCollector)` with
  `__init__(self, http_client, settings, *, source_name, url, threat_type, interval_minutes, indicator_confidence, default_tags)`; instance attrs `source_name`, `source_kind = SourceKind.rss`, `base_interval_minutes`. `fetch(since)` yields `RawEvent`; `to_event(raw)` returns a `CollectedEvent` with `enrichment_mode=True`.
- Constant: `MAX_FEED_BYTES = 5 * 1024 * 1024`.

- [ ] **Step 1: Create the fixture**

`tests/fixtures/rss_sample.xml`:

```xml
<?xml version="1.0"?>
<rss version="2.0"><channel><title>Sample</title>
<item>
  <title>Active exploitation of CVE-2021-44228</title>
  <link>https://example.test/post/1</link>
  <guid isPermaLink="false">post-1</guid>
  <description>Log4Shell exploited in the wild. C2 at hxxp://evil[.]example[.]net/x &lt;script&gt;alert(1)&lt;/script&gt;</description>
  <pubDate>Mon, 13 Dec 2021 00:00:00 GMT</pubDate>
  <category>advisory</category>
</item>
<item>
  <title>Threat actor report: new intrusion set</title>
  <link>https://example.test/post/2</link>
  <guid isPermaLink="false">post-2</guid>
  <description>No CVE here, just TTPs and an IP 8.8.8.8</description>
  <pubDate>Tue, 14 Dec 2021 00:00:00 GMT</pubDate>
</item>
</channel></rss>
```

- [ ] **Step 2: Write the failing tests**

`tests/unit/collectors/test_rss_collector.py`:

```python
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx

from threat_intel.collectors.rss import RSSCollector
from threat_intel.core.config import Settings
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent

SAMPLE = Path("tests/fixtures/rss_sample.xml").read_bytes()


def _collector(client: httpx.AsyncClient) -> RSSCollector:
    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    return RSSCollector(
        http_client=client,
        settings=settings,
        source_name="dfir_report",
        url="https://feeds.test/rss.xml",
        threat_type="report",
        interval_minutes=240,
        indicator_confidence=50,
        default_tags=["rss", "source:dfir_report"],
    )


def test_classvars_and_kind():
    c = _collector(httpx.AsyncClient())
    assert c.source_name == "dfir_report"
    assert c.source_kind is SourceKind.rss
    assert c.base_interval_minutes == 240


@pytest.mark.asyncio
async def test_fetch_yields_one_rawevent_per_item():
    async with httpx.AsyncClient() as client:
        with respx.mock(base_url="https://feeds.test") as mock:
            mock.get("/rss.xml").mock(return_value=httpx.Response(200, content=SAMPLE))
            c = _collector(client)
            # SSRF guard is bypassed because respx intercepts before socket;
            # patch the guard to a no-op for the unit test.
            c._assert_fetchable = lambda url: None  # type: ignore[attr-defined]
            events = [r async for r in c.fetch(datetime.now(UTC) - timedelta(days=1))]
    assert [r.external_id for r in events] == ["post-1", "post-2"]


def test_to_event_extracts_cve_and_sets_enrichment():
    c = _collector(httpx.AsyncClient())
    from threat_intel.collectors.base import RawEvent

    raw = RawEvent(
        external_id="post-1",
        payload={
            "guid": "post-1",
            "link": "https://example.test/post/1",
            "title": "Active exploitation of CVE-2021-44228",
            "summary": "Log4Shell exploited. C2 at hxxp://evil[.]example[.]net/x <script>alert(1)</script>",
            "published": "Mon, 13 Dec 2021 00:00:00 GMT",
            "tags": ["advisory"],
        },
        fetched_at=datetime.now(UTC),
    )
    ev = c.to_event(raw)
    assert isinstance(ev, CollectedEvent)
    assert ev.enrichment_mode is True
    assert ev.threat_type == "report"
    assert ev.indicator_confidence == 50
    assert ("cve", "CVE-2021-44228") in [(i.type, i.value) for i in ev.indicators]
    assert ("url", "http://evil.example.net/x") in [(i.type, i.value) for i in ev.indicators]
    # script content stripped by clean_text
    assert "<script>" not in (ev.summary or "")
    assert "alert(1)" not in (ev.summary or "")
    # unverified-ioc tag present because network IOCs were extracted
    assert "unverified-ioc" in ev.tags


def test_to_event_no_cve_still_valid():
    c = _collector(httpx.AsyncClient())
    from threat_intel.collectors.base import RawEvent

    raw = RawEvent(
        external_id="post-2",
        payload={
            "guid": "post-2",
            "link": "https://example.test/post/2",
            "title": "Threat actor report",
            "summary": "No CVE here, IP 8.8.8.8",
            "published": "Tue, 14 Dec 2021 00:00:00 GMT",
            "tags": [],
        },
        fetched_at=datetime.now(UTC),
    )
    ev = c.to_event(raw)
    assert ev.indicators  # at least the 8.8.8.8 ip
    assert all(i.type != "cve" for i in ev.indicators)
    assert ev.threat_type == "report"
```

- [ ] **Step 3: Run, verify fail** — `pytest tests/unit/collectors/test_rss_collector.py -q` → FAIL.

- [ ] **Step 4: Implement**

`src/threat_intel/collectors/rss.py`:

```python
"""Generic, config-driven RSS/Atom collector (M3b).

One instance per feed. Items that cite a CVE/GHSA become enrichment events
(enrichment_mode=True) that the ingestion layer fans out across matched
threats; items without a CVE become autonomous advisory/report threats.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import ClassVar, Literal

import httpx
import structlog

from threat_intel.collectors._extract import (
    extract_cves,
    extract_ghsa,
    extract_iocs,
    stable_external_id,
)
from threat_intel.collectors._feedparse import parse_feed
from threat_intel.collectors._net import assert_fetchable_url
from threat_intel.collectors._sanitize import clean_text
from threat_intel.collectors.base import BaseCollector, RawEvent
from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorHTTPError, CollectorParseError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator

logger = structlog.get_logger(__name__)

MAX_FEED_BYTES = 5 * 1024 * 1024
_ACCEPT = "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.1"
_SUMMARY_MAX = 2000


class RSSCollector(BaseCollector):
    source_kind: ClassVar[SourceKind] = SourceKind.rss

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        settings: Settings,
        *,
        source_name: str,
        url: str,
        threat_type: Literal["advisory", "report"],
        interval_minutes: int,
        indicator_confidence: int,
        default_tags: list[str],
    ) -> None:
        super().__init__(http_client, settings)
        self.source_name = source_name  # instance attr overriding ClassVar contract
        self.url = url
        self.threat_type = threat_type
        self.base_interval_minutes = interval_minutes
        self.indicator_confidence = indicator_confidence
        self.default_tags = list(default_tags)

    def _assert_fetchable(self, url: str) -> None:
        assert_fetchable_url(url)

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:
        self._assert_fetchable(self.url)
        total = 0
        chunks: list[bytes] = []
        async with self.http.stream(
            "GET",
            self.url,
            headers={"accept": _ACCEPT},
            timeout=30.0,
            follow_redirects=False,
        ) as resp:
            if resp.status_code >= 400:
                raise CollectorHTTPError(
                    status_code=resp.status_code, url=self.url, message="rss fetch failed"
                )
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > MAX_FEED_BYTES:
                    raise CollectorHTTPError(
                        status_code=0, url=self.url, message="feed exceeds size cap"
                    )
                chunks.append(chunk)
        raw = b"".join(chunks)
        for entry in parse_feed(raw):
            ext_id = stable_external_id(
                guid=entry.guid,
                link=entry.link,
                source_name=self.source_name,
                title=entry.title,
                published=entry.published,
            )
            yield RawEvent(
                external_id=ext_id,
                payload={
                    "guid": entry.guid,
                    "link": entry.link,
                    "title": entry.title,
                    "summary": entry.summary,
                    "published": entry.published,
                    "tags": entry.tags,
                },
                fetched_at=datetime.now(UTC),
            )

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        try:
            p = raw.payload
            title = clean_text(p.get("title")) or raw.external_id
            summary = clean_text(p.get("summary"))[:_SUMMARY_MAX]
            corpus = f"{p.get('title') or ''} {p.get('summary') or ''}"

            indicators: list[CollectedIndicator] = []
            for cve in extract_cves(corpus):
                indicators.append(CollectedIndicator(type="cve", value=cve))
            for ghsa in extract_ghsa(corpus):
                indicators.append(CollectedIndicator(type="ghsa", value=ghsa))
            iocs = extract_iocs(summary)
            for kind, value in iocs:
                indicators.append(CollectedIndicator(type=kind, value=value[:512]))  # type: ignore[arg-type]

            tags = list(self.default_tags)
            lower = corpus.lower()
            if "exploited in the wild" in lower or "actively exploited" in lower:
                tags.append("actively-exploited")
            if "ransomware" in lower:
                tags.append("ransomware")
            if any(k in ("ip", "domain", "url", "md5", "sha1", "sha256") for k, _ in iocs):
                tags.append("unverified-ioc")

            published_at = self._parse_dt(p.get("published")) or raw.fetched_at
            link = p.get("link")
            return CollectedEvent(
                source_name=self.source_name,
                external_id=raw.external_id,
                title=title,
                summary=summary or None,
                severity=None,
                cvss_score=None,
                tags=tags,
                indicators=indicators,
                published_at=published_at,
                last_modified_at=raw.fetched_at,
                raw_data={
                    "title": title,
                    "summary": summary,
                    "references": [link] if isinstance(link, str) else [],
                    "cwe_ids": [],
                },
                enrichment_mode=True,
                threat_type=self.threat_type,
                indicator_confidence=self.indicator_confidence,
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"RSS malformed for {raw.external_id}: {e}") from e

    @staticmethod
    def _parse_dt(value: object) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            dt = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            try:
                dt = datetime.fromisoformat(value)
            except ValueError:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
```

> `CollectedEvent` fields `enrichment_mode`, `threat_type`, `indicator_confidence` are added in **Task 6** — implement Task 6 before this compiles, OR add the three fields first then return here. Sequence-wise, Task 6 is small; do Step 4 of Task 6 (the schema fields) before running this task's tests if needed. The plan keeps them separate for review clarity; the implementer may interleave the 3-line schema add.

- [ ] **Step 5: Run, verify pass** — `pytest tests/unit/collectors/test_rss_collector.py -q` → PASS (after Task 6 schema fields exist).

- [ ] **Step 6: Type/lint** — `mypy src/threat_intel/collectors/rss.py && ruff check src/threat_intel/collectors/rss.py`.

- [ ] **Step 7: Commit**

```bash
git add src/threat_intel/collectors/rss.py tests/unit/collectors/test_rss_collector.py tests/fixtures/rss_sample.xml
git commit -m "feat(rss): generic config-driven RSSCollector with CVE/IOC extraction"
```

---

## Task 6: `CollectedEvent` enrichment fields

**Files:**
- Modify: `src/threat_intel/schemas/ingest.py`
- Test: `tests/unit/test_schemas.py`

**Interfaces:**
- Produces on `CollectedEvent`: `enrichment_mode: bool = False`, `threat_type: Literal["cve","advisory","report"] | None = None`, `indicator_confidence: int = 100`.

- [ ] **Step 1: Write failing test** — append to `tests/unit/test_schemas.py`:

```python
def test_collected_event_enrichment_defaults():
    from datetime import UTC, datetime
    from threat_intel.schemas.ingest import CollectedEvent

    now = datetime.now(UTC)
    ev = CollectedEvent(source_name="s", external_id="x", title="t",
                        published_at=now, last_modified_at=now)
    assert ev.enrichment_mode is False
    assert ev.threat_type is None
    assert ev.indicator_confidence == 100


def test_collected_event_enrichment_set():
    from datetime import UTC, datetime
    from threat_intel.schemas.ingest import CollectedEvent

    now = datetime.now(UTC)
    ev = CollectedEvent(source_name="s", external_id="x", title="t",
                        published_at=now, last_modified_at=now,
                        enrichment_mode=True, threat_type="report",
                        indicator_confidence=50)
    assert ev.enrichment_mode is True
    assert ev.threat_type == "report"
    assert ev.indicator_confidence == 50
```

- [ ] **Step 2: Run, verify fail** — `pytest tests/unit/test_schemas.py -k enrichment -q` → FAIL.

- [ ] **Step 3: Implement** — in `src/threat_intel/schemas/ingest.py`, append to `CollectedEvent` (after `raw_data`):

```python
    # --- RSS ingestion (M3b) ---
    enrichment_mode: bool = False
    threat_type: Literal["cve", "advisory", "report"] | None = None
    indicator_confidence: int = 100
```

(`Literal` is already imported at the top of the file.)

- [ ] **Step 4: Run, verify pass** — `pytest tests/unit/test_schemas.py -k enrichment -q` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/schemas/ingest.py tests/unit/test_schemas.py
git commit -m "feat(rss): add enrichment_mode/threat_type/indicator_confidence to CollectedEvent"
```

---

## Task 7: Fix `_create_threat` type derivation + parametrize confidence

**Files:**
- Modify: `src/threat_intel/services/ingest.py` (`_create_threat` lines 132-155; `_upsert_indicators` line 224)
- Test: `tests/unit/services/test_ingest_rss.py`

**Interfaces:**
- Consumes: `CollectedEvent.threat_type`, `CollectedEvent.indicator_confidence`.
- Produces: `_create_threat` honors explicit `threat_type`; default for no-CVE is `"advisory"` (fixes the line-138 bug). `_upsert_indicators` writes `event.indicator_confidence`.

- [ ] **Step 1: Run the canary first** — `pytest tests/integration/test_dedup_cross_source.py -q` → PASS (baseline).

- [ ] **Step 2: Write failing tests**

`tests/unit/services/test_ingest_rss.py`:

```python
from datetime import UTC, datetime

import pytest_asyncio
from sqlalchemy import select

from threat_intel.core.db import build_engine
from threat_intel.core.db import session_factory as make_factory
from threat_intel.models.base import Base, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator
from threat_intel.services.ingest import IngestService


@pytest_asyncio.fixture
async def factory():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = make_factory(engine)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture
async def rss_source(factory):
    async with factory() as s:
        src = Source(name="dfir_report", kind=SourceKind.rss, url="https://x", enabled=True)
        s.add(src)
        await s.commit()
        await s.refresh(src)
    return src


def _rss_event(ext_id, *, indicators=None, threat_type="report", confidence=50, tags=None):
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name="dfir_report",
        external_id=ext_id,
        title=f"t-{ext_id}",
        summary="s",
        tags=tags or [],
        indicators=[CollectedIndicator(type=t, value=v) for t, v in (indicators or [])],
        published_at=now,
        last_modified_at=now,
        raw_data={"references": [], "cwe_ids": []},
        enrichment_mode=True,
        threat_type=threat_type,
        indicator_confidence=confidence,
    )


async def test_create_threat_uses_explicit_report_type(factory, rss_source):
    svc = IngestService(factory)
    out, tid = await svc.process(_rss_event("post-1"), rss_source.id)
    assert out == "created"
    async with factory() as s:
        t = (await s.execute(select(Threat).where(Threat.id == tid))).scalar_one()
        assert t.threat_type == "report"


async def test_rss_ioc_confidence_is_degraded(factory, rss_source):
    svc = IngestService(factory)
    _, tid = await svc.process(
        _rss_event("post-2", indicators=[("ip", "8.8.8.8")], confidence=50), rss_source.id
    )
    async with factory() as s:
        ind = (
            await s.execute(select(ThreatIndicator).where(ThreatIndicator.threat_id == tid))
        ).scalar_one()
        assert ind.confidence == 50
```

- [ ] **Step 3: Run, verify fail** — `pytest tests/unit/services/test_ingest_rss.py -q` → FAIL (current code forces `threat_type="cve"`; confidence hard-coded 100; and `process` will not yet handle enrichment — Task 8 adds it. For THIS task, the two tests above also depend on Task 8's `process` split. To keep Task 7 independently testable, temporarily assert only via `_create_threat`/`_upsert_indicators` unit calls — see note).

> **Right-sizing note:** Tasks 7 and 8 are tightly coupled (the new `threat_type`/confidence are only exercised through the new enrichment path). Implement Task 7's code changes, then Task 8's `process` split, and run both tasks' tests together at the end of Task 8. Commit Task 7 and Task 8 separately (code is reviewable independently) but green-gate at Task 8. If you prefer strict per-task green, write Task 7 micro-tests that call `svc._create_threat` / `svc._upsert_indicators` directly inside a session.

- [ ] **Step 4: Implement `_create_threat`** — replace lines 132-138 logic:

```python
    async def _create_threat(self, session: AsyncSession, event: CollectedEvent) -> uuid.UUID:
        if event.threat_type is not None:
            threat_type = event.threat_type
        elif any(i.type == "cve" for i in event.indicators):
            threat_type = "cve"
        elif any(i.type == "ghsa" for i in event.indicators):
            threat_type = "advisory"
        else:
            threat_type = "advisory"
        # ... rest of method unchanged (Threat(...) construction) ...
```

- [ ] **Step 5: Implement `_upsert_indicators` confidence** — change the dict value `"confidence": 100,` to:

```python
                    "confidence": event.indicator_confidence,
```

- [ ] **Step 6: Commit** (green-gate deferred to Task 8)

```bash
git add src/threat_intel/services/ingest.py tests/unit/services/test_ingest_rss.py
git commit -m "fix(ingest): derive threat_type from event, parametrize indicator confidence"
```

---

## Task 8: Split `process()` into canonical + enrichment regimes

**Files:**
- Modify: `src/threat_intel/services/ingest.py` (`process` lines 76-130; add `_process_canonical`, `_process_enrichment`, `_get_or_create_autonomous`)
- Test: `tests/unit/services/test_ingest_rss.py` (extend), `tests/integration/test_rss_enrichment.py` (new)

**Interfaces:**
- Consumes: `CollectedEvent.enrichment_mode`.
- Produces: `process` dispatches on `enrichment_mode`. `_process_enrichment` fans CVE matches across all matched threats (no merge, no autonomous threat) and is idempotent on `(source_id, external_id)` for no-CVE items.

- [ ] **Step 1: Canary** — `pytest tests/integration/test_dedup_cross_source.py -q` → PASS.

- [ ] **Step 2: Write failing integration tests**

`tests/integration/test_rss_enrichment.py`:

```python
from datetime import UTC, datetime

import pytest_asyncio
from sqlalchemy import select

from threat_intel.core.db import build_engine
from threat_intel.core.db import session_factory as make_factory
from threat_intel.models.base import Base, Severity, SourceKind
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator
from threat_intel.services.ingest import IngestService


@pytest_asyncio.fixture
async def factory():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = make_factory(engine)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture
async def sources(factory):
    async with factory() as s:
        nvd = Source(name="nvd", kind=SourceKind.cve_feed, url="https://n", enabled=True)
        rss = Source(name="dfir_report", kind=SourceKind.rss, url="https://r", enabled=True)
        s.add_all([nvd, rss])
        await s.commit()
        await s.refresh(nvd)
        await s.refresh(rss)
    return {"nvd": nvd, "dfir_report": rss}


def _nvd(cve):
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name="nvd", external_id=cve, title=f"t-{cve}", severity=Severity.high,
        cvss_score=9.0, indicators=[CollectedIndicator(type="cve", value=cve)],
        published_at=now, last_modified_at=now,
        raw_data={"title": f"t-{cve}", "severity": "high", "cvss_score": 9.0, "cwe_ids": []},
    )


def _rss(ext_id, cves, *, tt="report"):
    now = datetime.now(UTC)
    return CollectedEvent(
        source_name="dfir_report", external_id=ext_id, title="rss", summary="s",
        tags=["rss"], indicators=[CollectedIndicator(type="cve", value=c) for c in cves],
        published_at=now, last_modified_at=now, raw_data={"references": [], "cwe_ids": []},
        enrichment_mode=True, threat_type=tt, indicator_confidence=50,
    )


async def test_rss_single_cve_enriches_existing(factory, sources):
    svc = IngestService(factory)
    _, tid = await svc.process(_nvd("CVE-2021-44228"), sources["nvd"].id)
    out, etid = await svc.process(_rss("post-1", ["CVE-2021-44228"]), sources["dfir_report"].id)
    assert out == "updated"
    assert etid == tid
    async with factory() as s:
        ts = (await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid))).scalars().all()
        assert {t.source_id for t in ts} == {sources["nvd"].id, sources["dfir_report"].id}
        assert "rss" in (await s.execute(select(Threat).where(Threat.id == tid))).scalar_one().tags


async def test_rss_multi_cve_fans_out_no_merge(factory, sources):
    svc = IngestService(factory)
    _, t1 = await svc.process(_nvd("CVE-2024-0001"), sources["nvd"].id)
    _, t2 = await svc.process(_nvd("CVE-2024-0002"), sources["nvd"].id)
    assert t1 != t2
    await svc.process(_rss("multi", ["CVE-2024-0001", "CVE-2024-0002"]), sources["dfir_report"].id)
    async with factory() as s:
        threats = (await s.execute(select(Threat))).scalars().all()
        # still exactly 2 threats — NOT merged into 1
        assert len([t for t in threats if t.threat_type == "cve"]) == 2
        for tid in (t1, t2):
            ts = (await s.execute(select(ThreatSource).where(ThreatSource.threat_id == tid))).scalars().all()
            assert sources["dfir_report"].id in {t.source_id for t in ts}


async def test_rss_no_cve_idempotent(factory, sources):
    svc = IngestService(factory)
    o1, tid1 = await svc.process(_rss("orphan-1", []), sources["dfir_report"].id)
    o2, tid2 = await svc.process(_rss("orphan-1", []), sources["dfir_report"].id)
    assert o1 == "created" and o2 == "updated"
    assert tid1 == tid2
    async with factory() as s:
        threats = (await s.execute(select(Threat))).scalars().all()
        assert len(threats) == 1
        assert threats[0].threat_type == "report"
```

- [ ] **Step 3: Run, verify fail** — `pytest tests/integration/test_rss_enrichment.py -q` → FAIL (current `process` merges multi-CVE; no idempotency).

- [ ] **Step 4: Implement** — in `src/threat_intel/services/ingest.py`, replace `process` (lines 76-130) with the dispatcher + two regimes, and add `_get_or_create_autonomous` after `_create_threat`:

```python
    async def process(
        self, event: CollectedEvent, source_id: int
    ) -> tuple[Literal["created", "updated"], uuid.UUID]:
        if event.enrichment_mode:
            return await self._process_enrichment(event, source_id)
        return await self._process_canonical(event, source_id)

    async def _process_canonical(
        self, event: CollectedEvent, source_id: int
    ) -> tuple[Literal["created", "updated"], uuid.UUID]:
        async with self._sf() as session:
            matches = await _lookup_threat_ids_by_indicators(session, event.indicators)
            created_threat = False
            if len(matches) == 0:
                threat_id = await self._create_threat(session, event)
                created_threat = True
            elif len(matches) > 1:
                threat_id = await self._pick_oldest(session, matches)
                others = [m for m in matches if m != threat_id]
                logger.warning(
                    "merge_candidate",
                    winner_threat_id=str(threat_id),
                    other_threat_ids=[str(o) for o in others],
                    triggered_by=event.external_id,
                    source=event.source_name,
                )
                event.raw_data = {**event.raw_data, "cross_references": [str(o) for o in others]}
            else:
                threat_id = matches[0]
            await self._upsert_threat_source(session, threat_id, source_id, event)
            await self._upsert_indicators(session, threat_id, event)
            await session.flush()
            await recompute_canonical(session, threat_id)
            await session.commit()
            outcome: Literal["created", "updated"] = "created" if created_threat else "updated"
            return outcome, threat_id

    async def _process_enrichment(
        self, event: CollectedEvent, source_id: int
    ) -> tuple[Literal["created", "updated"], uuid.UUID]:
        async with self._sf() as session:
            matches = await _lookup_threat_ids_by_indicators(session, event.indicators)
            if matches:
                for threat_id in matches:
                    await self._upsert_threat_source(session, threat_id, source_id, event)
                    await self._upsert_indicators(session, threat_id, event)
                await session.flush()
                for threat_id in matches:
                    await recompute_canonical(session, threat_id)
                await session.commit()
                return "updated", matches[0]

            threat_id, created = await self._get_or_create_autonomous(session, event, source_id)
            await self._upsert_threat_source(session, threat_id, source_id, event)
            await self._upsert_indicators(session, threat_id, event)
            await session.flush()
            await recompute_canonical(session, threat_id)
            await session.commit()
            return ("created" if created else "updated"), threat_id

    async def _get_or_create_autonomous(
        self, session: AsyncSession, event: CollectedEvent, source_id: int
    ) -> tuple[uuid.UUID, bool]:
        existing = (
            await session.execute(
                select(ThreatSource.threat_id).where(
                    ThreatSource.source_id == source_id,
                    ThreatSource.external_id == event.external_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False
        threat_id = await self._create_threat(session, event)
        return threat_id, True
```

- [ ] **Step 5: Run new tests + Task 7 tests + canary**

Run: `pytest tests/integration/test_rss_enrichment.py tests/unit/services/test_ingest_rss.py tests/integration/test_dedup_cross_source.py -q`
Expected: ALL PASS (Log4Shell canary still green — its events have `enrichment_mode=False`).

- [ ] **Step 6: Full suite + type** — `pytest -q && mypy src/threat_intel/services/ingest.py`.

- [ ] **Step 7: Commit**

```bash
git add src/threat_intel/services/ingest.py tests/integration/test_rss_enrichment.py tests/unit/services/test_ingest_rss.py
git commit -m "feat(ingest): RSS enrichment regime — fan-out multi-CVE, idempotent no-CVE"
```

---

## Task 9: `recompute_canonical` excludes RSS from canonical CVSS/severity

**Files:**
- Modify: `src/threat_intel/services/ingest.py` (`recompute_canonical` lines 232-333; import line 11)
- Test: `tests/integration/test_rss_enrichment.py` (extend)

**Interfaces:**
- Produces: RSS sources never set canonical `cvss_score`/`severity`; may provide `title`/`summary` only as last-resort fallback; tags always unioned.

- [ ] **Step 1: Canary** — `pytest tests/integration/test_dedup_cross_source.py -q` → PASS.

- [ ] **Step 2: Write failing test** — append to `tests/integration/test_rss_enrichment.py`:

```python
async def test_rss_never_overrides_canonical_cvss(factory, sources):
    svc = IngestService(factory)
    _, tid = await svc.process(_nvd("CVE-2025-1234"), sources["nvd"].id)

    now = datetime.now(UTC)
    rss_with_bogus_cvss = CollectedEvent(
        source_name="dfir_report", external_id="p9", title="rss",
        indicators=[CollectedIndicator(type="cve", value="CVE-2025-1234")],
        published_at=now, last_modified_at=now,
        # a malicious/low-quality feed claiming cvss 1.0 in raw_data
        raw_data={"title": "rss", "summary": "x", "cvss_score": 1.0, "severity": "low", "cwe_ids": []},
        enrichment_mode=True, threat_type="report", indicator_confidence=50,
    )
    await svc.process(rss_with_bogus_cvss, sources["dfir_report"].id)
    async with factory() as s:
        t = (await s.execute(select(Threat).where(Threat.id == tid))).scalar_one()
        assert t.cvss_score == 9.0  # NVD value preserved, RSS ignored
```

- [ ] **Step 3: Run, verify fail** — `pytest tests/integration/test_rss_enrichment.py -k canonical_cvss -q` → FAIL (RSS currently not in `_PRIORITY_ORDER`, so its cvss is already ignored — BUT confirm; if it already passes, this test is a guard. The real change is making the exclusion explicit and supporting the RSS summary fallback). 

> If Step 3 unexpectedly passes, keep the test as a regression guard and proceed to make the exclusion explicit so future `_PRIORITY_ORDER` edits cannot leak RSS CVSS.

- [ ] **Step 4: Implement** — import `SourceKind` (line 11):

```python
from threat_intel.models.base import IndicatorType, Severity, SourceKind
```

After the `by_name` build loop (after line 250), insert:

```python
    rss_names = {n for n, ts in by_name.items() if ts.source.kind == SourceKind.rss}
    extra_names = [n for n in by_name if n not in _PRIORITY_ORDER]
    effective_order = list(_PRIORITY_ORDER) + sorted(extra_names)
    canonical_order = [n for n in effective_order if n not in rss_names]
```

In `_first_str`, change `for name in _PRIORITY_ORDER:` → `for name in effective_order:`.
In the CVSS loop (lines 268-279), change `for pname in _PRIORITY_ORDER:` → `for pname in canonical_order:`.
In the severity loop (lines 282-292), change `for pname in _PRIORITY_ORDER:` → `for pname in canonical_order:`.

- [ ] **Step 5: Run tests + canary** — `pytest tests/integration/test_rss_enrichment.py tests/integration/test_dedup_cross_source.py -q` → PASS.

- [ ] **Step 6: Full suite + type** — `pytest -q && mypy src/threat_intel/services/ingest.py`.

- [ ] **Step 7: Commit**

```bash
git add src/threat_intel/services/ingest.py tests/integration/test_rss_enrichment.py
git commit -m "feat(ingest): exclude RSS sources from canonical cvss/severity, keep tag/summary union"
```

> **GATING CHECKPOINT — validate with the user before Task 10.** The full ingestion layer is now complete and verified; the next tasks wire real feeds and add config.

---

## Task 10: Feed catalog schema + `RSSFeedLoader`

**Files:**
- Create: `feeds/feeds.yaml`
- Create: `src/threat_intel/schemas/rss_feed.py`
- Create: `src/threat_intel/services/rss_feed_loader.py`
- Test: `tests/unit/services/test_rss_feed_loader.py`

**Interfaces:**
- Produces:
  - `RSSFeedSchema` (pydantic, `extra="forbid"`): `source_name: str`, `url: str`, `threat_type: Literal["advisory","report"]`, `interval_minutes: int`, `indicator_confidence: int`, `default_tags: list[str] = []`.
  - `RSSFeedLoader(http_client, settings, feeds_root)` with `build_collectors() -> list[RSSCollector]` (parses `feeds.yaml`, validates, instantiates one `RSSCollector` per entry; logs+skips invalid entries).

- [ ] **Step 1: Create the catalog**

`feeds/feeds.yaml`:

```yaml
# RSS/Atom threat-intel feeds (M3b MVP). Verify each URL with a real GET
# before enabling in production. confidence: gov=80, vendor=70, research=50.
feeds:
  - source_name: cisa_advisories
    url: https://www.cisa.gov/cybersecurity-advisories/all.xml
    threat_type: advisory
    interval_minutes: 120
    indicator_confidence: 80
    default_tags: [rss, "source:cisa_advisories", "category:advisory"]
  - source_name: cisa_ics
    url: https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml
    threat_type: advisory
    interval_minutes: 120
    indicator_confidence: 80
    default_tags: [rss, "source:cisa_ics", "category:ics"]
  - source_name: cisco_psirt
    url: https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml
    threat_type: advisory
    interval_minutes: 240
    indicator_confidence: 70
    default_tags: [rss, "source:cisco_psirt", "category:vendor"]
  - source_name: dfir_report
    url: https://thedfirreport.com/feed/
    threat_type: report
    interval_minutes: 240
    indicator_confidence: 50
    default_tags: [rss, "source:dfir_report", "category:research"]
```

- [ ] **Step 2: Write failing tests**

`tests/unit/services/test_rss_feed_loader.py`:

```python
from pathlib import Path

import httpx
import pytest

from threat_intel.core.config import Settings
from threat_intel.services.rss_feed_loader import RSSFeedLoader


def _settings() -> Settings:
    return Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_loader_builds_one_collector_per_feed(tmp_path: Path):
    (tmp_path / "feeds.yaml").write_text(
        """
feeds:
  - source_name: cisa_advisories
    url: https://www.cisa.gov/a.xml
    threat_type: advisory
    interval_minutes: 120
    indicator_confidence: 80
  - source_name: dfir_report
    url: https://thedfirreport.com/feed/
    threat_type: report
    interval_minutes: 240
    indicator_confidence: 50
""",
        encoding="utf-8",
    )
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, _settings(), feeds_root=tmp_path)
        collectors = loader.build_collectors()
    names = {c.source_name for c in collectors}
    assert names == {"cisa_advisories", "dfir_report"}
    dfir = next(c for c in collectors if c.source_name == "dfir_report")
    assert dfir.threat_type == "report"
    assert dfir.base_interval_minutes == 240
    assert dfir.indicator_confidence == 50


@pytest.mark.asyncio
async def test_loader_skips_invalid_entry(tmp_path: Path):
    (tmp_path / "feeds.yaml").write_text(
        """
feeds:
  - source_name: good
    url: https://x/a.xml
    threat_type: advisory
    interval_minutes: 120
    indicator_confidence: 80
  - source_name: bad
    url: https://y/b.xml
    threat_type: not_a_type
    interval_minutes: 120
    indicator_confidence: 80
""",
        encoding="utf-8",
    )
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, _settings(), feeds_root=tmp_path)
        collectors = loader.build_collectors()
    assert {c.source_name for c in collectors} == {"good"}


@pytest.mark.asyncio
async def test_loader_missing_file_returns_empty(tmp_path: Path):
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, _settings(), feeds_root=tmp_path)
        assert loader.build_collectors() == []
```

- [ ] **Step 3: Run, verify fail** — `pytest tests/unit/services/test_rss_feed_loader.py -q` → FAIL.

- [ ] **Step 4: Implement schema**

`src/threat_intel/schemas/rss_feed.py`:

```python
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RSSFeedSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_name: str = Field(min_length=1, max_length=64)
    url: str
    threat_type: Literal["advisory", "report"]
    interval_minutes: int = Field(ge=15, le=1440)
    indicator_confidence: int = Field(ge=0, le=100)
    default_tags: list[str] = []
```

- [ ] **Step 5: Implement loader**

`src/threat_intel/services/rss_feed_loader.py`:

```python
"""RSSFeedLoader — read feeds/feeds.yaml and build one RSSCollector per feed."""

from pathlib import Path

import httpx
import structlog
import yaml
from pydantic import ValidationError

from threat_intel.collectors.rss import RSSCollector
from threat_intel.core.config import Settings
from threat_intel.schemas.rss_feed import RSSFeedSchema

logger = structlog.get_logger(__name__)


class RSSFeedLoader:
    FILENAME = "feeds.yaml"

    def __init__(
        self, http_client: httpx.AsyncClient, settings: Settings, feeds_root: Path
    ) -> None:
        self._http = http_client
        self._settings = settings
        self._root = feeds_root

    def build_collectors(self) -> list[RSSCollector]:
        path = self._root / self.FILENAME
        if not path.is_file():
            logger.info("rss_feeds_file_missing", path=str(path))
            return []
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError) as e:
            logger.warning("rss_feeds_yaml_invalid", path=str(path), error=str(e))
            return []
        entries = raw.get("feeds") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            logger.warning("rss_feeds_no_feeds_list", path=str(path))
            return []

        collectors: list[RSSCollector] = []
        seen: set[str] = set()
        for item in entries:
            try:
                feed = RSSFeedSchema.model_validate(item)
            except ValidationError as e:
                logger.warning("rss_feed_invalid", entry=item, errors=e.errors())
                continue
            if feed.source_name in seen:
                logger.warning("rss_feed_duplicate", source_name=feed.source_name)
                continue
            seen.add(feed.source_name)
            collectors.append(
                RSSCollector(
                    http_client=self._http,
                    settings=self._settings,
                    source_name=feed.source_name,
                    url=feed.url,
                    threat_type=feed.threat_type,
                    interval_minutes=feed.interval_minutes,
                    indicator_confidence=feed.indicator_confidence,
                    default_tags=feed.default_tags,
                )
            )
        logger.info("rss_feeds_loaded", count=len(collectors))
        return collectors
```

- [ ] **Step 6: Run, verify pass** — `pytest tests/unit/services/test_rss_feed_loader.py -q` → PASS.

- [ ] **Step 7: Type/lint** — `mypy src/threat_intel/services/rss_feed_loader.py src/threat_intel/schemas/rss_feed.py && ruff check src/threat_intel/services/rss_feed_loader.py`.

- [ ] **Step 8: Commit**

```bash
git add feeds/feeds.yaml src/threat_intel/schemas/rss_feed.py src/threat_intel/services/rss_feed_loader.py tests/unit/services/test_rss_feed_loader.py
git commit -m "feat(rss): feeds.yaml catalog + RSSFeedLoader"
```

---

## Task 11: Wire RSS collectors into lifespan + CLI `rss` command

**Files:**
- Modify: `src/threat_intel/main.py` (lifespan, lines 117-143)
- Modify: `src/threat_intel/cli/collect_once.py`
- Test: `tests/unit/test_main_source_sync.py` (extend) or new `tests/unit/test_main_rss_wiring.py`

**Interfaces:**
- Consumes: `RSSFeedLoader`, `Settings.feeds_path`.
- Produces: RSS collectors appended to `collectors`; a `Source` row (`SourceKind.rss`) ensured per feed; CLI `threat-intel rss <source_name>` runs one cycle.

- [ ] **Step 1: Write failing test**

`tests/unit/test_main_rss_wiring.py`:

```python
from pathlib import Path

import pytest

from threat_intel.core.config import Settings
from threat_intel.services.rss_feed_loader import RSSFeedLoader


@pytest.mark.asyncio
async def test_feeds_yaml_in_repo_builds_four_collectors():
    import httpx

    settings = Settings(database_url="sqlite+aiosqlite:///:memory:", feeds_path=Path("feeds"))  # type: ignore[call-arg]
    async with httpx.AsyncClient() as client:
        loader = RSSFeedLoader(client, settings, feeds_root=settings.feeds_path)
        collectors = loader.build_collectors()
    assert {c.source_name for c in collectors} == {
        "cisa_advisories", "cisa_ics", "cisco_psirt", "dfir_report",
    }
```

- [ ] **Step 2: Run, verify fail/pass** — `pytest tests/unit/test_main_rss_wiring.py -q`. (Passes once `feeds/feeds.yaml` from Task 10 exists — this is the integration guard that the shipped catalog is valid.)

- [ ] **Step 3: Wire lifespan** — in `src/threat_intel/main.py`, add import near the collectors imports:

```python
from threat_intel.services.rss_feed_loader import RSSFeedLoader
```

In `lifespan`, after `ghsa = GitHubAdvisoriesCollector(...)` (line 124) and before `collectors = [nvd, kev, ghsa]`:

```python
        rss_collectors = RSSFeedLoader(http, settings, settings.feeds_path).build_collectors()
        collectors = [nvd, kev, ghsa, *rss_collectors]
```

After the existing `_ensure_source_row(...)` calls (after line 140), add:

```python
        for rc in rss_collectors:
            await _ensure_source_row(factory, rc.source_name, SourceKind.rss, rc.url)
```

- [ ] **Step 4: Add CLI command** — in `src/threat_intel/cli/collect_once.py`, add:

```python
@app.command()
def rss(source_name: str) -> None:
    """Run a single RSS feed collection cycle synchronously."""
    settings = get_settings()
    configure_logging(env=settings.app_env, level=settings.log_level)

    async def _run() -> None:
        from threat_intel.services.rss_feed_loader import RSSFeedLoader

        engine = build_engine(settings.database_url)
        factory = session_factory(engine)
        async with httpx.AsyncClient(timeout=30.0) as http:
            collectors = RSSFeedLoader(http, settings, settings.feeds_path).build_collectors()
            match = next((c for c in collectors if c.source_name == source_name), None)
            if match is None:
                typer.echo(f"no RSS feed named {source_name!r} in feeds.yaml")
                raise typer.Exit(code=1)
            async with factory() as s:
                existing = (
                    await s.execute(select(Source).where(Source.name == source_name))
                ).scalar_one_or_none()
                if existing is None:
                    s.add(Source(name=source_name, kind=SourceKind.rss, url=match.url, enabled=True))
                    await s.commit()
            service = IngestionService(session_factory=factory, collectors=[match])
            result = await service.run(source_name)
            typer.echo(f"inserted={result.inserted} updated={result.updated}")
        await engine.dispose()

    asyncio.run(_run())
```

- [ ] **Step 5: Run tests + full suite** — `pytest tests/unit/test_main_rss_wiring.py tests/unit/test_cli.py -q && pytest -q`.

- [ ] **Step 6: Type/lint** — `mypy src/threat_intel/main.py src/threat_intel/cli/collect_once.py && ruff check src/threat_intel/main.py src/threat_intel/cli/collect_once.py`.

- [ ] **Step 7: Commit**

```bash
git add src/threat_intel/main.py src/threat_intel/cli/collect_once.py tests/unit/test_main_rss_wiring.py
git commit -m "feat(rss): wire RSS feeds into lifespan + add CLI rss command"
```

---

## Task 12: Docs + SBOM + graph refresh

**Files:**
- Modify: `docs/COLLECTORS.md` (create if absent), `README.md`
- Modify: `sbom.cdx.json` (regenerate)

- [ ] **Step 1: Document the RSS collector** — in `docs/COLLECTORS.md`, add a section: the 4 feeds, the two-path mechanism (CVE → enrichment; no-CVE → advisory/report threat), the `enrichment_mode` flag, confidence tiers, the `unverified-ioc` quarantine, and the rule "RSS never sets canonical CVSS/severity". State the persona decision: advisory/report threats are excluded from sector feeds by default (read-side filter — Plan 2).

- [ ] **Step 2: README** — add an RSS bullet to the sources/roadmap section.

- [ ] **Step 3: Regenerate SBOM** — run the repo's SBOM command (the one that produced `sbom.cdx.json`) so `feedparser`/`defusedxml` appear; run Trivy/gitleaks if part of the local pipeline.

- [ ] **Step 4: Refresh the knowledge graph** — `graphify update .` (CLAUDE.md rule).

- [ ] **Step 5: Full green + lint + type gate**

Run: `pytest -q && ruff check . && mypy src`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add docs/COLLECTORS.md README.md sbom.cdx.json graphify-out
git commit -m "docs(rss): document RSS feeds, refresh SBOM and knowledge graph"
```

---

## Self-review (against the validated decisions)

- **4 feeds (CISA, CISA ICS, Cisco PSIRT, DFIR):** Task 10 catalog + Task 11 wiring + Task 11 guard test. ✓
- **CVE-bearing → enrichment of existing threat:** Task 8 `_process_enrichment` fan-out + `test_rss_single_cve_enriches_existing`. ✓
- **Multi-CVE not merged (anti-over-merge):** Task 8 `test_rss_multi_cve_fans_out_no_merge`. ✓
- **No-CVE idempotent autonomous threat:** Task 8 `_get_or_create_autonomous` + `test_rss_no_cve_idempotent`. ✓
- **threat_type advisory/report (bug fix):** Task 7. ✓
- **Confidence tiers + IOC quarantine:** Task 7 confidence + Task 5 `unverified-ioc` tag. ✓
- **RSS never sets canonical CVSS/severity:** Task 9 + `test_rss_never_overrides_canonical_cvss`. ✓
- **Security: XXE/SSRF/size/sanitize:** Tasks 3, 4, 5. ✓
- **No migration:** confirmed in Global Constraints; Task list touches no model/Alembic file. ✓
- **Log4Shell non-regression:** canary run gating Tasks 7-9. ✓
- **Persona default-exclusion:** intentionally deferred → Plan 2 (below), documented in Task 12.

---

## Follow-up: Plan 2 (separate plan, not in scope here)

**Read-side exposure & persona default** — to be written as `docs/superpowers/plans/<date>-rss-exposure-plan.md`:
- Exclude `threat_type in ("advisory","report")` from sector feeds / threat lists **by default**; add `?include_advisories=true` to opt in (honors the validated "défaut prudent" persona choice).
- Surface `SourceKind=rss` and per-source freshness (last item, items/24h) in the sources endpoint (`SourceHealth`/`CollectorRun`).
- Security read-side test: inject `<script>`/`]]>` into a threat and assert the outgoing `/api/v1/sectors/{id}/feed.rss` is inert.
- Optional hardening PR: `UNIQUE(source_id, external_id)` on `ThreatSource` (needs an Alembic migration + dup check).
