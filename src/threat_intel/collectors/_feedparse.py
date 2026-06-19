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
        DefusedET.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as e:
        raise CollectorParseError(f"unsafe XML rejected: {type(e).__name__}") from e
    except Exception:  # noqa: BLE001 - malformed XML is fine here; feedparser is tolerant
        return


def _entry_tags(entry: Any) -> list[str]:  # noqa: ANN401
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
