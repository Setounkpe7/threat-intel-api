"""ORM models. Importing this package registers all tables on Base.metadata."""

from threat_intel.models.base import (
    GUID,
    Base,
    Severity,
    SourceKind,
    TimestampMixin,
    UtcDateTime,
)
from threat_intel.models.cve import CVE
from threat_intel.models.cwe import CWE, threat_cwe
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat

__all__ = [
    "Base",
    "CVE",
    "CWE",
    "GUID",
    "Severity",
    "Source",
    "SourceKind",
    "Threat",
    "TimestampMixin",
    "UtcDateTime",
    "threat_cwe",
]
