"""ORM models. Importing this package registers all tables on Base.metadata."""

from threat_intel.models.base import (
    GUID,
    Base,
    CollectorRunStatus,
    IndicatorType,
    Severity,
    SourceKind,
    TimestampMixin,
    UtcDateTime,
)
from threat_intel.models.collector_run import CollectorRun
from threat_intel.models.cve import CVE
from threat_intel.models.cwe import CWE, threat_cwe
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.sector_score import ThreatSectorScore
from threat_intel.models.source import Source
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.models.threat_source import ThreatSource

__all__ = [
    "Base",
    "CollectorRun",
    "CollectorRunStatus",
    "CVE",
    "CWE",
    "GUID",
    "IndicatorType",
    "SectorProfile",
    "Severity",
    "Source",
    "SourceKind",
    "Threat",
    "ThreatIndicator",
    "ThreatSectorScore",
    "ThreatSource",
    "TimestampMixin",
    "UtcDateTime",
    "threat_cwe",
]
