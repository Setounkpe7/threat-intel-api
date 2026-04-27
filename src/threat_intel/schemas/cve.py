from typing import Any

from threat_intel.schemas.threat import ThreatBase


class ThreatDetail(ThreatBase):
    """Detail view returned by /api/v1/cve/{cve_id}. Includes raw_data."""

    raw_data: dict[str, Any]
    cwe_ids: list[str] = []
