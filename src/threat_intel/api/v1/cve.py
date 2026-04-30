from typing import Annotated

from fastapi import APIRouter, Depends, Path
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.core.exceptions import ThreatNotFoundException
from threat_intel.schemas.cve import ThreatDetail
from threat_intel.services.threats import _to_read, get_threat_by_cve

router = APIRouter(prefix="/cve", tags=["cve"])

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"


@router.get("/{cve_id}", response_model=ThreatDetail)
async def get_cve(
    session: Annotated[AsyncSession, Depends(get_db)],
    cve_id: Annotated[str, Path(pattern=CVE_PATTERN)],
) -> ThreatDetail:
    threat = await get_threat_by_cve(session, cve_id)
    if threat is None:
        raise ThreatNotFoundException(cve_id=cve_id)

    base = _to_read(threat)

    # Merge raw_data from the first available ThreatSource (prefer NVD)
    sources = list(threat.sources or [])
    nvd_source = next((s for s in sources if s.source and s.source.name == "nvd"), None)
    representative = nvd_source or (sources[0] if sources else None)
    raw_data = representative.raw_data if representative else {}

    return ThreatDetail(
        **base.model_dump(),
        raw_data=raw_data,
        cwe_ids=[c.id for c in (threat.cwes or [])],
    )
