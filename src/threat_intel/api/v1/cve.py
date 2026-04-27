from typing import Annotated

from fastapi import APIRouter, Depends, Path
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.deps import get_db
from threat_intel.core.exceptions import ThreatNotFoundException
from threat_intel.schemas.cve import ThreatDetail
from threat_intel.services.threats import get_threat_by_cve

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
    detail = ThreatDetail.model_validate(threat)
    detail.cwe_ids = [c.id for c in threat.cwes]
    return detail
