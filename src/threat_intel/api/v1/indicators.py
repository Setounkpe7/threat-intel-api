import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from threat_intel.models.base import IndicatorType
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.schemas.api.indicators import ThreatOut

router = APIRouter(prefix="/indicators", tags=["indicators"])


@router.get("", response_model=list[ThreatOut])
async def find_threats_by_indicator(
    request: Request,
    type: str = Query(
        ...,
        description="One of: cve, ghsa, cpe, package, ip, domain, url, md5, sha1, sha256",
    ),
    value: str = Query(..., min_length=1, max_length=512),
) -> list[ThreatOut]:
    try:
        ind_type = IndicatorType(type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid indicator type: {type}") from e
    sf = request.app.state.session_factory
    async with sf() as session:
        threat_ids: list[uuid.UUID] = (
            (
                await session.execute(
                    select(ThreatIndicator.threat_id).where(
                        ThreatIndicator.indicator_type == ind_type,
                        ThreatIndicator.value == value,
                    )
                )
            )
            .scalars()
            .all()
        )
        if not threat_ids:
            return []
        threats = (
            (await session.execute(select(Threat).where(Threat.id.in_(threat_ids)))).scalars().all()
        )
    return [ThreatOut.model_validate(t, from_attributes=True) for t in threats]
