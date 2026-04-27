from fastapi import APIRouter

from threat_intel.api.v1 import cve, threats

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(threats.router)
api_v1.include_router(cve.router)
