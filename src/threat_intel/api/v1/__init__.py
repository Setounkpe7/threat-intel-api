from fastapi import APIRouter

from threat_intel.api.v1 import admin, cve, indicators, sectors, sources, stats, threats

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(threats.router)
api_v1.include_router(cve.router)
api_v1.include_router(sectors.router)
api_v1.include_router(stats.router)
api_v1.include_router(sources.router)
api_v1.include_router(indicators.router)
api_v1.include_router(admin.router)
