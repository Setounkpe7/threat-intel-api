from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.status import HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR

from threat_intel.api.health import router as health_router
from threat_intel.api.v1 import api_v1
from threat_intel.collectors.nvd import NVDCollector
from threat_intel.core.config import Settings, get_settings
from threat_intel.core.db import build_engine, session_factory
from threat_intel.core.exceptions import (
    CollectorError,
    ConfigurationError,
    PersistenceError,
    ThreatIntelException,
    ThreatNotFoundException,
)
from threat_intel.core.logging import configure_logging
from threat_intel.core.scheduler import build_scheduler
from threat_intel.models.base import SourceKind
from threat_intel.models.source import Source
from threat_intel.services.ingestion import IngestionService

logger = structlog.get_logger(__name__)


def _problem(status: int, title: str, detail: str, type_: str = "about:blank") -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"type": type_, "title": title, "status": status, "detail": detail},
        media_type="application/problem+json",
    )


async def _ensure_source_row(
    factory: async_sessionmaker[AsyncSession],
    name: str,
    kind: SourceKind,
    url: str,
) -> None:
    async with factory() as s:
        existing = (
            await s.execute(select(Source).where(Source.name == name))
        ).scalar_one_or_none()
        if existing is None:
            s.add(Source(name=name, kind=kind, url=url, enabled=True))
            await s.commit()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(env=settings.app_env, level=settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = build_engine(settings.database_url)
        factory = session_factory(engine)
        http = httpx.AsyncClient(timeout=30.0)
        nvd = NVDCollector(http_client=http, settings=settings)
        ingestion = IngestionService(session_factory=factory, collectors=[nvd])

        await _ensure_source_row(factory, "nvd", SourceKind.cve_feed, settings.nvd_base_url)

        async def run_nvd() -> None:
            try:
                await ingestion.run("nvd")
            except Exception:  # noqa: BLE001
                logger.exception("scheduled_nvd_run_failed")

        scheduler = build_scheduler(settings, run_nvd)
        scheduler.start()

        app.state.settings = settings
        app.state.session_factory = factory
        app.state.ingestion = ingestion
        app.state.collector_names = ["nvd"]
        app.state.start_time = datetime.now(UTC)

        try:
            yield
        finally:
            scheduler.shutdown(wait=False)
            await http.aclose()
            await engine.dispose()

    app = FastAPI(
        title="CyberThreat Intelligence API",
        version="0.1.0",
        lifespan=lifespan,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["*"],
        )

    @app.exception_handler(ThreatNotFoundException)
    async def _not_found(_: Request, exc: ThreatNotFoundException) -> JSONResponse:
        return _problem(HTTP_404_NOT_FOUND, "Threat not found", str(exc))

    @app.exception_handler(ConfigurationError)
    async def _config_err(_: Request, exc: ConfigurationError) -> JSONResponse:
        return _problem(HTTP_500_INTERNAL_SERVER_ERROR, "Configuration error", str(exc))

    @app.exception_handler(CollectorError)
    async def _collector_err(_: Request, exc: CollectorError) -> JSONResponse:
        return _problem(502, "Upstream collector error", str(exc))

    @app.exception_handler(PersistenceError)
    async def _persistence_err(_: Request, exc: PersistenceError) -> JSONResponse:
        return _problem(HTTP_500_INTERNAL_SERVER_ERROR, "Persistence error", str(exc))

    @app.exception_handler(ThreatIntelException)
    async def _generic(_: Request, exc: ThreatIntelException) -> JSONResponse:
        return _problem(HTTP_500_INTERNAL_SERVER_ERROR, "Internal error", str(exc))

    app.include_router(health_router)
    app.include_router(api_v1)

    return app


app = create_app()
