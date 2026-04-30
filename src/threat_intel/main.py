from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.status import HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR

from threat_intel.api.docs import router as docs_router
from threat_intel.api.health import router as health_router
from threat_intel.api.middleware import SecurityHeadersMiddleware
from threat_intel.api.security import limiter
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
from threat_intel.services.profile_loader import SectorProfileLoader
from threat_intel.services.scoring_job import ThreatScoringJob, daily_recent_window

logger = structlog.get_logger(__name__)


def _init_sentry(settings: Settings) -> None:
    """Initialize Sentry if SENTRY_DSN is set; no-op otherwise.

    Errors-only configuration: traces_sample_rate=0.0, no profiling, no PII.
    Release tag uses the package __version__ so Sentry can group issues by
    app version.
    """
    if not settings.sentry_dsn:
        return

    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.starlette import StarletteIntegration

    from threat_intel import __version__

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment,
        release=__version__,
        send_default_pii=False,
        traces_sample_rate=0.0,
        integrations=[StarletteIntegration(), FastApiIntegration()],
    )


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
        existing = (await s.execute(select(Source).where(Source.name == name))).scalar_one_or_none()
        if existing is None:
            s.add(Source(name=name, kind=kind, url=url, enabled=True))
            await s.commit()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(
        env=settings.app_env,
        level=settings.log_level,
        log_file=settings.log_file,
        log_file_max_bytes=settings.log_file_max_bytes,
        log_file_backup_count=settings.log_file_backup_count,
    )
    _init_sentry(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = build_engine(settings.database_url)
        factory = session_factory(engine)
        http = httpx.AsyncClient(timeout=30.0)
        nvd = NVDCollector(http_client=http, settings=settings)
        scoring_job = ThreatScoringJob(session_factory=factory)
        ingestion = IngestionService(
            session_factory=factory, collectors=[nvd], scoring_job=scoring_job
        )

        await _ensure_source_row(factory, "nvd", SourceKind.cve_feed, settings.nvd_base_url)

        profile_loader = SectorProfileLoader(
            session_factory=factory, profiles_root=settings.profiles_path
        )
        load_result = await profile_loader.load_all()
        logger.info(
            "sector_profiles_startup",
            public=load_result.public_count,
            private=load_result.private_count,
            added=len(load_result.added),
            updated=len(load_result.updated),
            errors=len(load_result.errors),
        )

        async def run_nvd() -> None:
            try:
                await ingestion.run("nvd")
            except Exception:  # noqa: BLE001
                logger.exception("scheduled_nvd_run_failed")

        async def run_daily_rescore() -> None:
            try:
                await scoring_job.score_threats_since(daily_recent_window())
            except Exception:  # noqa: BLE001
                logger.exception("scheduled_rescore_failed")

        scheduler = build_scheduler(settings, run_nvd, run_daily_rescore)
        scheduler.start()

        app.state.settings = settings
        app.state.session_factory = factory
        app.state.ingestion = ingestion
        app.state.profile_loader = profile_loader
        app.state.scoring_job = scoring_job
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
        version="0.2.0",
        lifespan=lifespan,
        # /docs is served by `docs_router` with a per-request CSP nonce.
        docs_url=None,
    )

    app.state.settings = settings  # also exposed by lifespan but available at startup
    app.state.limiter = limiter
    limiter.enabled = settings.rate_limit_enabled
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_middleware(SlowAPIMiddleware)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["*", "X-Admin-Key"],
        )

    # Added last → outermost in the Starlette stack → runs on every response
    # path, including 4xx/5xx and CORS preflights.
    app.add_middleware(SecurityHeadersMiddleware)

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

    app.include_router(docs_router)
    app.include_router(health_router)
    app.include_router(api_v1)

    return app


app = create_app()
