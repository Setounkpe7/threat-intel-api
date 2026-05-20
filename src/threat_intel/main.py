import contextlib
import time
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from http import HTTPStatus

import httpx
import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.status import HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR

from threat_intel import __version__
from threat_intel.api.docs import router as docs_router
from threat_intel.api.health import router as health_router
from threat_intel.api.middleware import ProblemCORSMiddleware, SecurityHeadersMiddleware
from threat_intel.api.problem import problem_response
from threat_intel.api.security import limiter
from threat_intel.api.v1 import api_v1
from threat_intel.collectors.base import BaseCollector
from threat_intel.collectors.cisa_kev import CISAKEVCollector
from threat_intel.collectors.github_advisories import GitHubAdvisoriesCollector
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

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment,
        release=__version__,
        send_default_pii=False,
        traces_sample_rate=0.0,
        integrations=[StarletteIntegration(), FastApiIntegration()],
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


async def _sync_source_enabled_state(
    session: AsyncSession,
    collectors: Iterable[BaseCollector],
) -> None:
    # Bidirectional: must re-enable too. Otherwise a token-less startup disables
    # the row and a later token + redeploy never lifts the scheduler's filter.
    for c in collectors:
        src = (
            await session.execute(select(Source).where(Source.name == c.source_name))
        ).scalar_one_or_none()
        if src is None:
            continue
        if src.enabled != c.enabled:
            src.enabled = c.enabled
            event = "collector.enabled_at_startup" if c.enabled else "collector.disabled_at_startup"
            logger.info(event, source=c.source_name)
    await session.commit()


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
        kev = CISAKEVCollector(http_client=http, settings=settings)
        ghsa = GitHubAdvisoriesCollector(http_client=http, settings=settings)
        collectors = [nvd, kev, ghsa]
        scoring_job = ThreatScoringJob(session_factory=factory)
        ingestion = IngestionService(
            session_factory=factory, collectors=collectors, scoring_job=scoring_job
        )

        await _ensure_source_row(factory, "nvd", SourceKind.cve_feed, settings.nvd_base_url)
        await _ensure_source_row(
            factory,
            "cisa_kev",
            SourceKind.cve_feed,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )
        await _ensure_source_row(
            factory, "github_advisories", SourceKind.advisory, "https://api.github.com/graphql"
        )

        async with factory() as session:
            await _sync_source_enabled_state(session, collectors)

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

        async def run_daily_rescore() -> None:
            try:
                await scoring_job.score_threats_since(daily_recent_window())
            except Exception:  # noqa: BLE001
                logger.exception("scheduled_rescore_failed")

        scheduler = build_scheduler(
            settings,
            ingestion=ingestion,
            session_factory=factory,
            daily_rescore_runner=run_daily_rescore,
        )
        scheduler.start()

        app.state.settings = settings
        app.state.session_factory = factory
        app.state.ingestion = ingestion
        app.state.profile_loader = profile_loader
        app.state.scoring_job = scoring_job
        app.state.collector_names = [c.source_name for c in collectors]
        app.state.start_time = datetime.now(UTC)

        try:
            yield
        finally:
            scheduler.shutdown(wait=False)
            await http.aclose()
            await engine.dispose()

    app = FastAPI(
        title="CyberThreat Intelligence API",
        version=__version__,
        lifespan=lifespan,
        # /docs is served by `docs_router` with a per-request CSP nonce.
        docs_url=None,
    )

    # Lock debug=False so Starlette's debug traceback page can never leak,
    # even if a future env-var change tries to flip it.
    if app.debug:
        raise RuntimeError("FastAPI app.debug must be False in production")

    app.state.settings = settings  # also exposed by lifespan but available at startup
    app.state.limiter = limiter
    limiter.enabled = settings.rate_limit_enabled

    @app.exception_handler(RateLimitExceeded)
    def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        # Must be sync — SlowAPIMiddleware falls back to its plain-text default
        # handler if the registered handler is async (inspect.iscoroutinefunction
        # check in slowapi/middleware.py).
        view_limit = getattr(request.state, "view_rate_limit", None)
        retry_after = 60  # safe default if the limiter never populated request.state
        if view_limit is not None:
            # view_rate_limit is a (limit, key) tuple. The limit object is a
            # slowapi.wrappers.Limit; the reset epoch comes from limiter.get_window_stats.
            try:
                stats = request.app.state.limiter.get_window_stats(view_limit[0], *view_limit[1])
                # get_window_stats returns (reset_epoch, remaining) — first element is epoch.
                reset_epoch = stats[0]
                retry_after = max(1, int(reset_epoch - time.time()))
            except Exception:  # noqa: BLE001  — defensive: any limiter API drift falls back to 60
                retry_after = 60
        detail_msg = str(getattr(exc, "detail", "Rate limit exceeded"))
        return problem_response(
            request,
            429,
            "Too Many Requests",
            detail_msg,
            extra_headers={"Retry-After": str(retry_after)},
        )

    app.add_middleware(SlowAPIMiddleware)

    if settings.cors_origins:
        app.add_middleware(
            ProblemCORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["*", "X-Admin-Key"],
        )

    # Added last → outermost in the Starlette stack → runs on every response
    # path, including 4xx/5xx and CORS preflights.
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(ThreatNotFoundException)
    async def _not_found(request: Request, exc: ThreatNotFoundException) -> JSONResponse:
        return problem_response(request, HTTP_404_NOT_FOUND, "Threat not found", str(exc))

    @app.exception_handler(ConfigurationError)
    async def _config_err(request: Request, exc: ConfigurationError) -> JSONResponse:
        return problem_response(
            request, HTTP_500_INTERNAL_SERVER_ERROR, "Configuration error", str(exc)
        )

    @app.exception_handler(CollectorError)
    async def _collector_err(request: Request, exc: CollectorError) -> JSONResponse:
        return problem_response(request, 502, "Upstream collector error", str(exc))

    @app.exception_handler(PersistenceError)
    async def _persistence_err(request: Request, exc: PersistenceError) -> JSONResponse:
        return problem_response(
            request, HTTP_500_INTERNAL_SERVER_ERROR, "Persistence error", str(exc)
        )

    @app.exception_handler(ThreatIntelException)
    async def _generic(request: Request, exc: ThreatIntelException) -> JSONResponse:
        return problem_response(request, HTTP_500_INTERNAL_SERVER_ERROR, "Internal error", str(exc))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Sentry's ASGI integration captures this exception BEFORE us, so we do
        # NOT call sentry_sdk.capture_exception (would double-fire). Logging
        # still useful for non-Sentry environments.
        with contextlib.suppress(Exception):  # noqa: BLE001
            # Logger failure must not prevent the sanitised response.
            logger.error(
                "unhandled_exception",
                path=request.url.path,
                method=request.method,
                exc_info=exc,
            )
        return problem_response(
            request,
            HTTP_500_INTERNAL_SERVER_ERROR,
            "Internal server error",
            "Unexpected error",
        )

    # Generic HTTPException (raised by routers via fastapi.HTTPException). Without
    # this handler FastAPI falls back to {"detail": "..."} as application/json,
    # breaking the RFC 7807 contract the README advertises.
    @app.exception_handler(HTTPException)
    async def _http_exc(request: Request, exc: HTTPException) -> JSONResponse:
        title = HTTPStatus(exc.status_code).phrase or "Error"
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return problem_response(request, exc.status_code, title, detail)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem_response(
            request,
            status=422,
            title="Validation error",
            detail="Request validation failed",
            errors=exc.errors(),
        )

    app.include_router(docs_router)
    app.include_router(health_router)
    app.include_router(api_v1)

    return app


app = create_app()
