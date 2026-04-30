"""Server-rendered landing at `/`, plus a custom Swagger UI handler with
a per-request CSP nonce.

The landing page (`/`) is an editorial bulletin: it consumes the project's
own services (no extra HTTP hop) to surface live numbers — total threats,
24h delta, severity buckets, public sector profiles — so the bare domain
is a useful entry point and a self-demo of the API. Admin endpoints are
deliberately omitted (visitors don't have an `X-Admin-Key`).

The `/docs` route is unchanged: FastAPI's auto-generated Swagger UI HTML
embeds an inline `<script>` that bootstraps the page, and a strict CSP
without `'unsafe-inline'` would block it. We rewrite the inline tag to
carry a per-request nonce and ship a per-route CSP that whitelists only
that nonce.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel import __version__
from threat_intel.api.deps import get_db
from threat_intel.api.middleware import build_csp, build_landing_csp
from threat_intel.models.base import Severity
from threat_intel.services import sectors as sector_svc
from threat_intel.services.threats import collector_health

router = APIRouter(include_in_schema=False)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# Public endpoints we advertise on the landing. Admin routes are excluded
# on purpose — they require an X-Admin-Key the visitor doesn't have.
_PUBLIC_ENDPOINTS: tuple[dict[str, str], ...] = (
    {
        "path": "/api/v1/threats",
        "description": "Paginated list of indexed threats, filterable by severity and source.",
    },
    {
        "path": "/api/v1/cve/{cve_id}",
        "description": "Lookup a single CVE record with CVSS, CWE links and references.",
    },
    {
        "path": "/api/v1/sectors",
        "description": "Public sector profiles available for sector-scored views.",
    },
    {
        "path": "/api/v1/sectors/{sector_id}/dashboard",
        "description": "Top scored threats over 24h and 7d, plus sector-level statistics.",
    },
    {
        "path": "/api/v1/sectors/{sector_id}/feed.rss",
        "description": "RSS feed of high-severity threats scored against a sector.",
    },
    {
        "path": "/api/v1/stats/global",
        "description": "Aggregate counts and severity distribution across all sources.",
    },
)

_SEVERITY_ORDER: tuple[tuple[Severity, str, bool], ...] = (
    (Severity.critical, "Critical", True),
    (Severity.high, "High", False),
    (Severity.medium, "Medium", False),
    (Severity.low, "Low", False),
)

_LEDE = (
    "An open-source intelligence pipeline that collects software vulnerabilities "
    "from public feeds, scores them against industry profiles and exposes the "
    "result as a documented HTTP API. The page you are reading is rendered from "
    "the same service it describes — every number below is a live read."
)


def _format_last_sync(last_run: datetime | None) -> str:
    if last_run is None:
        return "no sync recorded"
    if last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - last_run
    minutes = int(delta.total_seconds() // 60)
    if minutes < 1:
        return "moments ago"
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def _build_severity_rows(by_severity: dict[str, int]) -> list[dict[str, Any]]:
    counts = {sev: int(by_severity.get(sev.value, 0)) for sev, _, _ in _SEVERITY_ORDER}
    peak = max(counts.values()) if counts else 0
    rows: list[dict[str, Any]] = []
    for sev, label, is_critical in _SEVERITY_ORDER:
        count = counts[sev]
        # Width of the bar relative to the largest bucket — keeps the
        # visual proportions stable regardless of absolute volume.
        width_pct = round((count / peak) * 100) if peak > 0 else 0
        rows.append(
            {
                "label": label,
                "count": count,
                "is_critical": is_critical,
                "width_pct": width_pct,
            }
        )
    return rows


@router.get("/")
async def root(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db)],
) -> HTMLResponse:
    stats = await sector_svc.global_stats_payload(session)
    profiles = await sector_svc.list_profiles(session, include_private=False)

    src, _ = await collector_health(session, "nvd")
    last_sync_label = _format_last_sync(src.last_run_at if src is not None else None)

    settings = request.app.state.settings
    sources_active = len(stats.get("sources_active", []) or [])

    context: dict[str, Any] = {
        "project_title": request.app.title,
        "version": __version__,
        "environment": getattr(settings, "app_env", "prod"),
        "lede": _LEDE,
        "last_sync_label": last_sync_label,
        "total_threats": int(stats.get("total_threats", 0)),
        "last_24h": int(stats.get("last_24h", 0)),
        "critical_count": int(stats.get("by_severity", {}).get("critical", 0)),
        "sources_active": sources_active,
        "severity_rows": _build_severity_rows(stats.get("by_severity", {}) or {}),
        "endpoints": list(_PUBLIC_ENDPOINTS),
        "sectors": [{"id": p.id, "name": p.name} for p in profiles],
    }
    response = templates.TemplateResponse(request, "landing.html", context)
    response.headers["Content-Security-Policy"] = build_landing_csp()
    return response


def _inject_nonce(html: bytes, nonce: str) -> bytes:
    # FastAPI's swagger HTML template uses a literal `<script>` (no
    # attributes) for its inline initializer, so a single targeted
    # replacement is safe. External `<script src="...">` tags are not
    # touched.
    return html.replace(b"<script>", f'<script nonce="{nonce}">'.encode(), 1)


@router.get("/docs")
async def swagger_ui_html(request: Request) -> HTMLResponse:
    nonce = secrets.token_urlsafe(16)
    raw = get_swagger_ui_html(
        openapi_url=request.app.openapi_url or "/openapi.json",
        title=f"{request.app.title} - Swagger UI",
    )
    body = _inject_nonce(bytes(raw.body), nonce)
    return HTMLResponse(
        content=body,
        headers={"Content-Security-Policy": build_csp(nonce=nonce)},
    )
