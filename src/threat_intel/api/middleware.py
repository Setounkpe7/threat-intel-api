"""HTTP-level security middleware.

`SecurityHeadersMiddleware` attaches a hardened set of response headers on
every request — including error responses — without touching route logic.

Defaults follow OWASP Secure Headers Project guidance. The default CSP is a
strict floor (``default-src 'none'``) appropriate for JSON/RSS API responses.
Routes that serve HTML (``/docs``, ``/``) override this via direct header
assignment in ``api/docs.py`` before the middleware's ``setdefault`` runs.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


# CSP tuned for FastAPI: the only HTML routes are /docs (Swagger UI) and
# /redoc, both loading JS/CSS/font from jsdelivr. Swagger UI also needs
# an inline initializer script — that one carries a per-request nonce
# (see `api/docs.py`) so we never ship 'unsafe-inline' for script-src.
def build_csp(nonce: str | None = None) -> str:
    script_src = "'self' https://cdn.jsdelivr.net"
    if nonce is not None:
        script_src = f"'self' 'nonce-{nonce}' https://cdn.jsdelivr.net"
    return (
        "default-src 'self'; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        f"script-src {script_src}; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'"
    )


def build_landing_csp() -> str:
    """CSP for the editorial landing page at `/`.

    Tighter than the global default in two ways: no script CDN (the page
    ships zero JS) and no jsdelivr in style-src. Wider in one way: the
    landing pulls Newsreader and JetBrains Mono from Google Fonts, so
    `style-src` and `font-src` whitelist those origins explicitly. Inline
    styles are kept (the template embeds a single `<style>` block) — this
    matches the global posture (`'unsafe-inline'` for style is already
    accepted on /docs).
    """
    return (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'"
    )


# Strict floor: every response gets this unless a route explicitly overrides
# (currently /docs and / do, via `response.headers["Content-Security-Policy"] = …`).
# default-src 'none' does NOT cover form-action or frame-ancestors per CSP3 §6.1,
# so those are listed explicitly.
_DEFAULT_CSP = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'; object-src 'none'; script-src 'none'; style-src 'none'"
)

# Keep this list small and focused — every entry is one fewer browser API
# any compromised dependency can call from a /docs page.
_DEFAULT_PERMISSIONS_POLICY = (
    "geolocation=(), camera=(), microphone=(), payment=(), usb=(), "
    "accelerometer=(), gyroscope=(), magnetometer=(), midi=(), interest-cohort=()"
)


@dataclass(frozen=True)
class SecurityHeadersConfig:
    hsts_max_age: int = 63_072_000  # 2 years, recommended for prod
    hsts_include_subdomains: bool = True
    hsts_preload: bool = False
    content_security_policy: str = _DEFAULT_CSP
    permissions_policy: str = _DEFAULT_PERMISSIONS_POLICY
    referrer_policy: str = "strict-origin-when-cross-origin"
    frame_options: str = "DENY"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, config: SecurityHeadersConfig | None = None) -> None:
        super().__init__(app)
        self._config = config or SecurityHeadersConfig()
        self._hsts = self._build_hsts(self._config)

    @staticmethod
    def _build_hsts(cfg: SecurityHeadersConfig) -> str:
        parts = [f"max-age={cfg.hsts_max_age}"]
        if cfg.hsts_include_subdomains:
            parts.append("includeSubDomains")
        if cfg.hsts_preload:
            parts.append("preload")
        return "; ".join(parts)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        headers = response.headers
        # setdefault so a route that wants to override (e.g. CSP for an
        # embedded HTML preview) can still do so explicitly.
        headers.setdefault("Strict-Transport-Security", self._hsts)
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", self._config.frame_options)
        headers.setdefault("Referrer-Policy", self._config.referrer_policy)
        headers.setdefault("Permissions-Policy", self._config.permissions_policy)
        headers.setdefault("Content-Security-Policy", self._config.content_security_policy)
        # Block Spectre-style cross-origin reads; safe for a SIEM-facing API.
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return response


class ProblemCORSMiddleware(CORSMiddleware):
    """CORSMiddleware variant that emits problem+json on preflight rejection.

    The stock Starlette middleware returns `400 text/plain "Disallowed CORS …"`
    which breaks our RFC 7807 contract advertised in README/docs. We delegate
    the policy decision to the parent and just rewrap the failure body.
    """

    def preflight_response(self, request_headers: Headers) -> Response:
        response = super().preflight_response(request_headers)
        if response.status_code < 400:
            return response

        raw = bytes(response.body) if response.body else b""
        failure_text = raw.decode("utf-8") if raw else "Disallowed CORS"
        # Drop the original content headers so JSONResponse can set its own.
        cors_headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower() not in {"content-type", "content-length"}
        }
        return JSONResponse(
            status_code=response.status_code,
            content={
                "type": "about:blank",
                "title": "CORS preflight rejected",
                "status": response.status_code,
                "detail": failure_text,
            },
            media_type="application/problem+json",
            headers=cors_headers,
        )
