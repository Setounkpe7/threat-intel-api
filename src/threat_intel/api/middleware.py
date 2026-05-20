"""HTTP-level security middleware.

`SecurityHeadersMiddleware` attaches a hardened set of response headers on
every request — including error responses — without touching route logic.

Defaults follow OWASP Secure Headers Project guidance. The default CSP is a
strict floor (``default-src 'none'``) appropriate for JSON/RSS API responses.
Routes that serve HTML (``/docs``, ``/``) override this via direct header
assignment in ``api/docs.py`` before the middleware's ``setdefault`` runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


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


class SecurityHeadersMiddleware:
    """Pure ASGI middleware so it does not swallow exceptions into 500.

    BaseHTTPMiddleware intercepts route exceptions and turns them into a
    500 before FastAPI's @exception_handler(Exception) can fire. Switching
    to pure ASGI lets exceptions propagate to Starlette's ServerErrorMiddleware
    which routes them to our handler.
    """

    def __init__(self, app: ASGIApp, config: SecurityHeadersConfig | None = None) -> None:
        self.app = app
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

    # Headers that fingerprint the server runtime — stripped on every response.
    # Defence-in-depth: uvicorn --server-header=false handles the Server header
    # in production, but the middleware covers TestClient and any other ASGI
    # transport too.
    _DENY_HEADERS = (
        "server",
        "x-powered-by",
        "via",
        "x-runtime",
        "x-aspnet-version",
        "x-process-time",
        "sentry-trace",
        "baggage",
    )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
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
                for forbidden in self._DENY_HEADERS:
                    if forbidden in headers:
                        del headers[forbidden]
            await send(message)

        await self.app(scope, receive, send_with_headers)


class ProblemCORSMiddleware(CORSMiddleware):
    """CORSMiddleware variant that emits problem+json on preflight rejection.

    The stock Starlette middleware returns `400 text/plain "Disallowed CORS …"`
    which breaks our RFC 7807 contract advertised in README/docs. We delegate
    the policy decision to the parent and just rewrap the failure body.
    """

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Stash path so preflight_response can populate the problem+json instance.
        self._current_path = scope.get("path", "") if scope.get("type") == "http" else ""
        await super().__call__(scope, receive, send)

    def preflight_response(self, request_headers: Headers) -> Response:
        response = super().preflight_response(request_headers)
        if response.status_code < 400:
            return response

        raw = bytes(response.body) if response.body else b""
        failure_text = raw.decode("utf-8") if raw else "Disallowed CORS"
        # Keep CORS headers from the base response (Access-Control-Allow-Origin,
        # Access-Control-Allow-Methods, etc.) but drop content-type/content-length
        # since we're replacing the body.
        cors_headers = {
            k: v
            for k, v in response.headers.items()
            if k.lower() not in {"content-type", "content-length"}
        }
        instance = getattr(self, "_current_path", None) or None
        content: dict[str, Any] = {
            "type": "about:blank",
            "title": "CORS preflight rejected",
            "status": response.status_code,
            "detail": failure_text,
        }
        if instance is not None:
            content["instance"] = instance
        return JSONResponse(
            status_code=response.status_code,
            content=content,
            media_type="application/problem+json",
            headers={
                **cors_headers,
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )
