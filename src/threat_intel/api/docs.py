"""Custom Swagger UI handler with a per-request nonce, plus root redirect.

FastAPI's auto-generated /docs HTML embeds an inline <script> that
bootstraps Swagger UI. With a strict CSP (no 'unsafe-inline'), browsers
block the inline script and the page renders blank. We override the
route so that:

  * a fresh nonce is generated per request,
  * the inline <script> opening tag is rewritten to carry that nonce,
  * the response ships an explicit CSP that whitelists exactly that
    nonce — keeping `'unsafe-inline'` out of script-src globally.

The middleware uses `setdefault` for security headers, so the per-route
CSP set here wins over the default CSP for /docs only.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, RedirectResponse

from threat_intel.api.middleware import build_csp

router = APIRouter(include_in_schema=False)


def _inject_nonce(html: bytes, nonce: str) -> bytes:
    # FastAPI's swagger HTML template uses a literal `<script>` (no
    # attributes) for its inline initializer, so a single targeted
    # replacement is safe. External `<script src="...">` tags are not
    # touched.
    return html.replace(b"<script>", f'<script nonce="{nonce}">'.encode(), 1)


@router.get("/")
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/docs", status_code=302)


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
