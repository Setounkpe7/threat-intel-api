"""Admin auth + rate limiting (M2 phase 7)."""

import secrets
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from threat_intel.core.config import Settings


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def require_admin_key(
    request: Request,
    x_admin_key: Annotated[str | None, Header()] = None,
) -> None:
    """Reject the request unless X-Admin-Key matches `settings.admin_api_key`.

    If the server has no admin key configured, all admin endpoints are disabled
    (returns 503 to make the misconfiguration visible).
    """
    settings = _get_settings(request)
    expected = settings.admin_api_key
    if expected is None or expected == "":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API key not configured on server",
        )
    if x_admin_key is None or not secrets.compare_digest(x_admin_key, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing X-Admin-Key",
        )


def has_admin_key(
    request: Request,
    x_admin_key: Annotated[str | None, Header()] = None,
) -> bool:
    """Soft check — does NOT raise. Used to widen results for admins."""
    settings = _get_settings(request)
    expected = settings.admin_api_key
    if not expected or x_admin_key is None:
        return False
    return secrets.compare_digest(x_admin_key, expected)


def forbid_browser_origin(
    origin: Annotated[str | None, Header()] = None,
) -> None:
    """Reject any request that carries an Origin header.

    Browsers always send Origin on cross-origin POST/PUT/DELETE. SIEM/SOAR
    clients and curl do not. Combined with CORS allow_headers=["*"], this
    is the simplest CSRF block for admin endpoints without removing CORS
    on public routes.
    """
    if origin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin endpoints reject browser-originated requests",
        )


ForbidBrowserOrigin = Depends(forbid_browser_origin)

# Module-level limiter; `enabled` is set when the app starts.
limiter = Limiter(key_func=get_remote_address, default_limits=[], headers_enabled=True)


AdminAuth = Depends(require_admin_key)
HasAdminKey = Annotated[bool, Depends(has_admin_key)]
