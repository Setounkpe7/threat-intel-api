"""RFC 7807 problem+json response helper.

Single source of truth for error response shape so every 4xx/5xx the API
emits looks the same to a SIEM that consumes us. Used by the exception
handlers registered in `main.py` and by `ProblemCORSMiddleware`.
"""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse
from starlette.requests import Request


def problem_response(
    request: Request | None,
    status: int,
    title: str,
    detail: str,
    type_: str = "about:blank",
    *,
    extra_headers: dict[str, str] | None = None,
    **extra: object,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": type_,
        "title": title,
        "status": status,
        "detail": detail,
    }
    if request is not None:
        body["instance"] = request.url.path
    body.update(extra)
    headers: dict[str, str] = {}
    if extra_headers:
        headers.update(extra_headers)
    return JSONResponse(
        status_code=status,
        content=body,
        media_type="application/problem+json",
        headers=headers if headers else None,
    )
