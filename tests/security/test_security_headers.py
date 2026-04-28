"""Asserts the SecurityHeadersMiddleware sets the expected hardening headers
on every response (HTML routes like /docs as well as JSON routes)."""

from collections.abc import Iterable

import pytest


def _expected_required_headers() -> dict[str, str | Iterable[str]]:
    """Header → exact value, or iterable of substrings that must all appear."""
    return {
        "strict-transport-security": ("max-age=", "includeSubDomains"),
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": ("geolocation=()", "camera=()", "microphone=()"),
        "content-security-policy": (
            "default-src 'self'",
            "frame-ancestors 'none'",
        ),
    }


def _assert_required(headers: dict[str, str]) -> None:
    lower = {k.lower(): v for k, v in headers.items()}
    for name, expected in _expected_required_headers().items():
        assert name in lower, f"missing header: {name}"
        if isinstance(expected, str):
            assert lower[name] == expected, (
                f"header {name}: got {lower[name]!r}, want {expected!r}"
            )
        else:
            for token in expected:
                assert token in lower[name], (
                    f"header {name}: missing token {token!r} in {lower[name]!r}"
                )


@pytest.mark.parametrize("path", ["/health", "/api/v1/threats", "/openapi.json"])
async def test_security_headers_on_json_routes(client, path):
    resp = await client.get(path)
    # Whatever the status (404 / 200), middleware must still attach the headers.
    _assert_required(dict(resp.headers))


async def test_security_headers_on_swagger_html(client):
    resp = await client.get("/docs")
    assert resp.status_code == 200
    _assert_required(dict(resp.headers))
    csp = resp.headers["content-security-policy"]
    # Swagger UI ships from a CDN — CSP must allow it without opening the world.
    assert "cdn.jsdelivr.net" in csp


async def test_csp_does_not_use_unsafe_eval(client):
    resp = await client.get("/health")
    csp = resp.headers["content-security-policy"]
    assert "'unsafe-eval'" not in csp
