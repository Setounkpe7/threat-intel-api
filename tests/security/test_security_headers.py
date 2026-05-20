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
        # Strict floor: default-src 'none' (not 'self') since task B2.
        # Routes that need broader access (/docs, /) use direct assignment.
        "content-security-policy": (
            "default-src 'none'",
            "frame-ancestors 'none'",
        ),
    }


def _assert_required(headers: dict[str, str]) -> None:
    lower = {k.lower(): v for k, v in headers.items()}
    for name, expected in _expected_required_headers().items():
        assert name in lower, f"missing header: {name}"
        if isinstance(expected, str):
            assert lower[name] == expected, f"header {name}: got {lower[name]!r}, want {expected!r}"
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
    # /docs carries a relaxed CSP (not the strict floor) — use a targeted check
    # instead of _assert_required() which now asserts default-src 'none'.
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for name in (
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "content-security-policy",
    ):
        assert name in headers_lower, f"missing header: {name}"
    csp = resp.headers["content-security-policy"]
    # Swagger UI ships from a CDN — CSP must allow it without opening the world.
    assert "cdn.jsdelivr.net" in csp


async def test_csp_does_not_use_unsafe_eval(client):
    resp = await client.get("/health")
    csp = resp.headers["content-security-policy"]
    assert "'unsafe-eval'" not in csp


# ---------------------------------------------------------------------------
# B2: strict CSP floor + COOP/CORP on every response
# ---------------------------------------------------------------------------

STRICT_CSP_FLOOR = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'; object-src 'none'; script-src 'none'; style-src 'none'"
)


@pytest.mark.parametrize(
    "path",
    [
        "/health",
        "/api/v1/threats?limit=1",
        "/api/v1/sectors/finance/feed.rss?min_score=0",
        "/api/v1/cve/CVE-0000-9999",
    ],
)
async def test_strict_csp_on_api_and_error_responses(client, path):
    resp = await client.get(path)
    csp = resp.headers["content-security-policy"]
    assert csp == STRICT_CSP_FLOOR, f"unexpected CSP on {path}: {csp}"


async def test_docs_keeps_relaxed_csp(client):
    resp = await client.get("/docs")
    csp = resp.headers["content-security-policy"]
    assert "cdn.jsdelivr.net" in csp
    assert "nonce-" in csp


async def test_landing_keeps_its_csp(client):
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    assert "fonts.googleapis.com" in csp


@pytest.mark.parametrize("path", ["/health", "/api/v1/threats?limit=1", "/docs"])
async def test_coop_corp_present(client, path):
    resp = await client.get(path)
    assert resp.headers["cross-origin-resource-policy"] == "same-origin"
    assert resp.headers["cross-origin-opener-policy"] == "same-origin"
