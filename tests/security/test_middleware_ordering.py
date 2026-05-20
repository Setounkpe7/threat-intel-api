"""Proves that catch-all Exception handler actually fires.

If SecurityHeadersMiddleware (BaseHTTPMiddleware) sits outside and swallows
exceptions into its own 500, this test catches it.
"""

import pytest


@pytest.fixture
async def probe_client(client, app):
    """Mount a route that always raises, then probe it."""

    @app.get("/__probe_unhandled")
    async def _probe() -> dict:
        raise RuntimeError("probe-exception")

    return client


async def test_unhandled_exception_returns_problem_json(probe_client):
    resp = await probe_client.get("/__probe_unhandled")
    assert resp.status_code == 500
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body == {
        "type": "about:blank",
        "title": "Internal server error",
        "status": 500,
        "detail": "Unexpected error",
        "instance": "/__probe_unhandled",
    }


async def test_unhandled_exception_does_not_leak_message(probe_client):
    resp = await probe_client.get("/__probe_unhandled")
    body_text = resp.text
    assert "probe-exception" not in body_text
    assert "RuntimeError" not in body_text
    assert "Traceback" not in body_text
