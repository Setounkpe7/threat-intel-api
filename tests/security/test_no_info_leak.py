"""Cross-cutting: no response from the app may leak fingerprinting headers,
exception messages, or stack traces.

This file grows in later tasks (T3 adds Server/X-Powered-By/etc.). For T1
we cover the exception-message + traceback case.
"""

import pytest

LEAK_PATTERNS = ["Traceback", "RuntimeError", "ValueError", " line ", "  File "]


@pytest.fixture
async def probe_client_unhandled(client, app):
    @app.get("/__probe_leak")
    async def _r() -> dict:
        raise RuntimeError("very-secret-internal-message-9999")

    return client


@pytest.mark.parametrize("pattern", LEAK_PATTERNS + ["very-secret-internal-message-9999"])
async def test_500_body_does_not_leak(probe_client_unhandled, pattern):
    resp = await probe_client_unhandled.get("/__probe_leak")
    assert resp.status_code == 500
    assert pattern not in resp.text, f"{pattern!r} leaked into 500 body"


async def test_500_does_not_leak_traceback_in_headers(probe_client_unhandled):
    resp = await probe_client_unhandled.get("/__probe_leak")
    joined_headers = " ".join(f"{k}:{v}" for k, v in resp.headers.items())
    assert "Traceback" not in joined_headers
    assert "very-secret-internal-message-9999" not in joined_headers


def test_structlog_does_not_render_locals():
    """Prevent log leak: locals can hold DB rows, Settings (API keys), SQL params."""
    from threat_intel.core.logging import _build_processors

    procs = _build_processors(env="prod")
    # Callable processors may be functions (have __name__) or class instances
    # (use __class__.__name__); hasattr disambiguates without importing
    # private structlog internals.
    proc_names = [p.__name__ if hasattr(p, "__name__") else p.__class__.__name__ for p in procs]
    forbidden = ["ExceptionPrettyPrinter", "set_exc_info"]
    for f in forbidden:
        assert f not in proc_names, f"{f} renders local vars; remove from prod log chain"
