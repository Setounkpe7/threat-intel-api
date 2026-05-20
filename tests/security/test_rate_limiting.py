"""Rate limiting must actually trigger 429 once the per-IP budget is spent.

We use a fresh, low-budget Limiter for the duration of this test so we don't
have to fire 100 requests per assertion (and so we don't pollute the
module-level limiter used elsewhere).
"""

import contextlib

import pytest
import pytest_asyncio
from slowapi import Limiter

from threat_intel.api import security as security_module


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Clear slowapi state before each test so prior tests' counters don't bleed."""
    yield
    # slowapi versions differ on whether reset() exists / what it raises.
    with contextlib.suppress(Exception):
        security_module.limiter.reset()


@pytest_asyncio.fixture
async def rate_limited_client(client, monkeypatch):
    """Re-bind the module-level limiter to a 3/minute budget so rate limit
    behaviour is observable in a few requests."""
    test_limiter = Limiter(key_func=lambda _r: "test-client", default_limits=["3/minute"])
    test_limiter.enabled = True
    monkeypatch.setattr(security_module, "limiter", test_limiter)
    return client


async def test_excess_requests_get_429(client, security_seed):
    """100 requests against a 100/minute endpoint — the next one must 429.

    Slow but accurate. Kept narrow (one endpoint) to bound the runtime."""
    burst = 105
    statuses: list[int] = []
    for _ in range(burst):
        r = await client.get("/api/v1/sectors")
        statuses.append(r.status_code)
    assert any(s == 429 for s in statuses), (
        f"Expected at least one 429 within {burst} requests, got: {sorted(set(statuses))}"
    )


async def test_429_response_is_problem_json_or_text(client, security_seed):
    """When 429 fires, the body must be RFC 7807 problem+json, not a stack trace."""
    burst_until_429 = 110
    last = None
    for _ in range(burst_until_429):
        last = await client.get("/api/v1/sectors")
        if last.status_code == 429:
            break
    assert last is not None and last.status_code == 429
    # Must be RFC 7807 problem+json — the old plain-text shape is no longer acceptable.
    assert last.headers["content-type"].startswith("application/problem+json"), (
        f"Expected application/problem+json, got {last.headers.get('content-type')}"
    )
    body = last.json()
    assert body["status"] == 429
    assert body["title"] == "Too Many Requests"
    assert "traceback" not in last.text.lower()


@pytest.fixture
async def tight_rate_limit_client(client, app):
    """Force a 1/minute limit so we can exercise 429 deterministically."""
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    # Reset SlowAPI limiter to a 1/minute default
    app.state.limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1/minute"],
        headers_enabled=True,
    )
    yield client


async def test_rate_limit_headers_on_200(tight_rate_limit_client):
    resp = await tight_rate_limit_client.get("/health")
    assert "x-ratelimit-limit" in {k.lower() for k in resp.headers}
    assert "x-ratelimit-remaining" in {k.lower() for k in resp.headers}
    assert "x-ratelimit-reset" in {k.lower() for k in resp.headers}


async def test_429_returns_problem_json_with_retry_after(tight_rate_limit_client):
    # Burn the budget
    for _ in range(2):
        last = await tight_rate_limit_client.get("/health")
    assert last.status_code == 429
    assert last.headers["content-type"].startswith("application/problem+json")
    body = last.json()
    assert body["status"] == 429
    assert body["title"] == "Too Many Requests"
    assert "instance" in body
    retry_after = last.headers.get("retry-after")
    assert retry_after is not None
    # Integer seconds (SIEMs handle this reliably; HTTP-date is also valid but we standardise)
    assert retry_after.isdigit()
