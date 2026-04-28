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
    """When 429 fires, the body must be a defined error shape, not a stack trace."""
    burst_until_429 = 110
    last = None
    for _ in range(burst_until_429):
        last = await client.get("/api/v1/sectors")
        if last.status_code == 429:
            break
    assert last is not None and last.status_code == 429
    # slowapi default body is plain "Rate limit exceeded" text — accept either
    # JSON or text/plain, just verify no traceback was rendered.
    body = last.text.lower()
    assert "traceback" not in body
    assert "rate limit" in body or "too many" in body
