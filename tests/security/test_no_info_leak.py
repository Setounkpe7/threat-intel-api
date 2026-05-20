"""No fingerprinting/identifying headers may leak from any response.

This file is shared with Task 1 (500-body leak tests). On this branch,
T3 ships only the DENY_HEADERS parametrised test. The umbrella branch
merges this with T1's body+structlog tests.
"""

import pytest

DENY_HEADERS = [
    "server",
    "x-powered-by",
    "via",
    "x-runtime",
    "x-aspnet-version",
    "x-process-time",
    "sentry-trace",
    "baggage",
]

PATHS = ["/health", "/api/v1/threats?limit=1", "/api/v1/cve/CVE-0000-9999", "/docs"]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("hdr", DENY_HEADERS)
async def test_response_strips_fingerprinting_headers(client, path, hdr):
    resp = await client.get(path)
    assert hdr not in {k.lower() for k in resp.headers}, (
        f"{hdr} leaked on {path} (status={resp.status_code})"
    )
