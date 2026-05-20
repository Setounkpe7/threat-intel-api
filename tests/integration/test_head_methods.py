"""HEAD support on cheap endpoints. Not enabled on /api/v1/threats — that
would amplify load on uptime probes (full DB query, discarded body)."""

import pytest

HEAD_OK = ["/health", "/", "/docs", "/redoc", "/openapi.json"]
HEAD_405 = ["/api/v1/threats", "/api/v1/sectors", "/api/v1/sectors/finance/dashboard"]


@pytest.mark.parametrize("path", HEAD_OK)
async def test_head_ok_endpoints(client, path):
    resp = await client.head(path)
    assert resp.status_code == 200, f"HEAD {path} -> {resp.status_code}"
    assert resp.content == b"", f"HEAD {path} returned body"


@pytest.mark.parametrize("path", HEAD_405)
async def test_head_405_on_data_plane(client, path):
    resp = await client.head(path)
    assert resp.status_code == 405


async def test_head_preserves_headers(client):
    head = await client.head("/health")
    get = await client.get("/health")
    # Same status, same content-type, same security headers
    assert head.headers.get("content-type") == get.headers.get("content-type")
    hsts_head = head.headers.get("strict-transport-security")
    hsts_get = get.headers.get("strict-transport-security")
    assert hsts_head == hsts_get
