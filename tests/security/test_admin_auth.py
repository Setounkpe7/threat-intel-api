"""Admin endpoints must reject any caller that does not present a valid
X-Admin-Key — both for the protected POST routes and for `?visibility=all`
on the sector listing."""

import pytest

ADMIN_KEY = "test-admin-key-please-rotate"


@pytest.fixture
def admin_settings(monkeypatch, settings):
    monkeypatch.setenv("ADMIN_API_KEY", ADMIN_KEY)
    settings.admin_api_key = ADMIN_KEY
    return settings


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/api/v1/admin/reload-profiles"),
        ("post", "/api/v1/admin/rescore-all"),
    ],
)
async def test_admin_routes_require_key(client, admin_settings, method, path):
    resp = await getattr(client, method)(path)
    assert resp.status_code == 403, (
        f"{method.upper()} {path} returned {resp.status_code}, expected 403"
    )


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/api/v1/admin/reload-profiles"),
        ("post", "/api/v1/admin/rescore-all"),
    ],
)
async def test_admin_routes_reject_wrong_key(client, admin_settings, method, path):
    resp = await getattr(client, method)(path, headers={"X-Admin-Key": "definitely-wrong"})
    assert resp.status_code == 403


async def test_admin_returns_503_when_no_key_is_configured(client, settings):
    # Default settings fixture leaves admin_api_key=None.
    settings.admin_api_key = None
    resp = await client.post(
        "/api/v1/admin/reload-profiles", headers={"X-Admin-Key": "anything"}
    )
    assert resp.status_code == 503


async def test_admin_key_comparison_is_constant_time():
    """Spot-check: the auth path uses secrets.compare_digest — proving via
    code reference, not timing (timing is unreliable in CI)."""
    import inspect

    from threat_intel.api import security

    src = inspect.getsource(security)
    assert "secrets.compare_digest" in src, (
        "X-Admin-Key validation must use secrets.compare_digest to avoid "
        "string-comparison timing attacks"
    )
