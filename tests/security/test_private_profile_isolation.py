"""Private profiles must never leak — neither their existence, nor their
contents, nor their score data — through unauthenticated endpoints."""


async def test_default_listing_excludes_private_profiles(client, security_seed):
    resp = await client.get("/api/v1/sectors")
    assert resp.status_code == 200
    body = resp.json()
    ids = [s["id"] for s in body["items"]]
    assert "finance" in ids
    assert "corp-secret" not in ids


async def test_visibility_all_without_admin_is_403(client, security_seed):
    resp = await client.get("/api/v1/sectors?visibility=all")
    assert resp.status_code == 403


async def test_private_profile_detail_404_without_admin(client, security_seed):
    resp = await client.get("/api/v1/sectors/corp-secret")
    # 404 (not 403) — never confirm or deny existence to anonymous callers.
    assert resp.status_code == 404


async def test_private_profile_threats_404_without_admin(client, security_seed):
    resp = await client.get("/api/v1/sectors/corp-secret/threats")
    assert resp.status_code == 404


async def test_private_profile_secret_keywords_not_in_public_responses(
    client, security_seed
):
    """Even at the bytes level, no internal keyword/tech should bleed through."""
    paths = [
        "/api/v1/sectors",
        "/api/v1/sectors/finance",
        "/api/v1/sectors/finance/threats",
        "/api/v1/threats",
        "/openapi.json",
    ]
    for path in paths:
        resp = await client.get(path)
        body = resp.text
        assert "confidential-internal-keyword" not in body, f"leaked via {path}"
        assert "MySecretInternalTool" not in body, f"leaked via {path}"
        assert "corp-secret" not in body, f"leaked via {path}"
