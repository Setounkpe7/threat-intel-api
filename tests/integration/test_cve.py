async def test_get_cve_returns_detail(client, seeded_db):
    resp = await client.get("/api/v1/cve/CVE-2026-1000")
    assert resp.status_code == 200
    body = resp.json()
    assert body["external_id"] == "CVE-2026-1000"
    assert "raw_data" in body
    assert body["cwe_ids"] == ["CWE-79"]


async def test_get_cve_404_problem_json(client):
    resp = await client.get("/api/v1/cve/CVE-2026-9999")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["title"] == "Threat not found"
    assert body["status"] == 404


async def test_get_cve_invalid_format_returns_422(client):
    resp = await client.get("/api/v1/cve/NOT-A-CVE")
    assert resp.status_code == 422
