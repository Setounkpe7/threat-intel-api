async def test_health_returns_ok_with_seeded_data(client, seeded_db):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"
    assert body["database"] == "connected"
    assert "nvd" in body["collectors"]
    assert body["collectors"]["nvd"]["last_success"] is True
    assert body["stats"]["total_threats"] == 3


async def test_health_no_collectors_state_when_no_source(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["collectors"] == {}
    assert body["stats"]["total_threats"] == 0
