async def test_global_stats_endpoint(client, seeded_db):
    # seeded_db inserts 3 threats but no sector scores
    resp = await client.get("/api/v1/stats/global")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_threats"] == 3
    assert body["last_24h"] >= 2  # 2 of the 3 are within 24h
    assert "by_severity" in body
    assert "sources_active" in body
    assert "nvd" in body["sources_active"]
