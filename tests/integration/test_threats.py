from datetime import UTC, datetime, timedelta


async def test_list_threats_empty(client):
    resp = await client.get("/api/v1/threats")
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


async def test_list_threats_filter_by_severity(client, seeded_db):
    resp = await client.get("/api/v1/threats?severity=critical")
    body = resp.json()
    assert resp.status_code == 200
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "critical"


async def test_list_threats_filter_since(client, seeded_db):
    cutoff = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
    resp = await client.get("/api/v1/threats", params={"since": cutoff})
    body = resp.json()
    assert body["total"] == 2  # only the two recent rows


async def test_list_threats_pagination(client, seeded_db):
    resp = await client.get("/api/v1/threats?limit=2&offset=0")
    body = resp.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert body["limit"] == 2


async def test_list_threats_sorted_desc_by_published(client, seeded_db):
    resp = await client.get("/api/v1/threats")
    items = resp.json()["items"]
    pubs = [i["published_at"] for i in items]
    assert pubs == sorted(pubs, reverse=True)


async def test_list_threats_excludes_raw_data(client, seeded_db):
    resp = await client.get("/api/v1/threats?limit=1")
    item = resp.json()["items"][0]
    assert "raw_data" not in item
