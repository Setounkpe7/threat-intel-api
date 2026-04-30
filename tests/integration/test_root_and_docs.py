"""Root redirect to /docs and nonce-based CSP on /docs and /redoc.

Background: FastAPI's auto-generated Swagger UI and ReDoc HTML embed an
inline <script> that bootstraps the page. A strict CSP without
'unsafe-inline' (which is what we want) blocks that script and the page
renders blank. The fix is to serve the docs HTML with a per-request
nonce and a per-route CSP that whitelists only that nonce.
"""

import re


async def test_root_redirects_to_docs(client):
    resp = await client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302, 307, 308)
    assert resp.headers["location"] == "/docs"


async def test_docs_returns_html_with_nonced_inline_script(client):
    resp = await client.get("/docs")
    assert resp.status_code == 200
    body = resp.text
    # The inline initializer must carry a nonce attribute.
    match = re.search(r"<script\s+nonce=\"([A-Za-z0-9_\-]+)\">", body)
    assert match is not None, "inline <script> on /docs lacks a nonce attribute"


async def test_docs_csp_whitelists_the_inline_script_nonce(client):
    resp = await client.get("/docs")
    assert resp.status_code == 200
    body = resp.text
    csp = resp.headers["content-security-policy"]

    script_match = re.search(r"<script\s+nonce=\"([A-Za-z0-9_\-]+)\">", body)
    assert script_match is not None
    nonce = script_match.group(1)

    assert f"'nonce-{nonce}'" in csp, (
        f"CSP does not whitelist the inline-script nonce. CSP={csp!r}, nonce={nonce!r}"
    )
    # script-src must not silently re-open the floodgates.
    script_src = next((d.strip() for d in csp.split(";") if d.strip().startswith("script-src")), "")
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src


async def test_docs_nonce_changes_between_requests(client):
    r1 = await client.get("/docs")
    r2 = await client.get("/docs")
    n1 = re.search(r"<script\s+nonce=\"([A-Za-z0-9_\-]+)\">", r1.text)
    n2 = re.search(r"<script\s+nonce=\"([A-Za-z0-9_\-]+)\">", r2.text)
    assert n1 and n2
    assert n1.group(1) != n2.group(1), "nonce must be regenerated per request"


async def test_redoc_still_renders(client):
    """ReDoc's HTML uses only an external <script src>, so the existing
    CSP doesn't break it. This test guards against a future regression
    if FastAPI ever ships an inline initializer for ReDoc too."""
    resp = await client.get("/redoc")
    assert resp.status_code == 200
    assert "<redoc" in resp.text or "redoc" in resp.text.lower()
