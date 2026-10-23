"""Smoke tests against a deployed instance.

    SMOKE_URL=https://demo-host SMOKE_PASSWORD=... python -m pytest -m smoke

TLS verification is off by default because the standard deployment uses Caddy's internal CA;
set SMOKE_VERIFY_TLS=true for an admin-provided certificate.
"""

import os

import httpx
import pytest

pytestmark = pytest.mark.smoke

URL = os.environ.get("SMOKE_URL", "").rstrip("/")
PASSWORD = os.environ.get("SMOKE_PASSWORD", "")
VERIFY = os.environ.get("SMOKE_VERIFY_TLS", "false").lower() == "true"


@pytest.fixture
def client():
    if not URL or not PASSWORD:
        pytest.skip("SMOKE_URL and SMOKE_PASSWORD are required")
    with httpx.Client(base_url=URL, verify=VERIFY, timeout=15, follow_redirects=False) as c:
        yield c


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_page_and_headers(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert 'name="password"' in response.text
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_anonymous_index_redirects(client):
    response = client.get("/")
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_login_and_index(client):
    response = client.post("/login", data={"password": PASSWORD})
    assert response.status_code == 303, "login failed (wrong SMOKE_PASSWORD or rate limited)"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    if URL.startswith("https://"):
        assert "secure" in cookie
    index = client.get("/")
    assert index.status_code == 200 and "<h1>Runs</h1>" in index.text
