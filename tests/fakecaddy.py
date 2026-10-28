"""A stand-in for Caddy's admin API as app/tls_settings.py uses it: GET /config/, then POST /load with the same
config. A forced load re-reads cert.pem/key.pem from the live directory like Caddy does – a pair that does not load
is refused with 400 and the previously served certificate stays (Caddy keeps its running config)."""

import json
from pathlib import Path

import httpx
import pytest
from cryptography import x509

from app import tls_settings, tls_setup

CONFIG = {"admin": {"listen": "unix//run/caddy-admin/admin.sock|0666"}, "apps": {"http": {}}}


class FakeCaddy:
    def __init__(self, live: Path):
        self.live = live
        self.served: x509.Certificate | None = None
        self.loads = 0
        self.fail: str | None = None  # "refuse" (400), "unreachable" (connection error), "lost" (applied, no answer)
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail == "unreachable":
            raise httpx.ConnectError("no socket")
        if request.method == "GET" and request.url.path == "/config/":
            return httpx.Response(200, json=CONFIG)
        if request.method == "POST" and request.url.path == "/load":
            assert json.loads(request.content) == CONFIG and request.headers["content-type"] == "application/json"
            if request.headers.get("cache-control") != "must-revalidate":
                return httpx.Response(200)  # same config, not forced: Caddy does nothing
            if self.fail == "refuse":
                return httpx.Response(400, json={"error": "loading certificates: tls: failed to find any PEM data"})
            try:
                chain, key = tls_setup.from_pem((self.live / "cert.pem").read_bytes(),
                                                (self.live / "key.pem").read_bytes())
                tls_setup.check(chain, key)
            except (OSError, tls_setup.TLSError):
                return httpx.Response(400, json={"error": "loading certificates"})
            self.served, self.loads = chain[0], self.loads + 1
            if self.fail == "lost":
                self.fail = None  # the rollback's reload gets through
                raise httpx.ReadTimeout("no answer")
            return httpx.Response(200)
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler), base_url="http://127.0.0.1")


@pytest.fixture
def caddy(tmp_path, monkeypatch) -> FakeCaddy:
    live = tmp_path / "tls-live"
    live.mkdir()
    monkeypatch.setattr(tls_settings, "LIVE", live)
    fake = FakeCaddy(live)
    monkeypatch.setattr(tls_settings, "admin_client", fake.client)
    return fake
