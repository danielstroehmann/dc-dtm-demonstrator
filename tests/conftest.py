import asyncio
import json
import os
import ssl
import sys
import time
from pathlib import Path

import httpx

import pytest
from fastapi.testclient import TestClient

from app import cleanup, evergreen
from app.auth import Auth
from app.main import create_app
from app.store import Store
from tests.fakedtm import ACCOUNT_ID, API_KEY, HOST, FakeDTM, cert_pem, key_pem

PASSWORD = "correct horse battery staple 42!"
SECRET = "s" * 48


def pytest_collection_modifyitems(config, items):
    """Live tests create real DTM objects – run them only when explicitly selected with -m live."""
    markexpr = config.getoption("markexpr") or ""
    if "live" in markexpr and "not live" not in markexpr:
        return
    skip = pytest.mark.skip(reason="live DTM tests run only with -m live")
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def fast_timing(request, monkeypatch):
    """No real waiting in mocked tests; live tests keep the production timing."""
    if request.node.get_closest_marker("live"):
        return
    monkeypatch.setattr(evergreen, "POLL_INTERVAL", 0.0)
    monkeypatch.setattr(cleanup, "CONFIRM_DELAY_S", 0.0)
    monkeypatch.setattr(cleanup, "IDLE_BACKOFF_S", 0.0)
    # Hard-coded waits (lookup retries, batch-job wait) must not slow the suite down; the fake
    # DTM keeps its own reference to the real sleep.
    # The cleanup heartbeat keeps real (short) timing – an instant heartbeat would spin and flood the log.
    monkeypatch.setattr(cleanup, "HEARTBEAT_S", 0.05)
    real_sleep = asyncio.sleep
    sleeps: list[float] = []

    async def instant_sleep(delay, result=None):
        if delay == cleanup.HEARTBEAT_S:
            return await real_sleep(delay, result)
        sleeps.append(delay)
        return await real_sleep(0, result)

    monkeypatch.setattr(asyncio, "sleep", instant_sleep)
    return sleeps


@pytest.fixture
def fake() -> FakeDTM:
    return FakeDTM()


@pytest.fixture
def store(tmp_path) -> Store:
    return Store(tmp_path / "data" / "demonstrator.db")


@pytest.fixture
def configured_store(store) -> Store:
    store.save_connection(None, "Default", HOST, ACCOUNT_ID, API_KEY)
    return store


@pytest.fixture
def auth() -> Auth:
    return Auth(PASSWORD, SECRET)


@pytest.fixture
def data_dir(tmp_path):
    return tmp_path / "data"


def make_web(store, auth, fake, data_dir):
    app = create_app(store, auth, client_factory=fake.factory(), data_dir=data_dir)
    return TestClient(app, base_url="https://testserver", raise_server_exceptions=False)


@pytest.fixture
def web(store, auth, fake, data_dir):
    """Anonymous browser. The cookie is Secure, so the client talks https."""
    with make_web(store, auth, fake, data_dir) as client:
        yield client


@pytest.fixture
def user(web):
    """Logged-in browser."""
    response = web.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert response.status_code == 303, response.text
    return web


@pytest.fixture
def configured_user(configured_store, user):
    return user


def wait_for(predicate, timeout: float = 15.0, what: str = "condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.fixture(autouse=True)
def no_time_suffix_in_events(request, monkeypatch):
    """Author rule: timeline messages carry no "(t+Xs)" suffix – the timeline shows the time itself."""
    if request.node.get_closest_marker("live"):
        yield
        return
    from app.store import Store as _Store
    original = _Store.add_event
    offending = []

    def add_event(self, run_id, message, level="info"):
        if "(t+" in message:
            offending.append(message)
        return original(self, run_id, message, level)

    monkeypatch.setattr(_Store, "add_event", add_event)
    yield
    assert not offending, offending


# --- UC-3: the factory station's network and the openssl cmp client ---------------------------

class _RecordingContext(ssl.SSLContext):
    """A real client SSL context that also tells the fake DTM which client certificate the station
    loaded for mTLS – the mock transport cannot see the TLS handshake."""
    fake: FakeDTM

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        super().load_cert_chain(certfile, keyfile, password)  # still fails on a cert/key mismatch
        self.fake.tls_client_cert = Path(certfile).read_text()


@pytest.fixture
def enroll_net(monkeypatch, fake):
    """Routes the station's own httpx client (enrollment calls, no API key) to the fake DTM's
    enrollment endpoints and records the mTLS client certificate."""
    from app import enrollment

    class Httpx:
        def __getattr__(self, name):
            return getattr(httpx, name)

        @staticmethod
        def AsyncClient(**kwargs):  # noqa: N802 – mirrors httpx.AsyncClient
            assert isinstance(kwargs.get("verify"), ssl.SSLContext)  # TLS verification stays on
            return httpx.AsyncClient(transport=fake.enroll_transport(), **kwargs)

    class Ssl:
        def __getattr__(self, name):
            return getattr(ssl, name)

        @staticmethod
        def create_default_context(cafile=None):
            context = _RecordingContext(ssl.PROTOCOL_TLS_CLIENT)
            context.fake = fake
            context.load_verify_locations(cafile=cafile)
            return context

    monkeypatch.setattr(enrollment, "httpx", Httpx())
    monkeypatch.setattr(enrollment, "ssl", Ssl())
    return fake


class FakeOpenSSL:
    TOOL, SCRIPT = "openssl", "fake_openssl.py"

    def __init__(self, bin_dir: Path, fake: FakeDTM):
        bin_dir.mkdir(exist_ok=True)
        self.bin_dir, self.fake = bin_dir, fake
        self.record = bin_dir / f"{self.TOOL}-calls.jsonl"
        self.config = {"ca_cert": cert_pem(fake.ica_cert), "ca_key": key_pem(fake.ica_key),
                       "record": str(self.record), "fail": None}
        self._write()
        script = bin_dir / self.TOOL
        script.write_text(f"#!{sys.executable}\n" + (Path(__file__).parent / self.SCRIPT).read_text())
        script.chmod(0o755)

    def _write(self):
        (self.bin_dir / "config.json").write_text(json.dumps(self.config))

    def pass_through(self, real_openssl: str) -> None:
        """Hand every non-cmp openssl command to the real binary (for executing whole snippets)."""
        self.config["real_openssl"] = real_openssl
        self._write()

    def fail_with(self, message: str) -> None:
        self.config["fail"] = message
        self._write()

    def calls(self) -> list[dict]:
        if not self.record.exists():
            return []
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def sync_to_dtm(self) -> None:
        """Make the certificates openssl received known to the fake DTM (DTM lists them under the
        policy behind DIOT_<alternative_id>), so the cleanup has something real to revoke."""
        from cryptography import x509
        for call in self.calls():
            if not call["issued"]:
                continue
            alternative_id = call["argv"][call["argv"].index("-server") + 1].rsplit("DIOT_", 1)[1]
            policy_id = next(p["id"] for p in self.fake.policies.values() if p["alternative_id"] == alternative_id)
            self.fake.register_certificate(policy_id, x509.load_pem_x509_certificate(call["issued"].encode()))


@pytest.fixture
def cmp_openssl(tmp_path, monkeypatch, fake):
    """A fake `openssl` first on PATH (see tests/fake_openssl.py)."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    tool = FakeOpenSSL(bin_dir, fake)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return tool


class FakeScepClient(FakeOpenSSL):
    TOOL, SCRIPT = "scepclient", "fake_scepclient.py"

    def sync_to_dtm(self) -> None:
        """Make the certificates the client received known to the fake DTM under the policy behind
        DIOT_<alternative_id>, so the cleanup has something real to revoke."""
        from cryptography import x509
        for call in self.calls():
            if call["issued"]:
                url = call["argv"][call["argv"].index("-server-url") + 1]
                alternative_id = url.rsplit("DIOT_", 1)[1]
                policy_id = next(p["id"] for p in self.fake.policies.values() if p["alternative_id"] == alternative_id)
                self.fake.register_certificate(policy_id, x509.load_pem_x509_certificate(call["issued"].encode()))


@pytest.fixture
def scep_client(tmp_path, monkeypatch, fake):
    """A fake `scepclient` first on PATH (see tests/fake_scepclient.py) – its own bin dir."""
    tool = FakeScepClient(tmp_path / "fake-scep-bin", fake)
    monkeypatch.setenv("PATH", f"{tool.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return tool
