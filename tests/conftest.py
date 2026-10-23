import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app import cleanup, evergreen
from app.auth import Auth
from app.main import create_app
from app.store import Store
from tests.fakedtm import ACCOUNT_ID, API_KEY, HOST, FakeDTM

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
