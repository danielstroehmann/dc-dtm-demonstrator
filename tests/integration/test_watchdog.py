"""Watchdog (v1.1.0): automatic full rollback after 3 h and after 24 h without login, dangling minions, backoff.
Runs against the fake DTM through the app's own wiring (create_app → its client per run); time is injected."""

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app import minions, watchdog
from app.dtm import DTMClient
from app.main import create_app
from app.store import rolled_back
from tests.fakedocker import FakeDocker
from tests.integration.test_uc01_flow import start

HOUR = 3600.0


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc).timestamp()

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def dog(configured_store, auth, fake, data_dir, clock) -> watchdog.Watchdog:
    app = create_app(configured_store, auth, client_factory=fake.factory(), data_dir=data_dir)
    dog = app.state.watchdog
    dog.clock, dog.started = clock, clock.now
    configured_store.set_setting(watchdog.LAST_LOGIN, _iso(clock.now))  # somebody is around
    return dog


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds")


async def run_aged(store, fake, run_id, tmp_path, clock, age_s, **params):
    await start(store, fake, run_id, tmp_path, **params)
    store.update_run(run_id, created_at=_iso(clock.now - age_s))
    return store.get_run(run_id)


def messages(store, run_id) -> list[str]:
    return [e["message"] for e in store.events(run_id)]


# --- rule 1: 3 h lifetime ---------------------------------------------------------------------

async def test_a_run_is_rolled_back_3_h_after_it_started(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, watchdog.LIFETIME_S)
    await run_aged(store, fake, "young", tmp_path, clock, watchdog.LIFETIME_S - 60)
    young_events = len(store.events("young"))
    await dog.tick()
    old, young = store.get_run("old"), store.get_run("young")
    assert rolled_back(old), messages(store, "old")
    assert "Rolled back automatically – 3 h lifetime" in messages(store, "old")
    assert young["cleanup_status"] is None
    # the full rollback of the UI: the old run's policy and division are gone, the young run's stay
    assert len(fake.policies) == 1 and len(fake.divisions) == 1
    assert len(store.events("young")) == young_events  # no DTM call, no event for the young run


async def test_a_tick_with_nothing_due_does_not_call_dtm(dog, configured_store, fake, tmp_path, clock):
    await run_aged(configured_store, fake, "young", tmp_path, clock, 60)
    fake.calls.clear()
    await dog.tick()
    assert fake.calls == []


@pytest.mark.parametrize("busy", [{"status": "running"}, {"status": "renewing"}, {"cleanup_status": "running"},
                                  {"result": {"busy": ["robot-x-device-0001"]}}])
async def test_a_busy_run_waits_until_it_is_done(dog, configured_store, fake, tmp_path, clock, busy):
    store = configured_store
    run = await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    store.update_run("old", **busy)
    fake.calls.clear()
    await dog.tick()
    assert fake.calls == [] and not any("Automatic" in m for m in messages(store, "old"))
    store.update_run("old", status="completed", cleanup_status=None, result=run["result"])  # done now
    clock.now += watchdog.TICK_S
    await dog.tick()
    assert rolled_back(store.get_run("old")), messages(store, "old")


async def test_a_rolled_back_run_is_not_touched_again(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    await dog.tick()
    assert rolled_back(store.get_run("old"))
    fake.calls.clear()
    events = len(store.events("old"))
    await dog.tick()
    assert fake.calls == [] and len(store.events("old")) == events


async def test_a_run_of_another_account_is_never_rolled_back_via_the_configured_one(
        dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    params = store.get_run("old")["params"] | {"account_id": "another-account", "connection_id": None}
    store.update_run("old", params=params)
    fake.calls.clear()
    await dog.tick()
    assert fake.calls == []
    assert store.get_run("old")["cleanup_status"] is None
    assert any(m.startswith("Automatic rollback failed – next attempt at") for m in messages(store, "old"))


# --- rule 2: 24 h without login -----------------------------------------------------------------

@pytest.mark.parametrize("last_login_age, rolled", [(watchdog.IDLE_S, True), (watchdog.IDLE_S - 60, False)])
async def test_runs_are_rolled_back_after_24_h_without_login(dog, configured_store, fake, tmp_path, clock,
                                                             last_login_age, rolled):
    store = configured_store
    await run_aged(store, fake, "young", tmp_path, clock, 60)
    store.set_setting(watchdog.LAST_LOGIN, _iso(clock.now - last_login_age))
    await dog.tick()
    assert rolled_back(store.get_run("young")) is rolled
    assert ("Rolled back automatically – no login for 24 h" in messages(store, "young")) is rolled


@pytest.mark.parametrize("started_age, rolled", [(watchdog.IDLE_S, True), (HOUR, False)])
async def test_without_any_login_idle_counts_from_the_app_start(dog, configured_store, fake, tmp_path, clock,
                                                                started_age, rolled):
    store = configured_store
    await run_aged(store, fake, "young", tmp_path, clock, 60)
    store.delete_setting(watchdog.LAST_LOGIN)
    dog.started = clock.now - started_age
    await dog.tick()
    assert rolled_back(store.get_run("young")) is rolled


async def test_a_successful_login_is_recorded(store, auth, fake, data_dir):
    from tests.conftest import PASSWORD, make_web
    with make_web(store, auth, fake, data_dir) as web:
        web.post("/login", data={"password": "wrong password!!"})
        assert store.get_setting(watchdog.LAST_LOGIN) is None
        web.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    recorded = datetime.fromisoformat(store.get_setting(watchdog.LAST_LOGIN))
    assert abs((datetime.now(timezone.utc) - recorded).total_seconds()) < 60


# --- failures and backoff -----------------------------------------------------------------------

def dtm_down(dog):
    """DTM answers 503 to everything for this run's client."""
    def client_for(run_id):
        config = dog.store.connection(None)
        from app.dtm import DTMConfig
        return DTMClient(DTMConfig(config["host"], config["api_key"], config["account_id"]), None,
                         transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    return client_for


async def test_a_failed_rollback_backs_off_and_is_retried_later(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    working = dog.client_for
    dog.client_for = dtm_down(dog)
    await dog.tick()
    assert store.get_run("old")["cleanup_status"] == "failed"
    attempts = lambda: sum(m.startswith("Automatic full rollback") for m in messages(store, "old"))  # noqa: E731
    assert attempts() == 1
    clock.now += watchdog.TICK_S  # next tick: no hot loop
    await dog.tick()
    assert attempts() == 1
    clock.now += watchdog.RETRY_S
    await dog.tick()  # retried, fails again – the wait doubles
    assert attempts() == 2
    clock.now += watchdog.RETRY_S
    await dog.tick()
    assert attempts() == 2
    dog.client_for = working  # DTM is back
    clock.now += watchdog.RETRY_S
    await dog.tick()
    assert attempts() == 3 and rolled_back(store.get_run("old")), messages(store, "old")
    assert "old" not in dog.retry


def test_the_backoff_is_capped(dog, configured_store, clock):
    for _ in range(12):
        dog._failed("gone", "test")
    assert dog.retry["gone"][1] == clock.now + watchdog.MAX_RETRY_S


async def test_the_loop_survives_a_failing_tick(dog):
    ticks, sleeps = [], []

    async def tick():
        ticks.append(1)
        if len(ticks) == 1:
            raise RuntimeError("boom")

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 2:
            raise asyncio.CancelledError

    dog.tick, dog.sleep = tick, sleep
    with pytest.raises(asyncio.CancelledError):
        await dog.run()
    assert ticks == [1, 1] and sleeps == [watchdog.TICK_S] * 3


def test_the_watchdog_starts_and_stops_with_the_app(store, auth, fake, data_dir):
    from tests.conftest import make_web
    web = make_web(store, auth, fake, data_dir)
    dog, slept = web.app.state.watchdog, []

    async def sleep(seconds):
        slept.append(seconds)
        await asyncio.Event().wait()  # until the app shuts down

    dog.sleep = sleep
    with web:
        assert web.get("/healthz").status_code == 200
    assert slept == [watchdog.TICK_S]  # started; the shutdown cancelled it without an error


# --- rule 3: dangling minions -------------------------------------------------------------------

async def test_dangling_minions_are_removed(dog, configured_store, fake, tmp_path, clock, monkeypatch):
    store = configured_store
    docker = FakeDocker().install(monkeypatch)
    await run_aged(store, fake, "live", tmp_path, clock, 60)
    await run_aged(store, fake, "done", tmp_path, clock, 60)
    store.update_run("done", cleanup_mode="full", cleanup_status="done")
    keep = docker.add("robot-live-minion-0001", "live")
    foreign = docker.add("someone-elses", None)
    docker.add("robot-done-minion-0001", "done")
    docker.add("robot-gone-minion-0001", "gone")
    docker.add("robot-gone-minion-0002", "gone")
    fake.calls.clear()
    await dog.tick()
    assert set(docker.containers) == {keep["Id"], foreign["Id"]}
    assert fake.calls == []


async def test_minions_of_a_run_that_is_rolling_back_stay(dog, configured_store, fake, tmp_path, clock, monkeypatch):
    docker = FakeDocker().install(monkeypatch)
    await run_aged(configured_store, fake, "r1", tmp_path, clock, 60)
    configured_store.update_run("r1", cleanup_mode="full", cleanup_status="running")
    docker.add("robot-r1-minion-0001", "r1")
    await dog.tick()
    assert len(docker.containers) == 1


async def test_an_unreachable_launcher_is_logged_and_skipped(dog, monkeypatch, caplog):
    monkeypatch.setattr(minions, "LAUNCHER", "http://127.0.0.1:9")  # nothing listens there
    await dog.tick()
    assert "cannot list minions" in caplog.text


async def test_a_failing_removal_is_logged_and_the_next_run_still_cleaned(dog, monkeypatch, caplog):
    docker = FakeDocker().install(monkeypatch)
    docker.add("robot-gone1-minion-0001", "gone1")
    docker.add("robot-gone2-minion-0001", "gone2")
    real = minions.remove_run

    async def remove_run(run_id):
        if run_id == "gone1":
            raise minions.MinionError("refused")
        return await real(run_id)

    monkeypatch.setattr(minions, "remove_run", remove_run)
    await dog.tick()
    assert [c["name"] for c in docker.running()] == ["robot-gone1-minion-0001"]
    assert "cannot remove the minions of run gone1" in caplog.text


async def test_without_a_launcher_no_minion_call_is_made(dog, monkeypatch):
    monkeypatch.setattr(minions, "LAUNCHER", "")

    async def boom():
        raise AssertionError("launcher called")

    monkeypatch.setattr(minions, "labelled_runs", boom)
    await dog.tick()


# --- the runs list's lifetime clock -------------------------------------------------------------

@pytest.mark.parametrize("minutes, quarter", [(0, 0), (44, 0), (45, 1), (89, 1), (90, 2), (134, 2), (135, 3),
                                              (179, 3), (240, 3), (-5, 0)])
def test_the_clock_fills_in_quarters_of_45_minutes(minutes, quarter):
    started = datetime(2026, 10, 27, 11, 32, tzinfo=timezone.utc)
    run = {"created_at": started.isoformat(), "cleanup_mode": None, "cleanup_status": None}
    at = (started + timedelta(minutes=minutes)).timestamp()
    assert watchdog.lifetime(run, at) == {"quarter": quarter, "due": "14:32"}


def test_the_clock_is_gone_once_rolled_back():
    run = {"created_at": "2026-10-27T11:32:00+00:00", "cleanup_mode": "full", "cleanup_status": "done"}
    assert watchdog.lifetime(run, 0) is None


def test_the_runs_list_shows_the_clock_until_the_rollback(configured_user, store):
    import re
    from tests.component.test_web_runs import finished, form
    configured_user.post("/runs", data=form())
    started = datetime.fromisoformat(finished(store, "r1")["created_at"])
    due = (started + timedelta(seconds=watchdog.LIFETIME_S)).strftime("%H:%M")
    html = configured_user.get("/").text
    clock = re.search(r'<span class="lifetime ([a-z0-9 ]+)"[^>]*data-tip="([^"]+)"', html)
    assert clock and clock.groups() == ("q0", f"Rolled back automatically at {due} UTC")
    store.update_run("r1", created_at=_iso(datetime.now(timezone.utc).timestamp() - 140 * 60))
    html = configured_user.get("/").text
    assert 'class="lifetime q3 late"' in html and 'd="M12 12V3A9 9 0 1 1 3 12z"' in html
    store.update_run("r1", cleanup_mode="full", cleanup_status="done")
    assert 'class="lifetime' not in configured_user.get("/").text
