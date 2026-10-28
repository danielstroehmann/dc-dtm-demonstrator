"""Watchdog edge cases beyond the main flow (independent test agent): partial and failed rollbacks, restart with an
old login, exact backoff, isolation of failures, the manual rollback racing the watchdog, a shutdown during an
automatic rollback, login recording, the runs list's clock and access control. Fake DTM and fake Docker only."""

import asyncio
import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.routing import APIRoute

from app import launcher, watchdog
from app.auth import COOKIE, Auth
from app.main import create_app
from app.store import rolled_back
from tests.conftest import PASSWORD, SECRET, make_web
from tests.fakedocker import FakeDocker
from tests.fakedtm import API_KEY, HOST, OTHER_ACCOUNT_ID
from tests.integration.test_watchdog import HOUR, Clock, _iso, dtm_down, messages, run_aged


@pytest.fixture
def clock() -> Clock:
    return Clock()


def new_dog(store, auth, fake, data_dir, clock, last_login_age: float | None = 0.0):
    """A freshly started app's watchdog (a restart: its own start time), with a login that long ago (None: none)."""
    app = create_app(store, auth, client_factory=fake.factory(), data_dir=data_dir)
    dog = app.state.watchdog
    dog.clock, dog.started = clock, clock.now
    if last_login_age is None:
        store.delete_setting(watchdog.LAST_LOGIN)
    else:
        store.set_setting(watchdog.LAST_LOGIN, _iso(clock.now - last_login_age))
    return app, dog


@pytest.fixture
def app_dog(configured_store, auth, fake, data_dir, clock):
    return new_dog(configured_store, auth, fake, data_dir, clock)


@pytest.fixture
def dog(app_dog):
    return app_dog[1]


def automatic(store, run_id) -> list[str]:
    return [m for m in messages(store, run_id) if m.startswith(("Automatic", "Rolled back automatically"))]


def called(fake, name) -> int:
    return sum(1 for n, _ in fake.calls if n == name)


# --- rule 1: what counts as rolled back ---------------------------------------------------------

async def test_a_certificates_only_cleanup_does_not_count_as_rolled_back(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    store.update_run("old", cleanup_mode="certificates", cleanup_status="done")
    await dog.tick()
    assert rolled_back(store.get_run("old")), messages(store, "old")
    assert not fake.policies and not fake.divisions  # the configuration went too, not only the certificates


@pytest.mark.parametrize("left", ["failed", "interrupted"])
async def test_a_failed_or_interrupted_manual_rollback_is_finished_by_the_watchdog(
        dog, configured_store, fake, tmp_path, clock, left):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    store.update_run("old", cleanup_mode="full", cleanup_status=left)
    await dog.tick()
    assert rolled_back(store.get_run("old")), messages(store, "old")
    assert "Rolled back automatically – 3 h lifetime" in messages(store, "old")


async def test_a_busy_young_run_is_not_touched_and_no_client_is_built(dog, configured_store, fake, tmp_path, clock):
    """Nothing due: not even a DTM client is created (no connection is read for DTM)."""
    store = configured_store
    await run_aged(store, fake, "young", tmp_path, clock, HOUR)
    await run_aged(store, fake, "done", tmp_path, clock, 5 * HOUR)
    store.update_run("done", cleanup_mode="full", cleanup_status="done")

    def boom(_run_id):
        raise AssertionError("client built although nothing is due")

    dog.client_for = boom
    fake.calls.clear()
    await dog.tick()
    assert fake.calls == [] and automatic(store, "young") == [] and automatic(store, "done") == []


# --- rule 2: restart with an old login ------------------------------------------------------------

async def test_a_restart_does_not_reset_an_old_login(configured_store, auth, fake, data_dir, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "young", tmp_path, clock, 60)
    _, dog = new_dog(store, auth, fake, data_dir, clock, last_login_age=watchdog.IDLE_S + HOUR)  # app just started
    await dog.tick()
    assert rolled_back(store.get_run("young")), messages(store, "young")
    assert "Rolled back automatically – no login for 24 h" in messages(store, "young")


async def test_without_a_login_a_restart_counts_from_its_own_start(configured_store, auth, fake, data_dir, tmp_path,
                                                                   clock):
    store = configured_store
    await run_aged(store, fake, "young", tmp_path, clock, 60)
    _, dog = new_dog(store, auth, fake, data_dir, clock, last_login_age=None)
    clock.now += watchdog.IDLE_S - 60
    store.update_run("young", created_at=_iso(clock.now - 60))  # still young: only rule 2 can apply
    await dog.tick()
    assert store.get_run("young")["cleanup_status"] is None
    clock.now += 60
    store.update_run("young", created_at=_iso(clock.now - 60))
    await dog.tick()
    assert rolled_back(store.get_run("young")), messages(store, "young")


async def test_a_login_after_an_idle_day_stops_rule_2(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "young", tmp_path, clock, 60)
    dog.started = clock.now - 2 * watchdog.IDLE_S  # the app has been up for two days, nobody logged in for one
    store.set_setting(watchdog.LAST_LOGIN, _iso(clock.now - watchdog.IDLE_S - HOUR))
    clock.now -= HOUR  # a tick an hour earlier would not have acted yet – then somebody logs in
    store.set_setting(watchdog.LAST_LOGIN, _iso(clock.now - 10))
    clock.now += HOUR
    await dog.tick()
    assert store.get_run("young")["cleanup_status"] is None


# --- backoff -------------------------------------------------------------------------------------

def gone_account(store, run_id):
    """The run's account is no longer configured: every attempt fails before DTM."""
    store.update_run(run_id, params=store.get_run(run_id)["params"] | {"account_id": OTHER_ACCOUNT_ID,
                                                                       "connection_id": None})


def counting(dog):
    """Wraps client_for: the number of rollback attempts is the number of clients asked for."""
    asked, real = [], dog.client_for

    def client_for(run_id):
        asked.append(run_id)
        return real(run_id)

    dog.client_for = client_for
    return asked


def attempts(store, run_id) -> int:
    """Automatic rollbacks that reached DTM."""
    return sum(m.startswith("Automatic full rollback") for m in messages(store, run_id))


async def test_the_backoff_waits_30_then_60_minutes_and_never_hot_loops(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    dog.client_for = dtm_down(dog)  # DTM answers 503 to everything
    t0 = clock.now
    schedule = [(0, 1), (watchdog.TICK_S, 1), (watchdog.RETRY_S - 1, 1), (watchdog.RETRY_S, 2),
                (watchdog.RETRY_S + 2 * watchdog.TICK_S, 2), (3 * watchdog.RETRY_S - 1, 2), (3 * watchdog.RETRY_S, 3)]
    for offset, expected in schedule:
        clock.now = t0 + offset
        await dog.tick()
        assert attempts(store, "old") == expected, (offset, messages(store, "old"))
    assert not rolled_back(store.get_run("old"))


async def test_a_failing_run_does_not_block_the_next_one(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "bad", tmp_path, clock, 5 * HOUR)
    await run_aged(store, fake, "good", tmp_path, clock, 4 * HOUR)
    gone_account(store, "bad")
    for _ in range(3):  # at most a few ticks, whatever the per-tick limit
        await dog.tick()
        clock.now += watchdog.TICK_S
    assert rolled_back(store.get_run("good")), messages(store, "good")
    assert not rolled_back(store.get_run("bad"))


async def test_a_changed_connection_is_never_used_for_the_runs_account(dog, configured_store, fake, tmp_path, clock):
    """The run's bound connection now points to another account: no DTM call at all (not via the new account)."""
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    conn_id = store.connection(None)["id"]
    store.update_run("old", params=store.get_run("old")["params"] | {"connection_id": conn_id})
    store.save_connection(conn_id, "Default", HOST, OTHER_ACCOUNT_ID, API_KEY)
    fake.calls.clear()
    await dog.tick()
    assert fake.calls == [] and store.get_run("old")["cleanup_status"] is None


async def test_an_unexpected_client_error_is_contained(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    asked = []

    def broken(run_id):
        asked.append(run_id)
        raise KeyError("params")

    dog.client_for = broken
    fake.calls.clear()
    await dog.tick()  # no exception escapes the tick
    clock.now += watchdog.TICK_S
    await dog.tick()
    assert asked and fake.calls == [] and not rolled_back(store.get_run("old"))
    assert attempts(store, "old") == 0


async def test_a_deleted_run_with_a_pending_retry_is_ignored(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    working, dog.client_for = dog.client_for, dtm_down(dog)
    await dog.tick()  # fails, a retry is pending
    dog.client_for = working
    store.delete_run("old")
    clock.now += watchdog.MAX_RETRY_S
    asked = counting(dog)
    fake.calls.clear()
    await dog.tick()
    assert fake.calls == [] and asked == []


# --- the manual rollback racing the watchdog -----------------------------------------------------

def browser(app, auth):
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://testserver")
    client.cookies.set(COOKIE, auth.issue())
    return client


async def wait_until(predicate, what):
    for _ in range(5000):
        if predicate():
            return
        await asyncio.sleep(0)
        await asyncio.sleep(0.001)
    raise AssertionError(f"timed out waiting for {what}")


async def test_the_button_is_refused_while_the_watchdog_rolls_back(app_dog, auth, configured_store, fake, tmp_path,
                                                                   clock):
    app, dog = app_dog
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    fake.revoke_delay = 0.05
    tick = asyncio.create_task(dog.tick())
    await wait_until(lambda: store.get_run("old")["cleanup_status"] == "running", "the automatic rollback")
    async with browser(app, auth) as web:
        response = await web.post("/runs/old/cleanup", data={"mode": "full"})
    assert response.status_code == 409
    await tick
    assert rolled_back(store.get_run("old")), messages(store, "old")
    assert called(fake, "policy_delete") == 1


async def test_the_watchdog_skips_a_run_the_button_is_rolling_back(app_dog, auth, configured_store, fake, tmp_path,
                                                                   clock):
    app, dog = app_dog
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    fake.revoke_delay = 0.05
    async with browser(app, auth) as web:
        response = await web.post("/runs/old/cleanup", data={"mode": "full"})
    assert response.status_code == 303
    await dog.tick()
    await wait_until(lambda: rolled_back(store.get_run("old")), "the manual rollback")
    assert automatic(store, "old") == []
    assert called(fake, "policy_delete") == 1


async def test_button_and_watchdog_at_the_same_moment_roll_back_once(app_dog, auth, configured_store, fake, tmp_path,
                                                                     clock):
    app, dog = app_dog
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    fake.revoke_delay = 0.02
    async with browser(app, auth) as web:
        response, _ = await asyncio.gather(web.post("/runs/old/cleanup", data={"mode": "full"}), dog.tick())
    await wait_until(lambda: rolled_back(store.get_run("old")), "the rollback")
    await asyncio.sleep(0.1)  # a second cleanup would still be running now
    assert called(fake, "policy_delete") == 1 and called(fake, "division_delete") == 1
    # exactly one of the two acted
    assert (response.status_code == 303) != bool(automatic(store, "old")), (response.status_code, automatic(store, "old"))


# --- shutdown during an automatic rollback --------------------------------------------------------

async def test_a_shutdown_mid_rollback_cancels_cleanly_and_the_next_start_finishes_it(
        app_dog, configured_store, auth, fake, data_dir, tmp_path, clock):
    _, dog = app_dog
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    fake.revoke_delay = 5.0  # the rollback hangs on DTM
    slept = []

    async def sleep(seconds):
        slept.append(seconds)
        if len(slept) > 1:
            await asyncio.Event().wait()

    dog.sleep = sleep
    task = asyncio.create_task(dog.run())
    await wait_until(lambda: store.get_run("old")["cleanup_status"] == "running", "the automatic rollback")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 2)
    assert task.cancelled()
    fake.revoke_delay = 0.0
    _, restarted = new_dog(store, auth, fake, data_dir, clock)  # the restart marks the cleanup interrupted
    assert store.get_run("old")["cleanup_status"] == "interrupted"
    await restarted.tick()
    assert rolled_back(store.get_run("old")), messages(store, "old")


# --- last login: only successful /login and /setup ------------------------------------------------

def test_a_successful_setup_is_recorded_a_refused_one_not(store, fake, data_dir):
    with make_web(store, Auth(None, SECRET, store=store), fake, data_dir) as web:
        for password, repeat in (("short", "short"), ("a long enough password 1", "a different password 12")):
            assert web.post("/setup", data={"password": password, "repeat": repeat},
                            follow_redirects=False).status_code == 400
        assert store.get_setting(watchdog.LAST_LOGIN) is None
        good = "first visitor's password 7"
        assert web.post("/setup", data={"password": good, "repeat": good}, follow_redirects=False).status_code == 303
    assert store.get_setting(watchdog.LAST_LOGIN) is not None


def test_setup_when_a_password_exists_records_nothing(store, auth, fake, data_dir):
    with make_web(store, auth, fake, data_dir) as web:
        response = web.post("/setup", data={"password": PASSWORD, "repeat": PASSWORD}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert store.get_setting(watchdog.LAST_LOGIN) is None


def test_a_rate_limited_login_is_not_recorded(store, auth, fake, data_dir):
    with make_web(store, auth, fake, data_dir) as web:
        for _ in range(5):
            assert web.post("/login", data={"password": "wrong password!!"}).status_code == 401
        response = web.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert response.status_code == 429
    assert store.get_setting(watchdog.LAST_LOGIN) is None


def test_browsing_with_a_session_does_not_count_as_a_login(user, store):
    store.delete_setting(watchdog.LAST_LOGIN)
    assert user.get("/").status_code == 200
    assert store.get_setting(watchdog.LAST_LOGIN) is None


def test_a_login_overwrites_an_older_one(store, auth, fake, data_dir):
    store.set_setting(watchdog.LAST_LOGIN, "2020-01-01T00:00:00+00:00")
    with make_web(store, auth, fake, data_dir) as web:
        web.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    recorded = datetime.fromisoformat(store.get_setting(watchdog.LAST_LOGIN))
    assert recorded.tzinfo is not None
    assert abs((datetime.now(timezone.utc) - recorded).total_seconds()) < 60


# --- rule 3: one launcher call per tick, only the right runs -------------------------------------

async def test_a_tick_makes_one_read_only_launcher_call_when_nothing_dangles(dog, configured_store, fake, tmp_path,
                                                                             clock, monkeypatch):
    docker = FakeDocker().install(monkeypatch)
    await run_aged(configured_store, fake, "live", tmp_path, clock, 60)
    docker.add("robot-live-minion-0001", "live")
    await dog.tick()
    assert [(r.method, r.url.path.removeprefix(launcher.API_VERSION)) for r in docker.requests] == [("GET", "/containers/json")]
    assert len(docker.containers) == 1


@pytest.mark.parametrize("state", [{"cleanup_mode": "full", "cleanup_status": "failed"},
                                   {"cleanup_mode": "certificates", "cleanup_status": "done"},
                                   {"status": "failed"}])
async def test_minions_of_a_run_not_fully_rolled_back_stay(dog, configured_store, fake, tmp_path, clock,
                                                           monkeypatch, state):
    docker = FakeDocker().install(monkeypatch)
    await run_aged(configured_store, fake, "r1", tmp_path, clock, 60)
    configured_store.update_run("r1", **state)
    docker.add("robot-r1-minion-0001", "r1")
    await dog.tick()
    assert len(docker.containers) == 1


async def test_minions_of_a_run_deleted_after_its_rollback_go(app_dog, auth, configured_store, fake, tmp_path, clock,
                                                              monkeypatch):
    app, dog = app_dog
    docker = FakeDocker().install(monkeypatch)
    await run_aged(configured_store, fake, "r1", tmp_path, clock, 60)
    configured_store.update_run("r1", cleanup_mode="full", cleanup_status="done")
    docker.add("robot-r1-minion-0001", "r1")
    async with browser(app, auth) as web:
        assert (await web.post("/runs/r1/delete")).status_code == 303
    assert not configured_store.run_exists("r1")
    await dog.tick()
    assert docker.containers == {}


# --- the runs list's clock -----------------------------------------------------------------------

@pytest.mark.parametrize("minutes, cls, arc", [
    (10, "lifetime q0", None),
    (50, "lifetime q1", "0 0 1 21 12"),
    (100, "lifetime q2", "0 0 1 12 21"),
    (150, "lifetime q3 late", "0 1 1 3 12"),
])
def test_the_clock_is_green_up_to_half_and_orange_from_three_quarters(configured_user, store, minutes, cls, arc):
    from tests.component.test_web_runs import finished, form
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    store.update_run("r1", created_at=_iso(datetime.now(timezone.utc).timestamp() - minutes * 60))
    html = configured_user.get("/").text
    span = re.search(r'<span class="(lifetime[^"]*)"[^>]*>(.*?)</span>', html, re.S)
    assert span and span.group(1) == cls
    paths = re.findall(r'<path [^>]*d="M12 12V3A9 9 ([0-9 ]+)z"', span.group(2))
    assert paths == ([arc] if arc else [])


def test_the_clock_is_shown_for_a_failed_run_and_due_is_utc(configured_user, store):
    from tests.component.test_web_runs import finished, form
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    started = datetime.now(timezone.utc) - timedelta(minutes=10)  # the page uses the real clock
    store.update_run("r1", status="failed", created_at=started.isoformat())
    html = configured_user.get("/").text
    assert f'data-tip="Rolled back automatically at {(started + timedelta(hours=3)):%H:%M} UTC"' in html
    # across midnight, in UTC
    midnight = {"created_at": datetime(2026, 10, 27, 23, 10, tzinfo=timezone.utc).isoformat(), "status": "failed"}
    at = datetime(2026, 10, 28, 0, 0, tzinfo=timezone.utc).timestamp()
    assert watchdog.lifetime(midnight, at)["tip"] == "Rolled back automatically at 02:10 UTC"


# --- OWASP: the app has no new unauthenticated endpoint -----------------------------------------

def test_every_route_but_login_setup_and_health_needs_a_login(web):
    public = {"/login", "/setup", "/healthz", "/version"}  # build identity: no secrets, for every build
    checked = 0
    for route in web.app.routes:
        if not isinstance(route, APIRoute) or route.path in public:
            continue
        path = re.sub(r"\{[^}]+\}", "x1", route.path)
        for method in route.methods - {"HEAD"}:
            response = web.request(method, path, follow_redirects=False)
            assert response.status_code == 303 and response.headers["location"] == "/login", (method, path)
            checked += 1
    assert checked > 20


# --- parking, the per-tick limit and instance isolation (review fixes) ---------------------------

async def park(dog, store, clock, run_id):
    working, dog.client_for = dog.client_for, dtm_down(dog)
    for _ in range(watchdog.MAX_FAILURES):
        await dog.tick()
        clock.now += watchdog.MAX_RETRY_S
    dog.client_for = working
    assert watchdog.parked(store.get_run(run_id))


async def test_a_parked_run_can_still_be_rolled_back_by_hand(app_dog, auth, configured_store, fake, tmp_path, clock):
    app, dog = app_dog
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    await park(dog, store, clock, "old")
    async with browser(app, auth) as web:
        assert (await web.post("/runs/old/cleanup", data={"mode": "full"})).status_code == 303
    await wait_until(lambda: rolled_back(store.get_run("old")), "the manual rollback")


async def test_a_parked_run_is_left_alone_by_rule_2_too(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    await park(dog, store, clock, "old")
    store.set_setting(watchdog.LAST_LOGIN, _iso(clock.now - 2 * watchdog.IDLE_S))
    events = len(store.events("old"))
    fake.calls.clear()
    await dog.tick()
    assert fake.calls == [] and len(store.events("old")) == events


async def test_a_busy_oldest_run_does_not_use_up_the_tick(dog, configured_store, fake, tmp_path, clock):
    store = configured_store
    await run_aged(store, fake, "busy", tmp_path, clock, 6 * HOUR)
    await run_aged(store, fake, "old", tmp_path, clock, 4 * HOUR)
    store.update_run("busy", status="renewing")
    await dog.tick()
    assert rolled_back(store.get_run("old")) and store.get_run("busy")["cleanup_status"] is None


@pytest.mark.parametrize("filter_ignored", [False, True])
async def test_the_same_run_id_on_another_install_keeps_its_minions(dog, monkeypatch, filter_ignored):
    """Run IDs are short and random – another install's run may carry the same ID as one deleted here."""
    docker = FakeDocker().install(monkeypatch)
    docker.filter_ignored = filter_ignored  # a proxy that ignores the filter: the launcher re-checks
    docker.add("robot-gone-minion-0001", "gone")
    theirs = docker.add("robot-gone-minion-0002", "gone", instance="other-demonstrator")
    await dog.tick()
    assert set(docker.containers) == {theirs["Id"]}
