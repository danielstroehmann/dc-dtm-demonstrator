"""UC-8 minions: the app's client (app/minions.py) asks the launcher service (app/launcher.py), which alone talks
to Docker behind the socket proxy – container start/removal with checked values only, and what the tile reads
from a minion's log (multiplexed frames, timestamps, TrustEdge's lifecycle)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import launcher, minions
from tests.fakedocker import FakeDocker, frame


@pytest.fixture
def docker(monkeypatch) -> FakeDocker:
    return FakeDocker().install(monkeypatch)


def event(name: str) -> str:
    return json.dumps({"minion": "robot-t1-uc08-iot-minion-0001", "event": name}, separators=(",", ":"))


def firmware(version: int) -> str:
    return json.dumps({"minion": "robot-t1-uc08-iot-minion-0001", "event": "firmware", "version": version},
                      separators=(",", ":"))


def at(minute: int, second: int) -> str:
    return f"2026-10-27T10:{minute:02d}:{second:02d}.123456789Z"


# --- lines: Docker's multiplexed log stream (launcher) ------------------------------------------------------------

def test_lines_join_frames_of_both_streams():
    raw = frame("one\ntw", 1) + frame("o\n", 2) + frame("three\n", 1)
    assert launcher.lines(raw) == ["one", "two", "three"]


def test_lines_ignore_a_truncated_header_and_decode_leniently():
    raw = frame("ok\n") + frame("caf\xe9\n")[:-3] + b"\x01\x00\x00"  # cut body, then a partial header
    lines = launcher.lines(frame("ok\n") + b"\x01\x00\x00\x00\x00\x00\x00\x02\xff\xfe" + b"\x01\x00")
    assert lines == ["ok", "��"]
    assert launcher.lines(raw)[0] == "ok"
    assert launcher.lines(b"") == []


# --- state: what the tile shows ------------------------------------------------------------------------

async def test_state_reads_event_firmware_and_agent(docker):
    c = docker.add("robot-t1-uc08-iot-minion-0001", "t1", logs=[
        (at(0, 0), event("bootstrap_enrolling")),
        (at(0, 5), event("configured")),
        (at(0, 10), "INFO Starting connection to MQTT endpoint mqtt.example"),
        (at(0, 11), "INFO Connected to endpoint mqtt.example"),
        (at(0, 20), "INFO Writing issued certificate to /var/lib/trustedge"),
        (at(0, 21), firmware(3)),
        (at(0, 22), '{"minion":"x","event":"<script>"}'),  # no event of ours – the pattern refuses it
    ])
    seen = await minions.state(c["Id"])
    assert seen["status"] == "running" and seen["event"] == "configured" and seen["firmware"] == 3
    assert (seen["agent"], seen["since"]) == ("certificate received", "2026-10-27T10:00:20")


async def test_state_of_a_stopped_or_gone_container(docker):
    c = docker.add("robot-t1-uc08-iot-minion-0001", "t1", status="exited",
                   logs=[(at(0, 0), "INFO Connected to endpoint x"), (at(0, 1), firmware(2))])
    seen = await minions.state(c["Id"])
    assert seen["status"] == "exited" and seen["firmware"] == 2
    assert seen["agent"] is None and seen["since"] is None and seen["next_connect"] is None  # only while running
    gone = await minions.state("0123456789abcdef")
    assert gone["status"] == "gone" and gone["agent"] is None and gone["firmware"] is None


async def test_a_pending_check_turns_online_after_a_while(docker):
    recent = (datetime.now(timezone.utc) - timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    c = docker.add("robot-t1-uc08-iot-minion-0001", "t1", logs=[(recent, "INFO Processing pending policies")])
    assert (await minions.state(c["Id"]))["agent"] == "checking for updates"
    old = docker.add("robot-t1-uc08-iot-minion-0002", "t1", logs=[(at(0, 0), "INFO Processing pending policies")])
    assert (await minions.state(old["Id"]))["agent"] == "online"  # nothing pending leaves no further line


def test_next_connect_defaults_without_a_full_cycle():
    connect = datetime(2026, 10, 27, 10, 0, 10, tzinfo=timezone.utc)
    assert minions._next_connect([], []) is None
    # online since 10:00:10 – the defaults: 100 s online, 10 s offline
    assert minions._next_connect([connect], []) == "2026-10-27T10:02:00Z"


def test_next_connect_learns_the_cycle_while_online():
    """Connected 50 s, offline 20 s, connected again: the next connect follows the observed cycle."""
    c1 = datetime(2026, 10, 27, 10, 0, 10, tzinfo=timezone.utc)
    e1, c2 = c1 + timedelta(seconds=50), c1 + timedelta(seconds=70)
    assert minions._next_connect([c1, c2], [e1]) == "2026-10-27T10:02:30Z"  # c2 + 50 s + 20 s


def test_next_connect_learns_the_cycle_while_offline():
    c1 = datetime(2026, 10, 27, 10, 0, 10, tzinfo=timezone.utc)
    e1, c2, e2 = (c1 + timedelta(seconds=s) for s in (50, 70, 120))
    assert minions._next_connect([c1, c2], [e1, e2]) == "2026-10-27T10:02:30Z"  # e2 + 20 s offline


# --- container lifecycle (through the launcher) -------------------------------------------------------

ENV = {"DTM_HOST": "one.digicert.com", "SERIAL": "SN-T1-0001", "BOOT_POLICY": "IOT_abc-1", "GROUP_ID": "g-1",
       "PASSCODE": "0123456789abcdef0123456789abcdef"}


async def test_start_creates_a_labelled_unprivileged_container(docker):
    container = await minions.start("t1", "robot-t1-uc08-iot-minion-0001", ENV)
    (created,) = docker.containers.values()
    assert created["Id"] == container and created["status"] == "running"
    body = created["body"]
    assert body["Image"] == launcher.IMAGE and body["Labels"] == {launcher.LABEL: "t1"}
    assert sorted(body["Env"]) == sorted(f"{k}={v}" for k, v in ENV.items())
    host = body["HostConfig"]
    assert "Binds" not in host and "Mounts" not in body and not host.get("Privileged") and "CapAdd" not in host
    assert host["SecurityOpt"] == ["no-new-privileges:true"] and host["NetworkMode"] == launcher.NETWORK


@pytest.mark.parametrize("run_id,name", [
    ("t1", "../etc"), ("t1", "robot-t1-uc08-iot-minion-0001;rm"), ("t1", "ROBOT-x-y"), ("t1", "other-t1-x"),
    ("t1", "robot-" + "a" * 17 + "-x"), ("t1", ""), ("T1", "robot-t1-uc08-iot-minion-0001"),
    ("t1/../x", "robot-t1-uc08-iot-minion-0001"),
])
async def test_launcher_refuses_unexpected_names(docker, run_id, name):
    with pytest.raises(minions.MinionError, match="refused"):
        await minions.start(run_id, name, ENV)
    assert docker.requests == []


@pytest.mark.parametrize("change", [
    {"EXTRA": "1"},                                   # only the known variables
    {"DTM_HOST": "evil.example.com"},
    {"SERIAL": "SN-T1-0001\nX=1"},
    {"PASSCODE": "short"},
    {"BOOT_POLICY": "../x"},
    {"GROUP_ID": "a b"},
])
async def test_launcher_refuses_an_unexpected_environment(docker, change):
    with pytest.raises(minions.MinionError, match="unexpected minion environment"):
        await minions.start("t1", "robot-t1-uc08-iot-minion-0001", ENV | change)
    assert docker.requests == []


async def test_a_container_that_does_not_start_is_removed(docker):
    docker.fail_start = True
    with pytest.raises(minions.MinionError, match="returned 500"):
        await minions.start("t1", "robot-t1-uc08-iot-minion-0001", ENV)
    assert docker.containers == {} and [a for a, _ in docker.calls] == ["create", "start", "delete"]


@pytest.mark.parametrize("filter_ignored", [False, True])
async def test_remove_run_removes_only_the_runs_containers(docker, filter_ignored):
    docker.filter_ignored = filter_ignored
    mine = [docker.add(f"robot-t1-uc08-iot-minion-000{i}", "t1") for i in (1, 2)]
    other = docker.add("robot-t2-uc08-iot-minion-0001", "t2")
    foreign = docker.add("postgres", None)  # not the launcher's
    assert await minions.remove_run("t1") == 2
    assert set(docker.containers) == {other["Id"], foreign["Id"]} and not {c["Id"] for c in mine} & set(docker.containers)


@pytest.mark.parametrize("filter_ignored", [False, True])
async def test_labelled_runs_lists_only_labelled_containers_read_only(docker, filter_ignored):
    docker.filter_ignored = filter_ignored
    for name, run_id in (("robot-t1-minion-0001", "t1"), ("robot-t1-minion-0002", "t1"), ("robot-t2-minion-0001", "t2"),
                         ("odd", "Not/A-Run"), ("empty", "")):
        docker.add(name, run_id)
    docker.add("postgres", None)  # not the launcher's
    assert await minions.labelled_runs() == ["t1", "t2"]
    assert all(r.method == "GET" for r in docker.requests) and len(docker.containers) == 6


async def test_remove_run_refuses_an_unexpected_run_id(docker):
    with pytest.raises(minions.MinionError, match="refused"):
        await minions.remove_run("t1&all=1")
    assert docker.requests == []


@pytest.mark.parametrize("container", ["not-hex", "abc", "0" * 65, "../images"])
async def test_state_only_for_container_ids(docker, container):
    with pytest.raises(minions.MinionError, match="refused"):
        await minions.state(container)
    assert docker.requests == []


async def test_state_never_reads_a_container_the_launcher_did_not_create(docker):
    foreign = docker.add("postgres", None, logs=[(at(0, 0), "secret")])
    with pytest.raises(minions.MinionError, match="unknown container"):
        await minions.state(foreign["Id"])
    assert not [r for r in docker.requests if r.url.path.endswith("/logs")]


async def test_available_needs_the_launcher_and_the_image(docker, monkeypatch):
    assert await minions.available() is True
    docker.image_present = False
    assert await minions.available() is False
    monkeypatch.setattr(launcher, "DOCKER", "")  # the launcher has no Docker
    assert await minions.available() is False
    monkeypatch.setattr(minions, "LAUNCHER", "")
    assert await minions.available() is False


async def test_launcher_errors_become_minion_errors(docker, monkeypatch):
    monkeypatch.setattr(launcher, "DOCKER", "")
    with pytest.raises(minions.MinionError, match="no minion runtime configured"):
        await minions.remove_run("t1")
    monkeypatch.setattr(minions, "LAUNCHER", "")
    with pytest.raises(minions.MinionError, match="no minion runtime configured"):
        await minions.remove_run("t1")


async def test_unreachable_launcher(monkeypatch):
    monkeypatch.setattr(minions, "LAUNCHER", "http://127.0.0.1:9")  # nothing listens there
    with pytest.raises(minions.MinionError, match="not reachable"):
        await minions.remove_run("t1")
    assert await minions.available() is False


async def test_launcher_refuses_minions_above_the_host_cap(monkeypatch):
    """The cap holds in the launcher itself – a compromised app cannot exhaust the host with minions."""
    from fastapi import HTTPException

    from app import launcher

    class Listed:
        def json(self):
            return [{"Id": f"{i:064x}", "Labels": {launcher.LABEL: "r1"}} for i in range(launcher.MAX_MINIONS)]

    calls = []

    async def fake_call(method, path, expect=(200,), **kwargs):
        calls.append((method, path))
        return Listed()
    monkeypatch.setattr(launcher, "_call", fake_call)
    minion = launcher.Minion(run_id="r1", name="robot-r1-uc08-iot-minion-0001", env={"SERIAL": "SN-R1-0001"})
    with pytest.raises(HTTPException) as refused:
        await launcher.start(minion)
    assert refused.value.status_code == 429 and ("POST", "/containers/create") not in calls
