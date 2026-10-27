"""UC-8 – TrustEdge managed devices against the fake DTM and a fake Docker Engine API: the factory registers
each device with a one-time passcode bound to its serial number, the IoT minion (a container) gets its
certificates in the field, devices are added per click, firmware versions are built and deployed, and the
rollback removes the containers before it touches DTM."""

import json
import stat

import httpx
import pytest

from app import cleanup, devices, firmware, launcher, minions, trustedge
from tests.fakedocker import FakeDocker
from tests.fakedtm import ACCOUNT_ID, ECDSA_CA_ID, OTHER_ACCOUNT_ID, FakeDTM

UC = "uc08"


def params(fake: FakeDTM, **overrides) -> dict:
    return {"dtm_host": fake.host, "account_id": ACCOUNT_ID, "variant": "api", "mode": "single", "count": 1,
            "ca_id": ECDSA_CA_ID, "ca_name": "Fake ECDSA ICA", "key_type": "P_256", "approval": False,
            "protocol": "trustedge", "auth": "passcode", "pause": True} | overrides


def events(store, run_id) -> str:
    return "\n".join(e["message"] for e in store.events(run_id))


def policy(fake: FakeDTM, suffix: str) -> dict:
    return next(p for p in fake.policies.values() if p["name"].endswith(suffix))


class Minion:
    """Plays the device in the field: on start it checks its passcode against DTM's (bound to its serial number),
    then DTM files the bootstrap (CN = serial) and the operational certificate (CN = name) under the device."""

    def __init__(self, fake: FakeDTM, docker: FakeDocker):
        self.fake, self.docker, self.started = fake, docker, []
        self.behaviour = "operational"
        docker.on_start = self

    def __call__(self, container: dict) -> None:
        env = dict(e.split("=", 1) for e in container["body"]["Env"])
        self.started.append(env)
        device = next(d for d in self.fake.devices.values() if d["name"] == container["name"])
        passcode = next(o for o in self.fake.active_auth("passcode") if o["body"]["passcode"] == env["PASSCODE"])
        assert passcode["registered_cn"] == env["SERIAL"] == device["attributes"][0]["value"]
        if self.behaviour == "exits":
            container["status"] = "exited"
            return
        stamp = "2026-10-27T10:00:0{}.000Z"
        self.docker.log(container["Id"], stamp.format(1), '{"minion":"m","event":"bootstrap_enrolled"}')
        boot, _c, _k = self.fake._new_certificate(policy(self.fake, "-boot-policy")["id"], env["SERIAL"])
        boot["device_id"] = device["id"]
        if self.behaviour == "operational":
            self.docker.log(container["Id"], stamp.format(2), "INFO Writing issued certificate")
            op, _c, _k = self.fake._new_certificate(policy(self.fake, "-op-policy")["id"], device["name"])
            op["device_id"] = device["id"]


@pytest.fixture
def docker(monkeypatch) -> FakeDocker:
    return FakeDocker().install(monkeypatch)


@pytest.fixture
def minion(fake, docker) -> Minion:
    return Minion(fake, docker)


async def start(store, fake: FakeDTM, run_id: str, tmp_path, **overrides) -> dict:
    store.create_run(run_id, UC, params(fake, **overrides))
    client = fake.client()
    try:
        await trustedge.run(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


async def act(store, fake: FakeDTM, run_id: str, marker: str, coro_factory) -> dict:
    """What the routes do: mark the device (or action) busy, then run its task."""
    devices.commit(store, run_id, lambda r: r.update(busy=[*(r.get("busy") or []), marker]))
    client = fake.client()
    try:
        await coro_factory(client)
    finally:
        await client.aclose()
    run = store.get_run(run_id)
    assert marker not in run["result"]["busy"]  # never stays busy
    return run


async def do_cleanup(store, fake: FakeDTM, run_id: str, tmp_path, mode: str = "full") -> dict:
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, run_id, mode, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


# --- factory -------------------------------------------------------------------------------------------

async def test_factory_registers_devices_with_a_passcode_each(store, fake, docker, tmp_path):
    run = await start(store, fake, "t1", tmp_path, mode="batch", count=2)
    assert run["status"] == "completed", (run["error"], events(store, "t1"))
    assert fake.violations == [] and docker.containers == {}  # nothing in the field yet
    r = run["result"]
    names = [f"robot-t1-uc08-iot-minion-{i:04d}" for i in (1, 2)]
    assert [d["name"] for d in r["devices"]] == names
    assert all(d["stage"] == "factory" and d["issued"] == 0 for d in r["devices"]) and r["certificate_total"] == 0
    for d in r["devices"]:
        (device,) = [x for x in fake.devices.values() if x["id"] == d["id"]]
        assert device["attributes"] == [{"key": "serial_number", "value": d["serial"]}]
        secret = tmp_path / "runs" / "t1" / "devices" / d["name"] / "passcode"
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
        (record,) = [o for o in fake.active_auth("passcode") if o["body"]["passcode"] == secret.read_text()]
        assert record["registered_cn"] == d["serial"] and record["usage_limit"] == 1  # one-time, bound to the serial
        assert secret.read_text() not in json.dumps(run) + events(store, "t1")  # never in the run data
    boot, op = policy(fake, "-boot-policy"), policy(fake, "-op-policy")
    assert boot["certificate_management_methods"] == ["EST"] and boot["require_device_group_for_enroll"] is True
    assert op["certificate_management_methods"] == ["TRUST_EDGE", "EST"]
    (group,) = fake.device_groups.values()
    assert [(a["type"], a["policy_id"]) for a in group["policies"]] == [
        ("bootstrapCertificate", boot["id"]), ("operationalCertificate", op["id"])]
    assert store.get_setting(f"firmware_catalog:{ACCOUNT_ID}") == "[]"  # the catalogue was read


# --- field ---------------------------------------------------------------------------------------------

async def test_field_start_until_the_operational_certificate(store, fake, docker, minion, tmp_path):
    run = await start(store, fake, "t2", tmp_path, pause=False)
    assert run["status"] == "completed", (run["error"], events(store, "t2"))
    (d,) = run["result"]["devices"]
    assert (d["issued"], d["stage"]) == (1, "operational") and run["result"]["certificate_total"] == 2
    assert sorted(c["role"] for c in d["certificates"]) == ["bootstrap", "operational"]
    (container,) = docker.containers.values()
    assert container["labels"] == {launcher.LABEL: "t2"} and d["container"] == container["Id"]
    (env,) = minion.started
    assert env["SERIAL"] == d["serial"] and env["BOOT_POLICY"] == policy(fake, "-boot-policy")["id"]
    assert not (tmp_path / "runs" / "t2" / "devices" / d["name"] / "passcode").exists()  # one-time: handed over
    assert env["PASSCODE"] not in json.dumps(run) + events(store, "t2")


async def test_field_start_per_click_and_a_minion_that_stops(store, fake, docker, minion, tmp_path):
    await start(store, fake, "t3", tmp_path, mode="batch", count=2)
    first, second = (d["name"] for d in store.get_run("t3")["result"]["devices"])
    minion.behaviour = "exits"
    run = await act(store, fake, "t3", first, lambda c: trustedge.enroll(store, c, "t3", tmp_path / "runs" / "t3", first))
    assert f"Field start of {first} failed" in events(store, "t3") and "the IoT minion stopped" in events(store, "t3")
    assert run["status"] == "completed" and devices.device_of(run["result"], first)["issued"] == 0
    minion.behaviour = "operational"
    run = await act(store, fake, "t3", second,
                    lambda c: trustedge.enroll(store, c, "t3", tmp_path / "runs" / "t3", second))
    assert devices.device_of(run["result"], second)["issued"] == 1  # devices act independently
    # the first device's passcode is gone with its first start – it cannot start a second minion
    run = await act(store, fake, "t3", first, lambda c: trustedge.enroll(store, c, "t3", tmp_path / "runs" / "t3", first))
    assert "no bootstrap policy, device group or passcode" in events(store, "t3") and len(minion.started) == 2


async def test_no_operational_certificate_in_time_fails_the_device(store, fake, docker, minion, tmp_path, monkeypatch):
    minion.behaviour = "bootstrap only"
    monkeypatch.setattr(trustedge, "FIELD_TIMEOUT_S", 0.05)
    await start(store, fake, "t4", tmp_path)
    (name,) = (d["name"] for d in store.get_run("t4")["result"]["devices"])
    run = await act(store, fake, "t4", name, lambda c: trustedge.enroll(store, c, "t4", tmp_path / "runs" / "t4", name))
    d = devices.device_of(run["result"], name)
    assert d["issued"] == 0 and [c["role"] for c in d["certificates"]] == ["bootstrap"]
    assert "no operational certificate within" in events(store, "t4")


# --- add a device --------------------------------------------------------------------------------------

async def test_add_device_registers_one_more_with_its_passcode(store, fake, docker, tmp_path):
    await start(store, fake, "t5", tmp_path)
    run = await act(store, fake, "t5", trustedge.ADDING,
                    lambda c: trustedge.add_device(store, c, "t5", tmp_path / "runs" / "t5"))
    names = [d["name"] for d in run["result"]["devices"]]
    assert names == ["robot-t5-uc08-iot-minion-0001", "robot-t5-uc08-iot-minion-0002"]
    added = run["result"]["devices"][1]
    assert added["serial"] == devices.identity("t5", 2, "serial") and added["stage"] == "factory"
    assert len(fake.active_auth("passcode")) == 2 and len(store.objects("t5", "device")) == 2
    counts = {c["purpose"]: c["count"] for c in run["result"]["api_calls"]
              if c["purpose"].startswith(("Register the device", "Create the device's one-time passcode"))}
    assert set(counts.values()) == {2}


async def test_add_device_stops_at_the_limit(store, fake, docker, tmp_path, monkeypatch):
    monkeypatch.setattr(trustedge, "MAX_DEVICES", 2)
    await start(store, fake, "t6", tmp_path, mode="batch", count=2)
    before = len(fake.devices)
    run = await act(store, fake, "t6", trustedge.ADDING,
                    lambda c: trustedge.add_device(store, c, "t6", tmp_path / "runs" / "t6"))
    assert len(run["result"]["devices"]) == 2 and len(fake.devices) == before
    assert "at most 2 IoT minions per run" in events(store, "t6")


# --- firmware ------------------------------------------------------------------------------------------

async def test_new_version_joins_the_shared_catalogue(store, fake, docker, tmp_path):
    await start(store, fake, "t7", tmp_path)
    run = await act(store, fake, "t7", firmware.BUSY, lambda c: firmware.create(store, c, "t7", "ghost"))
    (artifact,) = fake.artifacts.values()
    (release,) = fake.releases.values()
    match = firmware.NAME.fullmatch(artifact["name"])
    assert match and match.group(1, 2) == ("2", "ghost") and release["name"] == artifact["name"]
    assert "#" + match.group(3) in firmware.PALETTE
    division = next(d for d in fake.divisions.values() if d["name"] == firmware.DIVISION)
    assert artifact["body"]["division_id"] == release["body"]["division_id"] == division["id"]
    (upload,) = fake.uploads.values()
    assert artifact["body"]["payload_ids"] == [upload["id"]] and b"install.sh" in upload["data"]
    (entry,) = firmware.catalog(store, ACCOUNT_ID)
    assert (entry["version"], entry["character"], entry["release_id"]) == (2, "ghost", release["id"])
    phases = {c["purpose"]: c.get("phase") for c in run["result"]["api_calls"]}
    assert phases["Create the release with the artifact"] == "firmware"
    assert run["result"]["api_variables"]["FIRMWARE_DIVISION_ID"] == division["id"]
    assert store.objects("t7", "division") and division["id"] not in {o["dtm_id"] for o in store.objects("t7")}
    # the next version: number up, another colour than the newest, the division is reused
    await act(store, fake, "t7", firmware.BUSY, lambda c: firmware.create(store, c, "t7", "ghost"))
    newest, previous = firmware.catalog(store, ACCOUNT_ID)
    assert (newest["version"], previous["version"]) == (3, 2) and newest["color"] != previous["color"]
    assert len([d for d in fake.divisions.values() if d["name"] == firmware.DIVISION]) == 1


async def test_unknown_figure_is_refused_before_dtm(store, fake, docker, tmp_path):
    await start(store, fake, "t8", tmp_path)
    before = list(fake.calls)
    await act(store, fake, "t8", firmware.BUSY, lambda c: firmware.create(store, c, "t8", "<svg onload=x>"))
    assert fake.calls == before and fake.artifacts == {} and "unknown figure" in events(store, "t8")


async def test_deploy_to_the_runs_group_and_its_limit(store, fake, docker, tmp_path, monkeypatch):
    monkeypatch.setattr(firmware, "MAX_DEPLOYMENTS", 2)
    await start(store, fake, "t9", tmp_path)
    for _ in range(3):
        await act(store, fake, "t9", firmware.BUSY, lambda c: firmware.create(store, c, "t9", "robot"))
    # someone disabled version 2 meanwhile – deploying re-enables it
    entry = next(e for e in firmware.catalog(store, ACCOUNT_ID) if e["version"] == 2)
    fake.artifacts[entry["artifact_id"]]["status"] = fake.releases[entry["release_id"]]["status"] = "DISABLED"
    run = await act(store, fake, "t9", firmware.BUSY, lambda c: firmware.deploy(store, c, "t9", entry["name"]))
    (deployment,) = fake.deployments.values()
    (group,) = fake.device_groups.values()
    assert deployment["name"] == "robot-t9-uc08-firmware-2" and deployment["body"]["device_group_id"] == group["id"]
    assert deployment["body"]["release_id"] == entry["release_id"]
    assert fake.releases[entry["release_id"]]["status"] == fake.artifacts[entry["artifact_id"]]["status"] == "ENABLED"
    assert [o["name"] for o in store.objects("t9", "deployment")] == ["robot-t9-uc08-firmware-2"]
    assert [(f["version"], f["name"]) for f in run["result"]["firmware"]] == [(2, entry["name"])]
    names = {e["version"]: e["name"] for e in firmware.catalog(store, ACCOUNT_ID)}
    await act(store, fake, "t9", firmware.BUSY, lambda c: firmware.deploy(store, c, "t9", names[3]))
    run = await act(store, fake, "t9", firmware.BUSY, lambda c: firmware.deploy(store, c, "t9", names[4]))
    assert len(fake.deployments) == 2 and len(run["result"]["firmware"]) == 2
    assert "at most 2 firmware deployments per run" in events(store, "t9")


async def test_deploy_refuses_legacy_runs_and_unknown_versions(store, fake, docker, tmp_path):
    await start(store, fake, "ta", tmp_path)
    await act(store, fake, "ta", firmware.BUSY, lambda c: firmware.deploy(store, c, "ta", "robot-firmware-7-robot-e53935"))
    assert "firmware robot-firmware-7-robot-e53935 is not in the catalogue" in events(store, "ta") and fake.deployments == {}
    devices.commit(store, "ta", lambda r: r.update(firmware=[{"version": 2, "character": "robot", "color": "#e53935"}]))
    before = list(fake.calls)
    await act(store, fake, "ta", firmware.BUSY, lambda c: firmware.deploy(store, c, "ta", "robot-firmware-2-robot-e53935"))
    assert "started before the firmware catalogue" in events(store, "ta") and fake.calls == before


# --- rollback ------------------------------------------------------------------------------------------

async def test_full_rollback_removes_the_minions_first(store, fake, docker, minion, tmp_path):
    await start(store, fake, "tb", tmp_path, mode="batch", count=2, pause=False)
    await act(store, fake, "tb", firmware.BUSY, lambda c: firmware.create(store, c, "tb", "alien"))
    await act(store, fake, "tb", firmware.BUSY, lambda c: firmware.deploy(
        store, c, "tb", firmware.catalog(store, ACCOUNT_ID)[0]["name"]))
    other = docker.add("robot-tz-uc08-iot-minion-0001", "tz")  # another run's minion stays
    # a deployment the run created but never recorded – and another run's
    div = next(iter(fake.deployments.values()))["body"]["division_id"]
    fake.deployments["lost"] = {"id": "lost", "name": "robot-tb-uc08-firmware-3", "status": "IN_PROGRESS",
                                "body": {"division_id": div}}
    fake.deployments["theirs"] = {"id": "theirs", "name": "robot-tz-uc08-firmware-2", "status": "IN_PROGRESS",
                                  "body": {}}
    assert len(fake.issued()) == 4
    start_calls, removed_at = len(fake.calls), []
    real = docker.handle

    def handle(request):
        if request.method == "DELETE":
            removed_at.append(len(fake.calls))
        return real(request)
    docker.handle = handle
    run = await do_cleanup(store, fake, "tb", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "tb")
    assert removed_at == [start_calls, start_calls]  # both minions removed before any DTM call
    assert set(docker.containers) == {other["Id"]}
    assert fake.issued() == [] and fake.active_devices() == [] and fake.policies == {} and fake.violations == []
    assert {d["status"] for d in fake.deployments.values() if d["id"] != "theirs"} == {"ABORTED"}
    assert fake.deployments["theirs"]["status"] == "IN_PROGRESS"
    order = fake.route_order()
    assert max(i for i, n in enumerate(order) if n == "deployment_abort") < order.index("device_delete")
    assert fake.active_auth("passcode") == [] and fake.active_auth("auth_policy") == []
    # the shared catalogue stays: division, artifact and release
    assert [d["name"] for d in fake.divisions.values()] == [firmware.DIVISION]
    assert {a["status"] for a in fake.artifacts.values()} == {r["status"] for r in fake.releases.values()} == {"ENABLED"}
    assert store.objects("tb") == [] and not (tmp_path / "runs" / "tb").exists()


async def test_rollback_stops_when_the_minions_cannot_be_removed(store, fake, docker, minion, tmp_path, monkeypatch):
    await start(store, fake, "tc", tmp_path, pause=False)
    docker.handle = lambda request: httpx.Response(500, json={"message": "proxy down"})
    start_calls = len(fake.calls)
    run = await do_cleanup(store, fake, "tc", tmp_path)
    assert run["cleanup_status"] == "failed" and "refused DELETE /runs/tc" in events(store, "tc")
    assert len(fake.calls) == start_calls and len(fake.issued()) == 2  # DTM untouched while agents may run


async def test_revoke_only_removes_minions_and_keeps_the_devices(store, fake, docker, minion, tmp_path):
    await start(store, fake, "td", tmp_path, pause=False)
    run = await do_cleanup(store, fake, "td", tmp_path, mode="certificates")
    assert run["cleanup_status"] == "done", events(store, "td")
    assert docker.containers == {} and fake.issued() == [] and len(fake.active_devices()) == 1


async def test_rollback_refuses_another_runs_deployment_in_the_ledger(store, fake, docker, tmp_path):
    """Ledger rows are ours by construction – a corrupted one with another run's name is refused."""
    await start(store, fake, "te", tmp_path)
    fake.deployments["x"] = {"id": "x", "name": "robot-tz-uc08-firmware-2", "status": "IN_PROGRESS",
                             "account_id": OTHER_ACCOUNT_ID, "body": {}}
    store.add_object("te", "deployment", "x", "robot-tz-uc08-firmware-2")
    run = await do_cleanup(store, fake, "te", tmp_path)
    assert run["cleanup_status"] == "failed" and "outside run prefix" in events(store, "te")
    assert fake.deployments["x"]["status"] == "IN_PROGRESS" and "deployment_abort" not in fake.route_order()


async def test_a_launcher_failure_frees_the_device_and_keeps_the_container(store, fake, docker, minion, tmp_path):
    """The minion started, then the launcher fails: the device leaves busy with the error logged, and the run
    still knows the container (committed before the passcode was handed over) – the rollback can remove it."""
    await start(store, fake, "tf", tmp_path)
    (name,) = (d["name"] for d in store.get_run("tf")["result"]["devices"])
    real = docker.handle

    def handle(request):
        if request.method == "GET" and request.url.path.endswith("/json") and "/containers/" in request.url.path:
            return httpx.Response(500, json={"message": "proxy down"})
        return real(request)
    docker.handle = handle
    run = await act(store, fake, "tf", name, lambda c: trustedge.enroll(store, c, "tf", tmp_path / "runs" / "tf", name))
    d = devices.device_of(run["result"], name)
    assert f"Field start of {name} failed" in events(store, "tf") and "launcher refused" in events(store, "tf")
    (container,) = docker.containers
    assert d["container"] == container and d["issued"] == 0
    docker.handle = real
    run = await do_cleanup(store, fake, "tf", tmp_path)
    assert run["cleanup_status"] == "done" and docker.containers == {}
