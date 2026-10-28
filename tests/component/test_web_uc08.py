"""UC-7 and UC-8 through the web UI: use-case gating (platform, minion runtime), per-device enroll/renew routes,
adding IoT minions, firmware routes with their limits, the polled tile and the rollback."""

import json
import re

import pytest

from app import devices, firmware, trustedge
from tests.component.test_web_runs import cleaned, finished
from tests.conftest import PASSWORD, make_web, wait_for
from tests.fakedocker import FakeDocker
from tests.fakedtm import ACCOUNT_ID, API_KEY, ECDSA_CA_ID, NL_HOST, FakeDTM
from tests.integration.test_uc08_flow import Minion


@pytest.fixture
def docker(monkeypatch) -> FakeDocker:
    return FakeDocker().install(monkeypatch)


@pytest.fixture
def minion(fake, docker) -> Minion:
    return Minion(fake, docker)


def form(**overrides) -> dict:
    return {"run_id": "t1", "use_case": "uc08", "mode": "batch", "count": "2", "ca_id": ECDSA_CA_ID,
            "pause": "true"} | overrides


def started(user, store, **overrides) -> dict:
    response = user.post("/runs", data=form(**overrides), follow_redirects=False)
    assert response.status_code == 303, response.text
    run = finished(store, overrides.get("run_id", "t1"))
    assert run["status"] == "completed", run["error"]
    return run


def idle(store, run_id="t1") -> dict:
    return wait_for(lambda: (r := store.get_run(run_id)) and not r["result"].get("busy") and r, what="devices idle")


def names(store, run_id="t1") -> list[str]:
    return [d["name"] for d in store.get_run(run_id)["result"]["devices"]]


# --- gating --------------------------------------------------------------------------------------------

def test_uc08_needs_the_minion_runtime(configured_user, monkeypatch, docker):
    assert configured_user.get("/runs/new/uc08").status_code == 200
    docker.image_present = False
    response = configured_user.get("/runs/new/uc08")
    assert response.status_code == 400 and "IoT minion runtime" in response.text
    assert 'aria-label="Start TrustEdge managed devices" disabled' in configured_user.get("/runs/new").text
    response = configured_user.post("/runs", data=form(), follow_redirects=False)
    assert response.status_code == 400 and "IoT minion runtime" in response.text


def test_uc08_only_on_a_us_connection(store, auth, data_dir, docker):
    nl = FakeDTM(host=NL_HOST)
    store.save_connection(None, "NL", NL_HOST, ACCOUNT_ID, API_KEY)
    with make_web(store, auth, nl, data_dir) as user:
        assert user.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
        response = user.get("/runs/new/uc08")
        assert response.status_code == 400 and "needs a connection to one.digicert.com" in response.text
        assert re.search(r'data-tip="Needs a connection to one.digicert.com"><button[^>]*disabled',
                         user.get("/runs/new").text)
        response = user.post("/runs", data=form(), follow_redirects=False)
        assert response.status_code == 400 and "a US connection" in response.text
    assert store.list_runs() == [] and nl.devices == {} and nl.policies == {}


def test_uc08_page_takes_the_us_connection_when_nl_is_the_default(user, store, docker):
    nl = store.save_connection(None, "NL", NL_HOST, ACCOUNT_ID, API_KEY)
    us = store.save_connection(None, "US", "one.digicert.com", ACCOUNT_ID, API_KEY)
    store.set_default_connection(nl)
    html = user.get("/runs/new/uc08").text
    assert re.search(rf'name="connection_id" value="{us}"', html), "the run must go to the US connection"


@pytest.mark.parametrize("count", [str(trustedge.MAX_DEVICES + 1), "0"])
def test_uc08_device_count_is_limited(configured_user, store, fake, docker, count):
    response = configured_user.post("/runs", data=form(count=count), follow_redirects=False)
    assert response.status_code == 400 and store.list_runs() == [] and fake.devices == {}


# --- UC-8 run page and device routes -------------------------------------------------------------------

def test_factory_run_shows_one_tile_per_minion(configured_user, store, fake, docker, data_dir):
    run = started(configured_user, store)
    assert run["params"]["protocol"] == "trustedge" and run["params"]["pause"] is True
    html = configured_user.get("/runs/t1").text
    for name in names(store):
        assert f'action="/runs/t1/devices/{name}/enroll"' in html
    assert html.count(">Start IoT minion</button>") == 2 and "Renew</button>" not in html
    assert 'action="/runs/t1/devices/add"' in html and "<h2>Firmware</h2>" in html
    assert all(f'action="/runs/t1/firmware/new/{c}"' in html for c in firmware.CHARACTERS)
    for d in store.get_run("t1")["result"]["devices"]:  # the passcode stays in the run dir, never in the page
        secret = (data_dir / "runs" / "t1" / "devices" / d["name"] / "passcode").read_text()
        assert secret not in html and secret not in json.dumps(store.get_run("t1"))


def test_start_a_minion_from_its_tile(configured_user, store, fake, docker, minion):
    started(configured_user, store)
    first, second = names(store)
    assert configured_user.post(f"/runs/t1/devices/{first}/enroll", follow_redirects=False).status_code == 303
    run = idle(store)
    d = devices.device_of(run["result"], first)
    assert d["issued"] == 1 and d["stage"] == "operational" and len(docker.containers) == 1
    # started once – a second start is refused; the other device is untouched
    response = configured_user.post(f"/runs/t1/devices/{first}/enroll", follow_redirects=False)
    assert response.status_code == 409 and "enrolled already" in response.text
    assert devices.device_of(run["result"], second)["issued"] == 0 and len(minion.started) == 1


def test_uc08_has_no_renewal_per_click(configured_user, store, fake, docker, minion):
    started(configured_user, store)
    first, _ = names(store)
    configured_user.post(f"/runs/t1/devices/{first}/enroll")
    idle(store)
    response = configured_user.post(f"/runs/t1/devices/{first}/renew", follow_redirects=False)
    assert response.status_code == 409 and "renews its certificate itself" in response.text
    assert store.get_run("t1")["result"].get("renewals") == []


def test_double_click_on_a_busy_device_starts_nothing(configured_user, store, fake, docker, minion):
    started(configured_user, store)
    first, _ = names(store)
    devices.commit(store, "t1", lambda r: r.update(busy=[first]))  # its task is running
    response = configured_user.post(f"/runs/t1/devices/{first}/enroll", follow_redirects=False)
    assert response.status_code == 303 and minion.started == [] and docker.containers == {}
    tile = configured_user.get(f"/runs/t1/devices/{first}/tile").text
    assert 'hx-trigger="every 2s"' in tile and 'aria-busy="true"' in tile


def test_tile_of_a_running_minion_reads_what_it_reports(configured_user, store, fake, docker, minion):
    started(configured_user, store)
    first, _ = names(store)
    configured_user.post(f"/runs/t1/devices/{first}/enroll")
    run = idle(store)
    container = devices.device_of(run["result"], first)["container"]
    docker.log(container, "2026-10-27T10:00:30.000Z", '{"minion":"m","event":"firmware","version":3}')
    docker.log(container, "2026-10-27T10:00:31.000Z", "INFO deployment progress message (Installed)")
    tile = configured_user.get(f"/runs/t1/devices/{first}/tile")
    assert tile.status_code == 200 and 'hx-trigger="every 5s"' in tile.text  # a running minion is watched
    d = devices.device_of(store.get_run("t1")["result"], first)
    assert (d["firmware"], d["agent"]) == (3, "update installed")
    assert "Firmware 3.0.0" in tile.text and "TrustEdge update installed" in tile.text
    docker.containers.clear()  # the container is gone – the tile still renders
    assert configured_user.get(f"/runs/t1/devices/{first}/tile").status_code == 200


# --- add an IoT minion ---------------------------------------------------------------------------------

def test_add_minion_and_its_limit(configured_user, store, fake, docker, monkeypatch):
    started(configured_user, store)
    monkeypatch.setattr(trustedge, "MAX_DEVICES", 3)
    assert configured_user.post("/runs/t1/devices/add", follow_redirects=False).status_code == 303
    idle(store)
    assert names(store)[-1] == "robot-t1-uc08-iot-minion-0003" and len(fake.devices) == 3
    response = configured_user.post("/runs/t1/devices/add", follow_redirects=False)
    assert response.status_code == 409 and "At most 3 IoT minions per run" in response.text


def test_add_minion_double_click_and_guards(configured_user, store, fake, docker):
    started(configured_user, store)
    devices.commit(store, "t1", lambda r: r.update(busy=[trustedge.ADDING]))
    assert configured_user.post("/runs/t1/devices/add", follow_redirects=False).status_code == 303
    assert len(names(store)) == 2 and len(fake.devices) == 2
    devices.commit(store, "t1", lambda r: r.update(busy=[]))
    assert configured_user.post("/runs/nope/devices/add", follow_redirects=False).status_code == 404
    configured_user.post("/runs/t1/cleanup", data={"mode": "full"})
    assert cleaned(store, "t1")["cleanup_status"] == "done"
    assert configured_user.post("/runs/t1/devices/add", follow_redirects=False).status_code == 409
    assert len(fake.devices) == 2


# --- firmware routes -----------------------------------------------------------------------------------

def test_firmware_new_and_deploy_through_the_web(configured_user, store, fake, docker):
    started(configured_user, store)
    assert configured_user.post("/runs/t1/firmware/new/ghost", follow_redirects=False).status_code == 303
    idle(store)
    (entry,) = firmware.catalog(store, ACCOUNT_ID)
    html = configured_user.get("/runs/t1").text
    assert f'action="/runs/t1/firmware/deploy/{entry["name"]}"' in html and firmware.svg(entry) in html
    assert configured_user.post(f"/runs/t1/firmware/deploy/{entry['name']}", follow_redirects=False).status_code == 303
    run = idle(store)
    assert [f["name"] for f in run["result"]["firmware"]] == [entry["name"]] and len(fake.deployments) == 1
    assert '<span class="pill ok">deployed</span>' in configured_user.get("/runs/t1").text


@pytest.mark.parametrize("path,status", [
    ("firmware/new/dragon", 404), ("firmware/new/%3Cscript%3E", 404), ("firmware/delete/2", 404),
    ("firmware/deploy/abc", 404), ("firmware/deploy/2", 404), ("firmware/deploy/%C2%B2", 404),
    ("firmware/deploy/robot-firmware-99-robot-e53935", 404),  # well-formed, but not in the catalogue
    ("firmware/deploy/robot-firmware-2-robot-e53935%22%3E%3Cscript%3E", 404),
])
def test_firmware_route_validation(configured_user, store, fake, docker, path, status):
    started(configured_user, store)
    before = list(fake.calls)
    response = configured_user.post(f"/runs/t1/{path}", follow_redirects=False)
    assert response.status_code == status and "<script>" not in response.text
    assert fake.calls == before and not store.get_run("t1")["result"].get("busy")


def test_firmware_deploy_limit_and_legacy_runs(configured_user, store, fake, docker):
    started(configured_user, store)
    configured_user.post("/runs/t1/firmware/new/robot")
    idle(store)
    (entry,) = firmware.catalog(store, ACCOUNT_ID)
    deployed = [{"name": f"robot-firmware-{n}-robot-e53935", "version": n, "character": "robot", "color": "#e53935"}
                for n in range(10, 10 + firmware.MAX_DEPLOYMENTS)]
    devices.commit(store, "t1", lambda r: r.update(firmware=deployed))
    response = configured_user.post(f"/runs/t1/firmware/deploy/{entry['name']}", follow_redirects=False)
    assert response.status_code == 409 and f"At most {firmware.MAX_DEPLOYMENTS} firmware deployments" in response.text
    devices.commit(store, "t1", lambda r: r.update(firmware=[{"version": 2, "character": "robot", "color": "#e53935"}]))
    for path in (f"firmware/deploy/{entry['name']}", "firmware/new/robot"):
        response = configured_user.post(f"/runs/t1/{path}", follow_redirects=False)
        assert response.status_code == 409 and "before the firmware catalogue" in response.text
    assert fake.deployments == {} and len(fake.artifacts) == 1


def test_firmware_double_click_and_other_use_cases(configured_user, store, fake, docker):
    started(configured_user, store)
    devices.commit(store, "t1", lambda r: r.update(busy=[firmware.BUSY]))
    assert configured_user.post("/runs/t1/firmware/new/robot", follow_redirects=False).status_code == 303
    assert fake.artifacts == {}
    store.create_run("m1", "uc06", {"dtm_host": fake.host, "account_id": ACCOUNT_ID})
    store.update_run("m1", status="completed", result={"devices": [{"name": "robot-m1-uc06-minion-0001"}]})
    assert configured_user.post("/runs/m1/firmware/new/robot", follow_redirects=False).status_code == 404
    assert configured_user.post("/runs/m1/devices/add", follow_redirects=False).status_code == 404


# --- rollback ------------------------------------------------------------------------------------------

def test_rollback_through_the_web_removes_the_minions(configured_user, store, fake, docker, minion):
    started(configured_user, store)
    first, _ = names(store)
    configured_user.post(f"/runs/t1/devices/{first}/enroll")
    idle(store)
    assert len(docker.containers) == 1
    configured_user.post("/runs/t1/cleanup", data={"mode": "full"})
    assert cleaned(store, "t1")["cleanup_status"] == "done"
    assert docker.containers == {} and fake.issued() == [] and fake.active_devices() == []
    assert configured_user.post(f"/runs/t1/devices/{first}/enroll", follow_redirects=False).status_code == 409


# --- UC-7 through the web ------------------------------------------------------------------------------

def uc07_form(**overrides) -> dict:
    return {"run_id": "u1", "use_case": "uc07", "mode": "single", "ca_id": ECDSA_CA_ID, "protocol": "est",
            "pause": "true"} | overrides


@pytest.mark.parametrize("change", [{"protocol": "scep"}, {"protocol": "rest"}, {"mode": "batch",
                                                                                   "count": str(devices.MAX_DEVICES + 1)}])
def test_uc07_invalid_choices_are_refused(configured_user, store, fake, change):
    response = configured_user.post("/runs", data=uc07_form(**change), follow_redirects=False)
    assert response.status_code == 400 and store.list_runs() == [] and fake.devices == {}


def test_uc07_enroll_then_renew_per_device(configured_user, store, enroll_net):
    response = configured_user.post("/runs", data=uc07_form(), follow_redirects=False)
    assert response.status_code == 303
    run = finished(store, "u1")
    assert run["status"] == "completed", run["error"]
    assert (run["params"]["protocol"], run["params"]["auth"], run["params"]["field"]) == ("est", "certificate", "est")
    (name,) = names(store, "u1")
    response = configured_user.post(f"/runs/u1/devices/{name}/renew", follow_redirects=False)
    assert response.status_code == 409 and "Enroll the device first" in response.text
    html = configured_user.get("/runs/u1").text
    assert f'action="/runs/u1/devices/{name}/enroll"' in html and ">Enroll</button>" in html
    assert configured_user.post(f"/runs/u1/devices/{name}/enroll", follow_redirects=False).status_code == 303
    run = idle(store, "u1")
    assert devices.device_of(run["result"], name)["issued"] == 1
    response = configured_user.post(f"/runs/u1/devices/{name}/enroll", follow_redirects=False)
    assert response.status_code == 409 and "enrolled already" in response.text
    assert configured_user.post(f"/runs/u1/devices/{name}/renew", follow_redirects=False).status_code == 303
    run = idle(store, "u1")
    assert devices.device_of(run["result"], name)["issued"] == 2 and enroll_net.violations == []
    html = configured_user.get("/runs/u1").text
    assert f'action="/runs/u1/devices/{name}/renew"' in html and "PRIVATE KEY" not in html


def test_uc08_needs_an_ecdsa_issuing_ca(configured_user, store, fake, docker):
    from tests.fakedtm import RSA_CA_ID
    response = configured_user.post("/runs", data=form(ca_id=RSA_CA_ID), follow_redirects=False)
    assert response.status_code == 400 and "ECDSA" in response.text
    assert store.list_runs() == [] and fake.devices == {}


async def test_launcher_healthz():
    import httpx as _httpx
    from app import launcher
    async with _httpx.AsyncClient(transport=_httpx.ASGITransport(app=launcher.api), base_url="http://l") as http:
        assert (await http.get("/healthz")).json() == {"ok": True}
        assert (await http.get("/docs")).status_code == 404  # no API browser on the launcher


# --- start all IoT minions -----------------------------------------------------------------------------

def start_all_button(html: str) -> str | None:
    found = re.search(r'<form method="post" action="/runs/t1/devices/start-all"[^>]*>\s*<button[^>]*>.*?</button>', html, re.S)
    return found and found.group(0)


def test_start_all_starts_each_waiting_minion_once(configured_user, store, fake, docker, minion, monkeypatch):
    monkeypatch.setattr(trustedge, "START_STAGGER_S", 0)
    started(configured_user, store, count="3")
    first, second, third = names(store)
    configured_user.post(f"/runs/t1/devices/{first}/enroll")
    idle(store)
    button = start_all_button(configured_user.get("/runs/t1").text)
    assert button and "Start all 2" in button and 'class="btn-sm btn-icon field-action"' in button
    assert 'hx-post="/runs/t1/devices/start-all" hx-target="#live"' in button
    devices.commit(store, "t1", lambda r: r.update(busy=[second]))  # its own click is starting it
    assert "Start all 1" in start_all_button(configured_user.get("/runs/t1").text)
    response = configured_user.post("/runs/t1/devices/start-all", headers={"HX-Request": "true"})
    # answered in place: #live polls with the started minion busy, its tile acting
    assert response.status_code == 200 and "HX-Refresh" not in response.headers
    assert f"busy={second}%2C{third}" in response.text
    wait_for(lambda: devices.device_of(store.get_run("t1")["result"], third)["issued"], what="the third minion")
    # only the waiting one started – the running and the busy one were skipped
    assert [m["SERIAL"] for m in minion.started] == [devices.device_of(store.get_run("t1")["result"], n)["serial"]
                                                      for n in (first, third)]
    devices.commit(store, "t1", lambda r: r.update(busy=[]))
    assert start_all_button(configured_user.get("/runs/t1").text) is not None  # the second one still waits


def test_start_all_double_click_and_guards(configured_user, store, fake, docker, minion, monkeypatch):
    monkeypatch.setattr(trustedge, "START_STAGGER_S", 0)
    started(configured_user, store)
    first, second = names(store)
    devices.commit(store, "t1", lambda r: r.update(busy=[first, second]))  # Start all is running
    assert start_all_button(configured_user.get("/runs/t1").text) is None  # nothing waits
    response = configured_user.post("/runs/t1/devices/start-all", follow_redirects=False)
    assert response.status_code == 303 and minion.started == []  # a double click starts nothing
    devices.commit(store, "t1", lambda r: r.update(busy=[]))
    docker.image_present = False  # the minion runtime is gone
    response = configured_user.post("/runs/t1/devices/start-all", follow_redirects=False)
    assert response.status_code == 409 and "runtime" in response.text and not store.get_run("t1")["result"]["busy"]
    docker.image_present = True
    assert configured_user.post("/runs/nope/devices/start-all", follow_redirects=False).status_code == 404
    configured_user.post("/runs/t1/cleanup", data={"mode": "full"})
    assert cleaned(store, "t1")["cleanup_status"] == "done"
    assert start_all_button(configured_user.get("/runs/t1").text) is None
    assert configured_user.post("/runs/t1/devices/start-all", follow_redirects=False).status_code == 409
    assert minion.started == []


def test_start_all_only_for_iot_minions(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc07_form())
    run = finished(store, "u1")
    assert run["status"] == "completed", run["error"]
    assert "/devices/start-all" not in configured_user.get("/runs/u1").text
    response = configured_user.post("/runs/u1/devices/start-all", follow_redirects=False)
    assert response.status_code == 409 and "IoT minions" in response.text


def test_start_all_requires_login(web, configured_store):
    response = web.post("/runs/t1/devices/start-all", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
