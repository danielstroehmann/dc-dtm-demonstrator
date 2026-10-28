"""UC-6 managed devices through the web UI: form, forced parameters, limits, run page, renew route and guards."""

import re

import pytest

from app import devices, evergreen, snippets
from tests.component.test_web_runs import cleaned, finished, phase_titles
from tests.conftest import wait_for
from tests.fakedtm import ECDSA_CA_ID, _error
from tests.guide_form import GuideForm


def uc06_form(**overrides) -> dict:
    # field=rest: these tests count the REST renew calls; the default (EST, like the form) has its own test
    return {"run_id": "m1", "use_case": "uc06", "mode": "single", "count": "2", "variant": "api",
            "ca_id": ECDSA_CA_ID, "field": "rest"} | overrides


def test_field_defaults_to_est_like_the_form(configured_user, store, fake):
    data = uc06_form()
    del data["field"]
    response = configured_user.post("/runs", data=data, follow_redirects=False)
    assert response.status_code == 303
    run = finished(store, "m1")
    assert run["status"] == "completed", run["error"]
    assert run["params"]["field"] == "est"


def renewals(store, run_id="m1") -> int:
    return len(store.get_run(run_id)["result"].get("renewals") or [])


def renewed(store, run_id="m1", count=1):
    """count renewal attempts recorded and no device acting any more."""
    return wait_for(lambda: (r := store.get_run(run_id)) and r["status"] == "completed" and not r["result"].get("busy")
                    and len(r["result"].get("renewals") or []) >= count and r, what=f"renewal of {run_id}")


def device_names(store, run_id="m1") -> list[str]:
    return [d["name"] for d in store.get_run(run_id)["result"]["devices"]]


def tiles(html: str) -> list[str]:
    return re.findall(r'<section class="device-tile[^"]*" id="tile-\d+".*?</section>', html, re.S)


def metrics(html: str, box: str) -> list[str]:
    """The four metrics of the overview's phase box whose title starts with box."""
    section = re.search(rf"</span>{box}.*?</section>", html, re.S).group(0)
    return re.findall(r'<p class="metric">(.*?)</p>', section)


def radios(html: str, name: str) -> list[tuple[str, str]]:
    return re.findall(rf'<input type="radio" name="{name}" value="([^"]+)" ?(checked)?', html)


def test_uc06_form(configured_user):
    html = configured_user.get("/runs/new/uc06").text
    assert radios(html, "mode") == [("single", "checked"), ("batch", "")]
    assert re.search(rf'<input id="count" type="number" name="count"[^>]*min="1" max="{devices.MAX_DEVICES}"', html)
    assert radios(html, "protocol") == [("rest", "checked"), ("est", ""), ("cmpv2", "")]
    assert radios(html, "auth_method") == [("apikey", "checked"), ("passcode", ""), ("certificate", "")]
    assert radios(html, "field") == [("est", "checked"), ("cmpv2", ""), ("rest", "")]
    assert radios(html, "identity") == [("serial", "checked"), ("mac", "")]
    assert '<input type="hidden" name="variant" value="api">' in html and 'name="approval"' not in html
    assert "robot-renewal-6m-profile" in html


@pytest.mark.parametrize("protocol", ["rest", "est", "cmpv2"])
@pytest.mark.parametrize("field", ["rest", "est", "cmpv2"])
def test_every_path_through_the_form_is_accepted(configured_user, protocol, field):
    """The browser's view of the form (data-when as in app.js): any field protocol after any factory protocol,
    the API key only with REST, and exactly one certificate profile – the bare-key one whenever CMPv2 is involved."""
    form = GuideForm(configured_user.get("/runs/new/uc06").text)
    form.choose("protocol", protocol)
    assert form.options("field") == ["est", "cmpv2", "rest"]  # independent of the factory protocol
    form.choose("field", field)
    assert ("apikey" in form.options("auth_method")) is (protocol == "rest")
    for auth in form.options("auth_method"):
        form.choose("auth_method", auth)
        data = form.submission()
        assert devices.check_choice(data["protocol"], data["auth_method"], data["field"], data["identity"]) is None
    bare = form.visible_text("robot-renewal-cmp-6m-profile")
    plain = form.visible_text("robot-renewal-6m-profile")
    assert (bare, plain) == (("cmpv2" in (protocol, field)), ("cmpv2" not in (protocol, field)))


def test_defaults_rest_with_api_key(configured_user, store, fake):
    data = uc06_form(count="7", variant="webui", approval="true", field="rest")  # single → one device, API
    response = configured_user.post("/runs", data=data, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/m1"
    run = finished(store, "m1")
    assert run["status"] == "completed", run["error"]
    p = run["params"]
    assert (p["mode"], p["count"], p["variant"], p["approval"]) == ("single", 1, "api", False)
    assert (p["protocol"], p["auth"], p["field"], p["identity"]) == ("rest", "apikey", "rest", "serial")
    assert len(fake.devices) == 1 and fake.violations == []
    html = configured_user.get("/runs/m1").text
    assert "Managed devices ·" not in html  # no subtitle under the run title – the tile shows the device
    (device,) = run["result"]["devices"]
    (tile,) = tiles(html)  # one tile per device
    assert f'<h3 data-tip="{device["name"]}">{device["name"]}</h3>' in tile and '<span class="pill ok">active</span>' in tile
    assert re.search(r'>Serial number</dt><dd class="mono">SN-M1-0001</dd>', tile)
    assert f'action="/runs/m1/devices/{device["name"]}/renew"' in tile and ">Renew</button>" in tile
    assert "<h2>Devices</h2>" in html and "robot-m1-uc06-group" not in re.search(r"<h2>Devices</h2>", html).group(0)
    titles = re.findall(r'<h3 class="phase-title">.*?</svg></span>(.*?)</h3>', html, re.S)
    assert titles[:2] == ["Device registration <small>REST API</small>", "Field renewal <small>REST API</small>"]
    # no run-wide renewal round any more – neither the button nor the route
    assert 'action="/runs/m1/renew"' not in html and "Renew all devices" not in html and "Renew now" not in html
    assert "devices ≈" not in html  # one device – no extrapolation
    assert "PRIVATE KEY" not in html
    # the PEM, per certificate in the detail view – DTM's list and the saved certificate may spell the hex serial in
    # another case
    assert f'data-certs="/runs/m1/devices/{device["name"]}/certificates"' in tile and "download" not in tile
    detail = configured_user.get(f'/runs/m1/devices/{device["name"]}/certificates').text
    link = re.search(rf'href="(/runs/m1/certificates/{device["certificates"][0]["serial"]}\.pem)" download', detail, re.I)
    assert link, "no PEM download in the certificate detail"
    assert configured_user.get(link.group(1)).status_code == 200


@pytest.mark.parametrize("protocol,auth_method,field,identity", [("est", "passcode", "est", "mac"),
                                                          ("cmpv2", "certificate", "rest", "serial")])
def test_protocol_choices_through_the_web(configured_user, store, enroll_net, cmp_openssl, protocol, auth_method,
                                          field, identity):
    data = uc06_form(protocol=protocol, auth_method=auth_method, field=field, identity=identity)
    assert configured_user.post("/runs", data=data, follow_redirects=False).status_code == 303
    run = finished(store, "m1")
    assert run["status"] == "completed", run["error"]
    p = run["params"]
    assert (p["protocol"], p["auth"], p["field"], p["identity"]) == (protocol, auth_method, field, identity)
    html = configured_user.get("/runs/m1").text
    label = {"rest": "REST API", "est": "EST", "cmpv2": "CMPv2"}
    titles = re.findall(r'<h3 class="phase-title">.*?</svg></span>(.*?)</h3>', html, re.S)
    assert titles[:2] == [f"Device registration <small>{label[protocol]}</small>",
                          f"Field renewal <small>{label[field]}</small>"]
    ident = devices.identity("m1", 1, identity)
    label = devices.IDENTITIES[identity][0]
    assert all(re.search(rf'>{label}</dt><dd class="mono">{ident if i == 0 else devices.identity("m1", 2, identity)}</dd>', t)
               for i, t in enumerate(tiles(html)))
    assert "PRIVATE KEY" not in html + configured_user.get("/runs/m1/api?dialect=curl").text


@pytest.mark.parametrize("change,message", [
    ({"protocol": "est", "auth_method": "apikey", "field": "est"}, "An API key works only with the REST API."),
    ({"protocol": "cmpv2", "auth_method": "apikey", "field": "rest"}, "An API key works only with the REST API."),
    ({"identity": "imei"}, "Select the factory protocol"),
    ({"protocol": "scep", "auth_method": "passcode"}, "Select the factory protocol"),
    ({"field": "<script>"}, "Select the factory protocol"),
])
def test_invalid_choices_are_refused_before_dtm(configured_user, store, fake, change, message):
    response = configured_user.post("/runs", data=uc06_form(**change), follow_redirects=False)
    assert response.status_code == 400 and message in response.text
    assert "<script>" not in response.text
    assert store.list_runs() == [] and fake.route_order() == []  # checked before DTM is asked


@pytest.mark.parametrize("count", ["0", "-1", str(devices.MAX_DEVICES + 1), str(evergreen.MAX_BATCH + 1)])
def test_batch_count_is_limited(configured_user, store, fake, count):
    response = configured_user.post("/runs", data=uc06_form(mode="batch", count=count), follow_redirects=False)
    assert response.status_code == 400 and store.list_runs() == []
    assert fake.devices == {} and fake.device_groups == {}
    if int(count) > 0 and int(count) <= evergreen.MAX_BATCH:
        assert f"Number of devices: 1–{devices.MAX_DEVICES}." in response.text


def test_batch_of_two_through_the_web(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form(mode="batch", count="2"))
    run = finished(store, "m1")
    assert run["status"] == "completed", run["error"]
    assert run["params"]["count"] == 2 and len(fake.devices) == 2
    html = configured_user.get("/runs/m1").text
    found = tiles(html)
    assert len(found) == 2
    for tile, device in zip(found, run["result"]["devices"]):
        assert device["name"] in tile and f'action="/runs/m1/devices/{device["name"]}/renew"' in tile
        assert device["name"] not in "".join(t for t in found if t is not tile)  # each tile its own device
    assert "Renew all devices" not in html and "devices ≈" in html


def test_renew_through_the_web(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form(mode="batch", count="2"))
    finished(store, "m1")
    first, second = device_names(store)
    response = configured_user.post(f"/runs/m1/devices/{first}/renew", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/m1"
    run = renewed(store)
    # only that device renewed – devices act independently
    assert [x["device"] for x in run["result"]["renewals"]] == [first]
    assert run["result"]["certificate_total"] == 3 and len(fake.issued()) == 3
    assert [d["issued"] for d in run["result"]["devices"]] == [2, 1]
    html = configured_user.get("/runs/m1").text
    renewed_tile, other = tiles(html)
    # a tile shows only the valid certificate – the renewed one is in the side panel's picker, not on the tile
    assert renewed_tile.count("<li>") == 1 and other.count("<li>") == 1
    assert renewed_tile.count('<span class="cert-state ok">active</span>') == 1
    assert "renewed</span>" not in renewed_tile and "earlier" not in renewed_tile
    picker = configured_user.get(f"/runs/m1/devices/{first}/certificates").text
    assert picker.count("<option ") == 2  # both certificates of the renewed device
    assert re.search(r'<span class="muted">Renewed in \d+\.\d\d s</span>', renewed_tile)
    assert metrics(html, "Field renewal")[1:] == ["1", "1", "3"]  # devices renewed, renewals, certificates
    configured_user.post(f"/runs/m1/devices/{second}/renew")
    renewed(store, count=2)
    html = configured_user.get("/runs/m1").text
    assert metrics(html, "Field renewal")[1:] == ["2", "2", "4"]
    api = configured_user.get("/runs/m1/api?dialect=curl").text
    titles = [t for _, _, t in phase_titles(api)]
    assert titles[-2:] == ["Device registration", "Field renewal"]
    renewal_box = api[api.index('<section class="box accent field">'):]
    assert "/renew" in renewal_box and "/renew" not in api[:api.index('<section class="box accent field">')]
    for dialect in snippets.DIALECTS:
        page = configured_user.get(f"/runs/m1/api?dialect={dialect}")
        assert page.status_code == 200 and "GROUP_ID" in page.text and "CERT_ID" in page.text
        code = "".join(re.findall(r"<pre[^>]*>(.*?)</pre>", page.text, re.S))  # the copyable commands
        assert "${CERT_ID}" in code or "$env:CERT_ID" in code, dialect
        assert not re.search(r"(?<![$\w:])\{(GROUP_ID|DEVICE_ID|CERT_ID)\}", code), dialect


def test_renew_double_click_starts_one_renewal(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (name,) = device_names(store)
    fake.renew_delay = 0.5
    first = configured_user.post(f"/runs/m1/devices/{name}/renew", follow_redirects=False)
    second = configured_user.post(f"/runs/m1/devices/{name}/renew", follow_redirects=False)  # idempotent while busy
    assert (first.status_code, second.status_code) == (303, 303)
    run = store.get_run("m1")
    assert run["status"] == "completed" and run["result"]["busy"] == [name]  # the run stays completed
    (tile,) = tiles(configured_user.get("/runs/m1").text)
    assert re.search(r'class="btn-sm btn-icon" disabled\s+aria-busy="true"', tile) and ">renewing</span>" in tile
    assert f'hx-get="/runs/m1/devices/{name}/tile?i=1" hx-trigger="every 2s"' in tile  # the tile follows the device
    renewed(store)
    assert renewals(store) == 1 and fake.route_order().count("renew") == 1
    assert store.get_run("m1")["result"]["busy"] == []


def test_at_most_max_renewals_per_device(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form(mode="batch", count="2"))
    finished(store, "m1")
    first, second = device_names(store)
    for count in range(1, devices.MAX_RENEWALS + 1):
        assert configured_user.post(f"/runs/m1/devices/{first}/renew", follow_redirects=False).status_code == 303
        renewed(store, count=count)
    response = configured_user.post(f"/runs/m1/devices/{first}/renew", follow_redirects=False)
    assert response.status_code == 409 and f"At most {devices.MAX_RENEWALS} renewals per device" in response.text
    assert renewals(store) == devices.MAX_RENEWALS and fake.route_order().count("renew") == devices.MAX_RENEWALS
    exhausted, other = tiles(configured_user.get("/runs/m1").text)
    assert re.search(rf'disabled\s+data-tip="At most {devices.MAX_RENEWALS} renewals per device"', exhausted)
    assert "disabled" not in other
    # the limit is per device: the other one still renews
    assert configured_user.post(f"/runs/m1/devices/{second}/renew", follow_redirects=False).status_code == 303
    renewed(store, count=devices.MAX_RENEWALS + 1)


def test_renew_guards(configured_user, store, fake):
    fake.fail["device_enroll"] = _error(403, "not licensed")
    configured_user.post("/runs", data=uc06_form(run_id="f1"))
    assert finished(store, "f1")["status"] == "failed"
    assert configured_user.post("/runs/f1/renew", follow_redirects=False).status_code == 409  # only UC-4 renews per run
    # a failed run has no device to renew
    name = "robot-f1-uc06-minion-0001"
    assert configured_user.post(f"/runs/f1/devices/{name}/renew", follow_redirects=False).status_code == 404
    assert store.get_run("f1")["status"] == "failed" and "renew" not in fake.route_order()


def test_run_wide_renew_is_gone_for_managed_devices(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    response = configured_user.post("/runs/m1/renew", follow_redirects=False)
    assert response.status_code == 409 and "renew" not in fake.route_order()
    assert store.get_run("m1")["status"] == "completed" and renewals(store) == 0


@pytest.mark.parametrize("path,status", [
    ("devices/robot-m1-uc06-minion-0002/renew", 404),           # not a device of the run
    ("devices/robot-m2-uc06-minion-0001/renew", 404),           # another run's device name
    ("devices/%3Cscript%3Ealert(1)%3C%2Fscript%3E/renew", 404),  # free input never reaches anything
    ("devices/..%2F..%2Fsettings/renew", 404),
    ("devices/robot-m1-uc06-minion-0001/delete", 404),          # unknown action
    ("devices/robot-m1-uc06-minion-0001/enroll", 409),          # UC-6 devices are enrolled in the factory
])
def test_device_route_refuses_what_is_not_the_runs(configured_user, store, fake, path, status):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    before = list(fake.calls)
    response = configured_user.post(f"/runs/m1/{path}", follow_redirects=False)
    assert response.status_code == status and "<script>" not in response.text
    assert fake.calls == before and not store.get_run("m1")["result"].get("busy")


def test_device_tile_route(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (name,) = device_names(store)
    response = configured_user.get(f"/runs/m1/devices/{name}/tile?i=3")
    assert response.status_code == 200 and 'id="tile-3"' in response.text and name in response.text
    assert "hx-get" not in response.text  # nothing acts – nothing to poll
    assert configured_user.get("/runs/m1/devices/robot-m1-uc06-minion-0009/tile").status_code == 404
    assert 'id="tile-2000"' in configured_user.get(f"/runs/m1/devices/{name}/tile?i=99999").text  # clamped to the wall
    assert configured_user.get("/runs/nope/devices/x/tile").status_code == 404


def test_live_view_swaps_the_cards_when_a_device_finishes(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (name,) = device_names(store)
    hx = {"HX-Request": "true"}
    devices.commit(store, "m1", lambda r: r.update(busy=[name]))
    acting = configured_user.get(f"/runs/m1/live?busy={name}&phase=completed%7C", headers=hx)
    assert acting.status_code == 200 and "HX-Refresh" not in acting.headers and "hx-swap-oob" not in acting.text
    devices.commit(store, "m1", lambda r: r.update(busy=[]))
    done = configured_user.get(f"/runs/m1/live?busy={name}&phase=completed%7C", headers=hx)
    # no reload: the device's tile, the overview and the timeline come out of band; polling stops
    assert done.status_code == 200 and "HX-Refresh" not in done.headers
    assert 'id="devices" hx-swap-oob="true"' in done.text and name in done.text and 'aria-busy="true"' not in done.text
    assert 'id="overview" hx-swap-oob="true"' in done.text and 'hx-get="/runs/m1/live' not in done.text
    # a page rendered before the phase was sent still reloads once nothing is active
    assert configured_user.get(f"/runs/m1/live?busy={name}", headers=hx).headers.get("HX-Refresh") == "true"


def test_renew_without_connection_does_not_stay_busy(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (name,) = device_names(store)
    (conn,) = store.connections()
    store.delete_connection(conn["id"])
    response = configured_user.post(f"/runs/m1/devices/{name}/renew", follow_redirects=False)
    assert response.status_code == 409
    run = store.get_run("m1")
    assert run["status"] == "completed" and run["result"]["busy"] == [] and "renew" not in fake.route_order()


def test_no_renewal_after_rollback(configured_user, store, fake, data_dir):
    configured_user.post("/runs", data=uc06_form(mode="batch", count="2"))
    finished(store, "m1")
    first, _second = device_names(store)
    configured_user.post(f"/runs/m1/devices/{first}/renew")
    renewed(store)
    configured_user.post("/runs/m1/cleanup", data={"mode": "full"})
    assert cleaned(store, "m1")["cleanup_status"] == "done"
    assert configured_user.post(f"/runs/m1/devices/{first}/renew", follow_redirects=False).status_code == 409
    assert fake.issued() == [] and fake.active_devices() == []
    assert [g["status"] for g in fake.device_groups.values()] == ["DELETED"]
    html = configured_user.get("/runs/m1").text
    devices_card = html.split("<h2>Devices</h2>", 1)[1].split("Timeline")[0]
    assert ">Renew</button>" not in html and 'action="/runs/m1/devices/' not in devices_card
    assert 'action="/runs/m1/renew"' not in html


def test_failed_renewals_count_and_render(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form(field="rest"))
    finished(store, "m1")
    (name,) = device_names(store)
    fake.fail["renew"] = _error(500, "upstream trouble")
    for count in range(1, devices.MAX_RENEWALS + 1):
        assert configured_user.post(f"/runs/m1/devices/{name}/renew", follow_redirects=False).status_code == 303
        renewed(store, count=count)
    run = store.get_run("m1")
    assert [x.get("failed") for x in run["result"]["renewals"]] == [True] * devices.MAX_RENEWALS
    response = configured_user.post(f"/runs/m1/devices/{name}/renew", follow_redirects=False)  # a broken one counts
    assert response.status_code == 409
    page = configured_user.get("/runs/m1")
    assert page.status_code == 200
    overview = page.text[page.text.index("<h2>Overview</h2>"):page.text.index("<h2>Devices</h2>")]
    assert ">None" not in overview and "Undefined" not in overview and '"metric"> s<' not in overview
    # no times from broken renewals: last renewal, devices renewed, renewals, certificates
    assert metrics(page.text, "Field renewal") == ["–", "0", "0", "1"]
    (tile,) = tiles(page.text)
    assert "Renewed in" not in tile and tile.count("<li>") == 1