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


def renewed(store, run_id="m1", rounds=1):
    return wait_for(lambda: (r := store.get_run(run_id)) and r["status"] == "completed"
                    and len(r["result"].get("renewals") or []) >= rounds and r, what=f"renewal of {run_id}")


def radios(html: str, name: str) -> list[tuple[str, str]]:
    return re.findall(rf'<input type="radio" name="{name}" value="([^"]+)" ?(checked)?', html)


def devices_table(html: str) -> str:
    return re.search(r'<table class="data-table devices-table">.*?</table>', html, re.S).group(0)


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
    assert "Managed devices · REST API → REST API · API key · Serial number · 1 device ·" in html
    (device,) = run["result"]["devices"]
    table = devices_table(html)
    headers = re.findall(r"<th>(.*?)</th>", table)
    assert headers == ["Device name", "Identity in certificate (CN)", "Certificate", "Status", "Valid until"]
    assert table.count("<tr") == 2 and device["name"] in table
    assert f'<td class="mono" data-tip="Serial number – DTM matched it to {device["name"]}">SN-M1-0001</td>' in table
    assert device["certificates"][0]["serial"] in table
    assert "Devices in DTM" in html and "group robot-m1-uc06-group" in html
    titles = re.findall(r'<h3 class="phase-title">.*?</svg></span>(.*?)</h3>', html, re.S)
    assert titles[:2] == ["Device registration <small>REST API</small>", "Renewal in the field <small>REST API</small>"]
    assert "<h2>Renewal in the field</h2>" in html and ">Renew now</button>" in html
    assert "devices ≈" not in html  # one device – no extrapolation
    assert "PRIVATE KEY" not in html


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
                          f"Renewal in the field <small>{label[field]}</small>"]
    ident = devices.identity("m1", 1, identity)
    assert f">{ident}</td>" in devices_table(html)
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
    table = re.search(r'<table class="data-table devices-table">.*?</table>', html, re.S).group(0)
    for device in run["result"]["devices"]:
        assert device["name"] in table
    assert table.count('class="group-start"') == 1  # the second device starts a new group of rows
    assert ">Renew all devices</button>" in html and "devices ≈" in html


def test_renew_through_the_web(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form(mode="batch", count="2"))
    finished(store, "m1")
    response = configured_user.post("/runs/m1/renew", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/m1"
    run = renewed(store)
    assert run["result"]["certificate_total"] == 4 and len(fake.issued()) == 4
    html = configured_user.get("/runs/m1").text
    table = re.search(r'<table class="data-table devices-table">.*?</table>', html, re.S).group(0)
    assert table.count("<tr") == 1 + 4 and table.count(" · renewal\">") == 2 and table.count(" · registration\">") == 2
    assert table.count('<span class="pill ok">active</span>') == 2 and table.count(">renewed</span>") == 2
    assert "<small>Rounds</small><p class=\"metric\">1</p>" in html
    api = configured_user.get("/runs/m1/api?dialect=curl").text
    titles = [t for _, _, t in phase_titles(api)]
    assert titles[-2:] == ["Device registration", "Renewal in the field"]
    renewal_box = api[api.index('<section class="box accent field">'):]
    assert "/renew" in renewal_box and "/renew" not in api[:api.index('<section class="box accent field">')]
    for dialect in snippets.DIALECTS:
        page = configured_user.get(f"/runs/m1/api?dialect={dialect}")
        assert page.status_code == 200 and "GROUP_ID" in page.text and "CERT_ID" in page.text
        code = "".join(re.findall(r"<pre[^>]*>(.*?)</pre>", page.text, re.S))  # the copyable commands
        assert "${CERT_ID}" in code or "$env:CERT_ID" in code, dialect
        assert not re.search(r"(?<![$\w:])\{(GROUP_ID|DEVICE_ID|CERT_ID)\}", code), dialect


def test_renew_double_click_starts_one_round(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    fake.renew_delay = 0.5
    first = configured_user.post("/runs/m1/renew", follow_redirects=False)
    second = configured_user.post("/runs/m1/renew", follow_redirects=False)  # idempotent while renewing
    assert (first.status_code, second.status_code) == (303, 303)
    assert re.search(r'class="btn-icon" disabled\s+aria-busy="true"', configured_user.get("/runs/m1").text)
    renewed(store)
    assert renewals(store) == 1 and fake.route_order().count("renew") == 1


def test_at_most_max_renewals(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    for round_ in range(1, devices.MAX_RENEWALS + 1):
        assert configured_user.post("/runs/m1/renew", follow_redirects=False).status_code == 303
        renewed(store, rounds=round_)
    response = configured_user.post("/runs/m1/renew", follow_redirects=False)
    assert response.status_code == 409 and f"At most {devices.MAX_RENEWALS} renewals per run" in response.text
    assert renewals(store) == devices.MAX_RENEWALS and fake.route_order().count("renew") == devices.MAX_RENEWALS
    html = configured_user.get("/runs/m1").text
    assert re.search(rf'disabled\s+data-tip="At most {devices.MAX_RENEWALS} renewals per run"', html)


def test_renew_guards(configured_user, store, fake):
    fake.fail["device_enroll"] = _error(403, "not licensed")
    configured_user.post("/runs", data=uc06_form(run_id="f1"))
    assert finished(store, "f1")["status"] == "failed"
    assert configured_user.post("/runs/f1/renew", follow_redirects=False).status_code == 409
    assert store.get_run("f1")["status"] == "failed" and "renew" not in fake.route_order()


def test_renew_without_connection_does_not_stay_renewing(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (conn,) = store.connections()
    store.delete_connection(conn["id"])
    response = configured_user.post("/runs/m1/renew", follow_redirects=False)
    assert response.status_code == 409
    assert store.get_run("m1")["status"] == "completed" and "renew" not in fake.route_order()


def test_no_renewal_after_rollback(configured_user, store, fake, data_dir):
    configured_user.post("/runs", data=uc06_form(mode="batch", count="2"))
    finished(store, "m1")
    configured_user.post("/runs/m1/renew")
    renewed(store)
    configured_user.post("/runs/m1/cleanup", data={"mode": "full"})
    assert cleaned(store, "m1")["cleanup_status"] == "done"
    assert configured_user.post("/runs/m1/renew", follow_redirects=False).status_code == 409
    assert fake.issued() == [] and fake.active_devices() == []
    assert [g["status"] for g in fake.device_groups.values()] == ["DELETED"]
    html = configured_user.get("/runs/m1").text
    assert ">Renew now</button>" not in html and "Renew all devices" not in html
    assert 'action="/runs/m1/renew"' not in html


def test_failed_rounds_count_and_render(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form(field="rest"))
    finished(store, "m1")
    fake.fail["renew"] = _error(500, "upstream trouble")
    for round_ in range(1, devices.MAX_RENEWALS + 1):
        assert configured_user.post("/runs/m1/renew", follow_redirects=False).status_code == 303
        wait_for(lambda: (r := store.get_run("m1"))["status"] == "completed" and renewals(store) >= round_,
                 what="failed round")
    run = store.get_run("m1")
    assert [x.get("failed") for x in run["result"]["renewals"]] == [True] * devices.MAX_RENEWALS
    response = configured_user.post("/runs/m1/renew", follow_redirects=False)  # a broken round counts, too
    assert response.status_code == 409
    page = configured_user.get("/runs/m1")
    assert page.status_code == 200
    overview = page.text[page.text.index("<h2>Overview</h2>"):page.text.index("Devices in DTM")]
    assert ">None" not in overview and "Undefined" not in overview and '"metric"> s<' not in overview
    renewal = re.findall(r'<p class="metric">(.*?)</p>', overview)[-4:]  # all devices, per device, rounds, certs
    assert renewal == ["–", "–", str(devices.MAX_RENEWALS), "1"]  # no times from broken rounds
