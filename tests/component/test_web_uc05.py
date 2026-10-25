"""UC-5 through the web: the form, its validation, the run page (factory provisioning, enrollment in
the field, what the passcode enforces) – no internal UC number anywhere."""

import re

import pytest

from app import enrollment, evergreen
from tests.component.test_web_platforms import finished_cleanup
from tests.component.test_web_runs import assert_phase_titles, finished
from tests.fakedtm import ECDSA_CA_ID


def uc05_form(**overrides) -> dict:
    return {"run_id": "p5", "use_case": "uc05", "protocol": "est", "mode": "single", "count": "1",
            "ca_id": ECDSA_CA_ID, "checks": "true"} | overrides


def test_uc05_form(configured_user, fake):
    html = configured_user.get("/runs/new/uc05").text
    assert "Protocol in the field" in html and "Show what the passcode enforces" in html
    assert re.search(r'<input[^>]*name="checks"[^>]*checked', html)  # on by default
    assert "How many devices?" in html and 'data-when="mode=batch"' in html
    assert re.search(r'<input[^>]*name="count"[^>]*max="%d"' % enrollment.MAX_PASSCODE_BATCH, html)
    assert enrollment.MAX_PASSCODE_BATCH == 100
    assert "robot-evergreen-5y-profile" in html and "robot-evergreen-cmp-5y-profile" in html
    assert not re.search(r"UC-?\d", html)
    assert '<input type="hidden" name="use_case" value="uc05">' in html or 'value="uc05"' in html


@pytest.mark.parametrize("protocol", ["scep", "rest", "EST", "cmp", "x"])
def test_uc05_refuses_other_protocols(configured_user, store, fake, protocol):
    response = configured_user.post("/runs", data=uc05_form(protocol=protocol), follow_redirects=False)
    assert response.status_code == 400 and "Enrollment in the field: EST or CMPv2." in response.text
    assert store.list_runs() == [] and fake.route_order() == []


@pytest.mark.parametrize("count", ["0", str(evergreen.MAX_BATCH + 1), "-1"])
def test_uc05_batch_count_is_validated(configured_user, store, fake, count):
    response = configured_user.post("/runs", data=uc05_form(mode="batch", count=count), follow_redirects=False)
    assert response.status_code == 400 and f"Number of certificates: 1–{evergreen.MAX_BATCH}." in response.text
    assert store.list_runs() == []


def test_uc05_params(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(mode="single", count="7", auth_method="certificate",
                                                 variant="webui", approval="true"))
    run = finished(store, "p5")
    p = run["params"]
    assert (p["mode"], p["count"], p["auth"], p["variant"], p["approval"], p["checks"]) == (
        "single", 1, "passcode", "api", False, True)
    assert run["status"] == "completed", run["error"]
    configured_user.post("/runs", data=uc05_form(run_id="p6", mode="batch", count="3", checks=""))
    run = finished(store, "p6")
    assert (run["params"]["count"], run["params"]["checks"]) == (3, False) and run["status"] == "completed"
    configured_user.post("/runs", data={k: v for k, v in uc05_form(run_id="p7").items() if k != "checks"})
    assert finished(store, "p7")["params"]["checks"] is False  # an unticked checkbox is not sent


def test_uc05_run_page(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(mode="batch", count="2"))
    run = finished(store, "p5")
    assert run["status"] == "completed", run["error"]
    html = configured_user.get("/runs/p5").text
    assert "Factory provisioning – 2 one-time passcodes" in html and "Enrollment in the field" in html
    assert html.index("Factory provisioning – 2") < html.index('<p class="metrics-title">Enrollment in the field</p>')
    assert "What the passcode enforces" in html
    assert '<span class="mono">robot-p5-uc05-est-0001</span>' in html
    table = html[html.index("What the passcode enforces"):]
    table = table[:table.index("</table>")]
    assert table.count('<span class="pill ok">completed</span>') == 3 and "pill bad" not in table
    assert "Passcode has reached its usage limit" in table
    assert "Invalid registered value provided in attribute: subject.common_name" in html
    assert "1,000 passcodes" in html or "1000 passcodes" in html
    assert "Passcode-bound device certificates" in html and not re.search(r"UC-?\d", html)
    api = configured_user.get("/runs/p5/api?dialect=curl").text
    assert_phase_titles(api, [("Factory Provisioning", "factory"), ("Enrollment in the Field", "key")])
    field = api[api.index('<section class="box accent field">'):]
    assert "Enrollment in the Field</h3>" in field and "simpleenroll" in field
    assert "simpleenroll" not in api[:api.index('<section class="box accent field">')]
    assert 'data-copy="script-field-curl"' in field
    index = configured_user.get("/").text
    assert "<td>Passcode-bound device certificates · batch (2)</td>" in index and "<td>EST · Passcode</td>" in index
    assert configured_user.post("/runs/p5/cleanup", data={"mode": "full"}, follow_redirects=False).status_code in (200, 303)
    assert finished_cleanup(store, "p5")["cleanup_status"] == "done"
    assert all(o["status"] == "DELETED" for o in enroll_net.auth_objects["passcode"].values())


def test_uc05_run_page_without_checks(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(checks=""))
    assert finished(store, "p5")["status"] == "completed"
    html = configured_user.get("/runs/p5").text
    assert "What the passcode enforces" not in html and "Factory provisioning – 1 one-time passcode" in html
    assert "1,000 passcodes" not in html  # one device – nothing to extrapolate


def test_wrongly_accepted_check_is_shown_as_failed(configured_user, store, enroll_net):
    enroll_net.passcode_rules = False
    configured_user.post("/runs", data=uc05_form())
    assert finished(store, "p5")["status"] == "completed"
    html = configured_user.get("/runs/p5").text
    table = html[html.index("What the passcode enforces"):]
    table = table[:table.index("</table>")]
    assert "issued – the usage limit did not hold" in table and "issued – the registered common name did not hold" in table
    assert table.count('<span class="pill bad">failed</span>') == 2 and table.count('<span class="pill ok">') == 1



@pytest.mark.parametrize("count,ok", [("100", True), ("101", False), (str(evergreen.MAX_BATCH), False)])
def test_uc05_count_limit_is_100_passcodes(configured_user, store, fake, monkeypatch, count, ok):
    from app import main
    started = []
    monkeypatch.setattr(main.enrollment, "run", lambda *a, **k: started.append(a) or _noop())
    response = configured_user.post("/runs", data=uc05_form(mode="batch", count=count), follow_redirects=False)
    if ok:
        assert response.status_code == 303 and store.get_run("p5")["params"]["count"] == 100
    else:
        assert response.status_code == 400
        assert "Number of devices: 1–100 (one passcode each)." in response.text and store.list_runs() == []


async def _noop():
    return None


def test_batch_overview_says_all_requests(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(mode="batch", count="2", checks=""))
    assert finished(store, "p5")["status"] == "completed"
    html = configured_user.get("/runs/p5").text
    assert "<small>All requests</small>" in html and "Upload done" not in html
