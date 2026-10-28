"""UC-5 through the web: the form, its validation, the run page (factory provisioning, enrollment in
the field, what the passcode enforces) – no internal UC number anywhere."""

import re

import pytest

from app import enrollment, evergreen
from tests.component.test_web_platforms import finished_cleanup
from tests.component.test_web_runs import assert_phase_titles, finished
from tests.fakedtm import ECDSA_CA_ID


def assert_title_without_subtitle(html):
    """The run is headed by the use case's title + status pill – and nothing under it (no subtitle line)."""
    assert re.search(r'<div class="page-head">\s*<div><h1>Passcode-bound device certificates <span class="pill [a-z]+">[a-z]+</span></h1></div>\s*</div>',
                     html), "page head is not just the use-case title"
    assert html.count("Passcode-bound device certificates") == 1  # only in the heading


def uc05_form(**overrides) -> dict:
    return {"run_id": "p5", "use_case": "uc05", "protocol": "est", "mode": "single", "count": "1",
            "ca_id": ECDSA_CA_ID, "checks": "true"} | overrides


def test_uc05_form(configured_user, fake):
    html = configured_user.get("/runs/new/uc05").text
    assert '<span class="seg-label" id="l-protocol">Protocol</span>' in html
    stack = html[html.index('<div class="switch-stack">'):]
    stack = stack[:stack.index("</div>")]
    # both on by default, stacked: the checks, then the pause before the field
    assert re.search(r'<label><input type="checkbox" name="checks" value="true" role="switch" checked> Run checks'
                     r'</label>\s*<label data-tip="[^"]+"><input type="checkbox" name="pause" value="true" '
                     r'role="switch" checked> Pause before certificate enrollment</label>', stack)
    assert '<span class="seg-label" id="l-mode">Devices</span>' in html and "<h3>Issuance</h3>" in html
    assert re.search(r'<div class="choice-with-count">.*?<input id="count" type="number" name="count" class="short" '
                     r'value="2"[^>]*aria-label="Number of devices" data-when="mode=batch">', html, re.S)
    assert re.search(r'<input[^>]*name="count"[^>]*max="%d"' % enrollment.MAX_PASSCODE_BATCH, html)
    assert enrollment.MAX_PASSCODE_BATCH == 100
    assert "robot-evergreen-5y-profile" in html and "robot-evergreen-cmp-5y-profile" in html
    assert not re.search(r"UC-?\d", html)
    assert '<input type="hidden" name="use_case" value="uc05">' in html or 'value="uc05"' in html


@pytest.mark.parametrize("protocol", ["scep", "rest", "EST", "cmp", "x"])
def test_uc05_refuses_other_protocols(configured_user, store, fake, protocol):
    response = configured_user.post("/runs", data=uc05_form(protocol=protocol), follow_redirects=False)
    assert response.status_code == 400 and "Field enrollment: EST or CMPv2." in response.text
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


def phase_boxes(html: str) -> dict[str, dict]:
    """The overview's two UC-5 phase boxes: title → {classes, icon, meta, metrics [(label, value)]}."""
    pair = html[html.index('<div class="phase-pair">'):]
    pair = pair[:pair.index('<p class="call-purpose">') if '<p class="call-purpose">' in pair else len(pair)]
    boxes = {}
    for classes, body in re.findall(r'<section class="(box accent[^"]*)">(.*?)</section>', pair, re.S):
        title = re.search(r'<h3 class="phase-title"><span class="phase-icon">(.*?)</span>([^<]+)</h3>', body, re.S)
        grids = re.findall(r'<div class="metrics metrics-4">(.*?)\n      </div>', body, re.S)
        metrics = re.findall(r"<small[^>]*>([^<]+)</small><p class=\"metric\">([^<]+)</p>", grids[0]) if grids else []
        meta = re.search(r'<span class="meta">([^<]+)</span>', body)
        boxes[title.group(2)] = {"classes": classes, "icon": title.group(1), "metrics": metrics, "body": body,
                                 "meta": meta.group(1).strip() if meta else None}
    return boxes


def checks_table(html: str) -> list[list[str]]:
    section = html[html.index('<section class="checks">'):]
    section = section[:section.index("</section>")]
    assert '<table class="data-table checks-table">' in section
    assert "<thead><tr><th>Check</th><th>Expected</th><th>Result</th></tr></thead>" in section
    return [re.findall(r"<td[^>]*>(.*?)</td>", row, re.S) for row in re.findall(r"<tr>(.*?)</tr>", section, re.S)[1:]]


@pytest.mark.parametrize("count", [1, 2])
def test_uc05_overview_phase_pair(configured_user, store, enroll_net, count):
    configured_user.post("/runs", data=uc05_form(mode="batch" if count > 1 else "single", count=str(count)))
    run = finished(store, "p5")
    assert run["status"] == "completed", run["error"]
    html = configured_user.get("/runs/p5").text
    boxes = phase_boxes(html)
    assert list(boxes) == ["Factory provisioning", "Field enrollment"]
    factory, field = boxes.values()
    assert (factory["classes"], field["classes"]) == ("box accent", "box accent field")
    assert 'd="M3 21V10l6 4V10l6 4V6l6 3v12z"' in factory["icon"] and 'd="M11 12l9-9M17 6l3 3M15 8l2 2"' in field["icon"]
    assert [m[0] for m in factory["metrics"]] == ["All passcodes", "Per passcode", "Per minute",
                                                 "1,000 passcodes ≈" if count > 1 else "Median"]
    assert [m[0] for m in field["metrics"]] == ["All requests", "Per certificate", "Per minute",
                                               "1,000 devices ≈" if count > 1 else "Key generation"]
    r = run["result"]
    assert factory["metrics"][0][1] == f"{r['provisioning']['duration_s']} s"
    assert field["metrics"][0][1] == f"{r['duration_s']} s"
    prov = r["provisioning"]  # per item: two decimals
    assert factory["metrics"][1][1] == "%.2f s" % (prov["per_certificate_s"] or prov["duration_s"])
    assert field["metrics"][1][1] == "%.2f s" % (r["per_certificate_s"] or r["duration_s"])
    if count == 1:
        assert factory["metrics"][3][1] == "%.2f s" % prov["median_s"]
    # "First enrollment" once, at the end of the overview card (not inside the field box), keys humanised
    assert "<summary>First enrollment</summary>" not in field["body"]
    assert html.count('<details class="overview-details"><summary>First enrollment</summary>') == 1
    card = html[html.index("<h2>Overview</h2>"):]
    card = card[:card.index("</article>")]
    assert card.rindex("overview-details") > card.rindex('<section class="checks">')
    assert "<dt>Common name</dt>" in card and "<dt>common_name</dt>" not in card
    assert "Upload done" not in html and "Time per certificate" not in html  # the generic grid is not shown
    # checks
    assert '<section class="checks">\n    <div class="box-head"><h3>Passcode enforced</h3></div>' in html
    rows = checks_table(html)
    assert [row[0] for row in rows] == ["Re-enroll with the used passcode", "CSR with a different common name",
                                        "Passcode usage afterwards"]
    assert '<colgroup><col class="c-check"><col class="c-expected"><col></colgroup>' in html
    assert [row[1] for row in rows] == ["rejected", "rejected", "used up"]
    results = [row[2] for row in rows]
    assert all(cell.startswith('<span class="pill ok">passed</span> ') for cell in results)
    assert results[0].endswith(" Passcode has reached its usage limit")
    assert results[1].endswith(" Invalid registered value provided in attribute: subject.common_name")
    assert '{"errors"' not in html and "{&#34;errors" not in "".join(results)
    assert_title_without_subtitle(html)
    assert not re.search(r"UC-?\d", html)


def test_uc05_steps_and_rollback_from_the_web(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(mode="batch", count="2"))
    assert finished(store, "p5")["status"] == "completed"
    api = configured_user.get("/runs/p5/api?dialect=curl").text
    assert_phase_titles(api, [("Factory provisioning", "factory"), ("Field enrollment", "key")])
    field = api[api.index('<section class="box accent field">'):]
    assert "Field enrollment</h3>" in field and "simpleenroll" in field
    assert "simpleenroll" not in api[:api.index('<section class="box accent field">')]
    assert 'data-copy="script-field-curl"' in field
    index = configured_user.get("/").text
    assert "<td>Passcode-bound device certificates</td>" in index and "<td>EST · Passcode · 2×</td>" in index
    assert configured_user.post("/runs/p5/cleanup", data={"mode": "full"}, follow_redirects=False).status_code in (200, 303)
    assert finished_cleanup(store, "p5")["cleanup_status"] == "done"
    assert all(o["status"] == "DELETED" for o in enroll_net.auth_objects["passcode"].values())


def test_uc05_run_page_without_checks(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(checks=""))
    assert finished(store, "p5")["status"] == "completed"
    html = configured_user.get("/runs/p5").text
    assert '<section class="checks">' not in html and "Passcode enforced" not in html
    assert list(phase_boxes(html)) == ["Factory provisioning", "Field enrollment"]
    assert "1,000 passcodes" not in html  # one device – nothing to extrapolate


def test_stored_rows_with_raw_dtm_errors_show_only_the_message(configured_user, store, enroll_net):
    """Runs stored before outcomes were tidied: the overview shows DTM's message, never raw JSON;
    the full text stays in the tooltip."""
    configured_user.post("/runs", data=uc05_form())
    run = finished(store, "p5")
    raw_est = ('EST returned 400: {"errors":[{"code":"invalid_input","message":"Passcode has reached its usage limit"}]}')
    raw_cmp = ('CMPv2 request rejected: CMP error: request rejected by server:PKIStatus: rejection; StatusString: '
               '"Invalid registered value provided in attribute: subject.common_name"; PKIFailureInfo: badRequest')
    old = [{"check": "Second enrollment with the used passcode", "expected": "rejected", "ok": True, "outcome": raw_est},
           {"check": "CSR with another common name than the passcode's", "expected": "rejected", "ok": True,
            "outcome": raw_cmp},
           {"check": "The rejected request used up that passcode", "expected": "noted", "ok": True,
            "outcome": "usage 1 of 1 – the device could not enroll any more"}]
    store.update_run("p5", result=run["result"] | {"checks": old})
    html = configured_user.get("/runs/p5").text
    rows = checks_table(html)
    shown = [re.sub(r"<[^>]+>", "", row[2]).replace("passed", "", 1).strip() for row in rows]
    assert shown == ["Passcode has reached its usage limit",
                     "Invalid registered value provided in attribute: subject.common_name",
                     "usage 1 of 1 – the device could not enroll any more"]
    visible = re.sub(r'data-tip="[^"]*"', "", html)
    assert '{"errors"' not in visible and "{&#34;errors" not in visible and "PKIFailureInfo" not in visible
    assert "{&#34;errors&#34;" in html  # the raw text is only in the tooltip (escaped)


def test_wrongly_accepted_check_is_shown_as_failed(configured_user, store, enroll_net):
    enroll_net.passcode_rules = False
    configured_user.post("/runs", data=uc05_form())
    assert finished(store, "p5")["status"] == "completed"
    html = configured_user.get("/runs/p5").text
    table = html[html.index('<section class="checks">'):]
    table = table[:table.index("</table>")]
    assert "issued – the usage limit did not hold" in table and "issued – the registered common name did not hold" in table
    assert table.count('<span class="pill bad">failed</span>') == 2 and table.count('<span class="pill ok">passed</span>') == 1



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


# --- the pause before the field -----------------------------------------------------------------

def enroll_buttons(html: str) -> list[str]:
    """The devices whose tile offers the field enrollment (no run-wide button any more)."""
    return re.findall(r'<form method="post" action="/runs/\w+/devices/([\w-]+)/enroll"[^>]* class="inline">\s*'
                      r'<button type="submit" class="btn-sm btn-icon field-action"\s*>.*?Enroll</button>', html, re.S)


@pytest.mark.parametrize("count", [1, 2])
def test_paused_run_shows_enroll_buttons_and_continues_on_click(configured_user, store, enroll_net, count):
    configured_user.post("/runs", data=uc05_form(pause="true", mode="batch" if count > 1 else "single",
                                                 count=str(count)))
    run = finished(store, "p5")  # stops at the pause
    assert run["status"] == "paused" and run["params"]["pause"] is True, run["error"]
    assert enroll_net.enroll_requests == []
    html = configured_user.get("/runs/p5").text
    names = [f"robot-p5-uc05-est-{i:04d}" for i in range(1, count + 1)]
    assert enroll_buttons(html) == names  # one per device tile – no run-wide button
    assert 'action="/runs/p5/enroll"' not in html
    assert html.count("Passcode bound to CN") == count and html.count(">unused</span>") == count
    assert "<h2>Overview</h2>" not in html and '<div class="phase-pair">' not in html  # no result yet
    assert '<li class="current" aria-current="step">Run</li>' in html
    # the live view of a paused run reloads into this page (it does not keep polling)
    live = configured_user.get("/runs/p5/live", headers={"hx-request": "true"})
    assert live.headers.get("hx-refresh") == "true"
    # the click continues the run
    response = configured_user.post("/runs/p5/enroll", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/p5"
    run = finished(store, "p5")
    assert run["status"] == "completed", run["error"]
    assert len(run["result"]["certificates"]) == count and [c["ok"] for c in run["result"]["checks"]] == [True] * 3
    html = configured_user.get("/runs/p5").text
    assert enroll_buttons(html) == [] and "<h2>Overview</h2>" in html
    # a later click on the (stale) button just shows the run as it is
    response = configured_user.post("/runs/p5/enroll", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/p5"
    assert store.get_run("p5")["status"] == "completed"


def test_paused_devices_enroll_one_per_click(configured_user, store, enroll_net):
    from tests.conftest import wait_for
    configured_user.post("/runs", data=uc05_form(pause="true", mode="batch", count="2"))
    assert finished(store, "p5")["status"] == "paused"
    first, second = "robot-p5-uc05-est-0001", "robot-p5-uc05-est-0002"
    response = configured_user.post(f"/runs/p5/devices/{second}/enroll", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/p5"
    run = wait_for(lambda: (r := store.get_run("p5"))["result"].get("certificates") and not r["result"].get("busy") and r,
                   what="the second device to enroll")
    assert run["status"] == "paused" and [c["common_name"] for c in run["result"]["certificates"]] == [second]
    assert len(enroll_net.enroll_requests) == 1
    html = configured_user.get("/runs/p5").text
    assert enroll_buttons(html) == [first] and html.count(">used</span>") == 1
    serial = run["result"]["certificates"][0]["serial"]
    assert configured_user.get(f"/runs/p5/certificates/{serial}.pem").status_code == 200  # downloadable at once
    # an enrolled device, another action or an unknown device is refused
    assert configured_user.post(f"/runs/p5/devices/{second}/enroll", follow_redirects=False).status_code == 409
    assert configured_user.post(f"/runs/p5/devices/{first}/renew", follow_redirects=False).status_code == 409
    assert configured_user.post("/runs/p5/devices/robot-p5-uc05-est-0003/enroll", follow_redirects=False).status_code == 404
    configured_user.post(f"/runs/p5/devices/{first}/enroll")
    run = finished_paused(store, "p5")
    assert run["status"] == "completed", run["error"]
    assert [c["common_name"] for c in run["result"]["certificates"]] == [second, first]
    assert run["result"]["bound_cn"] == second and not run["result"].get("busy")  # the checks use a used passcode
    assert enroll_buttons(configured_user.get("/runs/p5").text) == []
    assert configured_user.post(f"/runs/p5/devices/{first}/enroll", follow_redirects=False).status_code == 409


def finished_paused(store, run_id):
    from tests.conftest import wait_for
    return wait_for(lambda: (r := store.get_run(run_id)) and r["status"] in ("completed", "failed") and r,
                    what=f"run {run_id} to complete")


def test_device_enroll_only_while_paused(configured_user, store):
    paused_run(store)
    name = "robot-e5-uc05-est-0001"
    store.update_run("e5", cleanup_status="running")
    assert configured_user.post(f"/runs/e5/devices/{name}/enroll", follow_redirects=False).status_code == 409
    store.update_run("e5", status="completed", cleanup_status=None,
                     result={"policy": "robot-e5-uc05-policy", "provisioning": {"count": 1}})  # unenrolled when it ended
    assert configured_user.post(f"/runs/e5/devices/{name}/enroll", follow_redirects=False).status_code == 409
    assert not store.get_run("e5")["result"].get("busy")
    store.update_run("e5", status="paused")
    response = configured_user.post(f"/runs/e5/devices/{name}/enroll", headers={"Origin": "https://evil.example"},
                                    follow_redirects=False)
    assert response.status_code == 403 and not store.get_run("e5")["result"].get("busy")


def test_pause_is_off_when_the_switch_is_not_sent(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form())  # an unticked checkbox is not sent
    run = finished(store, "p5")
    assert run["params"]["pause"] is False and run["status"] == "completed", run["error"]
    assert enroll_buttons(configured_user.get("/runs/p5").text) == []


def test_rollback_from_the_runs_list_during_the_pause(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(pause="true", mode="batch", count="2"))
    assert finished(store, "p5")["status"] == "paused"
    # paused is not active: the runs list offers the rollback, and it is accepted
    response = configured_user.post("/runs/p5/cleanup", data={"mode": "full"}, follow_redirects=False)
    assert response.status_code in (200, 303)
    run = finished_cleanup(store, "p5")
    assert run["cleanup_status"] == "done"
    from tests.conftest import wait_for
    run = wait_for(lambda: (r := store.get_run("p5"))["status"] == "failed" and r, what="the run to end")
    assert run["error"] == "rolled back before the field enrollment"
    assert enroll_net.enroll_requests == []
    assert all(o["status"] == "DELETED" for o in enroll_net.auth_objects["passcode"].values())
    assert enroll_buttons(configured_user.get("/runs/p5").text) == []
    assert configured_user.post("/runs/p5/enroll", follow_redirects=False).status_code == 303
    assert store.get_run("p5")["status"] == "failed" and enroll_net.enroll_requests == []


def paused_run(store, run_id="e5", use_case="uc05", **fields):
    store.create_run(run_id, use_case, {"dtm_host": enrollment_host(), "protocol": "est", "auth": "passcode",
                                        "count": 1, "mode": "single", "variant": "api", "pause": True})
    store.update_run(run_id, status="paused", result={"policy": f"robot-{run_id}-{use_case}-policy"}, **fields)


def enrollment_host():
    from tests.fakedtm import HOST
    return HOST


@pytest.mark.parametrize("use_case", ["uc03", "uc04"])
def test_enroll_refused_for_other_use_cases(configured_user, store, use_case):
    paused_run(store, use_case=use_case)
    assert configured_user.post("/runs/e5/enroll", follow_redirects=False).status_code == 409
    assert store.get_run("e5")["status"] == "paused"
    assert enroll_buttons(configured_user.get("/runs/e5").text) == []


@pytest.mark.parametrize("status", ["completed", "failed", "interrupted", "pending"])
def test_enroll_changes_nothing_unless_paused(configured_user, store, status):
    """A stale button: no error, the run page shows the run as it is."""
    paused_run(store)
    store.update_run("e5", status=status)
    response = configured_user.post("/runs/e5/enroll", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/e5"
    assert store.get_run("e5")["status"] == status
    assert enroll_buttons(configured_user.get("/runs/e5").text) == []


@pytest.mark.parametrize("cleanup_status", ["running", "done", "failed"])
def test_enroll_does_not_continue_once_a_rollback_started(configured_user, store, cleanup_status):
    paused_run(store, cleanup_status=cleanup_status)
    response = configured_user.post("/runs/e5/enroll", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/e5"
    assert store.get_run("e5")["status"] == "paused"
    assert enroll_buttons(configured_user.get("/runs/e5").text) == []


def test_double_click_while_running_just_redirects(configured_user, store):
    paused_run(store)
    store.update_run("e5", status="running")  # the first click already claimed the run
    response = configured_user.post("/runs/e5/enroll", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/e5"
    assert store.get_run("e5")["status"] == "running"


def test_enroll_unknown_run_and_without_login(configured_user, store, web):
    assert configured_user.post("/runs/nope/enroll", follow_redirects=False).status_code == 404
    paused_run(store)
    web.cookies.clear()
    response = web.post("/runs/e5/enroll", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert store.get_run("e5")["status"] == "paused"


def test_paused_run_page_and_list(configured_user, store):
    paused_run(store)
    html = configured_user.get("/runs/e5").text
    assert enroll_buttons(html) == ["robot-e5-uc05-est-0001"]
    assert '<span class="pill ">paused</span>' in html  # waiting for the presenter: no pulsing dot
    assert "<h2>Overview</h2>" not in html


def enroll_all(html):
    return re.findall(r'action="/runs/e5/enroll" class="inline">\s*<button[^>]*>.*?Enroll all (\d+)</button>', html, re.S)


def test_wall_offers_enroll_all_for_the_waiting_devices(configured_user, store):
    paused_run(store)
    store.update_run("e5", params=store.get_run("e5")["params"] | {"count": 12, "mode": "batch"},
                     result={"policy": "robot-e5-uc05-policy", "busy": ["robot-e5-uc05-est-0002"],
                             "certificates": [{"common_name": "robot-e5-uc05-est-0001", "serial": "1A", "status": "issued"}]})
    html = configured_user.get("/runs/e5").text
    assert '<svg class="wall' in html and enroll_all(html) == ["10"]  # 12 minus one enrolled, one in progress
    card_head = re.search(r'<div class="card-head"><h2>Devices</h2>.*?</form>\s*</div>', html, re.S).group(0)
    assert enroll_all(card_head) == ["10"]  # the action sits in the card head, the filter bar follows below it
    assert html.index(card_head) < html.index('<div class="wall-bar"')
    response = configured_user.post("/runs/e5/enroll", follow_redirects=False)
    assert response.status_code == 303 and store.get_run("e5")["status"] == "running"
    assert enroll_all(configured_user.get("/runs/e5").text) == []


def test_no_enroll_all_on_tiles_or_after_a_rollback(configured_user, store):
    paused_run(store)  # one device: a tile with its own button
    assert enroll_all(configured_user.get("/runs/e5").text) == []
    store.update_run("e5", params=store.get_run("e5")["params"] | {"count": 12, "mode": "batch"}, cleanup_status="done")
    assert enroll_all(configured_user.get("/runs/e5").text) == []
