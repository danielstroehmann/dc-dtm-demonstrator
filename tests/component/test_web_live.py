"""The run page without reloads: a device starting or finishing swaps the cards that show devices in place (the live
poll's _run_update.html, also the htmx answer to a device click); only a new phase of the run reloads the page."""

import re

from app import devices
from app.main import live_busy, live_phase
from tests.component.test_web_runs import finished
from tests.component.test_web_uc04 import uc04_form
from tests.component.test_web_uc05 import uc05_form
from tests.component.test_web_uc06 import device_names, uc06_form
from tests.conftest import wait_for

HX = {"HX-Request": "true"}


def oob_ids(html: str) -> list[str]:
    return re.findall(r'id="([\w-]+)" hx-swap-oob="true"', html)


def test_phase_and_busy_keys():
    run = {"status": "completed", "cleanup_status": None, "result": {"busy": ["a", "adding"]}}
    assert (live_phase(run), live_busy(run)) == ("completed|", "a,adding")
    # UC-4 renewing is its device acting – same phase as completed, but a busy change
    renewing = run | {"status": "renewing", "result": {}}
    assert (live_phase(renewing), live_busy(renewing)) == ("completed|", "renewing")
    assert live_phase(run | {"cleanup_status": "running"}) == "completed|running"
    assert live_phase(run | {"status": "paused"}) == "paused|"


def test_a_new_phase_still_reloads_the_page(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    # the page was rendered while the run ran – it finished since
    assert configured_user.get("/runs/m1/live?busy=&phase=running%7C", headers=HX).headers.get("HX-Refresh") == "true"
    # a cleanup started (the runs list) while a device acted
    (name,) = device_names(store)
    devices.commit(store, "m1", lambda r: r.update(busy=[name]))
    store.update_run("m1", cleanup_status="running")
    live = configured_user.get(f"/runs/m1/live?busy={name}&phase=completed%7C", headers=HX)
    assert live.headers.get("HX-Refresh") == "true" and live.text == ""
    store.update_run("m1", cleanup_status=None)
    devices.commit(store, "m1", lambda r: r.update(busy=[]))


def test_a_device_click_swaps_the_cards_in_place(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (name,) = device_names(store)
    page = configured_user.get("/runs/m1").text
    # the tile's button posts with htmx into #live – no page load
    assert re.search(rf'<form method="post" action="/runs/m1/devices/{name}/renew" hx-post="/runs/m1/devices/{name}/renew"'
                     r' hx-target="#live" hx-swap="outerHTML"', page)
    assert 'hx-get="/runs/m1/live' not in page  # nothing acts – nothing polls
    devices.commit(store, "m1", lambda r: r.update(busy=[name]))  # its task runs: a click is a double click
    response = configured_user.post(f"/runs/m1/devices/{name}/renew", headers=HX, follow_redirects=False)
    assert response.status_code == 200 and response.text.lstrip().startswith('<div id="live"')
    # #live now polls with the device busy; the devices card shows its tile acting; the pill and timeline follow
    assert f'hx-get="/runs/m1/live?busy={name}&amp;phase=completed%7C"' in response.text
    assert oob_ids(response.text) == ["overview", "devices", "timeline"]
    assert 'hx-swap-oob="outerHTML:.page-head h1 .pill"' in response.text
    assert 'aria-busy="true"' in response.text and 'hx-get="/runs/m1/timeline"' in response.text
    assert renewals_started(store) == 0  # a double click starts nothing
    devices.commit(store, "m1", lambda r: r.update(busy=[]))
    # a plain form post still shows the run
    plain = configured_user.post(f"/runs/m1/devices/{name}/renew", follow_redirects=False)
    assert plain.status_code == 303 and plain.headers["location"] == "/runs/m1"
    wait_for(lambda: not store.get_run("m1")["result"].get("busy"), what="the renewal")


def renewals_started(store) -> int:
    return len(store.get_run("m1")["result"].get("renewals") or [])


def test_device_finishing_ends_with_its_result_without_reload(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (name,) = device_names(store)
    acting = configured_user.post(f"/runs/m1/devices/{name}/renew", headers=HX)
    poll = re.search(r'hx-get="(/runs/m1/live\?[^"]+)"', acting.text).group(1).replace("&amp;", "&")
    wait_for(lambda: not store.get_run("m1")["result"].get("busy"), what="the renewal")
    done = configured_user.get(poll, headers=HX)
    assert done.status_code == 200 and "HX-Refresh" not in done.headers
    assert 'hx-get="/runs/m1/live' not in done.text  # #live stops polling
    assert '<ol class="timeline" id="timeline" hx-swap-oob="true" >' in done.text  # so does the timeline
    assert 'aria-busy="true"' not in done.text and "Renewed in" in done.text  # the tile shows the result
    # the tile's own last poll shows the same final state – and stops polling
    tile = configured_user.get(f"/runs/m1/devices/{name}/tile")
    assert "hx-get" not in tile.text and "Renewed in" in tile.text


def test_uc04_renewal_swaps_in_place_with_the_status_pill(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc04_form())
    assert finished(store, "d1")["status"] == "completed"
    acting = configured_user.post("/runs/d1/renew", headers=HX)
    assert acting.status_code == 200 and "HX-Refresh" not in acting.headers
    wait_for(lambda: store.get_run("d1")["status"] == "completed", what="the renewal")
    # the page rendered while renewing polls with busy=renewing – the renewal ending is no new phase
    done = configured_user.get("/runs/d1/live?busy=renewing&phase=completed%7C", headers=HX)
    assert "HX-Refresh" not in done.headers and "devices" in oob_ids(done.text)
    assert '<span class="pill ok" hx-swap-oob="outerHTML:.page-head h1 .pill">completed</span>' in done.text
    assert "renewal 1 of 5" in done.text


def test_a_click_in_the_walls_side_panel_swaps_that_tile(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc05_form(pause="true", mode="batch", count="11"))
    assert finished(store, "p5")["status"] == "paused"
    name = "robot-p5-uc05-est-0003"
    response = configured_user.post(f"/runs/p5/devices/{name}/enroll", headers=HX)
    # the wall has no tiles – the side panel's tile (id by its cell) follows out of band, acting
    assert response.status_code == 200 and "tile-3" in oob_ids(response.text) and "devices" in oob_ids(response.text)
    tile = response.text.split('id="tile-3"')[1]
    assert name in tile and 'aria-busy="true"' in tile
    wait_for(lambda: not store.get_run("p5")["result"].get("busy"), what="the device to enroll")
