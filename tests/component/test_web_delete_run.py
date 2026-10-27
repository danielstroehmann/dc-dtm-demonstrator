"""Deleting a run from the demonstrator – only after a completed full rollback."""

import re

import pytest

from tests.component.test_web_runs import action_slot, cleaned, finished, form
from tests.conftest import wait_for

DELETE_FORM = 'action="/runs/r1/delete"'


def delete_form_has_confirm(html: str) -> bool:
    """Deleting a rolled-back run is harmless (the DTM account is already clean) – no confirm dialog."""
    forms = re.findall(r'<form[^>]*action="/runs/[a-z0-9]+/delete"[^>]*>', html)
    assert forms, "no delete-run form on the page"
    return any("hx-confirm" in f or "data-confirm-label" in f for f in forms)


def rolled_back(client, store, run_id="r1", **overrides):
    client.post("/runs", data=form(run_id=run_id, **overrides))
    finished(store, run_id)
    client.post(f"/runs/{run_id}/cleanup", data={"mode": "full"})
    run = cleaned(store, run_id)
    assert run["cleanup_status"] == "done" and run["cleanup_mode"] == "full", store.events(run_id)
    return run


def test_delete_after_full_rollback(configured_user, store, fake, data_dir):
    # another run that must stay untouched, with its own artifact directory
    configured_user.post("/runs", data=form(run_id="keep", variant="webui", mode="batch", count="2"))
    finished(store, "keep")
    keep_events = store.events("keep")
    configured_user.post("/runs", data=form(variant="webui", mode="batch", count="2"))
    finished(store, "r1")
    (data_dir / "runs" / "r1" / "extra.txt").write_text("x")
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    cleaned(store, "r1")
    (data_dir / "runs" / "r1").mkdir(parents=True, exist_ok=True)  # leftover files are removed too
    (data_dir / "runs" / "r1" / "extra.txt").write_text("x")

    index = configured_user.get("/").text  # delete lives in the runs list only
    assert DELETE_FORM in index and not delete_form_has_confirm(index)
    assert DELETE_FORM not in configured_user.get("/runs/r1").text

    response = configured_user.post("/runs/r1/delete", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert store.get_run("r1") is None
    assert store.events("r1") == [] and store.objects("r1", include_removed=True) == []
    assert not (data_dir / "runs" / "r1").exists()
    assert configured_user.get("/runs/r1").status_code == 404
    index = configured_user.get("/").text
    assert 'href="/runs/r1"' not in index and 'href="/runs/keep"' in index
    # the other run is untouched
    assert store.events("keep") == keep_events
    assert (data_dir / "runs" / "keep" / "batch.zip").is_file()
    assert {o["kind"] for o in store.objects("keep")} == {"division", "policy"}
    # deleting again → 404
    assert configured_user.post("/runs/r1/delete").status_code == 404


def test_deleted_run_id_can_be_reused(configured_user, store, fake):
    rolled_back(configured_user, store)
    assert configured_user.post("/runs/r1/delete", follow_redirects=False).status_code == 303
    response = configured_user.post("/runs", data=form(mode="batch", count="2"), follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/r1"
    run = finished(store, "r1")
    assert run["status"] == "completed", store.events("r1")
    assert run["cleanup_status"] is None and run["params"]["mode"] == "batch"
    # fresh log and ledger, nothing inherited from the deleted run
    assert not any("Cleanup done" in e["message"] for e in store.events("r1"))
    assert {o["kind"] for o in store.objects("r1", include_removed=True)} == {"division", "policy", "batch_job"}
    assert DELETE_FORM not in configured_user.get("/runs/r1").text
    assert fake.violations == []


def test_no_delete_before_cleanup(configured_user, store):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    assert DELETE_FORM not in configured_user.get("/runs/r1").text
    response = configured_user.post("/runs/r1/delete")
    assert response.status_code == 409 and "completed full rollback" in response.text
    assert store.run_exists("r1") and store.events("r1")


def test_no_delete_after_certificates_only_cleanup(configured_user, store, fake):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    configured_user.post("/runs/r1/cleanup", data={"mode": "certificates"})
    assert cleaned(store, "r1")["cleanup_status"] == "done"
    assert DELETE_FORM not in configured_user.get("/runs/r1").text
    assert configured_user.post("/runs/r1/delete").status_code == 409
    # the ledger is still needed for the pending full rollback
    assert {o["kind"] for o in store.objects("r1")} == {"division", "policy"}
    assert len(fake.policies) == 1


def test_no_delete_after_failed_full_cleanup(configured_user, store, fake):
    import httpx
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    fake.fail["policy_delete"] = httpx.Response(400, text="<html>no</html>")
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    run = cleaned(store, "r1")
    assert (run["cleanup_mode"], run["cleanup_status"]) == ("full", "failed")
    assert DELETE_FORM not in configured_user.get("/runs/r1").text
    assert configured_user.post("/runs/r1/delete").status_code == 409
    assert store.objects("r1", "policy")


@pytest.mark.parametrize("status,cleanup_mode,cleanup_status", [
    ("completed", "full", "running"),
    ("completed", "full", "interrupted"),
    ("completed", "certificates", "running"),
    ("running", None, None),
    ("waiting", None, None),
    ("failed", None, None),
    ("interrupted", "full", "failed"),
])
def test_delete_refused_states(configured_store, user, store, status, cleanup_mode, cleanup_status):
    store.create_run("r1", "uc01", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.update_run("r1", status=status, cleanup_mode=cleanup_mode, cleanup_status=cleanup_status)
    assert DELETE_FORM not in user.get("/runs/r1").text
    assert user.post("/runs/r1/delete").status_code == 409
    assert store.run_exists("r1")


@pytest.mark.parametrize("path", ["/runs/nope/delete", "/runs/BAD-ID/delete", "/runs/a_b/delete",
                                  "/runs/%2e%2e/delete", "/runs/" + "a" * 17 + "/delete"])
def test_delete_unknown_or_invalid_run_is_404(user, path, data_dir):
    (data_dir / "runs").mkdir(parents=True, exist_ok=True)
    (data_dir / "marker").write_text("keep")
    assert user.post(path).status_code == 404
    assert (data_dir / "marker").is_file() and (data_dir / "runs").is_dir()


def test_delete_requires_post(configured_user, store):
    rolled_back(configured_user, store)
    assert configured_user.get("/runs/r1/delete").status_code == 405
    assert store.run_exists("r1")


def test_delete_requires_login(configured_user, store, web):
    rolled_back(configured_user, store)
    configured_user.post("/logout")
    response = web.post("/runs/r1/delete", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    htmx = web.post("/runs/r1/delete", headers={"HX-Request": "true"}, follow_redirects=False)
    assert htmx.status_code == 401 and htmx.headers["hx-redirect"] == "/login"
    assert store.run_exists("r1") and store.events("r1")


def test_delete_form_shown_only_after_full_rollback(configured_user, store):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    assert DELETE_FORM not in configured_user.get("/").text and DELETE_FORM not in configured_user.get("/runs/r1").text
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    wait_for(lambda: store.get_run("r1")["cleanup_status"] == "done", what="full rollback")
    slot = action_slot(configured_user.get("/").text, "r1")
    assert re.fullmatch(r'\s*<form method="post" action="/runs/r1/delete" class="inline" hx-boost="true">\s*'
                        r'<button type="submit" class="row-action secondary outline" aria-label="Delete run r1">Delete'
                        r'</button>\s*</form>\s*', slot), slot
    assert "Full rollback" not in slot and not delete_form_has_confirm(slot)
    page = configured_user.get("/runs/r1").text
    assert DELETE_FORM not in page and "<h2>Delete run</h2>" not in page and "<h2>Clean up</h2>" not in page


# --- per-row delete form on the index ------------------------------------------------------

@pytest.mark.parametrize("status,cleanup_mode,cleanup_status,shown", [
    ("completed", "full", "done", True),
    ("failed", "full", "done", True),
    ("waiting", "full", "done", True),
    ("completed", None, None, False),
    ("running", None, None, False),
    ("waiting", None, None, False),
    ("completed", "certificates", "done", False),
    ("completed", "full", "running", False),
    ("completed", "full", "failed", False),
    ("completed", "full", "interrupted", False),
    ("interrupted", None, None, False),
])
def test_index_delete_form_only_after_full_rollback(configured_store, user, store, status, cleanup_mode,
                                                    cleanup_status, shown):
    params = {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"}
    store.create_run("r1", "uc01", params)
    store.update_run("r1", status=status, cleanup_mode=cleanup_mode, cleanup_status=cleanup_status)
    store.create_run("other", "uc01", params)  # never deletable – must not get a form
    store.update_run("other", status="completed")
    html = user.get("/").text
    assert (DELETE_FORM in html) is shown
    assert 'action="/runs/other/delete"' not in html
    if shown:
        assert html.count("/delete\"") == 1
        assert 'hx-boost="true"' in html and not delete_form_has_confirm(html)
        assert 'aria-label="Delete run r1"' in html
    else:
        assert 'aria-label="Delete run r1"' not in html


def test_index_delete_form_deletes_only_that_row(configured_user, store):
    rolled_back(configured_user, store)
    configured_user.post("/runs", data=form(run_id="r2"))
    finished(store, "r2")
    response = configured_user.post("/runs/r1/delete")  # what the index form posts, redirect followed
    assert response.status_code == 200 and response.url.path == "/"
    assert 'href="/runs/r1"' not in response.text and 'href="/runs/r2"' in response.text



# --- the action slot: one box, whatever state the run is in -------------------------------------------

BASE = {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256", "count": 1}
CLOCK = re.compile(r'<span class="lifetime q0" role="img" aria-label="Rolled back automatically at \d\d:\d\d UTC"'
                   r'[^>]*>.*?</svg></span>', re.S)


def without_clock(slot: str) -> str:
    """The slot without the watchdog's lifetime clock, which every run not rolled back shows left of its action."""
    assert len(CLOCK.findall(slot)) == 1, slot
    return CLOCK.sub("", slot)


ROLLBACK_CONFIRM = "Roll back run r1? Revokes its certificates and removes everything it created."


@pytest.mark.parametrize("status,cleanup", [("pending", None), ("running", None), ("renewing", None)])
def test_busy_run_shows_a_disabled_rollback(configured_store, user, store, status, cleanup):
    store.create_run("r1", "uc01", BASE)
    store.update_run("r1", status=status)
    slot = without_clock(action_slot(user.get("/").text, "r1"))
    assert re.fullmatch(r'\s*<span data-tip="The run is still busy" tabindex="0"><button type="button" '
                        r'class="row-action outline" disabled>Full rollback</button></span>\s*', slot), slot


@pytest.mark.parametrize("status,cleanup_mode,cleanup_status", [
    ("completed", None, None), ("failed", None, None), ("waiting", None, None), ("interrupted", None, None),
    ("completed", "full", "failed"), ("completed", "full", "interrupted"), ("completed", "certificates", "done")])
def test_rollback_button_otherwise(configured_store, user, store, status, cleanup_mode, cleanup_status):
    store.create_run("r1", "uc01", BASE)
    store.update_run("r1", status=status, cleanup_mode=cleanup_mode, cleanup_status=cleanup_status)
    html = user.get("/").text
    slot = without_clock(action_slot(html, "r1"))
    form = re.search(r"<form ([^>]*)>", slot).group(1)
    assert 'action="/runs/r1/cleanup"' in form and 'hx-post="/runs/r1/cleanup"' in form
    assert 'hx-target="closest tr"' in form and 'hx-swap="outerHTML"' in form
    assert f'hx-confirm="{ROLLBACK_CONFIRM}"' in form and 'data-confirm-label="Roll back"' in form
    assert '<input type="hidden" name="mode" value="full">' in slot
    assert re.search(r'<button type="submit" class="row-action outline\s*"\s*>Full rollback</button>', slot), slot
    assert "refused" not in slot and "data-tip" not in slot  # no refusal without a refused request
    assert 'hx-get="/runs/r1/row"' not in html  # only a running rollback polls


@pytest.mark.parametrize("progress,cls,text,aria", [
    ({"label": "Revoking certificates (pass 1)", "total": 3, "done": 1}, "p-35", "Revoking 1/3", 'aria-valuenow="35"'),
    ({"label": "Deleting policy", "total": 4, "done": 4}, "p-100", "Revoking 4/4", 'aria-valuenow="100"'),
    ({"label": "Deleting division"}, "indeterminate", "Rolling back", None),
    (None, "indeterminate", "Rolling back", None),
])
def test_running_rollback_shows_in_the_buttons_box_and_polls(configured_store, user, store, progress, cls, text, aria):
    store.create_run("r1", "uc01", BASE)
    store.update_run("r1", status="completed", cleanup_mode="full", cleanup_status="running", progress=progress)
    html = user.get("/").text
    row = re.search(r'<tr id="run-r1"([^>]*)>', html).group(1)
    assert 'hx-get="/runs/r1/row"' in row and 'hx-trigger="every 2s"' in row and 'hx-swap="outerHTML"' in row
    slot = action_slot(html, "r1")
    meter = re.search(r'<span class="row-action rollback-meter ([^"]+)" role="progressbar"([^>]*)>', slot)
    assert meter and meter.group(1) == cls
    assert (aria in meter.group(2)) if aria else "aria-valuenow" not in meter.group(2)
    assert f'data-tip="{(progress or {}).get("label") or "Rolling back"}"' in meter.group(2)
    assert f"<span>{text}</span>" in slot and "<button" not in slot and "<form" not in slot
    assert " style=" not in slot  # CSP: the fill is a class


def test_row_route_and_htmx_cleanup_return_the_row(configured_user, store, fake):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    row = configured_user.get("/runs/r1/row")
    assert row.status_code == 200 and row.text.lstrip().startswith('<tr id="run-r1"') and "<html" not in row.text
    gone = configured_user.get("/runs/nope1/row")  # htmx: 286 stops the polling and removes the row
    assert (gone.status_code, gone.text) == (286, "")
    response = configured_user.post("/runs/r1/cleanup", data={"mode": "full"}, headers={"HX-Request": "true"},
                                    follow_redirects=False)
    assert response.status_code == 200 and response.text.lstrip().startswith('<tr id="run-r1"')
    assert 'hx-get="/runs/r1/row"' in response.text and "rollback-meter" in response.text
    cleaned(store, "r1")
    final = configured_user.get("/runs/r1/row").text
    assert 'hx-get="/runs/r1/row"' not in final and 'action="/runs/r1/delete"' in final  # polling stops
    plain = configured_user.post("/runs/r1/delete", follow_redirects=False)
    assert plain.status_code == 303


def test_row_keeps_the_connection_column_when_several(configured_user, store, fake):
    """The standalone row must have the same cells as the list's – else an htmx swap shifts columns."""
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    store.save_connection(None, "Second", "one.nl.digicert.com", "0a1b2c3d-0000-4000-8000-00000000b002", "k")
    index_row = re.search(r'<tr id="run-r1".*?</tr>', configured_user.get("/").text, re.S).group(0)
    alone = configured_user.get("/runs/r1/row").text
    assert alone.count("<td") == index_row.count("<td") == 8



# --- refusals from the list come back as the current row; polling ends for a deleted run -------------

def htmx_rollback(client, run_id="r1", mode="full"):
    return client.post(f"/runs/{run_id}/cleanup", data={"mode": mode}, headers={"HX-Request": "true"},
                       follow_redirects=False)


def test_refusal_for_a_busy_run_returns_its_row(configured_store, user, store):
    store.create_run("r1", "uc04", BASE | {"protocol": "est", "auth": "passcode"})
    store.update_run("r1", status="renewing")  # became busy after the list was shown
    response = htmx_rollback(user)
    assert response.status_code == 200 and response.text.lstrip().startswith('<tr id="run-r1"')
    assert 'data-tip="The run is still busy"' in response.text and "rollback-meter" not in response.text
    assert store.get_run("r1")["cleanup_status"] is None  # nothing started
    assert user.post("/runs/r1/cleanup", data={"mode": "full"}, follow_redirects=False).status_code == 409


def test_refusal_for_a_rolled_back_run_returns_its_row(configured_store, user, store):
    store.create_run("r1", "uc01", BASE)
    store.update_run("r1", status="completed", cleanup_mode="full", cleanup_status="done")
    response = htmx_rollback(user)
    assert response.status_code == 200 and 'action="/runs/r1/delete"' in response.text
    assert store.get_run("r1")["cleanup_status"] == "done"
    assert user.post("/runs/r1/cleanup", data={"mode": "full"}, follow_redirects=False).status_code == 409


def test_refusal_when_the_connection_is_gone_shows_the_reason(configured_store, user, store, fake):
    store.create_run("r1", "uc01", BASE | {"account_id": "0a1b2c3d-0000-4000-8000-00000000ffff",
                                           "dtm_host": "one.digicert.com"})
    store.update_run("r1", status="completed")
    fake.calls.clear()
    response = htmx_rollback(user)
    assert response.status_code == 200 and response.text.lstrip().startswith('<tr id="run-r1"')
    button = re.search(r'<button type="submit" class="row-action outline refused"\s*data-tip="([^"]+)">Full rollback',
                       response.text)
    assert button and "no longer configured" in button.group(1)
    assert store.get_run("r1")["cleanup_status"] is None and fake.calls == []
    assert user.post("/runs/r1/cleanup", data={"mode": "full"}, follow_redirects=False).status_code == 409


def test_refusal_for_an_unknown_mode_shows_the_reason(configured_store, user, store):
    store.create_run("r1", "uc01", BASE)
    store.update_run("r1", status="completed")
    response = htmx_rollback(user, mode="everything")
    assert response.status_code == 200
    assert re.search(r'class="row-action outline refused"\s*data-tip="Cleanup not possible right now"', response.text)
    assert store.get_run("r1")["cleanup_status"] is None


def test_unknown_run_rollback_from_the_list_is_404(configured_user):
    assert htmx_rollback(configured_user, run_id="nope1").status_code == 404


def test_start_clears_leftover_progress(configured_user, store, fake):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    store.update_run("r1", progress={"label": "Requesting 5 certificates one by one", "total": 5, "done": 5})
    fake.revoke_delay = 0.2  # keep the rollback running while the answer is rendered
    response = htmx_rollback(configured_user)
    assert response.status_code == 200
    assert "Revoking 5/5" not in response.text and "Requesting 5 certificates" not in response.text
    cleaned(store, "r1")


def test_meter_without_done_is_indeterminate_and_accessible(configured_store, user, store):
    store.create_run("r1", "uc01", BASE)
    store.update_run("r1", status="completed", cleanup_mode="full", cleanup_status="running",
                     progress={"label": "Revoking certificates", "total": 7, "done": None})
    response = user.get("/")
    assert response.status_code == 200  # no TypeError on None / 7
    slot = action_slot(response.text, "r1")
    meter = re.search(r'<span class="row-action rollback-meter indeterminate" role="progressbar"([^>]*)>', slot)
    assert meter and 'tabindex="0"' in meter.group(1) and 'aria-valuetext="Revoking certificates"' in meter.group(1)
    assert "aria-valuenow" not in meter.group(1) and "<span>Rolling back</span>" in slot
    store.update_run("r1", progress={"label": "Revoking certificates (pass 1)", "total": 4, "done": 2})
    meter = re.search(r'<span class="row-action rollback-meter p-50"[^>]*>', action_slot(user.get("/").text, "r1"))
    assert meter and 'aria-valuetext="Revoking certificates (pass 1)"' in meter.group(0)
    assert 'tabindex="0"' in meter.group(0) and 'aria-valuenow="50"' in meter.group(0)


def test_deleted_run_row_stops_polling(configured_user, store):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    cleaned(store, "r1")
    assert configured_user.get("/runs/r1/row").status_code == 200
    configured_user.post("/runs/r1/delete")
    gone = configured_user.get("/runs/r1/row")
    assert (gone.status_code, gone.text) == (286, "")


def test_row_route_needs_login(web, configured_store, store):
    store.create_run("r1", "uc01", BASE)
    plain = web.get("/runs/r1/row", follow_redirects=False)
    assert plain.status_code == 303 and plain.headers["location"] == "/login"
    htmx = web.get("/runs/r1/row", headers={"HX-Request": "true"}, follow_redirects=False)
    assert htmx.status_code == 401 and htmx.headers["hx-redirect"] == "/login"
    assert 'id="run-r1"' not in plain.text + htmx.text


@pytest.mark.parametrize("progress,text", [
    ({"label": "Deleting certificate policy robot-r1-uc01-policy and verifying it is gone",
      "short": "Deleting policy"}, "Deleting policy"),
    ({"label": "Checking that no batch job is still issuing", "short": "Checking jobs"}, "Checking jobs"),
    ({"label": "Revoking certificates (pass 1)", "short": "Revoking", "total": 8, "done": 2}, "Revoking 2/8"),
    ({"label": "Preparing the cleanup"}, "Rolling back"),  # a progress of an older release: no short name
])
def test_meter_shows_the_short_phase_and_the_full_label_as_tooltip(configured_store, user, store, progress, text):
    store.create_run("r1", "uc01", BASE)
    store.update_run("r1", status="completed", cleanup_mode="full", cleanup_status="running", progress=progress)
    slot = action_slot(user.get("/").text, "r1")
    assert f"<span>{text}</span>" in slot
    assert f'data-tip="{progress["label"]}"' in slot and f'aria-valuetext="{progress["label"]}"' in slot
