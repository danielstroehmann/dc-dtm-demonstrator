"""Deleting a run from the demonstrator – only after a completed full rollback."""

import re

import pytest

from tests.component.test_web_runs import cleaned, finished, form
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

    page = configured_user.get("/runs/r1").text
    assert DELETE_FORM in page and not delete_form_has_confirm(page)

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
    assert DELETE_FORM not in configured_user.get("/runs/r1").text
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    wait_for(lambda: store.get_run("r1")["cleanup_status"] == "done", what="full rollback")
    page = configured_user.get("/runs/r1").text
    assert DELETE_FORM in page and 'hx-boost="true"' in page and not delete_form_has_confirm(page)
    card = page[page.index("<h2>Delete run</h2>"):]
    assert re.search(r'<div class="cleanup-actions">\s*<form method="post" action="/runs/r1/delete"', card)
    assert '<button type="submit" class="outline">Delete run</button>' in card
    assert "Full rollback" not in page and "<h2>Clean up</h2>" not in page
    assert DELETE_FORM not in configured_user.get("/runs/r1/live").text  # static part, not polled


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
