"""Runs through the web UI: creation/validation, background execution, results, XSS, artifacts, cleanup."""

import io
import json
import re
import zipfile

import httpx
import pytest

from app import evergreen
from app.main import create_app
from app.store import Store
from tests.conftest import PASSWORD, make_web, wait_for
from tests.fakedtm import ACCOUNT_ID, API_KEY, ECDSA_CA_ID, HOST, PROFILE_ID, RSA_CA_ID, FakeDTM

SCRIPT = "<script>alert('x')</script>"


def form(**overrides) -> dict:
    return {"run_id": "r1", "variant": "api", "mode": "single", "count": "1", "ca_id": ECDSA_CA_ID} | overrides


def finished(store, run_id):
    return wait_for(lambda: (r := store.get_run(run_id)) and r["status"] not in ("pending", "running") and r,
                    what=f"run {run_id} to finish")


def cleaned(store, run_id):
    return wait_for(lambda: (r := store.get_run(run_id)) and r["cleanup_status"] not in (None, "running") and r,
                    what=f"cleanup of {run_id}")


# --- new run page ------------------------------------------------------------------------

def test_new_run_requires_configuration(user):
    response = user.get("/runs/new/uc01")
    assert response.status_code == 409 and "not configured" in response.text
    index = user.get("/").text  # the welcome page offers the connection form instead of a dead end
    assert "<h1>Welcome</h1>" in index and 'action="/settings/connections"' in index
    assert "formaction" not in index and "Recent runs" not in index


def test_new_run_lists_only_usable_cas(configured_user, fake):
    html = configured_user.get("/runs/new/evergreen").text
    assert f'<option value="{ECDSA_CA_ID}">ECDSA · Fake ECDSA ICA</option>' in html  # key type first
    assert f'<option value="{RSA_CA_ID}">RSA · Fake RSA ICA</option>' in html
    for hidden in ("ca-root", "ca-disabled", "ca-other-account"):
        assert f'value="{hidden}"' not in html
    assert 'name="profile_id"' not in html and PROFILE_ID not in html  # shared profiles, nothing to choose
    assert f'max="{evergreen.MAX_BATCH}"' in html
    assert fake.violations == []


def test_new_run_dtm_error_is_502(configured_user, fake):
    fake.fail["cas"] = httpx.Response(500, text="<html>down</html>")
    response = configured_user.get("/runs/new/uc01")
    assert response.status_code == 502 and "Could not load data from DTM" in response.text


# --- use-case catalog ----------------------------------------------------------------------

def test_catalog_without_connection(user, fake):
    html = user.get("/runs/new").text
    assert '<ol class="stepper" aria-label="Getting started">' in html
    assert '<form method="post" action="/settings/connections">' in html and "formaction" not in html


def test_catalog_lists_the_guide_and_uc04(configured_user, store, fake):
    response = configured_user.get("/runs/new")
    assert response.status_code == 200
    html = response.text
    assert html.count('formaction="/runs/new/') == len(evergreen.CATALOG) == 2
    for key, use_case in evergreen.CATALOG.items():
        assert f'formaction="/runs/new/{key}"' in html and use_case.title in html
        assert use_case.summary[:40] not in html  # tiles show title and tags only (UI design v2)
        assert f'aria-label="Start {use_case.title}"' in html
        for tag in use_case.tags:
            assert f"<li>{tag}</li>" in html
    assert html.index('formaction="/runs/new/evergreen"') < html.index('formaction="/runs/new/uc04"')
    assert '<form method="get">' in html
    (conn,) = store.connections()
    assert f'<input type="hidden" name="connection" value="{conn["id"]}">' in html and "<select" not in html
    assert fake.requests == []  # the catalog needs no DTM call


def test_use_case_form_shows_title_and_breadcrumb_only(configured_user, store):
    conn = store.connections()[0]["id"]
    for key in ("evergreen", "uc04"):
        use_case = evergreen.CATALOG[key]
        html = configured_user.get(f"/runs/new/{key}").text
        assert re.search(r'<div class="page-head">\s*<div><h1>' + re.escape(use_case.title) + r'</h1></div>\s*</div>',
                         html)  # the page head is the title only
        assert re.search(r'href="/runs/new\?connection=\d+">Use cases</a>', html)
        assert use_case.summary[:40] not in html and "Connection:" not in html
        assert f'<input type="hidden" name="connection_id" value="{conn}">' in html
        assert 'action="/runs"' in html


@pytest.mark.parametrize("use_case", ["uc05", "uc00", "UC04", "UC03", "UC01", "uc01x", "uc01.", "%2e%2e%2fsettings"])
def test_unknown_use_case_is_404_without_dtm_call(configured_user, fake, use_case):
    assert configured_user.get(f"/runs/new/{use_case}").status_code == 404
    assert fake.requests == []


@pytest.mark.parametrize("path", ["/runs/new", "/runs/new/evergreen", "/runs/new/uc01", "/runs/new/uc04"])
def test_catalog_requires_login(web, path):
    response = web.get(path, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_catalog_and_form_escape_use_case_texts(configured_user, monkeypatch):
    monkeypatch.setitem(evergreen.CATALOG, "evergreen", evergreen.UseCase(f"T {SCRIPT}", f"S {SCRIPT}", "server_side"))
    for path in ("/runs/new", "/", "/runs/new/evergreen"):
        html = configured_user.get(path).text
        assert SCRIPT not in html and "T &lt;script&gt;" in html, path
    assert "S &lt;script&gt;" not in configured_user.get("/runs/new/evergreen").text  # no summary on the form any more


# --- run creation validation -----------------------------------------------------------------

@pytest.mark.parametrize("overrides,message", [
    ({"run_id": "Bad-ID"}, "Run ID"),
    ({"run_id": "a_b"}, "Run ID"),
    ({"run_id": "a" * 17}, "Run ID"),
    ({"run_id": "../etc"}, "Run ID"),
    ({"variant": "cli"}, "Invalid variant or mode"),
    ({"mode": "bulk"}, "Invalid variant or mode"),
    ({"mode": "batch", "count": "0"}, "Number of certificates"),
    ({"mode": "batch", "count": "-5"}, "Number of certificates"),
    ({"mode": "batch", "count": str(evergreen.MAX_BATCH + 1)}, "Number of certificates"),
    ({"ca_id": "ca-other-account"}, "Select an issuing CA of this account."),
    ({"ca_id": "ca-root"}, "Select an issuing CA of this account."),
    ({"ca_id": "ca-disabled"}, "Select an issuing CA of this account."),
])
def test_create_run_validation(configured_user, store, overrides, message):
    response = configured_user.post("/runs", data=form(**overrides), follow_redirects=False)
    assert response.status_code == 400
    assert message in response.text
    assert store.list_runs() == []


def test_create_run_rejects_ca_with_unknown_key_type(configured_store, auth, data_dir):
    fake = FakeDTM()
    fake.cas.append(fake._ca("ca-ed", "EdDSA ICA", "ed25519"))
    with make_web(configured_store, auth, fake, data_dir) as client:
        client.post("/login", data={"password": PASSWORD})
        response = client.post("/runs", data=form(ca_id="ca-ed"))
    assert response.status_code == 400 and "Select an issuing CA" in response.text


@pytest.mark.parametrize("count", ["abc", "1.5", "1e3"])
def test_create_run_non_integer_count(configured_user, store, count):
    response = configured_user.post("/runs", data=form(count=count))
    assert response.status_code == 400 and store.list_runs() == []


def test_duplicate_run_id(configured_user, store):
    assert configured_user.post("/runs", data=form(), follow_redirects=False).status_code == 303
    finished(store, "r1")
    response = configured_user.post("/runs", data=form())
    assert response.status_code == 400 and "already exists" in response.text


def test_run_id_is_normalised(configured_user, store):
    response = configured_user.post("/runs", data=form(run_id="  AbC9 "), follow_redirects=False)
    assert response.headers["location"] == "/runs/abc9"
    finished(store, "abc9")


# Run IDs end up in DTM object names, and DTM keeps the names of deleted policies reserved – so a
# generated ID must not repeat: 6 random characters [a-z0-9] instead of a timestamp.
GENERATED_ID = re.compile(r"[a-z0-9]{6}")


def created_id(response) -> str:
    assert response.status_code == 303, response.text
    return response.headers["location"].removeprefix("/runs/")


@pytest.mark.parametrize("submitted", ["", "   "])
def test_empty_run_id_gets_a_generated_one(configured_user, store, submitted):
    run_id = created_id(configured_user.post("/runs", data=form(run_id=submitted), follow_redirects=False))
    assert GENERATED_ID.fullmatch(run_id), run_id
    assert finished(store, run_id)["status"] == "completed"


def test_generated_run_ids_do_not_repeat(configured_user, store):
    ids = [created_id(configured_user.post("/runs", data=form(run_id=""), follow_redirects=False))
           for _ in range(3)]
    assert all(GENERATED_ID.fullmatch(i) for i in ids) and len(set(ids)) == 3  # 3 runs, no "already exists"
    for run_id in ids:
        finished(store, run_id)
    assert {r["id"] for r in store.list_runs()} == set(ids)


def test_form_default_run_id_is_random(configured_user):
    ids = [re.search(r'<input id="run_id" name="run_id"[^>]*value="([^"]*)"', configured_user.get("/runs/new/evergreen").text).group(1)
           for _ in range(5)]
    assert all(GENERATED_ID.fullmatch(i) for i in ids), ids
    # 36^6 ≈ 2.2e9 values: one collision among 5 is ~5e-9 likely, so allow it; a constant or
    # time-based default (same value within a second) fails
    assert len(set(ids)) >= 4, ids


def test_new_run_id_alphabet_and_spread():
    from app.main import new_run_id
    ids = [new_run_id() for _ in range(2000)]
    assert all(GENERATED_ID.fullmatch(i) for i in ids)
    assert len(set(ids)) >= 1998  # collisions are possible but must stay rare
    chars = set("".join(ids))
    assert chars == set("abcdefghijklmnopqrstuvwxyz0123456789")  # 12000 draws hit every character


@pytest.mark.parametrize("typed,stored", [("myrun1", "myrun1"), ("  MyRun1 ", "myrun1"), ("a", "a"),
                                          ("x" * 16, "x" * 16)])
def test_user_chosen_run_id_is_kept(configured_user, store, typed, stored):
    run_id = created_id(configured_user.post("/runs", data=form(run_id=typed), follow_redirects=False))
    assert run_id == stored and store.get_run(stored)["id"] == stored
    finished(store, stored)


def test_user_chosen_run_id_must_be_unique(configured_user, store):
    created_id(configured_user.post("/runs", data=form(run_id="dup1"), follow_redirects=False))
    finished(store, "dup1")
    response = configured_user.post("/runs", data=form(run_id="DUP1"), follow_redirects=False)
    assert response.status_code == 400 and "already exists" in response.text


@pytest.mark.parametrize("variant,mode,approval", [
    ("api", "batch", True), ("api", "single", False), ("webui", "batch", False), ("webui", "single", False),
])
def test_approval_only_for_api_batch(configured_user, store, variant, mode, approval):
    configured_user.post("/runs", data=form(variant=variant, mode=mode, count="2", approval="true"))
    run = finished(store, "r1")
    assert run["params"]["approval"] is approval


def test_single_ignores_the_count(configured_user, store, fake):
    """A single device is exactly one certificate, whatever count is posted."""
    for i, count in enumerate(("0", "-1", str(evergreen.MAX_BATCH + 1), "999999")):
        response = configured_user.post("/runs", data=form(run_id=f"s{i}", count=count), follow_redirects=False)
        assert response.status_code == 303
        assert finished(store, f"s{i}")["params"]["count"] == 1
    assert len(fake.issued()) == 4


def test_single_count_is_stored_and_account_bound(configured_user, store):
    configured_user.post("/runs", data=form(count="3"))
    params = finished(store, "r1")["params"]
    assert params["count"] == 1 and params["mode"] == "single"
    assert (params["dtm_host"], params["account_id"]) == (HOST, ACCOUNT_ID)
    assert params["key_type"] == "P_256" and params["ca_name"] == "Fake ECDSA ICA"
    assert API_KEY not in json.dumps(params)
    index = configured_user.get("/").text
    assert "single (1)" in index
    page = configured_user.get("/runs/r1").text
    assert "<small>All requests</small>" in page and "Upload done" not in page
    assert "robot-r1-uc01-single-0001" in page and "robot-r1-uc01-single-0002" not in page


def test_create_run_dtm_error_is_502_and_creates_nothing(configured_user, store, fake):
    fake.fail["cas"] = httpx.ConnectError("down")
    response = configured_user.post("/runs", data=form())
    assert response.status_code == 502 and store.list_runs() == []


def test_create_run_unconfigured_is_409(user, store):
    assert user.post("/runs", data=form()).status_code == 409 and store.list_runs() == []


# --- execution & result pages --------------------------------------------------------------

def test_api_batch_end_to_end_through_ui(configured_user, store, fake):
    response = configured_user.post("/runs", data=form(mode="batch", count="3"), follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/r1"
    run = finished(store, "r1")
    assert run["status"] == "completed", store.events("r1")
    page = configured_user.get("/runs/r1").text
    for cn in evergreen.common_names("r1", "batch", 3, "uc01"):
        assert cn in page
    assert "Full rollback" in page and "Certificates only" in page
    assert "PRIVATE KEY" not in page
    assert 'hx-trigger="every 1s"' not in page  # finished runs stop polling
    # a finished run tells a polling page to reload once (the result is not part of the polled fragment)
    live = configured_user.get("/runs/r1/live", headers={"HX-Request": "true"})
    assert live.status_code == 200 and live.text == "" and live.headers["hx-refresh"] == "true"
    plain = configured_user.get("/runs/r1/live")
    assert plain.text.lstrip().startswith('<div id="live"') and "hx-refresh" not in plain.headers
    assert "<h2>Result</h2>" not in plain.text
    index = configured_user.get("/").text
    assert 'href="/runs/r1"' in index and "completed" in index
    assert fake.violations == []


def test_active_run_page_polls(configured_store, user, store):
    store.create_run("p1", "uc01", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.update_run("p1", status="running")
    page = user.get("/runs/p1").text
    assert 'hx-get="/runs/p1/live"' in page and 'hx-trigger="every 1s"' in page
    assert "Full rollback" not in page


def test_event_log_is_capped_newest_first(configured_store, user, store):
    store.create_run("p2", "uc01", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.update_run("p2", status="failed")
    for i in range(250):
        store.add_event("p2", f"event-{i:03d}")
    page = user.get("/runs/p2").text
    assert "latest 200 of 250" in page
    assert "event-249" in page and "event-050" in page and "event-049" not in page
    assert page.index("event-249") < page.index("event-050")  # newest first
    assert page.count('<time class="t"') == 200


def test_timeline_shows_clock_relative_to_first_event(configured_store, user, store, monkeypatch):
    from app import store as store_module
    stamps = iter(["2026-10-23T09:00:00+00:00", "2026-10-23T10:00:00+00:00", "2026-10-23T10:00:07+00:00",
                   "2026-10-23T10:01:05+00:00", "2026-10-23T11:02:03+00:00"])
    monkeypatch.setattr(store_module, "now", lambda: next(stamps))
    store.create_run("p3", "uc01", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.update_run("p3", status="failed")
    store.add_event("p3", "first", "step")
    store.add_event("p3", "second", "success")
    store.add_event("p3", "third", "error")
    store.add_event("p3", "fourth", "wait")
    page = user.get("/runs/p3").text

    def entry(level, ts, clock, msg):
        return (f'<li class="{level}"><time class="t" datetime="{ts}" data-tip="{ts}">+{clock}</time>'
                f'<span class="msg">{msg}</span></li>')
    assert entry("wait", "2026-10-23T11:02:03+00:00", "1:02:03", "fourth") in page
    assert entry("error", "2026-10-23T10:01:05+00:00", "1:05", "third") in page
    assert entry("success", "2026-10-23T10:00:07+00:00", "0:07", "second") in page
    assert entry("step", "2026-10-23T10:00:00+00:00", "0:00", "first") in page
    assert page.index('<span class="msg">fourth') < page.index('<span class="msg">first')
    assert "4 events" in page
    assert 'hx-get="/runs/p3/timeline"' not in page  # finished runs do not poll


def test_timeline_route_returns_items_only(configured_store, user, store):
    store.create_run("p4", "uc01", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.update_run("p4", status="running")
    for i in range(250):
        store.add_event("p4", f"event-{i:03d}")
    page = user.get("/runs/p4").text
    assert re.search(r'<ol class="timeline"\s+hx-get="/runs/p4/timeline" hx-trigger="every 1s" hx-swap="innerHTML"', page)
    assert "latest 200 of 250" in page
    items = user.get("/runs/p4/timeline", headers={"HX-Request": "true"})
    assert items.status_code == 200
    html = items.text.strip()
    assert html.startswith('<li class=') and "<ol" not in html and "<article" not in html
    assert html.count("<li ") == 200 and html.index("event-249") < html.index("event-050")
    assert "event-049" not in html


def test_timeline_route_escapes_and_requires_login(configured_store, user, store, web):
    store.create_run("p5", "uc01", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.add_event("p5", SCRIPT, "error")
    html = user.get("/runs/p5/timeline").text
    assert SCRIPT not in html and "&lt;script&gt;" in html
    assert user.get("/runs/zz/timeline").status_code == 404
    user.post("/logout")
    assert web.get("/runs/p5/timeline", follow_redirects=False).status_code == 303
    htmx = web.get("/runs/p5/timeline", headers={"HX-Request": "true"}, follow_redirects=False)
    assert htmx.status_code == 401 and htmx.headers["hx-redirect"] == "/login"


def test_failed_run_shows_error(configured_user, store, fake):
    fake.fail["policy_create"] = httpx.Response(400, json={"errors": [{"message": "policy rejected"}]})
    configured_user.post("/runs", data=form())
    run = finished(store, "r1")
    assert run["status"] == "failed"
    assert "policy rejected" in configured_user.get("/runs/r1").text


@pytest.mark.parametrize("path", ["/runs/nope", "/runs/nope/live", "/runs/nope/artifact", "/runs/BAD-ID",
                                  "/runs/..%2f..%2fetc/artifact", "/runs/%2e%2e/artifact"])
def test_unknown_runs_are_404(user, path):
    assert user.get(path).status_code == 404


# --- XSS: everything DTM returns is untrusted ------------------------------------------------

@pytest.fixture
def evil():
    fake = FakeDTM(ica_cn=f"ICA {SCRIPT}", ca_name=f"CA {SCRIPT}", profile_name=f"client {SCRIPT}")
    fake.single_cn_override = f"robot-x1-uc01-{SCRIPT}"
    fake.single_overrides = {"status": "<img src=x onerror=alert(1)>", "valid_to": SCRIPT}
    return fake


@pytest.fixture
def evil_user(configured_store, auth, evil, data_dir):
    with make_web(configured_store, auth, evil, data_dir) as client:
        client.post("/login", data={"password": PASSWORD})
        yield client


def assert_escaped(html: str):
    assert SCRIPT not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_dtm_names_are_escaped_on_new_run_page(evil_user):
    assert_escaped(evil_user.get("/runs/new/uc01").text)


def test_dtm_values_are_escaped_on_run_page(evil_user, configured_store):
    evil_user.post("/runs", data=form())
    run = finished(configured_store, "r1")
    assert run["status"] == "completed", configured_store.events("r1")
    html = evil_user.get("/runs/r1").text
    assert_escaped(html)
    assert "&lt;img src=x onerror=alert(1)&gt;" in html  # DTM response field
    assert "ICA &lt;script&gt;" in html                  # issuer CN from the certificate
    assert "CA &lt;script&gt;" in html                   # CA name in params / log
    timeline = evil_user.get("/runs/r1/timeline").text   # polled timeline items
    assert_escaped(timeline)
    assert "CA &lt;script&gt;" in timeline


def test_dtm_error_message_is_escaped(configured_user, store, fake):
    fake.fail["division_create"] = httpx.Response(400, json={"errors": [{"message": SCRIPT}]})
    configured_user.post("/runs", data=form())
    assert finished(store, "r1")["status"] == "failed"
    assert_escaped(configured_user.get("/runs/r1").text)


# --- web UI variant & artifact -------------------------------------------------------------

def test_webui_batch_artifact_download(configured_user, store, data_dir):
    configured_user.post("/runs", data=form(variant="webui", mode="batch", count="3"))
    run = finished(store, "r1")
    assert run["status"] == "waiting"
    page = configured_user.get("/runs/r1").text
    assert 'href="/runs/r1/artifact"' in page
    response = configured_user.get("/runs/r1/artifact")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert 'filename="robot-r1-uc01-batch.zip"' in response.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        csv = archive.read("batch.csv").decode().splitlines()
    assert csv == ["subject.common_name", *evergreen.common_names("r1", "batch", 3, "uc01")]


def test_artifact_404_for_single_runs(configured_user, store):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    assert configured_user.get("/runs/r1/artifact").status_code == 404
    assert 'href="/runs/r1/artifact"' not in configured_user.get("/runs/r1").text


def test_api_batch_offers_its_upload_zip(configured_user, store):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    assert finished(store, "r1")["result"]["artifact"] == "batch.zip"
    page = configured_user.get("/runs/r1").text
    assert 'href="/runs/r1/artifact"' in page and "Upload in the DTM web UI" not in page
    response = configured_user.get("/runs/r1/artifact")
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.read("batch.csv").decode().splitlines() == [
            "subject.common_name", *evergreen.common_names("r1", "batch", 2, "uc01")]


def test_webui_single_shows_values(configured_user, store):
    configured_user.post("/runs", data=form(variant="webui"))
    assert finished(store, "r1")["status"] == "waiting"
    assert "robot-r1-uc01-single-0001" in configured_user.get("/runs/r1").text


# --- cleanup endpoint ----------------------------------------------------------------------

def test_full_cleanup_through_ui(configured_user, store, fake, data_dir):
    configured_user.post("/runs", data=form(variant="webui", mode="batch", count="2"))
    finished(store, "r1")
    response = configured_user.post("/runs/r1/cleanup", data={"mode": "full"}, follow_redirects=False)
    assert response.status_code == 303
    run = cleaned(store, "r1")
    assert run["cleanup_status"] == "done", store.events("r1")
    assert fake.divisions == {} and fake.policies == {}
    assert not (data_dir / "runs" / "r1").exists()
    page = configured_user.get("/runs/r1").text
    assert "Full rollback" not in page and "Certificates only" not in page
    again = configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    assert again.status_code == 409


def test_certificates_cleanup_keeps_full_rollback_available(configured_user, store, fake, data_dir):
    configured_user.post("/runs", data=form(variant="webui", mode="batch", count="2"))
    finished(store, "r1")
    configured_user.post("/runs/r1/cleanup", data={"mode": "certificates"})
    assert cleaned(store, "r1")["cleanup_status"] == "done"
    assert len(fake.policies) == 1 and (data_dir / "runs" / "r1" / "batch.zip").exists()
    page = configured_user.get("/runs/r1").text
    assert "Full rollback" in page and "Certificates only" not in page
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    wait_for(lambda: store.get_run("r1")["cleanup_mode"] == "full"
             and store.get_run("r1")["cleanup_status"] == "done", what="full rollback")
    assert fake.policies == {} and fake.divisions == {}


@pytest.mark.parametrize("mode", ["everything", "", "FULL"])
def test_cleanup_invalid_mode(configured_user, store, mode):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    response = configured_user.post("/runs/r1/cleanup", data={"mode": mode})
    assert response.status_code in (400, 409)
    assert store.get_run("r1")["cleanup_status"] is None


def test_cleanup_refused_while_run_active(configured_store, user, store):
    store.create_run("p1", "uc01", {"dtm_host": HOST, "account_id": ACCOUNT_ID})
    store.update_run("p1", status="running")
    assert user.post("/runs/p1/cleanup", data={"mode": "full"}).status_code == 409
    store.update_run("p1", status="failed", cleanup_status="running")
    assert user.post("/runs/p1/cleanup", data={"mode": "full"}).status_code == 409


def test_cleanup_refused_when_connection_no_longer_matches(configured_user, store, fake):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    (conn,) = store.connections()
    store.update_run("r1", status="completed")
    # simulate the binding broken behind the app's back (the UI refuses this edit while runs are open)
    store.save_connection(conn["id"], conn["name"], conn["host"], "0a1b2c3d-0000-4000-8000-00000000ffff",
                          conn["api_key"])
    fake.calls.clear()
    response = configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    assert response.status_code == 409 and "no longer configured" in response.text
    assert store.get_run("r1")["cleanup_status"] is None and fake.calls == []


def test_cleanup_failure_is_visible(configured_user, store, fake):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    fake.fail["policy_delete"] = httpx.Response(400, text="<html>no</html>")
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    assert cleaned(store, "r1")["cleanup_status"] == "failed"
    page = configured_user.get("/runs/r1").text
    assert "Full rollback" in page  # can be retried


# --- startup ------------------------------------------------------------------------------

def test_startup_marks_interrupted_runs(tmp_path, auth, fake):
    path = tmp_path / "db.sqlite"
    before = Store(path)
    before.create_run("a1", "uc01", {})
    before.update_run("a1", status="running")
    before.create_run("a2", "uc01", {})
    before.update_run("a2", status="completed", cleanup_status="running")
    before.create_run("a3", "uc01", {})
    before.update_run("a3", status="waiting")
    after = Store(path)
    create_app(after, auth, client_factory=fake.factory(), data_dir=tmp_path)
    assert after.get_run("a1")["status"] == "interrupted"
    assert after.get_run("a2")["cleanup_status"] == "interrupted"
    assert after.get_run("a3")["status"] == "waiting"


# --- progress card, certificate pages, API calls --------------------------------------------

BASE_PARAMS = {"mode": "batch", "count": 3, "variant": "api", "ca_name": "x", "key_type": "P_256", "dtm_host": HOST}


def test_progress_card_only_while_active(configured_store, user, store):
    import time as _time
    store.create_run("g1", "uc01", BASE_PARAMS)
    store.update_run("g1", status="running", progress={"label": "DTM is issuing 3 certificates",
                                                       "status": "in_progress", "started": _time.time() - 12,
                                                       "total": 3, "done": 2})
    html = user.get("/runs/g1/live").text
    assert 'aria-busy="true"' in html and "DTM is issuing 3 certificates" in html
    assert '<progress value="2" max="3">' in html and "2 / 3" in html
    assert re.search(r"<p class=\"metric\">1[23] s</p>", html)  # elapsed
    store.update_run("g1", status="completed")  # stale progress after the run ended
    assert 'aria-busy="true"' not in user.get("/runs/g1/live").text


def test_progress_without_counts_shows_indeterminate_bar(configured_store, user, store):
    store.create_run("g2", "uc01", BASE_PARAMS)
    store.update_run("g2", status="running", progress={"label": "Uploading 3 certificate requests", "started": 0})
    html = user.get("/runs/g2/live").text
    assert "<progress></progress>" in html and "Issued so far" not in html


def test_progress_label_is_escaped(configured_store, user, store):
    store.create_run("g3", "uc01", BASE_PARAMS)
    store.update_run("g3", status="running", progress={"label": SCRIPT, "status": SCRIPT, "started": 0})
    html = user.get("/runs/g3/live").text
    assert SCRIPT not in html and "&lt;script&gt;" in html


def make_certificates(n):
    return [{"common_name": f"robot-c1-uc01-batch-{i:04d}", "serial": f"{i:X}", "not_after": "2027-10-23 10:00 UTC",
             "issuer": "ICA", "key_type": "ECDSA secp256r1"} for i in range(1, n + 1)]


@pytest.fixture
def cert_run(configured_store, store):
    store.create_run("c1", "uc01", BASE_PARAMS)
    store.update_run("c1", status="completed", result={"division": "d", "policy": "p", "certificate_total": 23,
                                                       "certificates": make_certificates(23)})
    return store


def rows(html):
    return re.findall(r"<td[^>]*>(robot-c1-uc01-batch-\d{4})</td>", html)


def test_run_page_shows_first_certificate_page(user, cert_run):
    html = user.get("/runs/c1").text
    assert rows(html) == [f"robot-c1-uc01-batch-{i:04d}" for i in range(1, 11)]
    assert "Page 1 of 3" in html and "Issued certificates" not in html
    assert 'hx-get="/runs/c1/certificates?page=2"' in html
    assert re.search(r'<button class="outline btn-sm" disabled\s+hx-get="/runs/c1/certificates\?page=0"', html)


@pytest.mark.parametrize("page,first,last,label", [
    ("2", 11, 20, "Page 2 of 3"), ("3", 21, 23, "Page 3 of 3"), ("0", 1, 10, "Page 1 of 3"),
    ("-4", 1, 10, "Page 1 of 3"), ("99", 21, 23, "Page 3 of 3"),
])
def test_certificate_pages(user, cert_run, page, first, last, label):
    html = user.get(f"/runs/c1/certificates?page={page}", headers={"HX-Request": "true"}).text
    assert html.lstrip().startswith('<section id="certificates">')
    assert rows(html) == [f"robot-c1-uc01-batch-{i:04d}" for i in range(first, last + 1)]
    assert label in html


def test_certificate_cells(user, cert_run):
    html = user.get("/runs/c1/certificates?page=1").text
    assert "<td>robot-c1-uc01-batch-0001</td>" in html
    assert '<td data-tip="2027-10-23 10:00 UTC">2027-10-23</td>' in html  # date shown, full value as tooltip
    assert "<td>1</td>" in html and "<code>" not in html and " title=" not in html
    assert 'table class="striped compact"' in html and "<colgroup>" in html


def test_last_page_disables_next(user, cert_run):
    html = user.get("/runs/c1/certificates?page=3").text
    assert re.search(r'<button class="outline btn-sm" disabled\s+hx-get="/runs/c1/certificates\?page=4"', html)
    assert re.search(r'<button class="outline btn-sm" \s*hx-get="/runs/c1/certificates\?page=2"', html)


def test_single_page_has_no_pager(configured_store, user, store):
    store.create_run("c2", "uc01", BASE_PARAMS)
    store.update_run("c2", status="completed", result={"certificate_total": 4, "certificates": make_certificates(4)})
    html = user.get("/runs/c2/certificates").text
    assert "Page 1 of" not in html and len(re.findall("<td[^>]*>robot-", html)) == 4


@pytest.mark.parametrize("path,status", [("/runs/c1/certificates?page=abc", 400), ("/runs/zz/certificates", 404),
                                         ("/runs/BAD/certificates", 404)])
def test_certificate_page_errors(user, cert_run, path, status):
    assert user.get(path).status_code == status


def test_certificate_page_requires_login(web, cert_run):
    assert web.get("/runs/c1/certificates?page=2", follow_redirects=False).status_code == 303
    htmx = web.get("/runs/c1/certificates?page=2", headers={"HX-Request": "true"}, follow_redirects=False)
    assert htmx.status_code == 401 and htmx.headers["hx-redirect"] == "/login"


def test_certificate_pages_escape_dtm_values(evil_user, configured_store):
    evil_user.post("/runs", data=form())
    assert finished(configured_store, "r1")["status"] == "completed"
    assert_escaped(evil_user.get("/runs/r1/certificates?page=1").text)


def test_api_calls_section_through_ui(configured_user, store, fake):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    finished(store, "r1")
    html = configured_user.get("/runs/r1").text
    assert '<article class="card api-calls" id="api-calls">' in html and "<h2>Reproducible Steps</h2>" in html
    assert "export DTM_API_KEY=&#39;&lt;your API key&gt;&#39;" in html
    assert f"export DTM_HOST={HOST}" in html
    assert API_KEY not in html and "BEGIN" not in html
    assert "/jobs/certificate-enroll" in html and "-F &#34;encryption_certificate=&lt;enc.crt&#34;" in html
    assert "openssl cms -decrypt" in html
    assert "Time per certificate" in html and "Certificates per minute" in html
    assert "<small>DTM processing time</small><p class=\"metric\">1.23 s</p>" in html  # tile, not a note
    assert "Approved after" not in html  # no approval in this run
    for dialect in ("curl", "wget", "powershell"):
        assert f'hx-get="/runs/r1/api?dialect={dialect}"' in html
    assert re.search(r'<script src="/static/app\.js(\?v=[0-9a-f]{10})?" defer></script>', html)  # copy + confirm
    assert '<dialog id="confirm-dialog"' in html and "data-confirm-ok" in html


@pytest.mark.parametrize("dialect,marker", [("curl", "curl -sS"), ("wget", "wget --method=GET"),
                                            ("powershell", "Invoke-RestMethod -Method Get")])
def test_api_dialect_fragment(configured_user, store, dialect, marker):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    finished(store, "r1")
    response = configured_user.get(f"/runs/r1/api?dialect={dialect}", headers={"HX-Request": "true"})
    assert response.status_code == 200
    html = response.text
    assert html.lstrip().startswith('<article class="card api-calls" id="api-calls">')
    assert marker in html and f'id="script-all-{dialect}" hidden' in html
    assert f'id="script-setup-{dialect}" hidden' in html and f'id="script-recurring-{dialect}" hidden' in html
    assert 'aria-current="true"' in html and API_KEY not in html


@pytest.mark.parametrize("path,status", [("/runs/r1/api?dialect=bash", 404), ("/runs/r1/api?dialect=", 404),
                                         ("/runs/zz/api", 404), ("/runs/BAD/api?dialect=curl", 404)])
def test_api_dialect_errors(configured_user, store, path, status):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    assert configured_user.get(path).status_code == status


def test_api_fragment_requires_login(web, store):
    store.create_run("r1", "uc01", {})
    assert web.get("/runs/r1/api", follow_redirects=False).status_code == 303
    assert web.get("/runs/r1/api", headers={"HX-Request": "true"}, follow_redirects=False).status_code == 401


def test_failed_run_shows_api_calls(configured_user, store, fake):
    fake.fail["policy_create"] = httpx.Response(400, json={"errors": [{"message": "nope"}]})
    configured_user.post("/runs", data=form())
    assert finished(store, "r1")["status"] == "failed"
    html = configured_user.get("/runs/r1").text
    assert "Reproducible Steps" in html and "error</span>" in html
    # a setup failure has only setup calls
    assert '<details class="box neutral">' in html and phase_titles(html) == [] and "Certificate Order" not in html
    assert "<h2>Payload</h2>" not in html


def test_unknown_use_case_id_falls_back_to_raw_id(configured_store, user, store):
    store.create_run("x1", "uc99", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.update_run("x1", status="failed")
    page = user.get("/runs/x1")
    assert page.status_code == 200 and "<p>uc99 · Single" in page.text
    index = user.get("/")
    # an unknown use case shows its raw ID – no internal "UC-n" numbering, no tooltip attribute
    assert index.status_code == 200 and re.search(r"<td>uc99 · single", index.text)
    assert "UC-99" not in index.text
    # a non-numeric ID is shown raw – never "UC-legacy"
    store.create_run("x2", "legacy", {"mode": "single", "variant": "api", "ca_name": "x", "key_type": "P_256"})
    store.update_run("x2", status="failed")
    index = user.get("/").text
    assert re.search(r"<td\s*>legacy · single", index) and "UC-legacy" not in index
    assert "<p>legacy · Single" in user.get("/runs/x2").text


def test_progress_card_during_cleanup(configured_store, user, store):
    import time as _time
    store.create_run("g4", "uc01", BASE_PARAMS)
    store.update_run("g4", status="completed", cleanup_mode="full", cleanup_status="running",
                     progress={"label": "Revoking certificates (pass 1)", "started": _time.time() - 3,
                               "total": 40, "done": 17})
    html = user.get("/runs/g4/live", headers={"HX-Request": "true"}).text
    assert 'aria-busy="true"' in html and "Revoking certificates (pass 1)" in html
    assert '<progress value="17" max="40">' in html
    store.update_run("g4", cleanup_status="done")  # stale progress after the cleanup ended
    assert 'aria-busy="true"' not in user.get("/runs/g4/live").text



# --- result layout and reproducible-steps grouping --------------------------------------------

# A phase title of the reproducible steps: icon chip + text (Certificate Order / Factory Enrollment /
# Renewal in the Field), inside a <section class="box accent[ field]">.
PHASE_TITLE = re.compile(r'<section class="(box accent[^"]*)">\s*<div class="box-head">\s*'
                         r'<h3 class="phase-title"><span class="phase-icon">(.*?)</span>([^<]+)</h3>', re.S)


PHASE_ICONS = {"factory": 'd="M3 21V10l6 4V10l6 4V6l6 3v12z"', "refresh": 'd="M20 11a8 8 0 0 0-14.9-3M4 4v4h4"'}  # _icons.html


def phase_titles(html: str) -> list[tuple[str, str, str]]:
    """(box classes, icon markup, title) per phase box, in page order."""
    return PHASE_TITLE.findall(html)


def assert_phase_titles(html: str, expected: list[tuple[str, str]]) -> None:
    """expected: (title, icon name) – each title with exactly one icon of that kind; only the
    renewal box is the orange field box."""
    found = phase_titles(html)
    assert [t for _, _, t in found] == [t for t, _ in expected], found
    for (classes, icon_html, title), (_, name) in zip(found, expected):
        assert icon_html.count("<svg") == 1 and icon_html.count("</svg>") == 1, title
        assert PHASE_ICONS[name] in icon_html and all(p not in icon_html for n, p in PHASE_ICONS.items() if n != name)
        assert classes == ("box accent field" if title == "Renewal in the Field" else "box accent"), title


def section(html: str, phase: str) -> str:
    if phase == "setup":  # collapsed neutral box
        start = html.index('<details class="box neutral">')
        return html[start:html.index("</details>", start)]
    start = html.index("Certificate Order</h3>")  # highlighted accent box
    start = html.rindex('<section class="box accent">', 0, start)
    return html[start:html.index("</section>", start)]


def hidden_script(html: str, name: str) -> str:
    import html as html_lib
    match = re.search(rf'<pre id="{name}" hidden>(.*?)</pre>', html, re.S)
    assert match, name
    return html_lib.unescape(match.group(1))


def test_steps_grouped_by_phase(configured_user, store):
    configured_user.post("/runs", data=form(mode="batch", count="2", approval="true"))
    run = finished(store, "r1")
    calls = run["result"]["api_calls"]
    # setup incl. the shared profile lookup; recurring: CSV, encryption key, upload, wait for approval,
    # approve, poll, download, decrypt + unpack
    assert [c["phase"] for c in calls] == ["setup"] * 6 + ["recurring"] * 8
    html = configured_user.get("/runs/r1").text
    setup, recurring = section(html, "setup"), section(html, "recurring")
    assert "<summary>One-Time Setup</summary>" in setup
    assert '<details class="box neutral" open' not in html  # collapsed by default
    assert "Certificate Order</h3>" in recurring
    assert_phase_titles(html, [("Certificate Order", "factory")])
    assert html.index('<details class="box neutral">') < html.index("Certificate Order</h3>")
    assert '<ol class="calls">' in setup and '<ol class="calls">' in recurring
    assert '<div class="call-line">' in recurring and '<p class="call-purpose">' in recurring
    setup_purposes = [c["purpose"] for c in calls if c["phase"] == "setup"]
    recurring_purposes = [c["purpose"] for c in calls if c["phase"] == "recurring"]
    purpose = lambda p: f'<p class="call-purpose">{p}</p>'  # noqa: E731
    positions = [setup.index(purpose(p)) for p in setup_purposes]
    assert positions == sorted(positions)  # order preserved
    assert all(purpose(p) not in recurring for p in setup_purposes)
    assert all(purpose(p) not in setup for p in recurring_purposes)
    assert 'id="pre-setup-1"' in setup and 'id="pre-setup-6"' in setup and 'id="pre-setup-7"' not in html
    assert 'id="pre-recurring-1"' in recurring and 'id="pre-recurring-8"' in recurring
    assert 'id="pre-recurring-9"' not in html
    assert 'data-copy="script-setup-curl"' in setup and 'data-copy="script-recurring-curl"' in recurring
    s_setup, s_rec, s_all = (hidden_script(html, f"script-{n}-curl") for n in ("setup", "recurring", "all"))
    # each step is a block "# <purpose>\n<command>" after the preamble – commands may carry "# " comments
    # the whole script starts with a bash shebang block, the phase scripts directly with the preamble
    heads = lambda text: [block.split("\n", 1)[0].removeprefix("# ")  # noqa: E731
                          for block in text.removeprefix("#!/usr/bin/env bash\n\n").split("\n\n")[1:]]
    assert heads(s_setup) == setup_purposes
    assert heads(s_rec) == [c["purpose"] for c in calls if c["phase"] == "recurring" and c["spec"]]
    assert heads(s_all) == [c["purpose"] for c in calls if c["spec"]]
    zsh = '[ -n "${ZSH_VERSION:-}" ] && setopt interactivecomments\n'  # "#" lines stay comments in zsh
    assert s_all.startswith(f"#!/usr/bin/env bash\n\n{zsh}export DTM_API_KEY='<your API key>'\n")
    assert s_setup.startswith(f"{zsh}export DTM_API_KEY='<your API key>'\n")  # setup: plain exports, no shebang
    assert s_rec.startswith(zsh + """[ -n "${DTM_API_KEY:-}" ] || export DTM_API_KEY='<your API key>'\n""")  # keeps the key
    for text in (s_setup, s_rec, s_all):
        assert API_KEY not in text


def test_run_page_order_and_removed_texts(configured_user, store):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    finished(store, "r1")
    html = configured_user.get("/runs/r1").text
    marks = ['<h1>Run r1 <span class="pill ok">completed</span></h1>', '<ol class="stepper" aria-label="Run phases">',
             '<div id="live"', "<h2>Overview</h2>", "<h2>Timeline", "<h2>Payload</h2>",
             "<h2>Reproducible Steps</h2>", "<h2>Clean up</h2>"]
    assert "<h2>Delete run</h2>" not in html
    positions = [html.index(m) for m in marks]
    assert positions == sorted(positions), dict(zip(marks, positions))
    payload = html.index("<h2>Payload</h2>")
    assert payload < html.index('<section id="certificates">') < html.index('href="/runs/r1/artifact"')
    assert "Upload in DTM web UI" not in html
    # removed texts (author request)
    assert "Division <code>" not in html  # the division/policy line is gone (names stay in the snippets)
    for gone in ('class="objects"', "Issued certificates", "kept out of the UI",
                 "x-api-key: &lt;API key&gt;", "Status: ", "Revoke certificates, delete policy"):
        assert gone not in html, gone
    assert 'hx-confirm="Full rollback of run r1?"' in html
    assert 'hx-confirm="Revoke the certificates of run r1?"' in html


def test_payload_for_webui_batch_has_upload_hint_and_single_api_has_certificate(configured_user, store):
    configured_user.post("/runs", data=form(variant="webui", mode="batch", count="2"))
    finished(store, "r1")
    html = configured_user.get("/runs/r1").text
    assert "<h2>Payload</h2>" in html and "Upload in DTM web UI · policy <code>robot-r1-uc01-policy</code>" in html
    assert '<section id="certificates">' not in html
    configured_user.post("/runs", data=form(run_id="r2"))
    finished(store, "r2")
    html = configured_user.get("/runs/r2").text
    assert "<h2>Payload</h2>" in html and 'href="/runs/r2/artifact"' not in html


def test_webui_single_has_no_payload_section(configured_user, store):
    configured_user.post("/runs", data=form(variant="webui"))
    finished(store, "r1")
    html = configured_user.get("/runs/r1").text
    assert "<h2>Payload</h2>" not in html and "Enter in DTM web UI" in html
    assert '<details class="box neutral">' in html and phase_titles(html) == [] and "Certificate Order" not in html


def test_legacy_calls_without_phase_count_as_recurring(configured_store, user, store):
    store.create_run("l1", "uc01", BASE_PARAMS)
    store.update_run("l1", status="completed", result={
        "api_variables": {"DTM_HOST": HOST, "DTM_ACCOUNT_ID": ACCOUNT_ID},
        "api_calls": [{"purpose": "old call", "method": "GET", "path": "/x", "seconds": 0.1, "outcome": "ok",
                       "count": 1, "spec": {"method": "GET", "path": "/x"}}]})
    html = user.get("/runs/l1").text
    assert '<details class="box neutral">' not in html
    assert_phase_titles(html, [("Certificate Order", "factory")])
    assert '<p class="call-purpose">old call</p>' in section(html, "recurring")
    assert "# old call" in hidden_script(html, "script-recurring-curl")



def test_approval_time_is_a_metric_tile(configured_user, store, fake):
    fake.approve_delay = 0.05
    configured_user.post("/runs", data=form(mode="batch", count="2", approval="true"))
    run = finished(store, "r1")
    html = configured_user.get("/runs/r1").text
    assert f'<small>Approved after</small><p class="metric">{run["result"]["approval_s"]} s</p>' in html
    assert "kept out of the UI and discarded" not in html  # the note line is gone



def test_instant_approval_still_shows_tile(configured_user, store):
    configured_user.post("/runs", data=form(mode="batch", count="2", approval="true"))
    run = finished(store, "r1")
    # The fake approves without delay, but approval_s is wall time rounded to 0.01 s – on a busy
    # runner it can be 0.01 or more, so only bound it. The edge case (0.0 is falsy) is forced below.
    assert 0 <= run["result"]["approval_s"] < 0.5
    store.update_run("r1", result=run["result"] | {"approval_s": 0.0})
    html = configured_user.get("/runs/r1").text
    assert '<small>Approved after</small><p class="metric">0.0 s</p>' in html



# --- status line, cards, CTA ---------------------------------------------------------------

# The run status moved into the page header (pill in the h1); the live line reports only an
# unfinished cleanup.
@pytest.mark.parametrize("status,cleanup_status,expected", [
    ("completed", None, None),
    ("completed", "done", None),
    ("completed", "running", "Cleanup: <span class=\"status running\">running</span>"),
    ("completed", "failed", "Cleanup: <span class=\"status failed\">failed</span>"),
    ("failed", None, None),
    ("waiting", "done", None),
    ("running", None, None),
    ("failed", "running", "Cleanup: <span class=\"status running\">running</span>"),
])
def test_status_line_only_when_informative(configured_store, user, store, status, cleanup_status, expected):
    store.create_run("s1", "uc01", BASE_PARAMS)
    store.update_run("s1", status=status, cleanup_status=cleanup_status)
    live = user.get("/runs/s1/live").text
    if expected is None:
        assert 'class="status-line"' not in live
    else:
        assert 'class="status-line"' in live and expected in live
    assert "Status:" not in live
    page = user.get("/runs/s1").text
    assert re.search(rf'<h1>Run s1 <span class="pill[^"]*">{status}</span></h1>', page)


def test_progress_card_markup(configured_store, user, store):
    store.create_run("s3", "uc01", BASE_PARAMS)
    store.update_run("s3", status="running", progress={"label": "Uploading", "started": 0})
    live = user.get("/runs/s3/live").text
    assert '<article class="card progress-card">' in live and '<h2 aria-busy="true">Uploading</h2>' in live


def cta_count(html: str) -> int:
    return sum("cta" in classes.split() for classes in re.findall(r'class="([^"]*)"', html))


def test_cta_only_for_start_run_and_first_connection(user, store):
    """Orange only for the action that starts something: Start run and the very first connection."""
    assert {p: cta_count(user.get(p).text) for p in ("/", "/settings", "/runs/new")} == {
        "/": 1, "/settings": 1, "/runs/new": 1}
    assert '<button type="submit" class="cta">Check and save</button>' in user.get("/").text
    store.save_connection(None, "Default", HOST, ACCOUNT_ID, API_KEY)
    user.post("/runs", data=form())
    finished(store, "r1")
    pages = {path: user.get(path).text for path in
             ("/", "/runs/new", "/runs/new/uc01", "/settings", "/runs/r1", "/nope")}
    assert {p: cta_count(h) for p, h in pages.items()} == {
        "/": 0, "/runs/new": 0, "/runs/new/uc01": 1, "/settings": 0, "/runs/r1": 0, "/nope": 0}
    assert re.search(r'<button type="submit" class="cta btn-icon"><svg[^>]*>.*?</svg>Start run</button>',
                     pages["/runs/new/uc01"], re.S)


def test_page_structure_cards(configured_user, store):
    catalog = configured_user.get("/runs/new").text
    assert "<h1>Start a demo</h1>" in catalog and catalog.count('<article class="tile">') == 2
    assert "<h3>Evergreen device certificates</h3>" in catalog and 'class="uc-id"' not in catalog
    assert "<h3>Renewable device certificates</h3>" in catalog
    assert evergreen.GUIDE.title == "Evergreen device certificates"
    assert evergreen.USE_CASES["uc04"].title == "Renewable device certificates"
    assert re.search(r'<button type="submit" formaction="/runs/new/evergreen" class="btn-sm btn-icon"\s+'
                     r'aria-label="Start [^"]+"><svg[^>]*>.*?</svg>Start</button>', catalog, re.S)
    settings = configured_user.get("/settings").text
    assert "<h1>Settings</h1>" in settings and "<h2>DTM connections</h2>" in settings
    assert "<h2>Add connection</h2>" in settings
    assert "All calls are scoped" not in settings  # intro removed
    index = configured_user.get("/").text
    assert "<h1>Start a demo</h1>" in index and "<h2>Recent runs</h2>" in index
    assert "Every object a run creates" not in index
    new = configured_user.get("/runs/new/evergreen").text
    assert "a–z, 0–9, max. 16" in new and "Require approval (auto-approved)" in new
    assert '<span class="seg-label" id="l-key_location">Where is the key pair generated?</span>' in new
    assert '<span class="seg-label" id="l-mode">How many devices at once?</span>' in new
    assert '<span class="seg-label" id="l-variant">Run it</span>' in new
    # key location, mode, protocol, authentication, variant
    assert new.count('role="radiogroup"') == 5
    error = configured_user.get("/nope").text
    assert '<div class="card-head"><h2>Something went wrong</h2></div>' in error


def test_login_page_is_a_split_screen(web, configured_store):
    html = web.get("/login").text
    assert '<body class="auth">' in html and '<section class="auth-brand">' in html
    form_area = re.search(r'<(section|main) class="auth-form">', html)
    assert form_area and html.index('<section class="auth-brand">') < form_area.start()
    assert "<h2>Log in</h2>" in html and '<form method="post" action="/login">' in html
    assert '<div class="action-bar"><button type="submit">Log in</button></div>' in html
    # anonymous: no app shell – no navigation, no connection chip, no log-out
    assert "site-header" not in html and "conn-chip" not in html and 'action="/logout"' not in html


# --- CSRF posture with SameSite=Lax: no GET route may change state ------------------------------

def snapshot(store, data_dir, fake):
    db = store._db
    tables = {t: db.execute(f"SELECT * FROM {t} ORDER BY 1").fetchall()
              for t in ("settings", "runs", "run_objects", "run_events")}
    files = sorted(str(p.relative_to(data_dir)) for p in data_dir.rglob("*")) if data_dir.exists() else []
    writes = [n for n in fake.route_order() if not n.endswith(("list", "s")) and n not in ("account", "job", "result")]
    return {k: [tuple(r) for r in v] for k, v in tables.items()}, files, writes


def test_only_get_and_post_routes():
    from app.main import create_app
    from app.auth import Auth
    from app.store import Store
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(Store(pathlib.Path(tmp) / "db"), Auth("pw", "s" * 40), data_dir=pathlib.Path(tmp))
    methods = {m for r in app.routes for m in (getattr(r, "methods", None) or set())}
    assert methods <= {"GET", "HEAD", "POST"}
    posts = sorted(r.path for r in app.routes if "POST" in (getattr(r, "methods", None) or set()))
    assert posts == ["/login", "/logout", "/runs", "/runs/{run_id}/cleanup", "/runs/{run_id}/delete",
                     "/runs/{run_id}/renew",
                     "/settings/connections", "/settings/connections/{connection_id}/default",
                     "/settings/connections/{connection_id}/delete",
                     "/settings/connections/{connection_id}/profiles/retire"]


def test_no_get_route_changes_state(configured_user, store, fake, data_dir):
    configured_user.post("/runs", data=form(variant="webui", mode="batch", count="2"))
    finished(store, "r1")
    configured_user.post("/runs", data=form(run_id="r2", mode="batch", count="12"))
    finished(store, "r2")
    configured_user.post("/runs/r2/cleanup", data={"mode": "full"})
    cleaned(store, "r2")
    app = configured_user.app
    get_paths = sorted({r.path for r in app.routes if "GET" in (getattr(r, "methods", None) or set())})
    before = snapshot(store, data_dir, fake)
    hit = []
    for path in get_paths:
        for run_id in ("r1", "r2", "nope"):
            url = path.replace("{run_id}", run_id).replace("{use_case}", "uc01").replace("{path:path}", "app.css")
            for query in ("", "?page=2", "?dialect=wget"):
                for headers in ({}, {"HX-Request": "true"}):
                    response = configured_user.get(url + query, headers=headers, follow_redirects=False)
                    assert response.status_code < 500, (url, response.status_code)
                    hit.append(url)
    assert {"/runs/r1/live", "/runs/r2/certificates", "/runs/r1/api", "/runs/r1/artifact", "/settings"} <= set(hit)
    assert snapshot(store, data_dir, fake) == before



def test_running_run_has_no_result_cards(configured_store, user, store):
    store.create_run("q1", "uc01", BASE_PARAMS)
    store.update_run("q1", status="running", result={"api_calls": [], "api_variables": {}, "certificates": []})
    html = user.get("/runs/q1").text
    assert "<h2>Overview</h2>" not in html and "<h2>Payload</h2>" not in html
    assert "<h2>Timeline" in html and "<h2>Clean up</h2>" not in html


def test_every_confirm_has_a_label(configured_user, store):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    configured_user.post("/runs", data=form(run_id="r2"))
    finished(store, "r2")
    configured_user.post("/runs/r2/cleanup", data={"mode": "full"})
    cleaned(store, "r2")
    seen = {}
    for path in ("/", "/runs/r1", "/runs/r2", "/settings", "/runs/new", "/runs/new/uc01"):
        html = configured_user.get(path).text
        assert '<dialog id="confirm-dialog"' in html
        assert re.search(r'<script src="/static/app\.js(\?v=[0-9a-f]{10})?" defer></script>', html)
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), path  # CSP: no inline script
        assert not re.search(r"\son[a-z]+=", html) and not re.search(r"\sstyle=", html), path
        for tag in re.findall(r"<[a-z]+[^>]*hx-confirm=[^>]*>", html):
            label = re.search(r'data-confirm-label="([^"]+)"', tag)
            assert label, (path, tag)
            seen[re.search(r'hx-confirm="([^"]+)"', tag).group(1)] = label.group(1)
    assert seen == {"Full rollback of run r1?": "Roll back", "Revoke the certificates of run r1?": "Revoke"}
    # deleting a rolled-back run (run page card and index row) needs no confirmation
    for path in ("/", "/runs/r2"):
        forms = re.findall(r'<form[^>]*action="/runs/r2/delete"[^>]*>', configured_user.get(path).text)
        assert forms and not any("hx-confirm" in f for f in forms), path



def test_confirm_dialog_focuses_cancel(configured_user):
    html = configured_user.get("/").text
    dialog = html[html.index('<dialog id="confirm-dialog"'):html.index("</dialog>")]
    assert re.search(r'<button value="cancel"[^>]*autofocus', dialog)
    assert not re.search(r'<button value="ok"[^>]*autofocus', dialog)



def test_rolled_back_run_page_order(configured_user, store):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    finished(store, "r1")
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    cleaned(store, "r1")
    html = configured_user.get("/runs/r1").text
    marks = ["<h2>Overview</h2>", "<h2>Delete run</h2>", "<h2>Timeline", "<h2>Payload</h2>",
             "<h2>Reproducible Steps</h2>"]
    positions = [html.index(m) for m in marks]
    assert positions == sorted(positions), dict(zip(marks, positions))
    assert "<h2>Clean up</h2>" not in html and html.count("<h2>Delete run</h2>") == 1



# --- overview tiles: regression for the empty "Approved after" tile ------------------------------

@pytest.mark.parametrize("overrides,approved_tile", [
    ({}, False),                                              # single run: no approval_s key at all
    ({"mode": "batch", "count": "2"}, False),                 # batch without approval: approval_s None
    ({"mode": "batch", "count": "2", "approval": "true"}, True),
])
def test_approved_after_tile_only_with_approval(configured_user, store, overrides, approved_tile):
    configured_user.post("/runs", data=form(**overrides))
    run = finished(store, "r1")
    html = configured_user.get("/runs/r1").text
    assert ("Approved after" in html) is approved_tile
    assert not re.search(r'<p class="metric">\s*s</p>', html)  # never an empty value tile
    if approved_tile:
        assert f'<p class="metric">{run["result"]["approval_s"]} s</p>' in html


def test_uc01_has_no_key_generation_tile_and_first_response_summary(configured_user, store):
    configured_user.post("/runs", data=form(count="2"))
    finished(store, "r1")
    html = configured_user.get("/runs/r1").text
    assert "Key generation</small>" not in html
    assert "<summary>DTM response (first request)</summary>" in html



# --- UC-2 through the web UI ------------------------------------------------------------------

def test_uc02_form_and_run(configured_user, store, fake):
    response = configured_user.get("/runs/new/uc02", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/new/evergreen"
    configured_user.post("/runs", data=form(use_case="uc02", mode="batch", count="3"))
    run = finished(store, "r1")
    assert run["status"] == "completed", store.events("r1")
    assert run["use_case"] == "uc02" and "key_generation" not in run["params"]  # derived from the use case
    html = configured_user.get("/runs/r1").text
    assert re.search(r'<small data-tip="[^"]*factory[^"]*">Key generation</small><p class="metric">[0-9.]+ s</p>', html)
    assert "Download csrs.zip" in html and "robot-r1-uc02-batch-0003" in html
    assert "PRIVATE KEY" not in html and "@csrs.zip" in html and "enc.crt" not in html
    response = configured_user.get("/runs/r1/artifact")
    assert response.status_code == 200
    assert 'filename="robot-r1-uc02-csrs.zip"' in response.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.namelist() == [f"robot-r1-uc02-batch-000{i}.csr" for i in (1, 2, 3)]
        assert all(b"BEGIN CERTIFICATE REQUEST" in archive.read(n) for n in archive.namelist())
    index = configured_user.get("/").text
    assert evergreen.DISPLAY_NAMES["uc02"] == "Evergreen device certificates"
    assert "<td>Evergreen device certificates · batch (3)</td>" in index and "UC-" not in index


def test_uc02_single_overview(configured_user, store):
    configured_user.post("/runs", data=form(use_case="uc02", count="2"))
    run = finished(store, "r1")
    assert run["status"] == "completed" and run["result"]["private_keys_returned"] == 0
    html = configured_user.get("/runs/r1").text
    assert "Key generation</small>" in html and "Approved after" not in html
    assert '<small>Certificates</small><p class="metric">1</p>' in html  # single = one certificate


@pytest.mark.parametrize("use_case", ["uc03", "UC02", "", "../uc01"])
def test_unknown_use_case_on_create_is_400(configured_user, store, use_case):
    data = form(use_case=use_case)
    response = configured_user.post("/runs", data=data)
    if use_case == "":
        assert response.status_code in (303, 200)  # empty → default uc01
        assert finished(store, "r1")["use_case"] == "uc01"
    else:
        assert response.status_code == 400 and store.list_runs() == []


@pytest.mark.parametrize("artifact", ["../../demonstrator.db", "batch.zip/../x", "result.p7m", "csrs.zip "])
def test_artifact_route_only_serves_allowlisted_names(configured_store, user, store, data_dir, artifact):
    store.create_run("a1", "uc02", BASE_PARAMS)
    store.update_run("a1", status="completed", result={"artifact": artifact})
    (data_dir / "runs" / "a1").mkdir(parents=True)
    (data_dir / "runs" / "a1" / "x").write_text("secret")
    assert user.get("/runs/a1/artifact").status_code == 404


def test_ui_stays_responsive_during_large_uc02_keygen(configured_user, store):
    import time as _time
    configured_user.post("/runs", data=form(use_case="uc02", mode="batch", count="40", ca_id=RSA_CA_ID))
    wait_for(lambda: any("Factory generates" in e["message"] for e in store.events("r1")), what="keygen start")
    slow = []
    while not any("CSR(s) ready" in e["message"] for e in store.events("r1")):
        t0 = _time.monotonic()
        assert configured_user.get("/healthz").status_code == 200
        slow.append(_time.monotonic() - t0)
        _time.sleep(0.02)
    run = finished(store, "r1")
    assert run["status"] == "completed", store.events("r1")
    assert slow, "keygen finished before the UI could be probed"
    assert max(slow) < 0.3, max(slow)



def test_no_native_title_tooltips(configured_user, store):
    configured_user.post("/runs", data=form(use_case="uc02", mode="batch", count="2"))
    finished(store, "r1")
    for path in ("/", "/runs/new", "/runs/new/uc01", "/settings", "/runs/r1", "/runs/r1/timeline",
                 "/runs/r1/certificates", "/runs/r1/api?dialect=powershell", "/nope"):
        html = configured_user.get(path).text
        assert not re.search(r"<[a-z][^>]*\stitle=", html), path  # only the <title> element remains
    page = configured_user.get("/runs/r1").text
    assert re.search(r'<time class="t" datetime="[^"]+" data-tip="[^"]+">', page)
    assert re.search(r'<td data-tip="[^"]+ UTC">\d{4}-\d{2}-\d{2}</td>', page)
    assert re.search(r'<small data-tip="[^"]+">Key generation</small>', page)


# --- runs list: use case by its catalog name, variant by protocol + authentication --------------------

def runs_rows(html: str) -> dict[str, list[str]]:
    """Run ID → the text of its cells in the runs list (single-connection layout)."""
    rows = {}
    for row in re.findall(r"<tr>(.*?)</tr>", html, re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        link = re.search(r'<a href="/runs/([^"]+)">', row)
        if cells and link:
            rows[link.group(1)] = [re.sub(r"<[^>]+>", "", c).strip() for c in cells]
    return rows


@pytest.mark.parametrize("use_case,expected", [
    ("uc01", "Evergreen device certificates"), ("uc02", "Evergreen device certificates"),
    ("uc03", "Evergreen device certificates"), ("uc04", "Renewable device certificates"), ("legacy", "legacy")])
def test_runs_list_names_the_use_case_by_its_catalog_entry(configured_store, user, store, use_case, expected):
    store.create_run("n1", use_case, BASE_PARAMS | {"mode": "single", "count": 2})
    html = user.get("/").text
    assert runs_rows(html)["n1"][1] == f"{expected} · single (2)"
    cell = re.search(r'<a href="/runs/n1">n1</a></td>\s*(<td[^>]*>)', html).group(1)
    assert cell == "<td>"  # no data-tip – clipped cells get the automatic tooltip
    assert "UC-" not in html


@pytest.mark.parametrize("params,variant", [
    ({"protocol": "est", "auth": "passcode"}, "EST · Passcode"),
    ({"protocol": "cmpv2", "auth": "certificate"}, "CMPv2 · Factory certificate"),
    ({"protocol": "scep", "auth": "passcode"}, "SCEP · Passcode"),
    ({"protocol": "rest", "auth": "certificate"}, "REST API · Factory certificate"),
    ({"variant": "api"}, "API"),
    ({"variant": "webui"}, "Web UI"),
])
def test_runs_list_variant_cell(configured_store, user, store, params, variant):
    use_case = "uc03" if "protocol" in params else "uc01"
    store.create_run("v1", use_case, BASE_PARAMS | params)
    assert runs_rows(user.get("/").text)["v1"][2] == variant


def test_no_internal_use_case_numbers_on_index_and_run_pages(configured_user, store, enroll_net, cmp_openssl):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    finished(store, "r1")
    store.create_run("r2", "uc04", BASE_PARAMS | {"protocol": "est", "auth": "passcode", "count": 1})
    store.create_run("r3", "uc03", BASE_PARAMS | {"protocol": "cmpv2", "auth": "certificate", "count": 1})
    for path in ("/", "/runs/r1", "/runs/r2", "/runs/r3", "/runs/r1/api?dialect=powershell"):
        page = configured_user.get(path)
        assert page.status_code == 200, path
        assert not re.search(r"UC-?\d", page.text), (path, re.findall(r".{40}UC-?\d.{20}", page.text))
