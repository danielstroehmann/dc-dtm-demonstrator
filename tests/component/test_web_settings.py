"""Settings: DTM connections – validation, connection check, API key handling, default, delete."""

import re

import httpx
import pytest

from tests.fakedtm import ACCOUNT_ID, API_KEY, HOST, NL_HOST, OTHER_ACCOUNT_ID

XSS = '<img src=x onerror="alert(1)">'


def save(client, **form):
    data = {"name": "Default", "host": HOST, "account_id": ACCOUNT_ID, "api_key": API_KEY} | form
    data = {k: v for k, v in data.items() if v is not None}
    return client.post("/settings/connections", data=data, follow_redirects=False)


def only(store):
    (conn,) = store.connections()
    return conn


def test_settings_page_without_connections(user):
    html = user.get("/settings").text
    assert "<h2>Add connection</h2>" in html and 'value="one.digicert.com"' in html
    assert "DTM connections" not in html and "leave empty to keep it" not in html


def test_save_first_connection(user, store, fake):
    response = save(user, name="  US prod ", host=f"  {HOST.upper()} ", account_id=f" {ACCOUNT_ID} ")
    # the very first connection comes from the welcome page and goes straight on to the use cases
    assert response.status_code == 303 and response.headers["location"] == "/"
    conn = only(store)
    assert (conn["name"], conn["host"], conn["account_id"], conn["api_key"], conn["is_default"]) == (
        "US prod", HOST, ACCOUNT_ID, API_KEY, 1)
    assert fake.names("account") == [""] and fake.violations == []
    html = user.get("/settings").text
    assert '<span class="name">US prod</span>' in html and f'<span class="meta">{HOST} · ' in html
    assert f'<span class="mono">{ACCOUNT_ID}</span>' in html
    assert '<span class="badge">Default</span>' in html and f'href="/settings?edit={conn["id"]}#connection-form"' in html
    assert API_KEY not in html
    edit = user.get(f"/settings?edit={conn['id']}").text
    assert "<h2>Edit connection</h2>" in edit and 'value="US prod"' in edit and "leave empty to keep it" in edit
    assert f'<input type="hidden" name="id" value="{conn["id"]}">' in edit and API_KEY not in edit
    assert '<article class="tile">' in user.get("/").text  # configured: the home page offers the use cases


@pytest.mark.parametrize("host", ["https://one.digicert.com", "one digicert.com", "localhost", "one.digicert.com/x",
                                  "user@one.digicert.com", "one.digicert.com:8443", "10.0.0.1",
                                  "one.digicert.c0m", '"><script>x</script>.com'])
def test_invalid_host(user, store, fake, host):
    response = save(user, host=host)
    assert response.status_code == 400 and "Invalid host name." in response.text
    assert store.connections() == [] and fake.requests == []
    assert "<script>x</script>" not in response.text


@pytest.mark.parametrize("account_id", ["123", "not-a-uuid", ACCOUNT_ID + "0", ACCOUNT_ID.replace("0", "g"),
                                        "0a1b2c3d00004000800000000000a001", "-" * 36, "0" * 36,
                                        "{" + ACCOUNT_ID + "}", "urn:uuid:" + ACCOUNT_ID])
def test_invalid_account_id(user, store, fake, account_id):
    response = save(user, account_id=account_id)
    assert response.status_code == 400 and "must be a UUID" in response.text
    assert store.connections() == [] and fake.requests == []


@pytest.mark.parametrize("name", ["", "   ", "a" * 41, "<b>x</b>", "x;y", "naïve", "a/b", "tab\tname"])
def test_invalid_name(user, store, fake, name):
    response = save(user, name=name)
    assert response.status_code == 400
    assert store.connections() == [] and fake.requests == []
    assert "<b>x</b>" not in response.text


@pytest.mark.parametrize("name", ["US prod", "nl-1", "a.b_c", "a" * 40])
def test_valid_names(user, store, name):
    assert save(user, name=name).status_code == 303 and only(store)["name"] == name


def test_duplicate_name_is_case_insensitive(user, store, fake):
    assert save(user, name="Prod").status_code == 303
    fake.requests.clear()
    response = save(user, name="PROD")
    assert response.status_code == 400 and "already exists" in response.text and fake.requests == []
    conn = only(store)
    assert save(user, id=str(conn["id"]), name="prod", api_key="").status_code == 303  # renaming itself is fine
    assert only(store)["name"] == "prod"


@pytest.mark.parametrize("field", ["name", "host", "account_id"])
def test_missing_fields_are_a_handled_400(user, store, fake, field):
    response = save(user, **{field: None})
    assert response.status_code == 400 and "Invalid or missing form values." in response.text
    assert store.connections() == [] and fake.requests == []


def test_new_connection_requires_a_key(user, store, fake):
    response = save(user, api_key="   ")
    assert response.status_code == 400 and "An API key is required." in response.text
    assert store.connections() == [] and fake.requests == []


def test_account_not_accessible(user, store, fake):
    fake.accounts = [{"id": OTHER_ACCOUNT_ID}]
    response = save(user)
    assert response.status_code == 400 and "Connection check failed" in response.text and "no access" in response.text
    assert store.connections() == []


def test_dtm_error_message_is_escaped(user, store, fake):
    fake.fail["account"] = httpx.Response(401, json={"errors": [{"message": XSS}]})
    response = save(user)
    assert response.status_code == 400 and XSS not in response.text and "&lt;img src=x onerror=" in response.text
    assert store.connections() == []


def test_rejected_key_is_not_echoed_or_stored(user, store, fake):
    response = save(user, api_key="my-secret-key-123")  # the fake answers 401 for a wrong key
    assert response.status_code == 400 and "401" in response.text
    assert "my-secret-key-123" not in response.text and store.connections() == []


@pytest.mark.parametrize("failure,text", [
    (httpx.ConnectError("no route"), "ConnectError"),
    (httpx.Response(200, text="<html>DigiCert ONE login</html>"), "Connection check failed"),
    (httpx.Response(200, text=""), "Connection check failed"),
])
def test_unusable_dtm_answers_are_form_errors(user, store, fake, failure, text):
    fake.fail["account"] = failure
    response = save(user)
    assert response.status_code == 400 and text in response.text and store.connections() == []


# --- editing ---------------------------------------------------------------------------------

def test_edit_keeps_key_when_left_empty(user, store, fake):
    assert save(user).status_code == 303
    conn = only(store)
    other = "0a1b2c3d-0000-4000-8000-00000000c003"
    fake.accounts.append({"id": other})
    fake.account_id = other
    assert save(user, id=str(conn["id"]), account_id=other, api_key="").status_code == 303
    conn = only(store)
    assert conn["account_id"] == other and conn["api_key"] == API_KEY and fake.violations == []


def test_stored_key_is_never_sent_to_a_new_host(user, store, fake):
    assert save(user).status_code == 303
    conn = only(store)
    fake.requests.clear()
    # switching between the two supported platforms (US → NL) without a key: the stored key stays home
    response = save(user, id=str(conn["id"]), host=NL_HOST, api_key="")
    assert response.status_code == 400 and "Enter the API key again" in response.text
    assert fake.requests == [] and only(store)["host"] == HOST


@pytest.mark.parametrize("host", ["attacker.example", "one.digicert.com.attacker.example", "demo.one.digicert.com",
                                  "ONE.EU.DIGICERT.COM"])
def test_only_the_two_platforms_can_be_saved(user, store, fake, host):
    response = save(user, host=host)
    assert response.status_code == 400
    assert ("Only one.digicert.com (US) and one.nl.digicert.com (NL) are supported." in response.text
            or "Invalid host name." in response.text)
    assert store.connections() == [] and fake.requests == []  # refused before the key is sent anywhere
    assert API_KEY not in response.text


def test_unsupported_host_text(user, store, fake):
    response = save(user, host="attacker.example")
    assert "Only one.digicert.com (US) and one.nl.digicert.com (NL) are supported." in response.text


def test_failed_check_on_edit_keeps_previous_values(user, store, fake):
    assert save(user).status_code == 303
    conn = only(store)
    fake.fail["account"] = httpx.Response(403, json={"error": "forbidden"})
    response = save(user, id=str(conn["id"]), name="Renamed", api_key="new-bad-key")
    assert response.status_code == 400
    assert only(store) == conn
    assert "new-bad-key" not in response.text and API_KEY not in response.text


def test_edit_unknown_connection_is_404(user, store):
    assert save(user, id="999").status_code == 404 and store.connections() == []


@pytest.mark.parametrize("edit,status", [("999", 404), ("0", 200), ("-1", 404), ("9" * 30, 404),
                                         ("abc", 400)])
def test_edit_page_for_unknown_or_odd_ids(user, store, edit, status):
    # 0 is treated as "no edit" (plain add form); huge ids must not overflow SQLite → 404, not 500
    assert user.get(f"/settings?edit={edit}").status_code == status


# --- several connections: default, delete ------------------------------------------------------

def add_second(user, fake, name="NL"):
    fake.accounts.append({"id": OTHER_ACCOUNT_ID})
    account = fake.account_id
    fake.account_id = OTHER_ACCOUNT_ID
    try:
        assert save(user, name=name, account_id=OTHER_ACCOUNT_ID).status_code == 303
    finally:
        fake.account_id = account


def test_second_connection_and_make_default(user, store, fake):
    assert save(user, name="US").status_code == 303
    add_second(user, fake)
    by_name = {c["name"]: c for c in store.connections()}
    assert (by_name["US"]["is_default"], by_name["NL"]["is_default"]) == (1, 0)
    html = user.get("/settings").text
    assert f'action="/settings/connections/{by_name["NL"]["id"]}/default"' in html
    assert f'action="/settings/connections/{by_name["US"]["id"]}/default"' not in html  # already default
    response = user.post(f"/settings/connections/{by_name['NL']['id']}/default", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/settings"
    assert {c["name"]: c["is_default"] for c in store.connections()} == {"US": 0, "NL": 1}
    assert store.connection(None)["name"] == "NL"


def test_delete_unused_connection_and_default_moves(user, store, fake):
    assert save(user, name="US").status_code == 303
    add_second(user, fake)
    us = next(c for c in store.connections() if c["name"] == "US")
    html = user.get("/settings").text
    assert f'action="/settings/connections/{us["id"]}/delete"' in html
    assert 'hx-confirm="Delete connection US?"' in html and 'data-confirm-label="Delete"' in html
    response = user.post(f"/settings/connections/{us['id']}/delete", follow_redirects=False)
    assert response.status_code == 303
    (nl,) = store.connections()
    assert nl["name"] == "NL" and nl["is_default"] == 1  # the remaining one became the default


def test_connection_with_open_runs_cannot_be_deleted(user, store, fake):
    assert save(user).status_code == 303
    conn = only(store)
    store.create_run("r1", "uc01", {"connection_id": conn["id"], "dtm_host": HOST, "account_id": ACCOUNT_ID,
                                    "mode": "single", "variant": "api", "count": 1})
    store.update_run("r1", status="completed")
    html = user.get("/settings").text
    assert f'action="/settings/connections/{conn["id"]}/delete"' not in html
    assert re.search(r'<span data-tip="Has runs that are not rolled back"[^>]*><button type="button"[^>]*disabled>'
                     r'Delete</button></span>', html)
    response = user.post(f"/settings/connections/{conn['id']}/delete")
    assert response.status_code == 409 and "not rolled back" in response.text
    assert store.connections()
    # once the run is rolled back, the connection can go
    store.update_run("r1", cleanup_mode="full", cleanup_status="done")
    assert user.post(f"/settings/connections/{conn['id']}/delete", follow_redirects=False).status_code == 303
    assert store.connections() == []


@pytest.mark.parametrize("action", ["default", "delete"])
def test_unknown_connection_actions_are_404(user, store, action):
    assert user.post(f"/settings/connections/999/{action}").status_code == 404
    assert user.post(f"/settings/connections/abc/{action}").status_code in (400, 404, 422)


def test_old_settings_route_is_gone(user, store):
    response = user.post("/settings", data={"host": HOST, "account_id": ACCOUNT_ID, "api_key": API_KEY})
    assert response.status_code in (404, 405) and store.connections() == []


def test_api_keys_are_never_rendered(user, store, fake):
    assert save(user, name="US").status_code == 303
    add_second(user, fake)
    ids = [c["id"] for c in store.connections()]
    pages = ["/settings", *(f"/settings?edit={i}" for i in ids), "/", "/runs/new",
             *(f"/runs/new/uc01?connection={i}" for i in ids)]
    for path in pages:
        assert API_KEY not in user.get(path).text, path



# --- host choice: the supported platforms only; several accounts per host -------------------------------

def test_platform_regions_cover_exactly_the_platforms():
    from app import dtm
    assert set(dtm.PLATFORM_REGIONS) == set(dtm.PLATFORMS)
    assert dtm.PLATFORM_REGIONS == {"one.digicert.com": "US", "one.nl.digicert.com": "NL"}


def test_host_select_offers_the_platforms_and_keeps_the_saved_one(user, store, fake):
    from tests.component.test_web_ui_v2 import host_options
    expected = [("one.digicert.com", "one.digicert.com · US"), ("one.nl.digicert.com", "one.nl.digicert.com · NL")]
    add = host_options(user.get("/settings").text)
    assert [(v, label) for v, _, label in add] == expected and [s for _, s, _ in add] == [True, False]
    store.save_connection(None, "NL demo", NL_HOST, ACCOUNT_ID, API_KEY)
    conn = only(store)
    edit = host_options(user.get(f"/settings?edit={conn['id']}").text)
    assert [(v, label) for v, _, label in edit] == expected and [s for _, s, _ in edit] == [False, True]
    assert "unsupported" not in user.get(f"/settings?edit={conn['id']}").text


def test_host_select_keeps_an_unsupported_saved_host_editable(user, store):
    from tests.component.test_web_ui_v2 import host_options
    store.save_connection(None, "Old", "dtm.example.com", ACCOUNT_ID, API_KEY)
    conn = only(store)
    options = host_options(user.get(f"/settings?edit={conn['id']}").text)
    assert options[-1] == ("dtm.example.com", True, "dtm.example.com · unsupported")
    assert [s for _, s, _ in options[:-1]] == [False, False] and len(options) == 3
    assert "unsupported" not in user.get("/settings").text  # the add form offers the platforms only



def test_connection_actions_order_and_side_by_side_fields(user, store, fake):
    store.save_connection(None, "US", HOST, ACCOUNT_ID, API_KEY)
    store.save_connection(None, "NL", NL_HOST, OTHER_ACCOUNT_ID, "k")
    html = user.get("/settings").text
    for block in re.findall(r'<div class="actions">(.*?)</div>', html, re.S):
        labels = re.findall(r">(Make default|Edit|Delete)<", block)
        assert labels in (["Make default", "Edit", "Delete"], ["Edit", "Delete"]), labels  # the default has no button
    rows = re.findall(r'<div class="field-row">(.*?)</div>', html, re.S)
    assert any("name=\"account_id\"" in r and "name=\"api_key\"" in r for r in rows)  # side by side
    assert any("name=\"name\"" in r and "name=\"host\"" in r for r in rows)
    summaries = re.findall(r'<summary class="meta">(Profiles: [^<]+)</summary>', html)
    assert sorted(summaries) == ["Profiles: per run", "Profiles: shared"]


def test_unsupported_summary(user, store):
    store.save_connection(None, "Old", "dtm.example.com", ACCOUNT_ID, API_KEY)
    assert '<summary class="meta">Profiles: –</summary>' in user.get("/settings").text


def test_a_refused_host_is_not_offered_back(user, store, fake):
    """A crafted POST with an unsupported host: the re-rendered form offers the platforms only."""
    from tests.component.test_web_ui_v2 import host_options
    response = save(user, host="attacker.example")
    assert response.status_code == 400
    assert "attacker.example" not in [v for v, _, _ in host_options(response.text)]
    assert "· unsupported" not in response.text
