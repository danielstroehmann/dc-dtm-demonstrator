"""Several DTM connections: selection for new runs, runs bound to their connection, cleanup."""

import re

import pytest
from fastapi.testclient import TestClient

from app.dtm import DTMClient
from app.main import create_app
from tests.component.test_web_runs import cleaned, finished, form
from tests.conftest import PASSWORD
from tests.fakedtm import ACCOUNT_ID, API_KEY, HOST, OTHER_ACCOUNT_ID, FakeDTM

KEY_B = "second-account-key-for-tests"


@pytest.fixture
def fakes():
    a = FakeDTM()
    b = FakeDTM(account_id=OTHER_ACCOUNT_ID, api_key=KEY_B, ca_name="NL ECDSA ICA", profile_name="NL client profile")
    return {ACCOUNT_ID: a, OTHER_ACCOUNT_ID: b}


@pytest.fixture
def two(store, auth, fakes, data_dir):
    """Logged-in browser with two connections: US (default, account A) and NL (account B)."""
    us = store.save_connection(None, "US", HOST, ACCOUNT_ID, API_KEY)
    nl = store.save_connection(None, "NL", HOST, OTHER_ACCOUNT_ID, KEY_B)

    def factory(config, on_call):  # route each connection to the fake of its account
        return DTMClient(config, on_call, transport=fakes[config.account_id].transport())

    app = create_app(store, auth, client_factory=factory, data_dir=data_dir)
    with TestClient(app, base_url="https://testserver", raise_server_exceptions=False) as client:
        assert client.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
        client.ids = {"US": us, "NL": nl}
        yield client


def test_catalog_offers_a_connection_select(two, store):
    html = two.get("/runs/new").text
    assert '<select name="connection"' in html
    assert re.search(rf'<option value="{two.ids["US"]}" selected>US – {HOST}</option>', html)
    assert re.search(rf'<option value="{two.ids["NL"]}" >NL – {HOST}</option>', html)
    store.set_default_connection(two.ids["NL"])
    assert re.search(rf'<option value="{two.ids["NL"]}" selected>', two.get("/runs/new").text)
    assert re.search(rf'<option value="{two.ids["NL"]}" selected>', two.get(f"/runs/new?connection={two.ids['NL']}").text)


@pytest.mark.parametrize("value", ["999", "abc", "-1", "1.0", "9" * 30, " 1", "0x1"])
def test_unknown_connection_is_404(two, value):
    assert two.get(f"/runs/new?connection={value}").status_code == 404
    assert two.get(f"/runs/new/uc01?connection={value}").status_code == 404


def test_form_loads_data_from_the_selected_connection(two, fakes):
    html = two.get(f"/runs/new/evergreen?connection={two.ids['NL']}").text
    assert "NL ECDSA ICA" in html and "Fake ECDSA ICA" not in html
    assert fakes[OTHER_ACCOUNT_ID].names("profiles")  # the profile hints come from the selected account
    assert "Connection:" not in html  # no connection line any more – the hidden field carries it
    # the header chip shows the connection of this form, not the default one
    assert re.search(r'class="conn-chip" data-tip="DTM connection: NL · [^"]*"><span>NL · ', html)
    assert not re.search(r'class="conn-chip"[^>]*><span>US · ', html) and "Default connection:" not in html
    # elsewhere the chip shows the default connection
    assert re.search(r'class="conn-chip" data-tip="DTM connection: US · [^"]*"><span>US · ', two.get("/").text)
    assert f'<input type="hidden" name="connection_id" value="{two.ids["NL"]}">' in html
    assert f'href="/runs/new?connection={two.ids["NL"]}">' in html  # breadcrumb keeps the choice
    assert fakes[ACCOUNT_ID].requests == []
    default = two.get("/runs/new/evergreen").text
    assert "Fake ECDSA ICA" in default and "NL ECDSA ICA" not in default
    assert f'<input type="hidden" name="connection_id" value="{two.ids["US"]}">' in default


def test_run_on_a_non_default_connection_and_cleanup_uses_it(two, store, fakes):
    a, b = fakes[ACCOUNT_ID], fakes[OTHER_ACCOUNT_ID]
    two.post("/runs", data=form(mode="batch", count="2", connection_id=str(two.ids["NL"])))
    run = finished(store, "r1")
    assert run["status"] == "completed", store.events("r1")
    p = run["params"]
    assert (p["connection_id"], p["connection_name"], p["dtm_host"], p["account_id"]) == (
        two.ids["NL"], "NL", HOST, OTHER_ACCOUNT_ID)
    assert b.policies and not a.policies and a.violations == b.violations == []
    index = two.get("/").text
    assert "<th>Connection</th>" in index and "<td>NL</td>" in index
    store.set_default_connection(two.ids["US"])  # the default changes meanwhile – the run keeps its own
    two.post("/runs/r1/cleanup", data={"mode": "full"})
    assert cleaned(store, "r1")["cleanup_status"] == "done"
    assert b.policies == {} and b.issued() == [] and a.requests == []


def test_empty_connection_id_uses_the_default(two, store, fakes):
    store.set_default_connection(two.ids["NL"])
    two.post("/runs", data=form(connection_id=""))
    run = finished(store, "r1")
    assert run["params"]["connection_id"] == two.ids["NL"] and fakes[OTHER_ACCOUNT_ID].issued()


@pytest.mark.parametrize("value", ["999", "abc"])
def test_create_run_with_unknown_connection(two, store, value):
    assert two.post("/runs", data=form(connection_id=value)).status_code == 404
    assert store.list_runs() == []


def test_no_connection_column_with_one_connection(configured_user, store):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    assert "<th>Connection</th>" not in configured_user.get("/").text


def test_editing_host_or_account_of_a_connection_in_use_is_refused(two, store, fakes):
    two.post("/runs", data=form(connection_id=str(two.ids["NL"])))
    finished(store, "r1")
    data = {"id": str(two.ids["NL"]), "name": "NL", "host": HOST, "account_id": ACCOUNT_ID, "api_key": API_KEY}
    response = two.post("/settings/connections", data=data)
    assert response.status_code == 400 and "create a new connection for another account" in response.text
    assert store.connection(two.ids["NL"])["account_id"] == OTHER_ACCOUNT_ID
    # name and key changes stay allowed
    data |= {"name": "Netherlands", "account_id": OTHER_ACCOUNT_ID, "api_key": ""}
    assert two.post("/settings/connections", data=data, follow_redirects=False).status_code == 303
    assert store.connection(two.ids["NL"])["name"] == "Netherlands"
    # after a full rollback the account may change
    two.post("/runs/r1/cleanup", data={"mode": "full"})
    cleaned(store, "r1")
    data |= {"account_id": "0a1b2c3d-0000-4000-8000-00000000c003", "api_key": "k3"}
    fakes["0a1b2c3d-0000-4000-8000-00000000c003"] = FakeDTM(account_id="0a1b2c3d-0000-4000-8000-00000000c003",
                                                            api_key="k3")
    assert two.post("/settings/connections", data=data, follow_redirects=False).status_code == 303


def test_run_falls_back_to_an_equivalent_connection(two, store, fakes):
    two.post("/runs", data=form(connection_id=str(two.ids["NL"])))
    finished(store, "r1")
    # binding broken behind the app's back, then an equivalent connection appears
    conn = store.connection(two.ids["NL"])
    store.save_connection(conn["id"], "NL-old", HOST, "0a1b2c3d-0000-4000-8000-00000000ffff", KEY_B)
    assert two.post("/runs/r1/cleanup", data={"mode": "full"}).status_code == 409
    assert "NL (not configured)" in two.get("/").text
    store.save_connection(None, "NL again", HOST, OTHER_ACCOUNT_ID, KEY_B)
    assert "<td>NL again</td>" in two.get("/").text
    two.post("/runs/r1/cleanup", data={"mode": "full"})
    assert cleaned(store, "r1")["cleanup_status"] == "done" and fakes[OTHER_ACCOUNT_ID].policies == {}


def test_old_runs_without_connection_id_are_matched_by_account(two, store, fakes):
    b = fakes[OTHER_ACCOUNT_ID]
    two.post("/runs", data=form(connection_id=str(two.ids["NL"])))
    finished(store, "r1")
    run = store.get_run("r1")
    params = {k: v for k, v in run["params"].items() if k not in ("connection_id", "connection_name")}
    store.update_run("r1", params=params)  # what a pre-connections run looks like
    assert "<td>NL</td>" in two.get("/").text
    two.post("/runs/r1/cleanup", data={"mode": "full"})
    assert cleaned(store, "r1")["cleanup_status"] == "done" and b.policies == {}


def test_connection_changed_between_form_and_insert_is_409(two, store, fakes, monkeypatch):
    """create_run loads CAs from the connection, then re-checks it right before inserting the run."""
    original = fakes[OTHER_ACCOUNT_ID]._list_cas

    def change_meanwhile(request):
        conn = store.connection(two.ids["NL"])
        store.save_connection(conn["id"], conn["name"], "eu.example.com", conn["account_id"], conn["api_key"])
        return original(request)

    fakes[OTHER_ACCOUNT_ID].router.routes["cas"].side_effect = fakes[OTHER_ACCOUNT_ID]._wrap(
        "cas", change_meanwhile)
    response = two.post("/runs", data=form(connection_id=str(two.ids["NL"])))
    assert response.status_code == 409 and "changed meanwhile" in response.text
    assert store.list_runs() == []


def test_concurrent_duplicate_name_is_a_form_error(two, store, monkeypatch):
    """The name check passes, but another request inserts the same name first → IntegrityError."""
    original = store.save_connection

    def racing(connection_id, name, *args):
        original(None, name.upper(), HOST, "0a1b2c3d-0000-4000-8000-00000000dddd", "k")  # the other request
        return original(connection_id, name, *args)

    monkeypatch.setattr(store, "save_connection", racing)
    data = {"name": "Brand new", "host": HOST, "account_id": ACCOUNT_ID, "api_key": API_KEY}
    response = two.post("/settings/connections", data=data)
    assert response.status_code == 400 and "already exists" in response.text


def test_templates_never_get_api_keys(two, store):
    two.post("/runs", data=form())
    finished(store, "r1")
    for path in ("/", "/settings", f"/settings?edit={two.ids['NL']}", "/runs/new",
                 f"/runs/new/uc01?connection={two.ids['NL']}", "/runs/r1", "/runs/r1/api?dialect=powershell"):
        html = two.get(path).text
        assert API_KEY not in html and KEY_B not in html, path


def test_connection_routes_refuse_cross_site_posts(two, store):
    for path in (f"/settings/connections/{two.ids['NL']}/default", f"/settings/connections/{two.ids['NL']}/delete",
                 "/settings/connections"):
        response = two.post(path, headers={"Sec-Fetch-Site": "cross-site"},
                            data={"name": "x", "host": HOST, "account_id": ACCOUNT_ID, "api_key": "k"})
        assert response.status_code == 403, path
    assert {c["name"] for c in store.connections()} == {"US", "NL"}
    assert store.connection(None)["name"] == "US"


def test_unconfigured_catalog_and_form(user):
    html = user.get("/runs/new").text
    assert 'action="/settings/connections"' in html and "formaction" not in html  # welcome form, no tiles
    assert user.get("/runs/new/uc01").status_code == 409
    assert user.post("/runs", data=form()).status_code == 409


# --- global table rule: single-line tables with tooltips for clipped cells ------------------------

def test_every_table_is_a_data_table_or_compact(two, store):
    two.post("/runs", data=form(mode="batch", count="12", connection_id=str(two.ids["NL"])))
    finished(store, "r1")
    pages = {path: two.get(path).text for path in ("/", "/settings", "/runs/r1", "/runs/r1/certificates?page=2")}
    seen = 0
    for path, html in pages.items():
        for table in re.findall(r"<table[^>]*>.*?</table>", html, re.S):
            seen += 1
            classes = re.search(r'<table class="([^"]*)"', table).group(1).split()
            assert "data-table" in classes or "compact" in classes, (path, classes)
            assert "<code>" not in table, path  # no chips inside single-line cells
    assert seen == 3  # home runs table + certificate tables; settings lists connections without a table
    settings = pages["/settings"]
    assert "<table" not in settings and settings.count('<ul class="conn-list">') == 1
    assert f'<span class="mono">{OTHER_ACCOUNT_ID}</span>' in settings
    assert settings.count('<div class="actions">') == 2
    assert pages["/"].count('<td class="actions-cell">') == 1


def test_tooltip_selector_covers_all_table_kinds(web):
    js = web.get("/static/app.js").text
    selector = re.search(r'const TRUNCATING = "([^"]+)"', js).group(1)
    parts = {p.strip() for p in selector.split(",")}
    assert {"table.compact td", "table.compact th", "table.data-table td", "table.data-table th"} <= parts
