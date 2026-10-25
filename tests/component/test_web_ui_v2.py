"""UI v2 (docs/design/04-ui-design.md): welcome page, use-case tiles, app shell, run stepper, CSS contract."""

import re
from pathlib import Path

import httpx
import pytest

from app import evergreen
from tests.component.test_web_connections import fakes, two  # noqa: F401 (fixtures)
from tests.component.test_web_runs import BASE_PARAMS
from tests.fakedtm import ACCOUNT_ID, API_KEY, HOST, OTHER_ACCOUNT_ID

STATIC = Path(__file__).resolve().parents[2] / "app" / "static"
XSS_NAME = '<img src=x onerror="alert(1)">'


def save(client, **form):
    data = {"name": "Default", "host": HOST, "account_id": ACCOUNT_ID, "api_key": API_KEY} | form
    return client.post("/settings/connections", data=data, follow_redirects=False)


def stepper(html: str, label: str) -> list[tuple[str, bool, str]]:
    """(class, aria-current, text) per step of the stepper with the given aria-label."""
    match = re.search(rf'<ol class="stepper" aria-label="{label}">(.*?)</ol>', html, re.S)
    assert match, label
    return [(cls, bool(cur), text) for cls, cur, text in
            re.findall(r'<li(?: class="([^"]*)")?\s*(aria-current="step")?\s*>([^<]+)</li>', match.group(1))]


def nav_current(html: str) -> list[str]:
    return re.findall(r'<a class="nav-link" href="[^"]+"\s*aria-current="page">([^<]+)</a>', html)


# --- welcome page (no DTM connection) ----------------------------------------------------------

def test_unconfigured_home_is_the_welcome_page(user):
    html = user.get("/").text
    assert "<h1>Welcome</h1>" in html
    assert stepper(html, "Getting started") == [
        ("current", True, "Connect DTM"), ("", False, "Choose a use case"), ("", False, "Run and roll back")]
    assert '<form method="post" action="/settings/connections">' in html
    assert host_options(html) == [("one.digicert.com", True, "one.digicert.com · US"),
                                  ("one.nl.digicert.com", False, "one.nl.digicert.com · NL")]  # US preselected
    assert '<button type="submit" class="cta">Check and save</button>' in html
    assert 'class="tile"' not in html and "formaction" not in html and "<table" not in html
    assert 'name="id"' not in html  # a new connection, not an edit
    assert "conn-chip" not in html  # no default connection yet


def test_first_connection_redirects_home_later_ones_to_settings(user, store, fake):
    first = save(user, name="US")
    assert first.status_code == 303 and first.headers["location"] == "/"
    home = user.get("/").text
    assert '<article class="tile">' in home and "<h1>Welcome</h1>" not in home and "<h1>" not in home
    second = save(user, name="US backup")  # the fake DTM knows one account; a second name is enough
    assert second.status_code == 303 and second.headers["location"] == "/settings"
    (us,) = [c for c in store.connections() if c["name"] == "US"]
    edit = save(user, id=str(us["id"]), name="US renamed", api_key="")
    assert edit.status_code == 303 and edit.headers["location"] == "/settings"
    assert sorted(c["name"] for c in store.connections()) == ["US backup", "US renamed"]


def test_failed_first_check_rerenders_with_error_and_keeps_values(user, store, fake):
    fake.fail["account"] = httpx.Response(401, json={"errors": [{"message": "bad key"}]})
    response = save(user, name="US", api_key="rejected-key-for-tests")
    assert response.status_code == 400 and store.connections() == []
    html = response.text
    assert re.search(r'<p class="error" role="alert">[^<]+</p>', html)
    assert 'value="US"' in html and f'value="{ACCOUNT_ID}"' in html
    assert "rejected-key-for-tests" not in html  # the entered key is never echoed back
    assert '<button type="submit" class="cta">Check and save</button>' in html  # still the first connection
    # no connection yet: the error comes back on the welcome page, not on the settings page
    assert "<h1>Welcome</h1>" in html and "<h1>Settings</h1>" not in html
    assert stepper(html, "Getting started")[0] == ("current", True, "Connect DTM")
    del fake.fail["account"]
    retry = save(user, name="US")  # the retry is still the very first connection
    assert retry.status_code == 303 and retry.headers["location"] == "/"


def test_invalid_first_connection_keeps_the_user_on_the_welcome_page(user, store, fake):
    response = save(user, name="US", host="localhost")
    assert response.status_code == 400 and "Invalid host name." in response.text
    assert store.connections() == [] and fake.requests == []
    assert "location" not in response.headers
    assert "<h1>Welcome</h1>" in response.text and 'value="US"' in response.text


def test_failed_later_save_stays_on_settings(configured_user, store, fake):
    fake.fail["account"] = httpx.Response(401, json={"errors": [{"message": "bad key"}]})
    response = save(configured_user, name="Second")
    assert response.status_code == 400 and len(store.connections()) == 1
    html = response.text
    assert "<h1>Settings</h1>" in html and "<h1>Welcome</h1>" not in html and 'role="alert"' in html
    assert 'value="Second"' in html and "<h2>DTM connections</h2>" in html


# --- configured home: tiles, connection picker, recent runs ----------------------------------------

def test_configured_home_shows_one_tile_per_use_case(configured_user, store, fake):
    html = configured_user.get("/").text
    assert "<h1>" not in html  # no "Start a demo" heading – the tiles say it (author: less text)
    assert html.count('<article class="tile">') == len(evergreen.CATALOG) == 3
    for key, use_case in evergreen.CATALOG.items():
        assert html.count(f'formaction="/runs/new/{key}"') == 1
        assert f'aria-label="Start {use_case.title}"' in html
    assert (html.index('formaction="/runs/new/evergreen"') < html.index('formaction="/runs/new/uc04"')
            < html.index('formaction="/runs/new/uc05"'))
    assert "Server-side or factory keys" in html and "Renewal per click" in html and "One-time passcode" in html
    (conn,) = store.connections()
    assert f'<input type="hidden" name="connection" value="{conn["id"]}">' in html
    assert '<select name="connection"' not in html
    assert 'action="/settings/connections"' not in html  # no welcome form any more
    assert fake.requests == []  # home page needs no DTM call


def test_tile_start_carries_the_hidden_connection(configured_user, store, fake):
    (conn,) = store.connections()
    response = configured_user.get(f"/runs/new/uc01?connection={conn['id']}")  # what the GET form submits
    assert response.status_code == 200 and 'action="/runs"' in response.text


def test_connection_select_only_with_several_connections(two, store):
    html = two.get("/").text
    assert html.count('<select name="connection"') == 1 and '<input type="hidden" name="connection"' not in html
    options = re.findall(r'<option value="(\d+)"\s*(selected)?>([^<]+)</option>', html)
    assert {int(v): bool(sel) for v, sel, _ in options} == {two.ids["US"]: True, two.ids["NL"]: False}
    assert f"US · {HOST}" in html and f"NL · {HOST}" in html
    store.set_default_connection(two.ids["NL"])
    options = re.findall(r'<option value="(\d+)"\s*(selected)?>', two.get("/").text)
    assert {int(v) for v, sel in options if sel} == {two.ids["NL"]}


def test_empty_state_without_runs(configured_user):
    html = configured_user.get("/").text
    assert "<h2>Recent runs</h2>" in html and "No runs yet." in html and "<table" not in html


@pytest.mark.parametrize("status,kind", [
    ("completed", "ok"), ("failed", "bad"), ("interrupted", "bad"), ("running", "run"), ("pending", "run"),
    ("waiting", "run"),
])
def test_recent_runs_status_pills(configured_store, user, store, status, kind):
    store.create_run("p1", "uc01", BASE_PARAMS)
    store.update_run("p1", status=status)
    html = user.get("/").text
    assert "No runs yet." not in html
    row = re.search(r'<tr id="run-p1"[^>]*>\s*<td><a href="/runs/p1">p1</a></td>.*?</tr>', html, re.S).group(0)
    assert f'<span class="pill {kind}">{status}</span>' in row
    assert "<td>–</td>" in row  # no cleanup yet


@pytest.mark.parametrize("cleanup_status,kind", [("done", "ok"), ("failed", "bad"), ("running", "run")])
def test_recent_runs_cleanup_pill(configured_store, user, store, cleanup_status, kind):
    store.create_run("p2", "uc01", BASE_PARAMS)
    store.update_run("p2", status="completed", cleanup_status=cleanup_status)
    row = re.search(r'<tr id="run-p2"[^>]*>\s*<td><a href="/runs/p2">p2</a></td>.*?</tr>', user.get("/").text,
                    re.S).group(0)
    assert row.count('<span class="pill ') == 2
    assert f'<span class="pill {kind}">{cleanup_status}</span>' in row


# --- app shell: connection chip, nav, log-out ------------------------------------------------------

CHIP = r'<a href="/settings" class="conn-chip"[^>]*>(?:<span>)?{}(?:</span>)?</a>'
PAGES = ("/", "/settings", "/runs/new", "/runs/new/uc01", "/runs/c1", "/nope")


def test_header_chip_shows_default_connection_and_never_the_key(configured_user, store):
    store.create_run("c1", "uc01", BASE_PARAMS)
    store.update_run("c1", status="completed")
    for path in PAGES:
        html = configured_user.get(path).text
        assert re.search(CHIP.format(re.escape(f"Default · {HOST}")), html), path
        assert API_KEY not in html, path


def test_header_chip_follows_the_default(two, store):
    assert re.search(CHIP.format(re.escape(f"US · {HOST}")), two.get("/").text)
    store.set_default_connection(two.ids["NL"])
    html = two.get("/settings").text
    assert re.search(CHIP.format(re.escape(f"NL · {HOST}")), html)
    assert not re.search(CHIP.format(re.escape(f"US · {HOST}")), html)


def test_nav_marks_the_current_section(configured_user, store):
    store.create_run("c1", "uc01", BASE_PARAMS)
    # section pages are "current"; run pages and run forms belong to Runs; the catalog has its breadcrumb
    expected = {"/": ["Runs"], "/settings": ["Settings"], "/settings?edit=1": ["Settings"],
                "/runs/new": [], "/runs/c1": ["Runs"], "/runs/new/uc01": ["Runs"], "/runs/new/evergreen": ["Runs"],
                "/runs/new/uc04": ["Runs"], "/runs/new/uc05": ["Runs"], "/nope": []}
    assert {path: nav_current(configured_user.get(path).text) for path in expected} == expected


def test_logout_is_a_post_form(configured_user):
    html = configured_user.get("/").text
    assert re.search(r'<form method="post" action="/logout" class="inline"><button type="submit" class="logout" '
                     r'aria-label="Log out"', html)
    assert 'href="/logout"' not in html  # no GET link that would log out (or be prefetched)
    assert configured_user.get("/logout", follow_redirects=False).status_code in (404, 405)
    response = configured_user.post("/logout", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


@pytest.mark.parametrize("method,path,status", [("post", "/login", 400), ("get", "/static/nope.css", 404),
                                                ("put", "/login", 405)])
def test_anonymous_error_pages_have_no_app_shell(configured_store, web, method, path, status):
    response = web.request(method, path, data={} if method != "get" else None, follow_redirects=False)
    assert response.status_code == status
    html = response.text
    # still the error page (404: "Not found", plain text; other errors: "Something went wrong" + alert) …
    assert ("<h2>Not found</h2>" if status == 404 else "<h2>Something went wrong</h2>") in html
    # … but without what only a logged-in user may see: connection name/host, navigation, log-out
    assert "conn-chip" not in html and f"Default · {HOST}" not in html
    assert 'class="nav-link"' not in html and 'action="/logout"' not in html


def test_logged_in_error_page_keeps_the_app_shell(configured_user):
    html = configured_user.get("/nope").text
    assert "<h2>Not found</h2>" in html and 'class="conn-chip"' in html and 'action="/logout"' in html


# --- run page: header pill, phase stepper, live line ------------------------------------------------

@pytest.mark.parametrize("status,cleanup_mode,cleanup_status,steps", [
    ("pending", None, None, ["current", "", ""]),
    ("running", None, None, ["current", "", ""]),
    ("completed", None, None, ["done", "current", ""]),
    ("failed", None, None, ["done", "current", ""]),
    ("interrupted", None, None, ["done", "current", ""]),
    ("completed", "full", "running", ["done", "done", "current"]),
    ("completed", "full", "failed", ["done", "done", "current"]),
    ("failed", "full", "running", ["done", "done", "current"]),
    ("completed", "certificates", "running", ["done", "done", "current"]),
    # certificates only: the policy etc. still exist – "Clean up" stays open until a full rollback
    ("completed", "certificates", "done", ["done", "done", "current"]),
    ("completed", "full", "done", ["done", "done", "done"]),
])
def test_run_stepper_phase(configured_store, user, store, status, cleanup_mode, cleanup_status, steps):
    store.create_run("s1", "uc01", BASE_PARAMS)
    store.update_run("s1", status=status, cleanup_mode=cleanup_mode, cleanup_status=cleanup_status)
    html = user.get("/runs/s1").text
    got = stepper(html, "Run phases")
    assert [text for _, _, text in got] == ["Run", "Result", "Clean up"]
    assert [cls for cls, _, _ in got] == steps
    assert [cur for _, cur, _ in got] == [cls == "current" for cls in steps]  # aria-current only on the current one


@pytest.mark.parametrize("status,kind", [("completed", "ok"), ("failed", "bad"), ("running", "run"),
                                         ("interrupted", "bad")])
def test_run_header_pill(configured_store, user, store, status, kind):
    store.create_run("h1", "uc01", BASE_PARAMS | {"connection_name": "Default"})
    store.update_run("h1", status=status)
    html = user.get("/runs/h1").text
    assert f'<h1>Run h1 <span class="pill {kind}">{status}</span></h1>' in html
    title = evergreen.USE_CASES["uc01"].title
    assert f"<p>{title} · Batch (3) · via API · Default</p>" in html


def test_live_line_only_for_unfinished_cleanup(configured_store, user, store):
    store.create_run("l1", "uc01", BASE_PARAMS)
    store.update_run("l1", status="failed", cleanup_status="running")
    live = user.get("/runs/l1/live").text
    assert '<p class="status-line">Cleanup: <span class="status running">running</span></p>' in live
    assert "failed" not in live  # the run status is in the page header, not in the live line
    store.update_run("l1", cleanup_status="done")
    assert 'class="status-line"' not in user.get("/runs/l1/live").text


# --- XSS: connection and use-case texts in the new places ------------------------------------------

def test_connection_name_is_escaped_in_chip_select_and_run_pages(user, store):
    a = store.save_connection(None, XSS_NAME, HOST, ACCOUNT_ID, API_KEY)
    store.save_connection(None, "NL", HOST, OTHER_ACCOUNT_ID, "k2")
    store.create_run("x1", "uc01", BASE_PARAMS | {"connection_id": a, "connection_name": XSS_NAME,
                                                  "account_id": ACCOUNT_ID})
    escaped = "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;"
    for path in ("/", "/settings", "/runs/new", "/runs/x1"):
        html = user.get(path).text
        assert XSS_NAME not in html and "<img" not in html and 'onerror="alert' not in html, path
        assert re.search(CHIP.format(re.escape(f"{escaped} · {HOST}")), html), path
        chip = re.search(r'<a href="/settings" class="conn-chip"[^>]*>', html).group(0)
        assert 'onerror' not in chip or escaped in chip, path  # a name in the chip tooltip is escaped too
    home = user.get("/").text
    assert f"<option value=\"{a}\" selected>{escaped} · {HOST}</option>" in home
    assert f"<td>{escaped}</td>" in home  # runs table, connection column (two connections)
    assert f"· {escaped}</p>" in user.get("/runs/x1").text


def test_use_case_title_is_escaped_in_tiles_and_tooltips(configured_store, user, store, monkeypatch):
    from app import main
    hostile = 'T" onmouseover="alert(1)'
    monkeypatch.setitem(main.USE_CASES, "uc01", evergreen.UseCase(hostile, "S", "server_side"))  # run page
    monkeypatch.setitem(evergreen.DISPLAY_NAMES, "uc01", hostile)  # runs table
    monkeypatch.setitem(evergreen.CATALOG, "evergreen", evergreen.UseCase(hostile, "S", "server_side"))  # tile
    store.create_run("t1", "uc01", BASE_PARAMS)
    html = user.get("/").text
    assert hostile not in html and 'onmouseover="alert(1)' not in html
    escaped = "T&#34; onmouseover=&#34;alert(1)"
    assert f'aria-label="Start {escaped}"' in html  # tile button attribute
    assert f"<td>{escaped}</td>" in html  # runs table use-case cell (text, no tooltip attribute)
    page = user.get("/runs/t1").text
    assert hostile not in page and 'onmouseover="alert(1)' not in page
    assert f"<p>{escaped} · Batch (3)" in page  # run page title line


# --- CSS contract: buttons are never full width ------------------------------------------------------

def css_rules(css: str) -> list[tuple[list[str], dict[str, str]]]:
    """Innermost rules (also inside @media) as (selectors, declarations) – enough for a contract check."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rules = []
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        decls = dict((k.strip().lower(), v.strip().lower()) for k, _, v in
                     (d.partition(":") for d in body.split(";") if ":" in d))
        rules.append(([s.strip().replace("'", '"') for s in selector.split(",")], decls))
    return rules


def test_buttons_are_auto_width_and_override_pico():
    pico = (STATIC / "pico.min.css").read_text()
    assert "button[type=submit]" in pico  # the rule we must override still exists in the bundled Pico
    rules = css_rules((STATIC / "app.css").read_text())
    auto = [sel for sel, d in rules if d.get("width") == "auto"]
    assert any('button[type="submit"]' in sel and "button" in sel and 'a[role="button"]' in sel for sel in auto)
    buttonish = re.compile(r'(^|[\s>+~])(button|\.cta|\[type="?(submit|button|reset)"?\]|a\[role="?button"?\])')
    full = [sel for sels, d in rules if d.get("width") in ("100%", "100 %") for sel in sels
            if buttonish.search(sel.split()[-1] if sel.split() else sel)]
    assert full == []


def test_app_css_loads_after_pico(configured_user):
    html = configured_user.get("/").text
    assert html.index("/static/pico.min.css") < html.index("/static/app.css")


def test_single_line_controls_share_one_height():
    """Controls in one row line up: every single-line control in any form (selects, inputs but
    radio/checkbox/hidden), read-only values and segmented buttons take --control-h (a CSS contract;
    the look itself was verified in Chrome)."""
    rules = css_rules((STATIC / "app.css").read_text())
    sized = {sel for selectors, decls in rules if decls.get("height") == "var(--control-h)" for sel in selectors}
    for selector in (".segmented", ".readonly-value", "form select",
                     "form input:not([type=radio]):not([type=checkbox]):not([type=hidden])"):
        assert selector in sized, selector
    assert any("--control-h" in decls for _, decls in rules)  # defined once, not hard-coded per control



def host_options(html: str) -> list[tuple[str, bool, str]]:
    """(value, selected, label) of the connection form's host select."""
    select = re.search(r'<select name="host" required>(.*?)</select>', html, re.S)
    assert select, "no host select"
    return [(v, bool(sel), label) for v, sel, label in
            re.findall(r'<option value="([^"]+)" ?(selected)?>([^<]+)</option>', select.group(1))]


def test_one_grid_per_row_contract():
    """Author's quality bar: elements side by side share one grid – the connection select is exactly
    one tile wide, questions sit in three equal columns, every row action has the same box."""
    rules = css_rules((STATIC / "app.css").read_text())

    def decl(selector, prop):
        return [d[prop] for sels, d in rules if selector in sels and prop in d]
    assert "repeat(3, minmax(0, 1fr))" in decl(".tiles", "grid-template-columns")
    assert "repeat(3, minmax(0, 1fr))" in decl(".q-grid", "grid-template-columns")
    assert decl(".conn-select", "width") == ["calc((100% - 2 * var(--s4)) / 3)"]  # gap of .tiles is --s4
    assert "var(--s4)" in decl(".tiles", "gap")[0]
    assert decl(".actions-cell .row-action", "width") == ["7.5rem"]
    assert decl(".actions-cell .row-action", "height") == ["1.75rem"]
    assert decl("table.runs-table td", "line-height") == ["1.75rem"]  # = the action box
    widths = {s: d["width"] for sels, d in rules for s in sels if s.startswith(".rollback-meter.p-") and "width" in d}
    assert widths == {f".rollback-meter.p-{p}::before": f"{p}%" for p in range(0, 101, 5)}  # every step the row uses
