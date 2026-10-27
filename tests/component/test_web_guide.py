"""The guided entry: tiles, redirects, the form's
data-when contract (driven by tests/guide_form.py, a stand-in for app.js), what each path through the
guide submits and resolves to, server-side checks, profile hints and the Settings view of the
shared profiles."""

import re

import httpx
import pytest

from app import dtm, evergreen
from tests.component.test_web_runs import cleaned, finished
from tests.conftest import PASSWORD, make_web
from tests.fakedtm import ECDSA_CA_ID, RSA_CA_ID
from tests.guide_form import GuideForm

EVERGREEN, CMP, RENEWAL = dtm.PROFILE_EVERGREEN.name, dtm.PROFILE_EVERGREEN_CMP.name, dtm.PROFILE_RENEWAL.name
MISSING = {spec.name: "missing" for spec in dtm.SHARED_PROFILES}


def dtm_writes(fake) -> list[str]:
    return [n for n in fake.route_order() if n not in ("cas", "profiles")]


# --- tiles and redirects -----------------------------------------------------------------------

def test_one_tile_per_catalog_entry_without_uc_ids(configured_user, fake):
    html = configured_user.get("/").text
    assert len(re.findall(r'<article class="tile[ "]', html)) == 6 == len(evergreen.CATALOG)
    order = [html.index(f'formaction="/runs/new/{k}"') for k in ("evergreen", "uc04", "uc05", "uc06", "uc07", "uc08")]
    assert order == sorted(order)
    for key in ("uc01", "uc02", "uc03"):
        assert f'formaction="/runs/new/{key}"' not in html
    assert 'class="uc-id"' not in html and not re.search(r"UC-?\d", html)
    assert f"<h3>{evergreen.USE_CASES['uc05'].title}</h3>" in html and "<li>One-time passcode</li>" in html
    assert f"<h3>{evergreen.GUIDE.title}</h3>" in html and f"<h3>{evergreen.USE_CASES['uc04'].title}</h3>" in html
    for tag in evergreen.GUIDE.tags:
        assert f"<li>{tag}</li>" in html
    assert "REST · EST · CMPv2 · SCEP" in html
    assert "<li>EST · CMPv2</li>" in html  # UC-4: enrollment and renewal protocols
    assert fake.requests == []


@pytest.mark.parametrize("old", ["uc01", "uc02", "uc03"])
def test_old_links_redirect_to_the_guide(configured_user, store, old):
    response = configured_user.get(f"/runs/new/{old}", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/new/evergreen"
    conn = store.connections()[0]["id"]
    response = configured_user.get(f"/runs/new/{old}?connection={conn}", follow_redirects=False)
    assert response.headers["location"] == f"/runs/new/evergreen?connection={conn}"


def test_redirect_query_is_urlencoded(configured_user):
    response = configured_user.get("/runs/new/uc01?connection=1%26x%3D%22%3E", follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/runs/new/evergreen?connection=") and '"' not in location and "&x=" not in location


@pytest.mark.parametrize("path", ["/runs/new/uc09", "/runs/new/UC07", "/runs/new/UC06", "/runs/new/UC05", "/runs/new/UC01", "/runs/new/Evergreen", "/runs/new/evergreen."])
def test_unknown_entries_are_404(configured_user, fake, path):
    assert configured_user.get(path).status_code == 404 and fake.requests == []


def test_guide_and_uc04_need_login(web):
    for path in ("/runs/new/evergreen", "/runs/new/uc04", "/runs/new/uc01"):
        response = web.get(path, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/login"


# --- form contract -----------------------------------------------------------------------------

def guide(configured_user) -> GuideForm:
    response = configured_user.get("/runs/new/evergreen")
    assert response.status_code == 200
    return GuideForm(response.text)


def test_form_markup_contract(configured_user):
    html = configured_user.get("/runs/new/evergreen").text
    assert re.search(r'<form method="post" action="/runs" data-guide>', html)
    assert '<input type="hidden" name="use_case" value="evergreen">' in html
    # the questions in fixed slots (row/column) and the conditions under which they apply
    assert '<div class="slot r1c1">' in html  # key location
    assert '<div class="slot r1c2 choice-with-count">' in html  # devices + count inline
    assert re.search(r'<input id="count" type="number" name="count" class="short" value="2" min="1" max="\d+"\s+'
                     r'aria-label="Number of certificates" data-when="mode=batch">', html)
    assert html.count('data-when="mode=single key_location=factory">') == 2  # protocol | authentication
    assert '<div class="slot r2c1" data-when="mode=single key_location=factory">' in html
    assert '<div class="slot r2c2" data-when="mode=single key_location=factory">' in html
    assert '<label data-when="protocol=rest"><input type="radio" name="auth_method" value="apikey"' in html
    assert re.search(r'<label data-when="protocol=rest \| protocol=est \| protocol=cmpv2"><input type="radio" '
                     r'name="auth_method" value="certificate"', html)  # no factory certificate for SCEP
    assert '<div class="slot r1c3" data-when="mode=batch | key_location=server | auth_method=apikey">' in html
    assert re.search(r'<label class="slot r2c3 switch-cell" data-when="mode=batch variant=api" '
                     r'data-tip="Auto-approved by the demonstrator"><input type="checkbox" name="approval"[^>]*> '
                     r'Require approval</label>', html)
    for value in ("rest", "est", "cmpv2", "scep"):
        assert f'name="protocol" value="{value}"' in html
    assert 'name="profile_id"' not in html  # profiles are shared, not chosen


def test_guide_questions_share_one_q_grid_section(configured_user):
    """Desktop density: every guide question is a grid item of the single "Issuance" section."""
    form = guide(configured_user)
    sections = [n for n in form.nodes if n.tag == "section" and "form-section" in n.attrs.get("class", "")]
    titles = [next(c for c in s.walk() if c.tag == "h3").text for s in sections]
    assert titles == ["Issuance", "Certificate"]  # no separate "Keys" or "Run" sections
    issuance = sections[0]
    (grid,) = [n for n in issuance.children if n.tag == "div"]
    assert grid.attrs["class"].split() == ["fields", "q-grid"]
    questions = ("key_location", "mode", "count", "protocol", "auth_method", "variant", "approval")
    owner = {}
    for node in grid.walk():
        if node.tag == "input" and node.attrs.get("name") in questions:
            item = next(a for a in [node, *node.ancestors()] if a.parent is grid)  # the direct grid item
            owner.setdefault(node.attrs["name"], set()).add(id(item))
    assert set(owner) == set(questions)
    assert all(len(items) == 1 for items in owner.values())  # one grid item per question
    slots = {name: next(iter(items)) for name, items in owner.items()}
    assert slots["mode"] == slots["count"]  # the count sits inline next to the devices choice
    assert len(set(slots.values())) == 6  # six fixed slots, side by side, not nested
    items = [n for n in grid.children if n.tag in ("div", "label")]
    assert [next(c for c in n.attrs["class"].split() if c[:1] == "r") for n in items] == [
        "r1c1", "r1c2", "r1c3", "r2c1", "r2c2", "r2c3"]
    certificate = [n for n in sections[1].children if n.tag == "div"][0]
    assert "q-grid" in certificate.attrs["class"].split()
    names = {n.attrs.get("name") for n in certificate.walk() if n.tag in ("input", "select")}
    assert names == {"ca_id", "run_id"}  # the approval switch moved up into the Issuance grid


def test_initial_state(configured_user):
    form = guide(configured_user)
    assert form.options("key_location") == ["server", "factory"] and form.options("mode") == ["single", "batch"]
    assert form.visible("count") and form.visible("variant") and form.visible("approval")
    assert not form.visible("protocol") and not form.visible("auth_method")
    assert form.submission() | {"run_id": "x"} == {
        "use_case": "evergreen", "connection_id": form.submission()["connection_id"], "key_location": "server",
        "mode": "batch", "count": "2", "variant": "api", "ca_id": ECDSA_CA_ID, "run_id": "x"}  # batch preselected


def test_questions_follow_the_answers(configured_user):
    form = guide(configured_user)
    form.choose("mode", "single")
    assert not form.visible("count") and not form.visible("approval") and not form.visible("protocol")
    assert form.visible("variant")  # server-side single: API or web UI
    form.choose("key_location", "factory")
    assert form.options("protocol") == ["rest", "est", "cmpv2", "scep"]
    assert form.options("auth_method") == ["apikey", "passcode", "certificate"]
    form.choose("auth_method", "apikey")
    assert form.visible("variant")  # REST + API key = the factory calls the management API (UC-2)
    form.choose("auth_method", "passcode")
    assert not form.visible("variant")  # enrollment runs via API only
    form.choose("protocol", "est")
    assert form.options("auth_method") == ["passcode", "certificate"]
    form.choose("protocol", "scep")
    assert form.options("auth_method") == ["passcode"]
    # switching from REST + API key to EST falls back to the first offered method
    form.choose("protocol", "rest")
    form.choose("auth_method", "apikey")
    form.choose("protocol", "est")
    assert form.submission()["auth_method"] == "passcode"
    # back to batch: the single-device questions are not submitted at all
    form.choose("mode", "batch")
    assert not {"protocol", "auth_method"} & set(form.submission()) and form.submission()["count"] == "2"


def test_factory_single_keeps_the_default_api_key(configured_user):
    """The template preselects "API key"; revealing the protocol question must not switch it."""
    form = guide(configured_user)
    form.choose("mode", "single")
    form.choose("key_location", "factory")
    assert form.submission()["auth_method"] == "apikey" and form.visible("variant")


@pytest.mark.parametrize("protocol", ["est", "scep"])
def test_enrollment_path_submits_only_the_applicable_answers(configured_user, protocol):
    form = guide(configured_user)
    form.choose("mode", "single")
    form.choose("key_location", "factory")
    form.choose("protocol", protocol)  # API key does not apply: falls back to passcode
    data = form.submission()
    assert data["auth_method"] == "passcode"
    assert set(data) == {"use_case", "connection_id", "key_location", "mode", "protocol", "auth_method", "ca_id",
                         "run_id"}  # no variant, count or approval


def test_profile_hint_follows_the_protocol(configured_user):
    form = guide(configured_user)
    assert form.visible_text(EVERGREEN) and not form.visible_text(CMP)
    form.choose("mode", "single")
    form.choose("key_location", "factory")
    for protocol, shown, hidden in (("cmpv2", CMP, EVERGREEN), ("est", EVERGREEN, CMP), ("rest", EVERGREEN, CMP)):
        form.choose("protocol", protocol)
        assert form.visible_text(shown) and not form.visible_text(hidden), protocol
    form.choose("protocol", "scep")
    assert not form.visible_text(CMP)


PATHS = [
    # answers in click order → expected (use case, mode, count, variant, protocol, auth)
    ({"count": "3"}, ("uc01", "batch", 3, "api", None, None)),
    ({"variant": "webui"}, ("uc01", "batch", 2, "webui", None, None)),
    ({"mode": "single"}, ("uc01", "single", 1, "api", None, None)),
    ({"mode": "single", "variant": "webui"}, ("uc01", "single", 1, "webui", None, None)),
    ({"key_location": "factory", "count": "2"}, ("uc02", "batch", 2, "api", None, None)),
    ({"key_location": "factory", "mode": "single", "auth_method": "apikey"},
     ("uc02", "single", 1, "api", None, None)),  # REST + API key: the factory calls the management API
    ({"key_location": "factory", "mode": "single", "auth_method": "apikey", "variant": "webui"},
     ("uc02", "single", 1, "webui", None, None)),
    ({"key_location": "factory", "mode": "single", "auth_method": "passcode"},
     ("uc03", "single", 1, "api", "rest", "passcode")),
    ({"key_location": "factory", "mode": "single", "auth_method": "certificate"},
     ("uc03", "single", 1, "api", "rest", "certificate")),
    ({"key_location": "factory", "mode": "single", "protocol": "est"}, ("uc03", "single", 1, "api", "est", "passcode")),
    ({"key_location": "factory", "mode": "single", "protocol": "est", "auth_method": "certificate"},
     ("uc03", "single", 1, "api", "est", "certificate")),
    ({"key_location": "factory", "mode": "single", "protocol": "cmpv2"},
     ("uc03", "single", 1, "api", "cmpv2", "passcode")),
    ({"key_location": "factory", "mode": "single", "protocol": "cmpv2", "auth_method": "certificate"},
     ("uc03", "single", 1, "api", "cmpv2", "certificate")),
    ({"key_location": "factory", "mode": "single", "protocol": "scep", "ca_id": RSA_CA_ID},
     ("uc03", "single", 1, "api", "scep", "passcode")),
]


@pytest.mark.parametrize("answers,expected", PATHS)
def test_every_path_submits_what_the_server_resolves(configured_user, store, enroll_net, cmp_openssl,
                                                     scep_client, answers, expected):
    form = guide(configured_user)
    for name, value in answers.items():
        if name in ("count", "ca_id"):
            if name == "ca_id":
                select = next(n for n in form.inputs() if n.attrs.get("name") == "ca_id")
                for option in (o for o in select.walk() if o.tag == "option"):
                    option.attrs.pop("selected", None)
                    if option.attrs.get("value") == value:
                        option.attrs["selected"] = ""
            else:
                form.set(name, value)
        else:
            form.choose(name, value)
    data = form.submission() | {"run_id": "g1"}
    response = configured_user.post("/runs", data=data, follow_redirects=False)
    assert response.status_code == 303, response.text
    run = finished(store, "g1")
    use_case, mode, count, variant, protocol, auth = expected
    p = run["params"]
    assert (run["use_case"], p["mode"], p["count"], p["variant"], p.get("protocol"), p.get("auth")) == (
        use_case, mode, count, variant, protocol, auth)
    if variant == "api":
        assert run["status"] == "completed", run["error"]
    else:
        assert run["status"] == "waiting"


# --- server-side checks ------------------------------------------------------------------------

def guide_post(**fields) -> dict:
    return {"run_id": "g2", "use_case": "evergreen", "ca_id": ECDSA_CA_ID} | fields


@pytest.mark.parametrize("fields,message", [
    ({"mode": "batch"}, "Answer where the key is generated and how many devices."),
    ({"key_location": "cloud", "mode": "batch"}, "Answer where the key is generated and how many devices."),
    ({"key_location": "server"}, "Invalid or missing form values."),  # mode is a required field
    ({"key_location": "server", "mode": "bulk"}, "Answer where the key is generated and how many devices."),
    ({"key_location": "factory", "mode": "single", "protocol": "est", "auth_method": "apikey"},
     "An API key works only with the REST API."),
    ({"key_location": "factory", "mode": "single", "protocol": "cmpv2", "auth_method": "apikey"},
     "An API key works only with the REST API."),
    ({"key_location": "factory", "mode": "single", "protocol": "scep", "auth_method": "certificate",
      "ca_id": RSA_CA_ID}, "SCEP authenticates with a passcode (challenge password)."),
    ({"key_location": "factory", "mode": "single", "protocol": "scep", "auth_method": "passcode"},
     "SCEP needs an RSA issuing CA"),
    ({"key_location": "factory", "mode": "single", "protocol": "", "auth_method": "passcode"},
     "Select an enrollment protocol and an authentication method."),
    ({"key_location": "factory", "mode": "single", "protocol": "acme", "auth_method": "passcode"},
     "Select an enrollment protocol and an authentication method."),
    ({"key_location": "factory", "mode": "single", "protocol": "rest", "auth_method": "basic"},
     "Select an enrollment protocol and an authentication method."),
    ({"key_location": "server", "mode": "batch", "count": "0"}, "Number of certificates"),
    ({"key_location": "server", "mode": "batch", "variant": "cli"}, "Invalid variant or mode."),
])
def test_invalid_guide_answers_are_400_without_dtm_write(configured_user, store, fake, fields, message):
    response = configured_user.post("/runs", data=guide_post(**fields), follow_redirects=False)
    assert response.status_code == 400 and message in response.text
    assert store.list_runs() == [] and dtm_writes(fake) == []


@pytest.mark.parametrize("data", [
    {"use_case": "uc01", "mode": "single", "variant": "api", "count": "7"},
    {"use_case": "uc02", "mode": "single", "variant": "api", "count": "500"},
    {"use_case": "uc03", "mode": "batch", "protocol": "est", "auth_method": "passcode", "count": "5"},
    {"use_case": "evergreen", "key_location": "server", "mode": "single", "count": "9"},
    {"use_case": "evergreen", "key_location": "factory", "mode": "single", "protocol": "rest",
     "auth_method": "passcode", "count": "4"},
])
def test_single_is_always_one_certificate(configured_user, store, enroll_net, data):
    response = configured_user.post("/runs", data={"run_id": "c1", "ca_id": ECDSA_CA_ID} | data,
                                    follow_redirects=False)
    assert response.status_code == 303
    run = finished(store, "c1")
    assert run["status"] == "completed", run["error"]
    assert run["params"]["count"] == 1 and run["result"]["certificate_total"] == 1


def test_batch_keeps_its_count(configured_user, store):
    configured_user.post("/runs", data=guide_post(run_id="c2", key_location="server", mode="batch", count="4",
                                                  variant="api"))
    run = finished(store, "c2")
    assert run["params"]["count"] == 4 and run["result"]["certificate_total"] == 4


# --- profile hints on the form -----------------------------------------------------------------

def hint(html: str, name: str) -> str:
    """The read-only profile field: the name as value, below it "<validity>[ – <note>]"."""
    match = re.search(r'<span class="field-label">Certificate profile</span>\s*<div class="readonly-value mono" '
                      r'tabindex="0" data-tip="Shared per account – kept by DTM">' + re.escape(name) + r'</div>\s*'
                      r'<small class="field-help">([^<]*)</small>', html)
    assert match, name
    return match.group(1)


def test_profile_hints(configured_user, fake):
    from tests.integration.test_shared_profiles import shared
    shared(fake, dtm.PROFILE_EVERGREEN)
    shared(fake, dtm.PROFILE_EVERGREEN_CMP, status="DISABLED")
    html = configured_user.get("/runs/new/evergreen").text
    assert hint(html, EVERGREEN) == "5 years"
    assert hint(html, CMP) == "5 years · bare key · enabled again"
    uc04 = configured_user.get("/runs/new/uc04").text
    assert hint(uc04, RENEWAL) == "6 months · renew any time · new"
    assert EVERGREEN not in uc04
    assert dtm_writes(fake) == []  # the form only reads the status


def test_hints_ignore_a_foreign_account(configured_user, fake):
    from tests.fakedtm import OTHER_ACCOUNT_ID
    from tests.integration.test_shared_profiles import shared
    shared(fake, dtm.PROFILE_EVERGREEN, account_id=OTHER_ACCOUNT_ID)
    assert hint(configured_user.get("/runs/new/evergreen").text, EVERGREEN) == "5 years · new"  # theirs does not count


def test_form_with_dtm_error_is_502(configured_user, fake):
    fake.fail["profiles"] = httpx.Response(500, text="down")
    assert configured_user.get("/runs/new/evergreen").status_code == 502


def test_create_run_does_not_list_profiles(configured_user, store, fake):
    fake.fail["profiles"] = httpx.ConnectError("would only matter later, in the run")
    response = configured_user.post("/runs", data=guide_post(key_location="server", mode="batch", variant="api"),
                                    follow_redirects=False)
    assert response.status_code == 303 and "profiles" not in fake.route_order()[:2]


# --- Settings: shared profiles per connection --------------------------------------------------

def profiles_partial(user, conn_id):
    return user.get(f"/settings/connections/{conn_id}/profiles")


def pills(html: str) -> dict:
    return dict(re.findall(r'<li><span class="mono">([^<]+)</span> <span class="pill[^"]*">([^<]+)</span></li>', html))


def test_settings_loads_profiles_on_demand(configured_user, store, fake):
    conn = store.connections()[0]["id"]
    page = configured_user.get("/settings").text
    assert f'hx-get="/settings/connections/{conn}/profiles" hx-trigger="toggle once"' in page
    assert "profiles" not in fake.route_order()  # nothing loaded until opened
    html = profiles_partial(configured_user, conn).text
    assert pills(html) == MISSING and len(MISSING) == len(dtm.SHARED_PROFILES) >= 3
    assert "Retire shared profiles" not in html  # nothing to retire


def test_settings_status_and_retire(configured_user, store, fake):
    from tests.integration.test_shared_profiles import shared
    active, retired = shared(fake, dtm.PROFILE_EVERGREEN), shared(fake, dtm.PROFILE_RENEWAL, unit="months", value=6,
                                                                   status="DISABLED")
    conn = store.connections()[0]["id"]
    html = profiles_partial(configured_user, conn).text
    assert pills(html) == MISSING | {EVERGREEN: "active", RENEWAL: "retired"}
    assert f'hx-post="/settings/connections/{conn}/profiles/retire"' in html and "hx-confirm=" in html
    response = configured_user.post(f"/settings/connections/{conn}/profiles/retire")
    assert response.status_code == 200
    assert pills(response.text) == MISSING | {EVERGREEN: "retired", RENEWAL: "retired"}
    assert active["status"] == retired["status"] == "DISABLED"
    assert "Retire shared profiles" not in response.text


def test_retire_refused_while_runs_are_not_rolled_back(configured_user, store, fake):
    from tests.integration.test_shared_profiles import shared
    profile = shared(fake, dtm.PROFILE_EVERGREEN)
    configured_user.post("/runs", data=guide_post(key_location="server", mode="single", variant="api"))
    finished(store, "g2")
    conn = store.connections()[0]["id"]
    assert configured_user.post(f"/settings/connections/{conn}/profiles/retire").status_code == 409
    assert profile["status"] == "ACTIVE"
    configured_user.post("/runs/g2/cleanup", data={"mode": "full"})
    assert cleaned(store, "g2")["cleanup_status"] == "done"
    assert configured_user.post(f"/settings/connections/{conn}/profiles/retire").status_code == 200
    assert profile["status"] == "DISABLED"


def test_retire_button_hidden_while_the_connection_has_open_runs(configured_user, store, fake):
    from tests.integration.test_shared_profiles import shared
    shared(fake, dtm.PROFILE_EVERGREEN)
    conn = store.connections()[0]["id"]
    configured_user.post("/runs", data=guide_post(key_location="server", mode="single", variant="api"))
    finished(store, "g2")
    html = profiles_partial(configured_user, conn).text
    assert pills(html)[EVERGREEN] == "active" and "Retire shared profiles" not in html
    configured_user.post("/runs/g2/cleanup", data={"mode": "full"})
    cleaned(store, "g2")
    assert "Retire shared profiles" in profiles_partial(configured_user, conn).text


def test_retire_checks_every_connection_to_the_same_account(configured_user, store, fake):
    """Shared profiles belong to the account: open runs on another connection to it block retiring."""
    from tests.fakedtm import ACCOUNT_ID, API_KEY, HOST
    from tests.integration.test_shared_profiles import shared
    profile = shared(fake, dtm.PROFILE_EVERGREEN)
    first = store.connections()[0]["id"]
    second = store.save_connection(None, "Same account", HOST, ACCOUNT_ID, API_KEY)
    configured_user.post("/runs", data=guide_post(key_location="server", mode="single", variant="api",
                                                  connection_id=str(first)))
    finished(store, "g2")
    html = profiles_partial(configured_user, second).text
    assert pills(html)[EVERGREEN] == "active" and "Retire shared profiles" not in html
    assert configured_user.post(f"/settings/connections/{second}/profiles/retire").status_code == 409
    assert profile["status"] == "ACTIVE"
    configured_user.post("/runs/g2/cleanup", data={"mode": "full"})
    cleaned(store, "g2")
    assert "Retire shared profiles" in profiles_partial(configured_user, second).text


def test_legacy_cmp_profile_is_listed_only_while_active(configured_user, store, fake):
    from tests.fakedtm import _profile
    legacy = _profile("legacy-cmp", "robot-uc03-cmp-profile", "tpl-client", None)
    fake.profiles.append(legacy)
    conn = store.connections()[0]["id"]
    html = profiles_partial(configured_user, conn).text
    assert pills(html) == MISSING | {"robot-uc03-cmp-profile": "active"}
    assert "Retire shared profiles" in html  # an active legacy profile alone offers retiring
    response = configured_user.post(f"/settings/connections/{conn}/profiles/retire")
    assert legacy["status"] == "DISABLED"
    assert "robot-uc03-cmp-profile" not in pills(response.text)
    assert "robot-uc03-cmp-profile" not in profiles_partial(configured_user, conn).text


def test_failed_retire_says_so(configured_user, store, fake):
    from tests.integration.test_shared_profiles import shared
    profile = shared(fake, dtm.PROFILE_EVERGREEN)
    fake.fail["profile_disable"] = httpx.Response(500, text="upstream trouble")
    conn = store.connections()[0]["id"]
    response = configured_user.post(f"/settings/connections/{conn}/profiles/retire")
    assert response.status_code == 200
    assert re.search(r'<span class="meta error" data-tip="Retiring failed: [^"]*500[^"]*">Retiring failed</span>',
                     response.text)
    assert "Could not be loaded from DTM" not in response.text and profile["status"] == "ACTIVE"


def test_settings_profiles_dtm_error_is_shown_inline(configured_user, store, fake):
    fake.fail["profiles"] = httpx.Response(500, text="<b>boom</b>")
    conn = store.connections()[0]["id"]
    response = profiles_partial(configured_user, conn)
    assert response.status_code == 200
    assert "Could not be loaded from DTM" in response.text and "<b>boom</b>" not in response.text
    assert ">Retiring failed<" not in response.text
    assert re.search(r'class="meta error" data-tip="[^"]*500[^"]*"', response.text)


def test_settings_profiles_guards(web, configured_store, auth, fake, data_dir):
    conn = configured_store.connections()[0]["id"]
    for method, path in (("get", f"/settings/connections/{conn}/profiles"),
                         ("post", f"/settings/connections/{conn}/profiles/retire")):
        response = getattr(web, method)(path, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/login"
    web.post("/login", data={"password": PASSWORD})
    assert web.get("/settings/connections/999/profiles").status_code == 404
    assert web.post("/settings/connections/999/profiles/retire").status_code == 404
    cross = web.post(f"/settings/connections/{conn}/profiles/retire", headers={"Origin": "https://evil.example"})
    assert cross.status_code == 403 and "profile_disable" not in fake.route_order()



# --- labels are terms, never questions (author's style rule) ---------------------------------------

@pytest.mark.parametrize("path", ["/runs/new/evergreen", "/runs/new/uc04", "/runs/new/uc05"])
def test_run_form_labels_are_terms(configured_user, path):
    html = configured_user.get(path).text
    form = html[html.index('<form method="post" action="/runs"'):html.index("</form>", html.index('action="/runs"'))]
    labels = re.findall(r'<span class="seg-label"[^>]*>([^<]*)</span>', form)
    labels += re.findall(r'<span class="field-label">([^<]*)</span>', form)
    labels += [re.sub(r"<[^>]+>", "", m).strip() for m in re.findall(r"<label[^>]*>(.*?)</label>", form, re.S)]
    labels += re.findall(r"<legend[^>]*>([^<]*)</legend>", form) + re.findall(r'aria-label="([^"]*)"', form)
    labels += re.findall(r"<h3>([^<]*)</h3>", form)
    assert labels and not [label for label in labels if "?" in label], labels


def test_guide_labels_and_options(configured_user):
    html = configured_user.get("/runs/new/evergreen").text
    seg = dict(re.findall(r'<span class="seg-label" id="l-([a-z_]+)">([^<]*)</span>', html))
    assert seg == {"key_location": "Key generation", "mode": "Devices", "variant": "Run via", "protocol": "Protocol",
                   "auth_method": "Authentication"}
    form = guide(configured_user)

    def texts(name):
        return [re.sub(r"\s+", " ", n.parent.text).strip() for n in form.inputs()
                if n.attrs.get("name") == name and n.attrs.get("type") == "radio"]
    assert texts("key_location") == ["DTM (server-side)", "Factory"]
    assert texts("mode") == ["Single", "Batch"] and texts("variant") == ["API (measured)", "DTM web UI"]
