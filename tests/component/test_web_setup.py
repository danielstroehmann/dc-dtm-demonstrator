"""First-visit password setup: no password configured, whoever opens the app first sets it (author's decision)."""

import logging

import jwt
import pytest

from app.auth import COOKIE, MAX_PASSWORD, PASSWORD_KEY, Auth
from app.main import CSP
from tests.conftest import SECRET, make_web

NEW = "first visitor's password 7"


@pytest.fixture
def fresh_auth(store):
    return Auth(None, SECRET, store=store)


@pytest.fixture
def fresh(store, fresh_auth, fake, data_dir):
    """Anonymous browser on an app without a login password."""
    with make_web(store, fresh_auth, fake, data_dir) as client:
        yield client


def setup(client, password=NEW, repeat=None, **kwargs):
    return client.post("/setup", data={"password": password, "repeat": password if repeat is None else repeat},
                       follow_redirects=False, **kwargs)


def is_setup_form(text: str) -> bool:
    return 'action="/setup"' in text and 'name="repeat"' in text and 'action="/login"' not in text


def protected_get_paths(app) -> list[str]:
    paths = {r.path for r in app.routes if "GET" in (getattr(r, "methods", None) or set())}
    return sorted(p.replace("{run_id}", "r1").replace("{use_case}", "uc01").replace("{connection_id}", "1")
                  for p in paths if p not in ("/login", "/healthz") and not p.startswith("/static"))


# --- fresh app ------------------------------------------------------------------------------------------


def test_every_page_redirects_to_login_which_shows_the_setup_form(fresh):
    paths = protected_get_paths(fresh.app)
    assert "/" in paths and len(paths) > 3
    for path in paths:
        response = fresh.get(path, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/login", path
    page = fresh.get("/login")
    assert page.status_code == 200 and is_setup_form(page.text)
    assert page.headers["content-security-policy"] == CSP


def test_setup_form_attributes(fresh):
    text = fresh.get("/login").text
    assert text.count('autocomplete="new-password"') == 2
    assert text.count('minlength="12"') == 2 and text.count(f'maxlength="{MAX_PASSWORD}"') == 2


def test_login_post_without_password_redirects_to_setup(fresh, fresh_auth):
    response = fresh.post("/login", data={"password": "anything at all"}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert COOKIE not in response.headers.get("set-cookie", "") and not fresh_auth.has_password()


def test_setup_happy_path_logs_in(fresh, fresh_auth, store, caplog):
    with caplog.at_level(logging.WARNING, logger="demonstrator"):
        response = setup(fresh)
    assert response.status_code == 303 and response.headers["location"] == "/"
    cookie = response.headers["set-cookie"]
    flags = {part.strip().lower() for part in cookie.split(";")}
    assert "httponly" in flags and "secure" in flags and "samesite=lax" in flags
    token = cookie.split(";")[0].split("=", 1)[1]
    assert jwt.decode(token, SECRET, algorithms=["HS256"])["sub"] == "admin"
    assert fresh.get("/", follow_redirects=False).status_code == 200
    assert store.get_setting(PASSWORD_KEY).startswith("$argon2id$") and fresh_auth.check_password(NEW)
    assert "login password set from" in caplog.text and NEW not in caplog.text
    # From now on /login is the normal login form
    fresh.cookies.clear()
    page = fresh.get("/login").text
    assert 'action="/login"' in page and 'action="/setup"' not in page


@pytest.mark.parametrize("password,repeat,message", [
    ("x" * 11, "x" * 11, "At least 12 characters."),
    ("x" * (MAX_PASSWORD + 1), "x" * (MAX_PASSWORD + 1), f"At most {MAX_PASSWORD} characters."),
    ("long enough password 1", "long enough password 2", "The passwords do not match."),
], ids=["too-short", "too-long", "mismatch"])
def test_invalid_setup_rerenders_the_form(fresh, fresh_auth, password, repeat, message):
    response = setup(fresh, password, repeat)
    assert response.status_code == 400 and message in response.text and is_setup_form(response.text)
    assert COOKIE not in response.headers.get("set-cookie", "") and not fresh_auth.has_password()
    if password:
        assert password not in response.text  # the typed password is never echoed back


@pytest.mark.parametrize("length", [12, MAX_PASSWORD])
def test_boundary_lengths_are_accepted(fresh, fresh_auth, length):
    assert setup(fresh, "p" * length).status_code == 303 and fresh_auth.check_password("p" * length)


@pytest.mark.parametrize("data", [{"password": NEW}, {"password": "", "repeat": ""}, {}], ids=["no-repeat", "empty", "none"])
def test_missing_fields_are_a_handled_400(fresh, fresh_auth, data):
    """FastAPI's form validation answers before the handler (generic error page; the browser's `required` prevents it)."""
    response = fresh.post("/setup", data=data, follow_redirects=False)
    assert response.status_code == 400 and "Invalid or missing form values." in response.text
    assert not fresh_auth.has_password() and COOKIE not in response.headers.get("set-cookie", "")


def test_markup_in_password_is_not_reflected(fresh, fresh_auth):
    payload = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'
    response = setup(fresh, payload, payload + "x")
    assert response.status_code == 400 and "<script>alert(1)" not in response.text and "onerror=" not in response.text
    assert setup(fresh, payload).status_code == 303 and fresh_auth.check_password(payload)  # allowed as a password


def test_second_setup_cannot_change_the_password(fresh, fresh_auth, store):
    assert setup(fresh).status_code == 303
    stored = store.get_setting(PASSWORD_KEY)
    fresh.cookies.clear()
    response = setup(fresh, "attacker password 123")
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert COOKIE not in response.headers.get("set-cookie", "")
    assert store.get_setting(PASSWORD_KEY) == stored
    assert fresh.get("/", follow_redirects=False).status_code == 303  # not logged in by the attempt


def test_second_setup_while_logged_in_changes_nothing(fresh, store):
    assert setup(fresh).status_code == 303
    stored = store.get_setting(PASSWORD_KEY)
    assert setup(fresh, "attacker password 123").headers["location"] == "/login"
    assert store.get_setting(PASSWORD_KEY) == stored


def test_setup_lost_race_redirects_without_session(fresh, store, fake, data_dir):
    """Another request (here: another app instance on the same database) set the password in between."""
    other = Auth(None, SECRET, store=store)
    with make_web(store, other, fake, data_dir) as racer:
        racer_page = racer.get("/login")
        assert is_setup_form(racer_page.text)
        assert setup(fresh).status_code == 303
    assert not other.check_password("racer password 1234")


def test_login_with_the_new_password(fresh):
    assert setup(fresh).status_code == 303
    fresh.cookies.clear()
    wrong = fresh.post("/login", data={"password": NEW + "!"}, follow_redirects=False)
    assert wrong.status_code == 401 and "Wrong password." in wrong.text
    assert COOKIE not in wrong.headers.get("set-cookie", "")
    ok = fresh.post("/login", data={"password": NEW}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/"
    assert fresh.get("/", follow_redirects=False).status_code == 200


def test_setup_rate_limit_keeps_the_setup_form(fresh, fresh_auth):
    for _ in range(5):
        assert setup(fresh, "short").status_code == 400
    blocked = setup(fresh)
    assert blocked.status_code == 429 and "Too many attempts" in blocked.text and is_setup_form(blocked.text)
    assert not fresh_auth.has_password() and COOKIE not in blocked.headers.get("set-cookie", "")
    assert blocked.headers["content-security-policy"] == CSP


def test_login_429_shows_the_login_form_once_a_password_exists(web):
    for _ in range(5):
        web.post("/login", data={"password": "wrong"})
    blocked = web.post("/login", data={"password": "wrong"})
    assert blocked.status_code == 429 and 'action="/login"' in blocked.text and 'action="/setup"' not in blocked.text


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "https://testserver:8443"])
def test_cross_origin_setup_is_refused(fresh, fresh_auth, origin):
    response = setup(fresh, headers={"Origin": origin})
    assert response.status_code == 403 and "Cross-origin request refused" in response.text
    assert not fresh_auth.has_password() and COOKIE not in response.headers.get("set-cookie", "")


def test_cross_site_fetch_metadata_setup_is_refused(fresh, fresh_auth):
    response = setup(fresh, headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403 and not fresh_auth.has_password()


def test_same_origin_setup_is_accepted(fresh, fresh_auth):
    assert setup(fresh, headers={"Origin": "https://testserver"}).status_code == 303 and fresh_auth.has_password()


def test_htmx_request_on_fresh_app_gets_401_redirect(fresh):
    response = fresh.get("/", headers={"HX-Request": "true"}, follow_redirects=False)
    assert response.status_code == 401 and response.headers["hx-redirect"] == "/login"
