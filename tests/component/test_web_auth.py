"""Login, session cookie, access control and security headers through the real ASGI app."""

import re
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.auth import COOKIE
from app.main import CSP
from tests.conftest import PASSWORD, SECRET


def set_session(client, token):
    client.cookies.set(COOKIE, token)


# --- login ---------------------------------------------------------------------------------

def test_login_page_is_public(web):
    response = web.get("/login")
    assert response.status_code == 200
    assert 'type="password"' in response.text and "Log out" not in response.text


def test_wrong_password(web):
    response = web.post("/login", data={"password": "nope"}, follow_redirects=False)
    assert response.status_code == 401
    assert "Wrong password." in response.text
    assert COOKIE not in response.headers.get("set-cookie", "")
    assert web.get("/", follow_redirects=False).status_code == 303


def test_empty_password_is_a_handled_400(web):
    response = web.post("/login", data={}, follow_redirects=False)
    assert response.status_code == 400 and "Invalid or missing form values." in response.text


def test_right_password_sets_hardened_cookie(web):
    response = web.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/"
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    flags = {part.strip().lower() for part in cookie.split(";")}
    assert "httponly" in flags and "secure" in flags and "samesite=lax" in flags
    assert "path=/" in flags
    token = cookie.split(";")[0].split("=", 1)[1]
    assert jwt.decode(token, SECRET, algorithms=["HS256"])["sub"] == "admin"
    page = web.get("/")
    assert page.status_code == 200 and "<h1>Welcome</h1>" in page.text  # logged in, no connection yet


def test_logout_ends_session(user):
    response = user.post("/logout", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert re.search(rf"{COOKIE}=(\"\"|);", response.headers["set-cookie"])
    assert user.get("/", follow_redirects=False).status_code == 303


def test_login_rate_limit(web):
    for _ in range(5):
        assert web.post("/login", data={"password": "wrong"}).status_code == 401
    blocked = web.post("/login", data={"password": PASSWORD}, follow_redirects=False)
    assert blocked.status_code == 429
    assert "Too many attempts" in blocked.text
    assert COOKIE not in blocked.headers.get("set-cookie", "")
    assert blocked.headers["content-security-policy"] == CSP


def test_successful_logins_count_towards_the_limit(web):
    for _ in range(5):
        assert web.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    assert web.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 429


def test_rate_limit_is_per_app_instance(store, auth, fake, data_dir):
    from tests.conftest import make_web
    with make_web(store, auth, fake, data_dir) as first:
        for _ in range(6):
            first.post("/login", data={"password": "wrong"})
    with make_web(store, auth, fake, data_dir) as second:
        assert second.post("/login", data={"password": "wrong"}).status_code == 401


# --- access control ------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("GET", "/"), ("GET", "/settings"), ("POST", "/settings/connections"),
    ("POST", "/settings/connections/1/default"), ("POST", "/settings/connections/1/delete"), ("GET", "/runs/new"), ("POST", "/runs"),
    ("GET", "/runs/abc"), ("GET", "/runs/abc/live"), ("GET", "/runs/abc/artifact"),
    ("POST", "/runs/abc/cleanup"), ("POST", "/logout"), ("GET", "/does-not-exist"),
])
def test_anonymous_requests_redirect_to_login(web, method, path):
    response = web.request(method, path, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_htmx_requests_get_401_with_hx_redirect(web):
    response = web.get("/runs/abc/live", headers={"HX-Request": "true"}, follow_redirects=False)
    assert response.status_code == 401
    assert response.headers["hx-redirect"] == "/login"
    assert response.text == ""


def test_anonymous_post_settings_changes_nothing(web, store):
    response = web.post("/settings/connections", follow_redirects=False,
                        data={"name": "x", "host": "evil.example", "account_id": "x", "api_key": "k"})
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert store.connections() == []


@pytest.mark.parametrize("token_factory", [
    lambda: "not-a-jwt",
    lambda: jwt.encode({"sub": "admin", "exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
                       SECRET, algorithm="HS256"),
    lambda: jwt.encode({"sub": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                       "z" * 48, algorithm="HS256"),
    lambda: jwt.encode({"sub": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                       None, algorithm="none"),
], ids=["garbage", "expired", "foreign-secret", "alg-none"])
def test_invalid_session_cookies_are_rejected(web, token_factory):
    set_session(web, token_factory())
    assert web.get("/", follow_redirects=False).status_code == 303


def test_valid_foreign_issued_token_with_right_secret_is_accepted(web):
    # proves the cookie check above is not simply rejecting every injected cookie
    set_session(web, jwt.encode({"sub": "admin", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
                                SECRET, algorithm="HS256"))
    assert web.get("/", follow_redirects=False).status_code == 200


def test_public_endpoints(web):
    health = web.get("/healthz")
    assert health.status_code == 200 and health.json()["status"] == "ok"
    static = web.get("/static/app.css")
    assert static.status_code == 200
    assert static.headers.get("cache-control") != "no-store"


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_docs_are_disabled(user, path):
    assert user.get(path).status_code == 404


def test_unknown_route_renders_error_page(user):
    response = user.get("/nope")
    assert response.status_code == 404 and "<h2>Not found</h2>" in response.text
    assert "Something went wrong" not in response.text and 'role="alert"' not in response.text  # no red alert


def test_other_errors_keep_the_alert(user, store):
    response = user.post("/runs", data={"mode": "single", "ca_id": "x"})  # no connection yet
    assert response.status_code == 409
    assert "<h2>Something went wrong</h2>" in response.text and '<p class="error" role="alert">' in response.text


# --- headers & CSP -------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/login", "/", "/settings", "/nope"])
def test_security_headers(user, path):
    headers = user.get(path).headers
    assert headers["content-security-policy"] == CSP
    assert headers["x-content-type-options"] == "nosniff"
    # same-origin: browsers keep sending the real Origin on own form POSTs (no-referrer would make it "null")
    assert headers["referrer-policy"] == "same-origin"
    assert headers["cache-control"] == "no-store"


def test_csp_forbids_inline_code_and_framing():
    directives = dict(d.strip().split(" ", 1) for d in CSP.split(";"))
    assert directives["script-src"] == "'self'" and directives["style-src"] == "'self'"
    assert directives["frame-ancestors"] == "'none'" and directives["form-action"] == "'self'"
    assert "unsafe" not in CSP


@pytest.mark.parametrize("path", ["/login", "/", "/settings"])
def test_pages_contain_no_inline_script_or_style(user, configured_store, path):
    html = user.get(path).text
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline script would be blocked by the CSP"
    assert not re.search(r"\sstyle=", html) and "<style" not in html
    assert not re.search(r"\son[a-z]+=", html), "inline event handler would be blocked by the CSP"


def test_all_static_assets_referenced_by_pages_are_public(web):
    """Fonts, stylesheets and scripts load before login (login page) – none may require a session."""
    html = web.get("/login").text
    css = web.get("/static/app.css").text
    paths = set(re.findall(r'(?:href|src)="(/static/[^"]+)"', html)) | set(re.findall(r'url\("(/static/[^"]+)"\)', css))
    assert any(p.endswith(".woff2") for p in paths), paths
    for path in sorted(paths):
        response = web.get(path, follow_redirects=False)
        assert response.status_code == 200, path
        assert response.content, path
        if path.endswith(".woff2"):
            assert response.content[:4] == b"wOF2", path
            assert response.headers["content-type"] == "font/woff2"


def test_fonts_are_same_origin_so_csp_allows_them(web):
    html = web.get("/login").text
    assert 'rel="preload" href="/static/fonts/' in html
    assert "fonts.googleapis" not in html and "fonts.gstatic" not in html
    css = web.get("/static/app.css").text
    assert not re.search(r'url\("?https?:', css)  # font-src falls back to default-src 'self'


@pytest.mark.parametrize("weight", [400, 500, 700])
def test_roboto_fonts_served_without_login(web, weight):
    response = web.get(f"/static/fonts/roboto-latin-{weight}-normal.woff2", follow_redirects=False)
    assert response.status_code == 200
    assert response.headers["content-type"] == "font/woff2"
    assert response.content[:4] == b"wOF2"


def test_client_script_uses_text_content_only(web):
    """app.js puts the confirm question and copied text into the DOM – never as HTML."""
    js = web.get("/static/app.js").text
    assert "textContent" in js and "innerHTML" not in js and "insertAdjacentHTML" not in js
    assert "outerHTML" not in js and "document.write" not in js
    assert "eval(" not in js and "new Function" not in js
    # tooltip: built from data-tip / truncated text via textContent, announced as role=tooltip
    assert "el.dataset.tip" in js and 'setAttribute("role", "tooltip")' in js
    assert "scrollWidth > el.clientWidth" in js  # truncated text only


# --- cross-origin POST guard (defence in depth next to SameSite=Lax) ----------------------------

POST_ROUTES = [
    ("/login", {"password": PASSWORD}),
    ("/logout", {}),
    ("/settings/connections", {"name": "Evil", "host": "dtm.test", "account_id": "0a1b2c3d-0000-4000-8000-00000000a001",
                               "api_key": "k"}),
    ("/settings/connections/1/default", {}),
    ("/settings/connections/1/delete", {}),
    ("/runs", {"run_id": "x1", "variant": "api", "mode": "single", "ca_id": "a", "profile_id": "b"}),
    ("/runs/r1/cleanup", {"mode": "full"}),
    ("/runs/r1/delete", {}),
]


@pytest.mark.parametrize("path,data", POST_ROUTES)
@pytest.mark.parametrize("origin", ["https://evil.example", "https://testserver:8443", "https://testserver.evil.example",
                                    "null", "https://evil.example/https://testserver"])
def test_foreign_origin_is_refused_on_every_post(user, store, path, data, origin):
    store.create_run("r1", "uc01", {})
    store.update_run("r1", status="completed", cleanup_mode="full", cleanup_status="done")
    response = user.post(path, data=data, headers={"Origin": origin}, follow_redirects=False)
    assert response.status_code == 403 and "Cross-origin request refused" in response.text
    assert store.run_exists("r1") and store.connections() == [] and not store.run_exists("x1")
    assert COOKIE not in response.headers.get("set-cookie", "")
    assert user.get("/", follow_redirects=False).status_code == 200  # still logged in (logout refused too)


def test_foreign_origin_refused_before_authentication(web):
    response = web.post("/runs/r1/delete", headers={"Origin": "https://evil.example"}, follow_redirects=False)
    assert response.status_code == 403


def test_same_origin_post_works(web):
    response = web.post("/login", data={"password": PASSWORD}, headers={"Origin": "https://testserver"},
                        follow_redirects=False)
    assert response.status_code == 303
    response = web.post("/logout", headers={"Origin": "https://testserver"}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


@pytest.mark.parametrize("referer,status", [
    ("https://evil.example/page", 403), ("https://testserver:444/x", 403),
    ("https://testserver/login", 303), ("https://testserver/", 303),
])
def test_referer_fallback(web, referer, status):
    response = web.post("/login", data={"password": PASSWORD}, headers={"Referer": referer}, follow_redirects=False)
    assert response.status_code == status


def test_origin_wins_over_referer(web):
    response = web.post("/login", data={"password": PASSWORD}, follow_redirects=False,
                        headers={"Origin": "https://evil.example", "Referer": "https://testserver/login"})
    assert response.status_code == 403


def test_post_without_origin_or_referer_is_allowed(web):
    assert web.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303


def test_get_requests_ignore_origin(user):
    assert user.get("/", headers={"Origin": "https://evil.example"}).status_code == 200


def test_real_browser_form_post_is_accepted(web):
    """Regression for the 403-on-login defect: a form POST from a browser may carry Origin "null"
    (privacy settings, sandboxing); Sec-Fetch-Site states the real relation and decides."""
    assert web.get("/login").headers["referrer-policy"] == "same-origin"
    response = web.post("/login", data={"password": PASSWORD}, follow_redirects=False,
                        headers={"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"})
    assert response.status_code == 303


def test_scheme_mismatch_is_refused(web):
    response = web.post("/login", data={"password": PASSWORD}, headers={"Origin": "http://testserver"},
                        follow_redirects=False)
    assert response.status_code == 403



@pytest.mark.parametrize("site,origin,status", [
    ("cross-site", None, 403),
    ("same-site", None, 403),             # another app on this host (any port) is same-site, not same-origin
    ("cross-site", "https://testserver", 403),  # Sec-Fetch-Site decides, a matching Origin does not help
    ("none", None, 303),                  # user-initiated (typed URL, bookmark)
    ("same-origin", None, 303),
    ("same-origin", "https://evil.example", 303),  # Sec-Fetch-Site wins over Origin (browsers set both)
    ("SAME-ORIGIN", None, 403),           # values are lower-case tokens; anything else is refused
])
def test_sec_fetch_site_decides(web, site, origin, status):
    headers = {"Sec-Fetch-Site": site} | ({"Origin": origin} if origin else {})
    response = web.post("/login", data={"password": PASSWORD}, headers=headers, follow_redirects=False)
    assert response.status_code == status


@pytest.mark.parametrize("path,data", POST_ROUTES)
def test_cross_site_fetch_metadata_refused_on_every_post(user, store, path, data):
    store.create_run("r1", "uc01", {})
    store.update_run("r1", status="completed", cleanup_mode="full", cleanup_status="done")
    response = user.post(path, data=data, headers={"Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
    assert response.status_code == 403
    assert store.run_exists("r1") and not store.run_exists("x1")
    assert user.get("/", follow_redirects=False).status_code == 200


@pytest.mark.parametrize("origin", ["http://testserver", "http://testserver:443", "ftp://testserver"])
def test_scheme_variants_are_refused(web, origin):
    response = web.post("/login", data={"password": PASSWORD}, headers={"Origin": origin}, follow_redirects=False)
    assert response.status_code == 403



# --- cache busting ---------------------------------------------------------------------------

def test_static_urls_carry_the_asset_version(web):
    from app.main import HERE, _asset_hash
    version = _asset_hash(HERE / "static")
    assert re.fullmatch(r"[0-9a-f]{10}", version)
    html = web.get("/login").text
    for asset in ("pico.min.css", "app.css", "htmx.min.js", "app.js"):
        assert f"/static/{asset}?v={version}" in html, asset
        response = web.get(f"/static/{asset}?v={version}", follow_redirects=False)  # no login needed
        assert response.status_code == 200 and response.content
    assert web.get("/static/app.css?v=x", follow_redirects=False).status_code == 200


def test_asset_version_changes_with_static_content(tmp_path):
    from app.main import _asset_hash
    (tmp_path / "fonts").mkdir()
    (tmp_path / "app.css").write_text("body{}")
    (tmp_path / "fonts" / "a.woff2").write_bytes(b"wOF2-1")
    before = _asset_hash(tmp_path)
    assert _asset_hash(tmp_path) == before  # stable
    (tmp_path / "app.css").write_text("body{color:red}")
    changed = _asset_hash(tmp_path)
    assert changed != before
    (tmp_path / "fonts" / "a.woff2").write_bytes(b"wOF2-2")  # nested files count too
    assert _asset_hash(tmp_path) != changed
