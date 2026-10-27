"""Shared page head (breadcrumb + h1), product name, favicon and the Advanced-license tile marker."""

import re
from pathlib import Path
from xml.etree import ElementTree

import pytest

from app import evergreen
from tests.component.test_web_runs import finished, form

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = "Demonstrator · Device Trust Manager"
SPACER = '<nav aria-label="breadcrumb" aria-hidden="true" class="crumb-spacer">'


def head(html: str) -> tuple[str, str]:
    """(breadcrumb nav, h1 text) – the page head must come first in <main> and appear exactly once."""
    assert html.count('aria-label="breadcrumb"') == 1 and html.count("<h1>") == 1
    nav = re.search(r'<nav aria-label="breadcrumb"[^>]*>.*?</nav>', html, re.S).group(0)
    h1 = re.search(r"<h1>(.*?)</h1>", html, re.S).group(1)
    # breadcrumb directly followed by the page head – nothing between them that would shift the heading
    assert re.search(re.escape(nav) + r'\s*<div class="page-head">\s*<div><h1>', html)
    return nav, h1


@pytest.mark.parametrize("path", ["/", "/runs/new"])
def test_home_and_catalog_keep_an_invisible_breadcrumb(configured_user, path):
    nav, h1 = head(configured_user.get(path).text)
    assert h1 == "Use-Case Central"
    assert nav.startswith(SPACER)
    assert "<a " not in nav and "aria-current" not in nav  # nothing to navigate to, nothing announced


def test_crumb_spacer_is_hidden_but_keeps_its_space():
    css = (ROOT / "app" / "static" / "app.css").read_text()
    rule = re.search(r"\.crumb-spacer\s*\{([^}]*)\}", css).group(1)
    assert "visibility: hidden" in rule and "display: none" not in rule


def test_other_pages_show_use_case_central_and_the_page(configured_user, store):
    configured_user.post("/runs", data=form())
    finished(store, "r1")
    conn = store.connections()[0]["id"]
    expected = {"/runs/new/evergreen": ("Evergreen device certificates", f"/runs/new?connection={conn}"),
                "/runs/new/uc06": ("Managed devices", f"/runs/new?connection={conn}"),
                "/settings": ("Settings", "/"), "/runs/r1": ("r1", "/"), "/nope": ("Not found", "/")}
    for path, (label, home) in expected.items():
        nav, h1 = head(configured_user.get(path).text)
        assert "crumb-spacer" not in nav and "aria-hidden" not in nav, path
        crumbs = re.findall(r"<li[^>]*>(.*?)</li>", nav)
        assert crumbs == [f'<a href="{home}">Use-Case Central</a>', label], path
        assert f'<li aria-current="page">{label}</li>' in nav, path
    assert head(configured_user.get("/runs/r1").text)[1].startswith("Run r1 ")


def test_welcome_page_has_a_breadcrumb_too(user):
    nav, h1 = head(user.get("/").text)
    assert h1 == "Welcome" and '<li aria-current="page">Welcome</li>' in nav


def test_error_page_heading_is_the_h1(configured_user):
    html = configured_user.post("/runs", data=form(ca_id="no-such-ca")).text
    nav, h1 = head(html)
    assert h1 == "Error" and '<li aria-current="page">Error</li>' in nav
    assert "<h2>" not in html.split("<main", 1)[1] and 'role="alert"' in html


# --- product name and favicon -----------------------------------------------------------------------

@pytest.mark.parametrize("path,prefix", [("/", ""), ("/runs/new", "New run · "), ("/settings", "Settings · "),
                                         ("/nope", "Error · ")])
def test_page_titles_carry_the_product_name(configured_user, path, prefix):
    html = configured_user.get(path).text
    assert re.search(r"<title>(.*?)</title>", html).group(1) == prefix + PRODUCT
    assert '<span class="brand-name">Demonstrator <span>· Device Trust Manager</span></span>' in html
    assert "DTM Demonstrator" not in html


def test_login_page_carries_the_product_name(web, configured_store):
    html = web.get("/login").text
    assert f"<title>Log in · {PRODUCT}</title>" in html
    assert '<span class="brand-name">Demonstrator <span>· Device Trust Manager</span></span>' in html
    assert "DTM Demonstrator" not in html


def test_installer_and_readme_use_the_product_name():
    readme = (ROOT / "README.md").read_text()
    assert readme.splitlines()[0] == f"# {PRODUCT}"
    installer = (ROOT / "install.sh").read_text()
    assert PRODUCT in installer.splitlines()[1] and f"Description={PRODUCT}" in installer
    # the self-signed marker identifies certificates of earlier installs – it intentionally keeps the old name
    assert installer.count("DTM Demonstrator") == installer.count("DTM Demonstrator self-signed") == 2


@pytest.mark.parametrize("anonymous", [True, False])
def test_favicon_is_linked_and_served(web, configured_store, user, anonymous):
    client = web if anonymous else user
    html = client.get("/login" if anonymous else "/").text
    href = re.search(r'<link rel="icon" type="image/svg\+xml" href="(/static/favicon\.svg\?v=[0-9a-f]+)">', html)
    assert href, "favicon link missing"
    response = client.get(href.group(1))
    assert response.status_code == 200 and response.headers["content-type"].startswith("image/svg+xml")
    svg = ElementTree.fromstring(response.content)
    assert svg.tag == "{http://www.w3.org/2000/svg}svg"
    assert b"<script" not in response.content and b"href" not in response.content  # a static, self-contained icon


# --- Advanced license marker -----------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/runs/new"])
def test_only_the_advanced_tiles_are_marked(configured_user, path):
    html = configured_user.get(path).text
    tiles = dict(m[::-1] for m in re.findall(r'<article class="tile[^"]*">(.*?formaction="/runs/new/(\w+)".*?)</article>',
                                             html, re.S))
    assert set(tiles) == set(evergreen.CATALOG)
    for key, tile in tiles.items():
        advanced = evergreen.CATALOG[key].license == "advanced"
        assert ('<span class="tile-icon advanced' in tile) is advanced, key
        assert ("Advanced license" in tile) is advanced, key
        if not advanced:
            assert '<span class="tile-icon">' in tile, key
    assert [k for k, uc in evergreen.CATALOG.items() if uc.license == "advanced"] == ["uc06"]
    assert {uc.license for uc in evergreen.USE_CASES.values()} == {"essentials", "advanced"}


def test_card_head_button_is_centred_on_the_title():
    """The Renew/Enroll form beside a card title is a flex box without button margin – centred on the title."""
    css = (ROOT / "app" / "static" / "app.css").read_text()
    form = re.search(r"\.card-head > form\.inline\s*\{([^}]*)\}", css)
    button = re.search(r"\.card-head > form\.inline > button\s*\{([^}]*)\}", css)
    assert form and "display: flex" in form.group(1)
    assert button and re.search(r"margin:\s*0\s*;", button.group(1))
