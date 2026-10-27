"""Build identity (/version, footer) and the dev-only feedback overlay (excluded from release images)."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config
from app import main as app_main
from app.devtools import feedback
from app.main import create_app
from tests.conftest import PASSWORD

ROOT = Path(__file__).resolve().parents[2]
PNG = feedback.PNG_MAGIC + b"\x00" * 64
ITEM = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")


def client(store, auth, fake, data_dir, dev: bool) -> TestClient:
    app = create_app(store, auth, client_factory=fake.factory(), data_dir=data_dir, dev_mode=dev)
    return TestClient(app, base_url="https://testserver", raise_server_exceptions=False)


def login(web: TestClient) -> TestClient:
    assert web.post("/login", data={"password": PASSWORD}, follow_redirects=False).status_code == 303
    return web


@pytest.fixture
def build(monkeypatch):
    monkeypatch.setitem(config.BUILD, "version", "v9.8.7")
    monkeypatch.setitem(config.BUILD, "commit", "abc1234")
    monkeypatch.setitem(config.BUILD, "build_time", "2026-10-27T10:00:00Z")
    return config.BUILD


@pytest.fixture
def dev(store, auth, fake, data_dir, build):
    with client(store, auth, fake, data_dir, dev=True) as web:
        yield web


@pytest.fixture
def release(store, auth, fake, data_dir, build):
    with client(store, auth, fake, data_dir, dev=False) as web:
        yield web


def fields(**overrides) -> dict:
    return {"comment": "Shorter, please", "selector": "main > h1", "component": "settings.html › #conn",
            "text": "Settings", "url": "/settings?tab=1", "viewport": "1440x900@2"} | overrides


def post(web, data=None, png=PNG, **kwargs):
    files = {"screenshot": ("../../evil.png", png, "image/png")} if png is not None else None
    return web.post("/feedback", data=fields() if data is None else data, files=files, follow_redirects=False, **kwargs)


def items(data_dir: Path) -> list[Path]:
    folder = data_dir / "feedback"
    return sorted(folder.iterdir()) if folder.exists() else []


# --- build identity ----------------------------------------------------------------------------------------


def test_version_is_public_json_without_secrets(release):
    response = release.get("/version", follow_redirects=False)
    assert response.status_code == 200
    assert response.json() == {"version": "v9.8.7", "commit": "abc1234", "build_time": "2026-10-27T10:00:00Z",
                               "dev": False}


def test_version_reports_dev_mode(dev):
    assert dev.get("/version").json()["dev"] is True


def test_release_footer_shows_the_version_only(release):
    footer = re.search(r"<footer data-build>(.*?)</footer>", release.get("/login").text).group(1)
    assert footer == "Version v9.8.7"
    page = login(release).get("/settings").text
    assert "<small data-build>Version v9.8.7</small>" in page and "abc1234" not in page


def test_dev_footer_shows_version_commit_and_build_time(dev):
    expected = "Version v9.8.7 · abc1234 · built 2026-10-27T10:00:00Z"
    assert f"<footer data-build>{expected}</footer>" in dev.get("/login").text
    assert f"<small data-build>{expected}</small>" in login(dev).get("/settings").text


def test_dev_footer_without_build_args(dev, monkeypatch):
    monkeypatch.setitem(config.BUILD, "commit", None)
    monkeypatch.setitem(config.BUILD, "build_time", None)
    assert config.build_label(True) == "Version v9.8.7 · no commit · no build time"


# --- dev flag off / module missing: nothing of the overlay --------------------------------------------------


def test_release_build_has_no_feedback_route_and_no_overlay_assets(release, data_dir):
    page = login(release).get("/settings").text
    assert "devtools" not in page and "feedback" not in page.lower() and "data-component" not in page
    assert release.get("/devtools/static/feedback.js").status_code == 404
    assert post(release).status_code in (404, 405)
    assert not any(r.path in ("/feedback", "/devtools/static") for r in release.app.routes)
    assert items(data_dir) == []


def test_dev_flag_without_the_devtools_module_registers_nothing(store, auth, fake, data_dir, monkeypatch):
    """A release image lacks app/devtools – DEV_MODE=1 there must not break the app or expose a route."""
    real = app_main.importlib.util.find_spec
    monkeypatch.setattr(app_main.importlib.util, "find_spec",
                        lambda name, *a: None if name == "app.devtools" else real(name, *a))
    with client(store, auth, fake, data_dir, dev=True) as web:
        assert web.get("/version").json()["dev"] is False
        assert "devtools" not in login(web).get("/settings").text
        assert post(web).status_code in (404, 405)


def test_release_image_excludes_the_devtools_code():
    """.dockerignore is evaluated top-down: the exclusion must come after the `!app` re-include."""
    lines = [line.strip() for line in (ROOT / ".dockerignore").read_text().splitlines()]
    assert lines.index("app/devtools") > lines.index("!app")
    assert not any(line.startswith("!") and "devtools" in line for line in lines)


# --- dev flag on ----------------------------------------------------------------------------------------------


def test_dev_pages_load_the_overlay_only_when_logged_in(dev):
    assert "devtools" not in dev.get("/login").text
    page = login(dev).get("/settings").text
    assert '<script type="module" src="/devtools/static/feedback.js"></script>' in page
    assert "/devtools/static/vendor/html2canvas-1.4.1.min.js" in page
    assert '<main class="container" data-component="settings.html">' in page
    for asset in ("feedback.js", "feedback.css", "vendor/finder-4.0.2.js", "vendor/html2canvas-1.4.1.min.js"):
        response = dev.get(f"/devtools/static/{asset}")
        assert response.status_code == 200, asset
        assert "'unsafe-inline'" not in response.headers["content-security-policy"]


def test_vendored_libraries_carry_their_licenses():
    vendor = ROOT / "app" / "devtools" / "static" / "vendor"
    for lib in ("finder-4.0.2", "html2canvas-1.4.1"):
        assert "Permission is hereby granted, free of charge" in (vendor / f"{lib}.LICENSE").read_text(), lib


def test_saving_feedback_writes_json_and_png(dev, data_dir):
    response = post(login(dev), headers={"user-agent": "test-browser"})
    assert response.status_code == 201
    item_id = response.json()["id"]
    assert ITEM.fullmatch(item_id)
    assert [p.name for p in items(data_dir)] == [f"{item_id}.json", f"{item_id}.png"]
    assert (data_dir / "feedback" / f"{item_id}.png").read_bytes() == PNG
    item = json.loads((data_dir / "feedback" / f"{item_id}.json").read_text())
    assert item["status"] == "open" and item["note"] is None and item["id"] == item_id
    assert item["comment"] == "Shorter, please" and item["url"] == "/settings?tab=1"
    assert item["element"] == {"selector": "main > h1", "component": "settings.html › #conn", "text": "Settings"}
    assert item["viewport"] == "1440x900@2" and item["user_agent"] == "test-browser"
    assert item["build"] == {"version": "v9.8.7", "commit": "abc1234", "build_time": "2026-10-27T10:00:00Z"}
    assert item["screenshot"] == f"{item_id}.png" and item["created"].endswith("+00:00")


def test_two_items_never_overwrite_each_other(dev, data_dir):
    login(dev)
    ids = {post(dev).json()["id"] for _ in range(3)}
    assert len(ids) == 3 and len(items(data_dir)) == 6


def test_feedback_needs_login(dev, data_dir):
    response = post(dev)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert items(data_dir) == []


def test_feedback_refuses_cross_origin_posts(dev, data_dir):
    login(dev)
    assert post(dev, headers={"origin": "https://evil.example"}).status_code == 403
    assert post(dev, headers={"sec-fetch-site": "cross-site"}).status_code == 403
    assert items(data_dir) == []


@pytest.mark.parametrize("data", [
    fields(comment=" "),
    fields(comment="x" * 4001),
    fields(selector=""),
    fields(text="x" * 2001),
    fields(url="https://evil.example/"),
    fields(url="//evil.example/x"),
    fields(url="../../etc/passwd"),
    fields(viewport="1440x900"),
    fields(viewport="<script>"),
    {k: v for k, v in fields().items() if k != "url"},
], ids=["blank-comment", "long-comment", "no-selector", "long-text", "absolute-url", "scheme-relative-url",
        "relative-url", "viewport-no-dpr", "viewport-markup", "missing-url"])
def test_invalid_fields_are_refused(dev, data_dir, data):
    assert post(login(dev), data=data).status_code == 400
    assert items(data_dir) == []


@pytest.mark.parametrize("png", [None, b"GIF89a" + b"\x00" * 10, b""], ids=["missing", "not-png", "empty"])
def test_screenshot_must_be_a_png(dev, data_dir, png):
    assert post(login(dev), png=png).status_code == 400
    assert items(data_dir) == []


def test_screenshot_size_is_limited(dev, data_dir, monkeypatch):
    monkeypatch.setattr(feedback, "MAX_SCREENSHOT", len(PNG) - 1)
    assert post(login(dev)).status_code == 400
    assert items(data_dir) == []


def test_oversized_body_is_refused_before_parsing(dev, data_dir, monkeypatch):
    monkeypatch.setattr(feedback, "MAX_BODY", 100)
    assert post(login(dev)).status_code == 413
    assert items(data_dir) == []


def test_only_one_file_is_accepted(dev, data_dir):
    files = [("screenshot", ("a.png", PNG, "image/png")), ("screenshot", ("b.png", PNG, "image/png"))]
    response = login(dev).post("/feedback", data=fields(), files=files)
    assert response.status_code == 400
    assert items(data_dir) == []


def test_request_values_never_become_paths(dev, data_dir):
    """Selector, URL, component and the upload's file name are stored as data only."""
    response = post(login(dev), data=fields(selector="../../../x", component="../../y", text="/etc/passwd"))
    assert response.status_code == 201
    names = [p.name for p in items(data_dir)]
    assert all(ITEM.fullmatch(Path(n).stem) for n in names) and len(names) == 2
    assert not (data_dir.parent / "evil.png").exists()
