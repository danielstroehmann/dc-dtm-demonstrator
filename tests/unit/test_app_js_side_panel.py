"""The side panel's × button (app/static/app.js): the panel itself carries data-certs while it is open, so the
click handler must check data-panel-close before data-certs – otherwise the × click is taken for a click on the
panel's certificates and the panel cannot be closed. Runs the real app.js under node with a minimal DOM stand-in
(tests/unit/app_js_dom.js); skipped – visibly – where node is not installed."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="node is not installed – app.js click handling not exercised")
def test_close_button_closes_the_open_side_panel():
    out = subprocess.run([NODE, str(Path(__file__).with_name("app_js_dom.js")), str(ROOT / "app/static/app.js")],
                         capture_output=True, text=True, timeout=30, check=True).stdout
    report = json.loads(out)

    # A click on a tile's certificates opens the panel and loads them
    assert report["afterOpen"] == {"hidden": False, "certs": "/runs/r1/devices/d1/certificates",
                                   "ajax": ["/runs/r1/devices/d1/certificates"]}
    # The × closes it: hidden again, its certificates forgotten, nothing loaded again
    assert report["afterClose"] == {"hidden": True, "certs": None, "ajax": ["/runs/r1/devices/d1/certificates"]}
