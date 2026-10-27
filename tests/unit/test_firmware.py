"""UC-8 firmware: the dancing figure's markup (only known figures, validated colours – it is rendered |safe),
the OTA payload and the cached catalogue."""

import io
import json
import re
import stat
import zipfile

import pytest

from app import firmware


@pytest.mark.parametrize("look", [
    {"character": "robot", "color": "#e53935", "version": 2},
    {"character": "ghost", "color": "#00897b", "version": 7},
    {"character": "alien", "color": "#5e35b1", "version": 12},
])
def test_svg_of_known_figures(look):
    markup = firmware.svg(look)
    assert markup.startswith(f'<svg class="dancer {look["character"]}" viewBox="0 0 64 64" role="img"')
    assert f'aria-label="Firmware {look["version"]}.0.0"' in markup
    assert look["color"] in markup and "currentColor" not in markup
    assert "style=" not in markup  # the CSP allows no inline style


@pytest.mark.parametrize("look", [
    {"character": '"><script>alert(1)</script>', "color": "#e53935"},
    {"character": "robot", "color": 'red" onload="alert(1)'},
    {"character": "robot", "color": "#E53935"},          # the pattern allows lower case only
    {"character": "robot", "color": "#e53935;x"},
    {"character": "robot", "color": "url(#x)"},
    {"character": "__class__", "color": None},
    {},
])
def test_svg_falls_back_for_anything_unknown(look):
    markup = firmware.svg(look)
    assert '<svg class="dancer robot"' in markup
    assert "<script" not in markup and "onload" not in markup and "url(" not in markup and "#E5" not in markup
    # the robot in the factory colour – unless the colour itself was a valid one
    color = look.get("color") if look.get("color") == "#e53935" else firmware.FACTORY["color"]
    assert markup == firmware.svg({"character": "robot", "color": color})


def test_svg_label_is_the_semver_of_an_integer_version():
    assert 'aria-label="Firmware 1.0.0"' in firmware.svg({"character": "ghost", "color": "#43a047"})
    assert 'aria-label="Firmware 3.0.0"' in firmware.svg({"character": "ghost", "color": "#43a047", "version": "3"})


def test_payload_zip_holds_an_executable_install_script():
    look = {"version": 4, "character": "ghost", "color": "#00897b"}
    archive = zipfile.ZipFile(io.BytesIO(firmware.payload(look)))
    assert sorted(archive.namelist()) == ["firmware.html", "install.sh", "version.txt"]
    script = archive.getinfo("install.sh")
    mode = script.external_attr >> 16
    assert stat.S_ISREG(mode) and mode & 0o111 == 0o111  # unpacked as an executable file
    body = archive.read("install.sh").decode()
    assert body.startswith("#!/bin/sh\n") and "set -eu" in body and "/opt/firmware" in body
    assert '[ "$new" -le "$old" ]' in body  # an older version never replaces a newer one
    assert archive.read("version.txt") == b"4\n"
    page = archive.read("firmware.html").decode()
    assert firmware.svg(look) in page and "Firmware 4.0.0 · ghost #00897b" in page
    assert archive.testzip() is None


def test_name_pattern_of_catalogue_entries():
    assert firmware.NAME.fullmatch("robot-firmware-12-alien-5e35b1").groups() == ("12", "alien", "5e35b1")
    for name in ("robot-firmware-12-alien-5E35B1", "robot-firmware-1-dragon-e53935", "robot-firmware-x-robot-e53935",
                 "robot-firmware-2-robot-e53935-x", "robot-t1-uc08-firmware-2", "robot-firmware-12345-robot-e53935"):
        assert not firmware.NAME.fullmatch(name), name


def test_catalog_reads_the_cached_setting(store):
    assert firmware.catalog(store, "acct") == []
    entries = [{"name": "robot-firmware-2-robot-e53935", "version": 2, "character": "robot", "color": "#e53935"}]
    store.set_setting("firmware_catalog:acct", json.dumps(entries))
    assert firmware.catalog(store, "acct") == entries
    assert firmware.catalog(store, "other") == []  # per account
    store.set_setting("firmware_catalog:acct", "{not json")
    assert firmware.catalog(store, "acct") == []


def test_legacy_and_looks():
    assert not firmware.legacy({}) and not firmware.legacy({"firmware": []})
    current = {"name": "robot-firmware-2-ghost-00897b", "version": 2, "character": "ghost", "color": "#00897b"}
    assert not firmware.legacy({"firmware": [current]})
    assert firmware.legacy({"firmware": [current, {"version": 3, "character": "robot", "color": "#e53935"}]})
    assert firmware.looks({"firmware": [current]}) == {1: firmware.FACTORY, 2: current}


def test_palette_colours_pass_the_markup_check():
    assert all(re.fullmatch(firmware.COLOR, c) for c in firmware.PALETTE)
    assert firmware.FACTORY["color"] not in firmware.PALETTE  # the factory blue stays reserved for 1.0.0
