"""The certificate detail view: route (selection, foreign serials, login), PEM source per use case (saved at issuance,
UC-7's device-ID certificate, UC-8 read once from DTM and cached), and how the tiles reach it."""

import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app import devices
from tests.component.test_web_runs import BASE_PARAMS, cert_run, finished, form
from tests.component.test_web_uc06 import tiles, uc06_form
from tests.component.test_web_uc08 import docker, idle, minion, names, started, uc07_form  # noqa: F401 (fixtures)
from tests.fakedtm import _error


def detail(user, run_id: str, name: str, serial: str | None = None):
    return user.get(f"/runs/{run_id}/devices/{name}/certificates", params={"serial": serial} if serial else None)


def value(html: str, label: str) -> str:
    found = re.search(rf"<dt>{label}</dt><dd[^>]*>(.*?)</dd>", html, re.S)
    assert found, label
    return found.group(1)


def options(html: str) -> list[tuple[str, str, bool]]:
    return [(v, text, bool(sel)) for v, sel, text in
            re.findall(r'<option value="([^"]*)"( selected)?>([^<]*)</option>', html)]


def test_detail_of_a_saved_certificate(configured_user, store, data_dir):
    configured_user.post("/runs", data=form())
    c = finished(store, "r1")["result"]["certificates"][0]
    response = detail(configured_user, "r1", c["common_name"])
    assert response.status_code == 200
    html = response.text
    saved = x509.load_pem_x509_certificate((data_dir / "runs" / "r1" / "certificates" / f"{c['serial']}.pem").read_bytes())
    assert value(html, "CN") == c["common_name"] and value(html, "Serial") == c["serial"]
    assert value(html, "SHA-256").replace(":", "") == saved.fingerprint(hashes.SHA256()).hex().upper()
    assert value(html, "Chain") == "Fake ECDSA Issuing CA"  # the run keeps no CA chain – the leaf's issuer
    assert value(html, "Key") == "ECDSA P-256" and value(html, "Validity").endswith(" UTC")
    assert value(html, "Key usage") == "–" and value(html, "Extended key usage") == "–"  # the fake sets neither
    assert "<dt>SANs</dt>" not in html  # only when the certificate has some
    assert options(html) == [(c["serial"], f"{c['serial'][:3]}…{c['serial'][-3:]} · active", True)]
    assert f'hx-get="/runs/r1/devices/{c["common_name"]}/certificates"' in html and 'hx-target="#cert-detail"' in html
    assert f'href="/runs/r1/certificates/{c["serial"]}.pem" download' in html
    assert " style=" not in html and "<script" not in html and "PRIVATE KEY" not in html


def test_detail_picks_only_the_devices_own_certificates(configured_user, store):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    configured_user.post("/runs", data=form(run_id="r2"))
    first, second = finished(store, "r1")["result"]["certificates"]
    other = finished(store, "r2")["result"]["certificates"][0]
    assert detail(configured_user, "r1", first["common_name"], first["serial"]).status_code == 200
    assert detail(configured_user, "r1", first["common_name"], first["serial"].lower()).status_code == 200
    for run_id, name, serial in (("r1", first["common_name"], second["serial"]),  # the other device's
                                 ("r1", first["common_name"], other["serial"]),   # another run's
                                 ("r2", other["common_name"], first["serial"]),
                                 ("r1", first["common_name"], "../../demonstrator.db"),
                                 ("r1", "robot-r1-uc01-nope", first["serial"]),
                                 ("nope", first["common_name"], first["serial"])):
        response = detail(configured_user, run_id, name, serial)
        assert response.status_code == 404, (run_id, name, serial)
        assert "BEGIN CERTIFICATE" not in response.text


def test_detail_requires_login(web, configured_store, store):
    cert_run(store, 1)
    response = web.get("/runs/c1/devices/robot-c1-uc01-batch-0001/certificates", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    htmx = web.get("/runs/c1/devices/robot-c1-uc01-batch-0001/certificates", headers={"HX-Request": "true"},
                   follow_redirects=False)
    assert htmx.status_code == 401 and htmx.headers["hx-redirect"] == "/login"


def test_without_a_pem_only_what_the_run_knows(configured_store, user, store, fake):
    """A run without saved PEMs (from before them): fields from the run's data, "–" for the rest – and no DTM call."""
    cert_run(store, 1)
    html = detail(user, "c1", "robot-c1-uc01-batch-0001").text
    assert value(html, "CN") == "robot-c1-uc01-batch-0001" and value(html, "Serial") == "1"
    assert value(html, "Chain") == "ICA" and value(html, "Key") == "ECDSA P-256"
    assert value(html, "Validity") == "– → 2027-10-23 10:00 UTC"
    assert value(html, "SHA-256") == "–" and "download" not in html
    assert fake.calls == []


def test_renewed_device_lists_every_certificate_newest_first(configured_user, store, fake):
    configured_user.post("/runs", data=uc06_form())
    finished(store, "m1")
    (name,) = [d["name"] for d in store.get_run("m1")["result"]["devices"]]
    configured_user.post(f"/runs/m1/devices/{name}/renew")
    run = idle(store, "m1")
    first, renewal = run["result"]["certificates"]
    picked = options(detail(configured_user, "m1", name).text)
    assert [(v, sel) for v, _t, sel in picked] == [(renewal["serial"], True), (first["serial"], False)]
    assert picked[0][1].endswith(" · active") and picked[1][1].endswith(" · renewed")
    html = detail(configured_user, "m1", name, first["serial"]).text  # the picker's change loads the older one
    assert value(html, "Serial") == first["serial"] and f'<option value="{first["serial"]}" selected>' in html


def test_uc07_lists_the_device_id_certificate(configured_user, store, enroll_net, data_dir):
    configured_user.post("/runs", data=uc07_form())
    assert finished(store, "u1")["status"] == "completed"
    (name,) = names(store, "u1")
    html = configured_user.get("/runs/u1").text
    (tile,) = tiles(html)  # not enrolled yet: the device-ID certificate is the only one – still reachable
    assert f'data-certs="/runs/u1/devices/{name}/certificates"' in tile and "Certificate CN" not in tile
    html = detail(configured_user, "u1", name).text
    device_id = x509.load_pem_x509_certificate(
        (devices.device_dir(data_dir / "runs" / "u1", name) / "device-id.crt").read_bytes())
    serial = format(device_id.serial_number, "X")
    assert options(html) == [(serial, f"Device ID · {serial[:3]}…{serial[-3:]}", True)]
    assert value(html, "Chain") == "robot-u1-uc07-device-id-ica → robot-u1-uc07-manufacturer-root"
    assert "download" not in html  # demo material of the manufacturer, not a DTM certificate


def test_uc08_reads_the_certificate_from_dtm_once(configured_user, store, fake, docker, minion, data_dir):  # noqa: F811
    started(configured_user, store)
    first, _second = names(store)
    configured_user.post(f"/runs/t1/devices/{first}/enroll")
    d = devices.device_of(idle(store)["result"], first)
    operational = next(c for c in d["certificates"] if c["role"] == "operational")
    bootstrap = next(c for c in d["certificates"] if c["role"] == "bootstrap")
    html = detail(configured_user, "t1", first).text  # default: the operational certificate
    assert fake.names("cert_download") == [operational["serial"]] and fake.violations == []
    assert value(html, "CN") == first and value(html, "Serial") == operational["serial"].upper()
    assert value(html, "SHA-256") != "–" and value(html, "Chain") == "Fake ECDSA Issuing CA"
    short = {c["role"]: f"{c['serial'][:3]}…{c['serial'][-3:]}".upper() for c in (bootstrap, operational)}
    assert options(html) == [(bootstrap["serial"].upper(), f"Bootstrap · {short['bootstrap']} · active", False),
                             (operational["serial"].upper(), f"Operational · {short['operational']} · active", True)]
    link = f"/runs/t1/certificates/{operational['serial'].upper()}.pem"
    assert f'href="{link}" download' in html
    response = configured_user.get(link)
    assert response.status_code == 200 and "PRIVATE KEY" not in response.text
    assert x509.load_pem_x509_certificate(response.content).serial_number == int(operational["serial"], 16)
    detail(configured_user, "t1", first)  # cached: no second call
    assert fake.names("cert_download") == [operational["serial"]]
    # DTM unavailable: the listing's fields, "–" for the rest, nothing cached
    fake.fail["cert_download"] = _error(500, "upstream trouble")
    html = detail(configured_user, "t1", first, bootstrap["serial"]).text
    assert value(html, "CN") == d["serial"] and value(html, "SHA-256") == "–" and "download" not in html
    assert not (data_dir / "runs" / "t1" / "certificates" / f"{bootstrap['serial'].upper()}.pem").exists()


def test_uc08_dtm_answer_for_another_certificate_is_not_shown(configured_user, store, fake, docker, minion,  # noqa: F811
                                                              data_dir):
    started(configured_user, store)
    first, _second = names(store)
    configured_user.post(f"/runs/t1/devices/{first}/enroll")
    d = devices.device_of(idle(store)["result"], first)
    bootstrap, operational = sorted(d["certificates"], key=lambda c: c["role"])
    fake.pems[operational["serial"]] = fake.pems[bootstrap["serial"]]  # DTM answers with the wrong certificate
    html = detail(configured_user, "t1", first, operational["serial"]).text
    assert value(html, "SHA-256") == "–" and value(html, "CN") == first
    assert not (data_dir / "runs" / "t1" / "certificates").exists()


def test_tiles_open_the_detail_and_keep_it_out_of_the_poll(configured_store, user, store):
    cert_run(store, 2)
    html = user.get("/runs/c1").text
    for tile in tiles(html):
        certs = re.search(r'<ul class="tbox certs" data-certs="(/runs/c1/devices/[^"]+/certificates)"[^>]*>(.*?)</ul>',
                          tile, re.S)
        assert certs, tile
        # at a glance only: state and short serial – no tooltips or validity the detail view shows
        assert "data-tip" not in certs.group(2) and "2027-10-23" not in certs.group(2) and "download" not in tile
        assert user.get(certs.group(1)).status_code == 200
    # the side panel exists for large tiles too, outside every tile, kept while the card is polled
    panel = re.search(r'<aside id="side-panel" class="side-panel" hidden aria-label="Device" hx-preserve>(.*?)</aside>',
                      html, re.S)
    assert panel and '<div class="panel-tile"></div>' in panel.group(1) and '<div class="panel-certs"></div>' in panel.group(1)
    assert html.index('id="side-panel"') > html.rindex("</section>")


def test_detail_escapes_dtm_values(configured_store, user, store):
    evil = "<script>alert(1)</script>"
    store.create_run("c1", "uc01", BASE_PARAMS | {"count": 1})
    store.update_run("c1", status="completed", result={"certificates": [
        {"common_name": "robot-c1", "serial": "AB", "not_after": evil, "issuer": evil, "key_type": evil}]})
    html = detail(user, "c1", "robot-c1").text
    assert evil not in html and "&lt;script&gt;" in html
