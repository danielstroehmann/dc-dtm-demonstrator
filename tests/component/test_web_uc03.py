"""UC-3 through the web UI (form, validation, run page) and the certificate PEM downloads."""

import json
import re

import pytest
from cryptography import x509

from app import enrollment
from tests.component.test_web_runs import cleaned, finished, form
from tests.fakedtm import ECDSA_CA_ID, RSA_CA_ID


def uc03_form(**overrides) -> dict:
    """A direct UC-3 post (old clients / tests); the guide resolves to the same parameters."""
    return {"run_id": "e1", "use_case": "uc03", "protocol": "est", "auth_method": "passcode", "count": "1",
            "variant": "api", "mode": "single", "ca_id": ECDSA_CA_ID} | overrides


def management_writes(fake) -> list[str]:
    return [name for name in fake.route_order() if name not in ("cas", "profiles")]


# --- form (UC-3 lives in the guide now: tests/component/test_web_guide.py) -----------------------

def test_uc03_link_goes_to_the_guide(configured_user, fake):
    response = configured_user.get("/runs/new/uc03", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/new/evergreen"
    assert management_writes(fake) == []


# --- run creation ------------------------------------------------------------------------------

@pytest.mark.parametrize("overrides,message", [
    ({"protocol": ""}, "Select an enrollment protocol and an authentication method."),
    ({"protocol": "EST"}, "Select an enrollment protocol and an authentication method."),
    ({"protocol": "acme"}, "Select an enrollment protocol and an authentication method."),
    ({"auth_method": "basic"}, "Select an enrollment protocol and an authentication method."),
    ({"auth_method": ""}, "Select an enrollment protocol and an authentication method."),
    ({"auth_method": "apikey"}, "An API key works only with the REST API."),
    ({"protocol": "scep"}, "SCEP needs an RSA issuing CA"),
    ({"protocol": "scep", "auth_method": "certificate", "ca_id": RSA_CA_ID},
     "SCEP authenticates with a passcode (challenge password)."),
])
def test_uc03_validation(configured_user, store, fake, overrides, message):
    response = configured_user.post("/runs", data=uc03_form(**overrides), follow_redirects=False)
    assert response.status_code == 400 and message in response.text
    assert store.list_runs() == []
    assert management_writes(fake) == []  # at most the read-only CA lookup ran


def test_uc03_count_is_always_one(configured_user, store, enroll_net):
    for i, count in enumerate(("0", "11", "500")):
        assert configured_user.post("/runs", data=uc03_form(run_id=f"n{i}", count=count),
                                    follow_redirects=False).status_code == 303
        assert finished(store, f"n{i}")["params"]["count"] == 1
    assert len(enroll_net.issued()) == 3


def test_uc03_run_through_the_web(configured_user, store, enroll_net):
    # variant/mode/approval from the form are ignored: UC-3 is API-only, one device, no approval
    data = uc03_form(variant="webui", mode="batch", approval="true", protocol="rest", auth_method="certificate")
    response = configured_user.post("/runs", data=data, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs/e1"
    run = finished(store, "e1")
    assert run["status"] == "completed", run["error"]
    assert run["use_case"] == "uc03"
    p = run["params"]
    assert (p["variant"], p["mode"], p["approval"], p["protocol"], p["auth"], p["count"]) == (
        "api", "single", False, "rest", "certificate", 1)
    assert len(enroll_net.issued()) == 1 and enroll_net.violations == []
    html = configured_user.get("/runs/e1").text
    assert "REST API · Factory certificate · 1 request ·" in html
    assert "1,000 devices ≈" in html and f'{run["result"]["estimate_min"]} min' in html
    assert "<summary>First enrollment</summary>" in html
    assert "Upload done" not in html


def test_uc03_scep_through_the_web(configured_user, store, enroll_net, scep_client):
    response = configured_user.post("/runs", data=uc03_form(protocol="scep", ca_id=RSA_CA_ID), follow_redirects=False)
    assert response.status_code == 303
    run = finished(store, "e1")
    assert run["status"] == "completed", run["error"]
    assert "SCEP · Passcode · 1 request ·" in configured_user.get("/runs/e1").text
    passcode = enroll_net.active_auth("passcode")[0]["body"]["passcode"]
    for path in ("/runs/e1", "/runs/e1/timeline", "/runs/e1/api?dialect=curl", "/runs/e1/api?dialect=powershell"):
        assert passcode not in configured_user.get(path).text


def test_uc03_single_request_wording(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc03_form(count="1"))
    assert finished(store, "e1")["status"] == "completed"
    assert "EST · Passcode · 1 request ·" in configured_user.get("/runs/e1").text


def test_uc03_failed_run_page_shows_the_error_without_secret(configured_user, store, enroll_net):
    from tests.fakedtm import _error
    enroll_net.enroll_fail = _error(401, "invalid passcode")
    configured_user.post("/runs", data=uc03_form())
    run = finished(store, "e1")
    assert run["status"] == "failed" and run["error"].startswith("EST returned 401")
    passcode = enroll_net.active_auth("passcode")[0]["body"]["passcode"]
    pages = "".join(configured_user.get(path).text for path in
                    ("/runs/e1", "/runs/e1/live", "/runs/e1/timeline", "/runs/e1/api?dialect=curl",
                     "/runs/e1/api?dialect=powershell", "/runs/e1/api?dialect=wget"))
    assert passcode not in pages and "PRIVATE KEY" not in pages


@pytest.mark.parametrize("protocol", list(enrollment.PROTOCOLS))
def test_uc03_api_tab_renders_for_every_protocol(configured_user, store, enroll_net, cmp_openssl, scep_client,
                                                 protocol):
    extra = {"ca_id": RSA_CA_ID} if protocol == "scep" else {}
    configured_user.post("/runs", data=uc03_form(protocol=protocol, **extra))
    assert finished(store, "e1")["status"] == "completed"
    for dialect in ("curl", "wget", "powershell"):
        response = configured_user.get(f"/runs/e1/api?dialect={dialect}")
        assert response.status_code == 200
        assert enroll_net.active_auth("passcode")[0]["body"]["passcode"] not in response.text


def test_uc03_full_rollback_through_the_web(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc03_form())
    finished(store, "e1")
    configured_user.post("/runs/e1/cleanup", data={"mode": "full"})
    run = cleaned(store, "e1")
    assert run["cleanup_status"] == "done", store.events("e1")
    assert all(o["status"] == "DELETED" for objs in enroll_net.auth_objects.values() for o in objs.values())
    assert enroll_net.policies == {} and enroll_net.divisions == {} and enroll_net.issued() == []


# --- certificate PEM downloads (all use cases) -------------------------------------------------

def pem_links(html: str) -> list[str]:
    return re.findall(r'href="(/runs/[a-z0-9]+/certificates/[0-9A-F]+\.pem)" download', html)


def test_pem_download_happy_path(configured_user, store, data_dir):
    configured_user.post("/runs", data=form(mode="batch", count="2"))
    run = finished(store, "r1")
    assert run["status"] == "completed"
    certificates = run["result"]["certificates"]
    links = pem_links(configured_user.get("/runs/r1").text)
    assert links == [f"/runs/r1/certificates/{c['serial']}.pem" for c in certificates]
    for c, link in zip(certificates, links):
        response = configured_user.get(link)
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/x-pem-file"
        assert f'filename="{c["common_name"]}.pem"' in response.headers["content-disposition"]
        assert "PRIVATE KEY" not in response.text
        cert = x509.load_pem_x509_certificate(response.content)
        assert format(cert.serial_number, "X") == c["serial"]
        assert response.content == (data_dir / "runs" / "r1" / "certificates" / f"{c['serial']}.pem").read_bytes()
    # the polled devices card links the same way
    assert pem_links(configured_user.get("/runs/r1/devices").text) == links
    assert "BEGIN CERTIFICATE" not in json.dumps(store.get_run("r1"))


def test_pem_download_for_uc03(configured_user, store, enroll_net):
    configured_user.post("/runs", data=uc03_form())
    run = finished(store, "e1")
    (link,) = pem_links(configured_user.get("/runs/e1").text)
    response = configured_user.get(link)
    assert response.status_code == 200
    assert x509.load_pem_x509_certificate(response.content).serial_number == int(
        run["result"]["certificates"][0]["serial"], 16)


def test_pem_download_refuses_everything_else(configured_user, store, data_dir):
    configured_user.post("/runs", data=form(run_id="r1"))
    configured_user.post("/runs", data=form(run_id="r2"))
    r1, r2 = finished(store, "r1"), finished(store, "r2")
    serial = r1["result"]["certificates"][0]["serial"]
    other = r2["result"]["certificates"][0]["serial"]
    assert configured_user.get(f"/runs/r1/certificates/{serial}.pem").status_code == 200
    # a stray file in the directory that is not one of the run's certificates
    (data_dir / "runs" / "r1" / "certificates" / "ABCDEF.pem").write_text("not listed")
    for path in (f"/runs/r1/certificates/{other}.pem",        # another run's certificate
                 f"/runs/r2/certificates/{serial}.pem",        # ... and the other way round
                 f"/runs/r1/certificates/{serial.lower()}.pem",
                 "/runs/r1/certificates/ABCDEF.pem",
                 f"/runs/r1/certificates/{serial}.PEM",
                 f"/runs/r1/certificates/{serial}",
                 "/runs/r1/certificates/..%2F..%2Fdemonstrator.db.pem",
                 "/runs/r1/certificates/%2E%2E.pem",
                 "/runs/r1/certificates/../../demonstrator.db",
                 f"/runs/nope/certificates/{serial}.pem",
                 f"/runs/R1/certificates/{serial}.pem"):
        response = configured_user.get(path)
        assert response.status_code == 404, path
        assert "BEGIN CERTIFICATE" not in response.text and "SQLite" not in response.text


def test_pem_download_refuses_a_tampered_serial_in_the_result(configured_user, store, data_dir):
    """Even if a stored serial were not hex, it must not be used to build a path."""
    configured_user.post("/runs", data=form())
    run = finished(store, "r1")
    result = run["result"]
    result["certificates"][0]["serial"] = "..%2Fsecret"
    store.update_run("r1", result=result)
    (data_dir / "runs" / "r1" / "secret.pem").write_text("outside the certificates directory")
    assert configured_user.get("/runs/r1/certificates/..%2Fsecret.pem").status_code == 404


def test_pem_download_requires_login(web, configured_store, store):
    response = web.get("/runs/r1/certificates/ABC.pem", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_no_links_without_pem_files(configured_user, store, data_dir):
    """Runs from before the PEM downloads (no certificates directory) show plain names."""
    import shutil
    configured_user.post("/runs", data=form())
    run = finished(store, "r1")
    shutil.rmtree(data_dir / "runs" / "r1" / "certificates")
    html = configured_user.get("/runs/r1").text
    assert pem_links(html) == [] and run["result"]["certificates"][0]["common_name"] in html
    serial = run["result"]["certificates"][0]["serial"]
    assert configured_user.get(f"/runs/r1/certificates/{serial}.pem").status_code == 404


def test_pem_files_follow_the_cleanup_mode(configured_user, store, data_dir):
    configured_user.post("/runs", data=form())
    serial = finished(store, "r1")["result"]["certificates"][0]["serial"]
    link = f"/runs/r1/certificates/{serial}.pem"
    configured_user.post("/runs/r1/cleanup", data={"mode": "certificates"})
    assert cleaned(store, "r1")["cleanup_status"] == "done"
    assert configured_user.get(link).status_code == 200  # revoked, but the run keeps its downloads
    assert pem_links(configured_user.get("/runs/r1").text) == [link]
    configured_user.post("/runs/r1/cleanup", data={"mode": "full"})
    assert cleaned(store, "r1")["cleanup_status"] == "done"
    assert configured_user.get(link).status_code == 404
    assert pem_links(configured_user.get("/runs/r1").text) == []
    assert not (data_dir / "runs" / "r1").exists()
