"""Settings → HTTPS certificate: upload (PEM pair, PKCS#12), the form's errors, reset to default, a reload the proxy
refuses, and that only the logged-in admin gets there. Caddy's admin API is faked (tests/fakecaddy.py)."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app import tls_setup
from tests.fakecaddy import caddy  # noqa: F401 – fixture
from tests.unit.test_tls_settings import p12, self_signed_default
from tests.unit.test_tls_setup import key_pem, make_cert, pem

XSS = '<img src=x onerror="alert(1)">'


@pytest.fixture
def started(caddy, monkeypatch):  # noqa: F811
    cert, key = self_signed_default()
    monkeypatch.setattr(tls_setup, "TARGET", caddy.live)
    tls_setup.write([cert], key, tls_setup.DEFAULT)
    tls_setup.write([cert], key)
    caddy.served = cert
    return cert


@pytest.fixture
def pair():
    key = ec.generate_private_key(ec.SECP256R1())
    return make_cert("upload.demo", key, sans=("upload.demo",)), key


def send(client, mode="pem", **files):
    data = {"mode": mode} | {k: v for k, v in files.items() if isinstance(v, str)}
    uploads = {k: (f"{k}.bin", v) for k, v in files.items() if isinstance(v, bytes)}
    return client.post("/settings/tls", data=data, files=uploads or None, follow_redirects=False)


def test_page_shows_the_active_certificate(user, started):
    html = user.get("/settings").text
    assert '<h2>HTTPS certificate <span class="badge">Self-signed default</span></h2>' in html
    assert "<dt>Common name</dt><dd>192.0.2.10</dd>" in html and "Reset to default" not in html
    assert 'enctype="multipart/form-data"' in html and 'name="password"' in html


def test_page_without_live_directory(user, tmp_path, monkeypatch):
    from app import tls_settings
    monkeypatch.setattr(tls_settings, "LIVE", tmp_path / "missing")
    html = user.get("/settings").text
    assert "The active certificate cannot be read." in html  # an install without the mount: nothing breaks


def test_upload_pem_pair(user, caddy, started, pair):  # noqa: F811
    cert, key = pair
    response = send(user, certificate=pem(cert), private_key=key_pem(key))
    assert response.status_code == 303 and response.headers["location"] == "/settings#tls"
    assert caddy.served == cert
    html = user.get("/settings").text
    assert '<span class="badge">Settings</span>' in html and "<dd>upload.demo</dd>" in html
    assert "Reset to default" in html and "PRIVATE KEY" not in html


def test_upload_pkcs12(user, caddy, started, pair):  # noqa: F811
    cert, key = pair
    response = send(user, "pkcs12", keystore=p12(key, cert), password="p12-pass")
    assert response.status_code == 303 and caddy.served == cert
    assert x509.load_pem_x509_certificates((caddy.live / "settings-cert.pem").read_bytes()) == [cert]
    assert all(b"p12-pass" not in f.read_bytes() for f in caddy.live.iterdir())  # the password is never stored


@pytest.mark.parametrize("case,message", [
    ("wrong-password", "The PKCS#12 file could not be opened – wrong password or not a PKCS#12 file"),
    ("mismatch", "The private key does not belong to the certificate"),
    ("garbage", "The certificate file is not a PEM certificate"),
    ("expired", "The certificate has expired"),
    ("missing", "Choose the certificate and the private key file"),
])
def test_upload_errors_change_nothing(user, caddy, started, pair, case, message):  # noqa: F811
    cert, key = pair
    old_key = ec.generate_private_key(ec.SECP256R1())
    response = {
        "wrong-password": lambda: send(user, "pkcs12", keystore=p12(key, cert), password=f"wrong{XSS}"),
        "mismatch": lambda: send(user, certificate=pem(cert), private_key=key_pem(old_key)),
        "garbage": lambda: send(user, certificate=XSS.encode(), private_key=key_pem(key)),
        "expired": lambda: send(user, certificate=pem(make_cert("old.demo", old_key, days=-1)),
                                private_key=key_pem(old_key)),
        "missing": lambda: send(user, certificate=pem(cert)),
    }[case]()
    assert response.status_code == 400 and message in response.text
    assert XSS not in response.text and "PRIVATE KEY" not in response.text
    assert caddy.requests == [] and not (caddy.live / "settings-cert.pem").exists()
    if case == "wrong-password":  # the PKCS#12 fields stay selected; the password is not echoed
        assert 'value="pkcs12" checked' in response.text and 'value="wrong' not in response.text


def test_proxy_refusing_the_reload_rolls_back(user, caddy, started, pair):  # noqa: F811
    caddy.fail = "refuse"
    response = send(user, certificate=pem(pair[0]), private_key=key_pem(pair[1]))
    assert response.status_code == 400 and "The proxy refused the certificate – the previous one stays active." \
        in response.text
    assert "failed to find any PEM data" not in response.text  # no raw proxy text in the page
    assert caddy.served == started and '<span class="badge">Self-signed default</span>' in response.text


def test_too_large_upload_is_refused_before_parsing(user, caddy, started):  # noqa: F811
    response = send(user, certificate=b"x" * (3 * tls_setup.MAX_SIZE), private_key=b"k")
    assert response.status_code == 413 and "larger than 1 MB" in response.text and caddy.requests == []


def test_reset_to_default(user, caddy, started, pair):  # noqa: F811
    send(user, certificate=pem(pair[0]), private_key=key_pem(pair[1]))
    response = user.post("/settings/tls/reset", follow_redirects=False)
    assert response.status_code == 303 and caddy.served == started
    html = user.get("/settings").text
    assert '<span class="badge">Self-signed default</span>' in html and "Reset to default" not in html


def test_reset_failure_is_reported(user, caddy, started, pair):  # noqa: F811
    send(user, certificate=pem(pair[0]), private_key=key_pem(pair[1]))
    caddy.fail = "unreachable"
    response = user.post("/settings/tls/reset", follow_redirects=False)
    assert response.status_code == 400 and "The proxy could not be reached" in response.text
    assert '<span class="badge">Settings</span>' in response.text


@pytest.mark.parametrize("path", ["/settings/tls", "/settings/tls/reset"])
def test_login_required(web, caddy, started, pair, path):  # noqa: F811
    response = web.post(path, data={"mode": "pem"}, files={"certificate": ("c.pem", pem(pair[0]))},
                        follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert caddy.requests == [] and caddy.served == started


def test_cross_origin_post_is_refused(user, caddy, started, pair):  # noqa: F811
    response = user.post("/settings/tls", data={"mode": "pem"}, headers={"Origin": "https://evil.example"},
                         files={"certificate": ("c.pem", pem(pair[0])), "private_key": ("k.pem", key_pem(pair[1]))})
    assert response.status_code == 403 and caddy.requests == []
