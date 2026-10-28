"""Settings → HTTPS certificate → Path on host: the form (disabled without TLS_HOST_DIR), the request the app hands
to the tls-watch service and its answer, errors (escaped, no password echoed), the watcher not answering, and that
only the logged-in admin of this origin gets there. The watcher's request handling runs for real in a thread;
Caddy's admin API is faked (tests/fakecaddy.py)."""

import pytest

from app import tls_settings, tls_setup, tls_watch
from tests.fakecaddy import caddy  # noqa: F401 – fixture
from tests.unit.test_tls_watch import NAME, issue, pem_config
from tests.unit.test_tls_watch import host, started, watcher  # noqa: F401 – fixtures

XSS = '<img src=x onerror="alert(1)">'


def send(client, fmt="pem", headers=None, **fields):
    data = {"mode": "host", "host_format": fmt} | fields
    return client.post("/settings/tls", data=data, files={"certificate": ("", b"")}, headers=headers or {},
                       follow_redirects=False)


def test_without_host_directory_the_option_is_disabled(user, started, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tls_setup, "HOST_DIR", "")
    html = user.get("/settings").text
    assert '<input type="radio" name="mode" value="host"  disabled>' in html
    assert "Path on host: set TLS_HOST_DIR in .env (or run install.sh --tls-dir PATH) and run the installer again." \
        in html
    response = send(user, host_certificate="/etc/digicert/c.pem", host_private_key="/etc/digicert/k.pem")
    assert response.status_code == 400
    assert "Set TLS_HOST_DIR in .env first (or run install.sh --tls-dir PATH)" in response.text


def test_with_host_directory_the_option_is_offered(user, started, host):  # noqa: F811
    html = user.get("/settings").text
    assert '<input type="radio" name="mode" value="host" >' in html and "TLS_HOST_DIR in .env" not in html
    assert 'name="host_certificate"' in html and 'name="host_private_key"' in html
    assert 'name="host_keystore"' in html and 'type="password" name="host_password"' in html
    assert f'placeholder="{host}/live/…/fullchain.pem"' in html


def test_apply_host_paths(user, caddy, watcher, host):  # noqa: F811
    cert, _ = issue(host, 1)
    config = pem_config(host)
    response = send(user, host_certificate=config["certificate"], host_private_key=config["private_key"])
    assert response.status_code == 303 and response.headers["location"] == "/settings#tls"
    assert caddy.served == cert
    html = user.get("/settings").text
    assert '<span class="badge">From host path</span>' in html and f"<dd>{NAME}</dd>" in html
    assert f'<dd class="mono">{config["certificate"]} · {config["private_key"]}</dd>' in html
    assert "<dt>Renewal check</dt>" in html and "Reset to default" in html


def test_pkcs12_password_is_never_shown(user, caddy, watcher, host):  # noqa: F811
    from cryptography.hazmat.primitives.asymmetric import ec
    from tests.unit.test_tls_settings import p12
    from tests.unit.test_tls_setup import make_cert
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(NAME, key)
    (host / "demo.p12").write_bytes(p12(key, cert, password=b"Hidden-Pw-1"))
    response = send(user, "pkcs12", host_keystore=f"{host}/demo.p12", host_password="Hidden-Pw-1")
    assert response.status_code == 303 and caddy.served == cert
    html = user.get("/settings").text
    assert f'<dd class="mono">{host}/demo.p12</dd>' in html and "Hidden-Pw-1" not in html
    response = send(user, "pkcs12", host_keystore=f"{host}/demo.p12", host_password="Wrong-Pw-2")
    assert response.status_code == 400 and "Wrong-Pw-2" not in response.text
    assert "The PKCS#12 file could not be opened – wrong password or not a PKCS#12 file" in response.text


def test_watcher_error_is_shown_escaped_and_the_entries_stay(user, caddy, watcher, host):  # noqa: F811
    certificate = f"{host}/live/{XSS}/fullchain.pem"
    response = send(user, host_certificate=certificate, host_private_key=f"{host}/k.pem")
    assert response.status_code == 400
    assert XSS not in response.text
    escaped = "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;"
    assert f"The certificate file {host}/live/{escaped}/fullchain.pem does not exist" in response.text
    assert f'value="{host}/live/{escaped}/fullchain.pem"' in response.text  # the entry stays, escaped
    assert 'value="host" checked' in response.text and caddy.requests == []
    assert '<span class="badge">Self-signed default</span>' in response.text


@pytest.mark.parametrize("certificate,message", [
    ("relative/fullchain.pem", "The path of the certificate file must be absolute"),
    ("/etc/shadow", "The path of the certificate file must be inside "),
    ("", "Enter the path of the certificate file"),
])
def test_path_errors_are_refused_before_asking_the_watcher(user, caddy, started, host, certificate, message):  # noqa: F811
    response = send(user, host_certificate=certificate, host_private_key=f"{host}/k.pem")
    assert response.status_code == 400 and message in response.text
    assert not (caddy.live / tls_settings.REQUEST).exists() and caddy.requests == []


def test_watcher_not_answering(user, caddy, started, host, monkeypatch):  # noqa: F811
    issue(host, 1)
    monkeypatch.setattr(tls_settings, "ANSWER_TIMEOUT", 0.3)
    config = pem_config(host)
    response = send(user, host_certificate=config["certificate"], host_private_key=config["private_key"])
    assert response.status_code == 503
    assert "The tls-watch service did not answer – the request was withdrawn." in response.text
    assert not (caddy.live / tls_settings.REQUEST).exists() and caddy.served == started


def test_renewal_error_is_shown(user, caddy, watcher, host):  # noqa: F811
    issue(host, 1)
    config = pem_config(host)
    send(user, host_certificate=config["certificate"], host_private_key=config["private_key"])
    issue(host, 2, days=-1)
    tls_watch.check()
    html = user.get("/settings").text
    assert '<span class="badge">From host path</span>' in html
    assert "The certificate has expired – the current certificate stays" in html


def test_upload_after_host_paths_wins(user, caddy, watcher, host):  # noqa: F811
    from cryptography.hazmat.primitives.asymmetric import ec
    from tests.unit.test_tls_setup import key_pem, make_cert, pem
    issue(host, 1)
    config = pem_config(host)
    send(user, host_certificate=config["certificate"], host_private_key=config["private_key"])
    key = ec.generate_private_key(ec.SECP256R1())
    uploaded = make_cert("upload.example.com", key)
    response = user.post("/settings/tls", data={"mode": "pem"}, follow_redirects=False,
                         files={"certificate": ("c.pem", pem(uploaded)), "private_key": ("k.pem", key_pem(key))})
    assert response.status_code == 303 and caddy.served == uploaded
    html = user.get("/settings").text
    assert '<span class="badge">Settings</span>' in html and "<dt>Host path</dt>" not in html


def test_login_required(web, caddy, started, host):  # noqa: F811
    response = send(web, host_certificate=f"{host}/c.pem", host_private_key=f"{host}/k.pem")
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert not (caddy.live / tls_settings.REQUEST).exists()


def test_cross_origin_post_is_refused(user, caddy, started, host):  # noqa: F811
    response = send(user, headers={"Origin": "https://evil.example"}, host_certificate=f"{host}/c.pem",
                    host_private_key=f"{host}/k.pem")
    assert response.status_code == 403 and not (caddy.live / tls_settings.REQUEST).exists()
