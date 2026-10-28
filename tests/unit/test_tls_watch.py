"""Host paths in Settings → HTTPS certificate: the paths as text (app), the files below TLS_HOST_DIR (links followed,
nothing outside), the request/answer handshake with the tls-watch service, applying with rollback, renewals in a
certbot-style layout, what the `tls` service does with host paths at start, and who wins (the last choice).
Caddy's admin API is faked (tests/fakecaddy.py); the watcher's code runs for real."""

import json
import logging
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app import tls_settings, tls_setup, tls_watch
from app.tls_setup import TLSError
from tests.fakecaddy import caddy  # noqa: F401 – fixture
from tests.unit.test_tls_settings import p12, self_signed_default
from tests.unit.test_tls_setup import key_pem, make_cert, pem

NAME = "demonstrator.example.com"


@pytest.fixture
def host(tmp_path, monkeypatch):
    """TLS_HOST_DIR as certbot leaves it: live/<name>/*.pem are relative links into archive/<name>/."""
    root = (tmp_path / "digicert").resolve()  # macOS: /var is a link – the mount is at the real path
    (root / "live" / NAME).mkdir(parents=True)
    (root / "archive" / NAME).mkdir(parents=True)
    monkeypatch.setattr(tls_setup, "HOST_DIR", str(root))
    return root


def issue(root: Path, n: int, cn: str = NAME, days: float = 90, key=None):
    """Version n of the certificate in archive/, the live links pointing to it (what a renewal does)."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(cn, key, days=days, sans=(cn,))
    archive, live = root / "archive" / NAME, root / "live" / NAME
    (archive / f"fullchain{n}.pem").write_bytes(pem(cert))
    (archive / f"privkey{n}.pem").write_bytes(key_pem(key))
    (archive / f"privkey{n}.pem").chmod(0o600)
    for name in ("fullchain", "privkey"):
        (live / f"{name}.pem").unlink(missing_ok=True)
        (live / f"{name}.pem").symlink_to(f"../../archive/{NAME}/{name}{n}.pem")
    return cert, key


def pem_config(root: Path) -> dict:
    return {"mode": "pem", "certificate": f"{root}/live/{NAME}/fullchain.pem",
            "private_key": f"{root}/live/{NAME}/privkey.pem"}


@pytest.fixture
def started(caddy, monkeypatch, tmp_path):  # noqa: F811
    cert, key = self_signed_default()
    monkeypatch.setattr(tls_setup, "TARGET", caddy.live)
    monkeypatch.setattr(tls_setup, "SOURCE", tmp_path / "tls-in")  # nothing in .env
    monkeypatch.setattr(tls_watch, "_state", {})
    tls_setup.write([cert], key, tls_setup.DEFAULT)
    tls_setup.write([cert], key)
    caddy.served = cert
    return cert


def request(config: dict, request_id: str = "r1") -> None:
    """What tls_settings.request_host writes for the watcher."""
    (tls_settings.LIVE / tls_settings.REQUEST).write_text(json.dumps({"id": request_id} | config))


def answer() -> dict:
    return json.loads((tls_settings.LIVE / tls_settings.STATUS).read_text())


def files(live: Path) -> dict[str, bytes]:
    """The certificate files – without the watcher's answer."""
    return {p.name: p.read_bytes() for p in live.iterdir() if p.name != tls_settings.STATUS}


# --- the paths as text (app side) ---------------------------------------------------------------------

def test_host_config_normalises_paths_inside_the_directory(host):
    config = tls_settings.host_config("pem", f" {host}/live/./{NAME}/fullchain.pem ", f"{host}/live/{NAME}/privkey.pem",
                                      "", "ignored")
    assert config == pem_config(host)  # no password for PEM
    assert tls_settings.host_config("pkcs12", "", "", f"{host}/demo.p12", "pw") == {
        "mode": "pkcs12", "keystore": f"{host}/demo.p12", "password": "pw"}


@pytest.mark.parametrize("value,message", [
    ("", "enter the path of the certificate file"),
    ("live/x/fullchain.pem", "the path of the certificate file must be absolute"),
    ("/etc/shadow", "the path of the certificate file must be inside "),
    ("{root}/../shadow", "the path of the certificate file must be inside "),
    ("{root}-other/cert.pem", "the path of the certificate file must be inside "),  # a sibling with the same prefix
    ("{root}", "the path of the certificate file must be inside "),
    ("{root}/a\nb.pem", "the path of the certificate file is not valid"),
    ("{root}/" + "a" * 1100, "the path of the certificate file is not valid"),
])
def test_host_config_refuses(host, value, message):
    with pytest.raises(TLSError) as caught:
        tls_settings.host_config("pem", value.format(root=host), f"{host}/key.pem", "", "")
    assert str(caught.value).startswith(message)


def test_host_config_needs_the_directory_and_a_format(host, monkeypatch):
    with pytest.raises(TLSError, match="choose PEM or PKCS#12"):
        tls_settings.host_config("host", f"{host}/c.pem", f"{host}/k.pem", "", "")
    with pytest.raises(TLSError, match="the password is too long"):
        tls_settings.host_config("pkcs12", "", "", f"{host}/a.p12", "x" * 2000)
    monkeypatch.setattr(tls_setup, "HOST_DIR", "")
    with pytest.raises(TLSError, match=r"set TLS_HOST_DIR in \.env first \(or run install\.sh --tls-dir PATH\)"):
        tls_settings.host_config("pem", "/etc/digicert/c.pem", "/etc/digicert/k.pem", "", "")


# --- the files (watcher side) ---------------------------------------------------------------------------

def test_load_host_follows_relative_links_of_a_certbot_layout(host):
    cert, key = issue(host, 1)
    chain, loaded = tls_setup.load_host(pem_config(host))
    assert chain == [cert] and loaded.private_numbers() == key.private_numbers()


def test_load_host_pkcs12(host):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(NAME, key)
    (host / "demo.p12").write_bytes(p12(key, cert))
    config = {"mode": "pkcs12", "keystore": f"{host}/demo.p12", "password": "p12-pass"}
    assert tls_setup.load_host(config)[0] == [cert]
    with pytest.raises(TLSError) as caught:
        tls_setup.load_host(config | {"password": "wrong"})
    assert str(caught.value) == "the PKCS#12 file could not be opened – wrong password or not a PKCS#12 file"


@pytest.mark.parametrize("case", ["absolute", "relative"])
def test_a_link_out_of_the_directory_is_refused(host, tmp_path, case):
    secret = tmp_path / "secret.pem"
    secret.write_text("not for the admin")
    link = host / "live" / NAME / "fullchain.pem"
    link.symlink_to(secret if case == "absolute" else Path("../../..") / "secret.pem")
    assert link.resolve() == secret.resolve()
    with pytest.raises(TLSError) as caught:
        tls_setup.read_host(str(link), "the certificate file")
    assert str(caught.value) == f"the certificate file {link} is outside {host} (links followed)"


def test_a_path_outside_the_directory_is_refused_even_when_given_directly(host, tmp_path):
    with pytest.raises(TLSError, match="is outside"):
        tls_setup.read_host(str(tmp_path / "elsewhere.pem"), "the certificate file")


@pytest.mark.parametrize("case,message", [
    ("missing", "the certificate file {path} does not exist"),
    ("directory", "the certificate file {path} is not a file"),
    ("fifo", "the certificate file {path} is not a file"),
    ("large", "the certificate file {path} is larger than 1 MB – not a certificate or key"),
    ("unreadable", "the certificate file {path} cannot be read – it must be readable by root"),
])
def test_unusable_files(host, case, message):
    path = host / "live" / NAME / "cert.pem"
    if case == "directory":
        path.mkdir()
    if case == "fifo":
        os.mkfifo(path)  # opened non-blocking: no writer must not hang the service
    if case == "large":
        path.write_bytes(b"x" * (tls_setup.MAX_SIZE + 1))
    if case == "unreadable":
        if os.geteuid() == 0:
            pytest.fail("runs as root – file permissions cannot be tested")
        path.write_text("x")
        path.chmod(0)
    with pytest.raises(TLSError) as caught:
        tls_setup.read_host(str(path), "the certificate file")
    assert str(caught.value) == message.format(path=path)


def test_read_host_without_a_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(tls_setup, "HOST_DIR", "")
    (tmp_path / "c.pem").write_text("x")
    with pytest.raises(TLSError, match="no host directory is configured – set TLS_HOST_DIR in .env"):
        tls_setup.read_host(str(tmp_path / "c.pem"), "the certificate file")


@pytest.mark.parametrize("case,message", [
    ("expired", "the certificate has expired"),
    ("mismatch", "the private key does not belong to the certificate"),
])
def test_load_host_checks_like_an_upload(host, case, message):
    cert, _ = issue(host, 1, days=-1 if case == "expired" else 90)
    if case == "mismatch":
        (host / "archive" / NAME / "privkey1.pem").write_bytes(key_pem(ec.generate_private_key(ec.SECP256R1())))
    with pytest.raises(TLSError) as caught:
        tls_setup.load_host(pem_config(host))
    assert str(caught.value).startswith(message)


# --- request → answer (the watcher applies) --------------------------------------------------------------

def test_request_is_applied_and_answered(caddy, started, host):  # noqa: F811
    cert, _ = issue(host, 1)
    request(pem_config(host))
    tls_watch.handle_request()
    assert caddy.served == cert and not (caddy.live / tls_settings.REQUEST).exists()
    status = answer()
    assert status["request"] == "r1" and status["request_error"] is None and status["error"] is None
    assert json.loads((caddy.live / tls_setup.HOST_PATHS).read_text()) == pem_config(host)
    assert stat.S_IMODE((caddy.live / tls_setup.HOST_PATHS).stat().st_mode) == 0o640
    assert x509.load_pem_x509_certificates((caddy.live / "settings-cert.pem").read_bytes()) == [cert]
    info = tls_settings.status()
    assert info["source"] == "From host path" and info["common_name"] == NAME and info["can_reset"]
    assert info["host_paths"] == [pem_config(host)["certificate"], pem_config(host)["private_key"]]
    assert info["checked"].endswith(" UTC") and info["check_error"] is None


def test_refused_request_changes_nothing(caddy, started, host):  # noqa: F811
    issue(host, 1)
    (host / "archive" / NAME / "privkey1.pem").write_bytes(key_pem(ec.generate_private_key(ec.SECP256R1())))
    before = files(caddy.live)
    request(pem_config(host))
    tls_watch.handle_request()
    status = answer()
    assert status["request"] == "r1"
    assert status["request_error"].startswith("the private key does not belong to the certificate")
    assert caddy.served == started and caddy.requests == []
    assert files(caddy.live) == before


def test_request_outside_the_directory_is_refused_by_the_watcher_too(caddy, started, host, tmp_path):  # noqa: F811
    """The request file is no authority: the watcher checks the paths again."""
    request({"mode": "pem", "certificate": "/etc/passwd", "private_key": f"{host}/k.pem"})
    tls_watch.handle_request()
    assert answer()["request_error"].startswith("the path of the certificate file must be inside")
    assert caddy.requests == []


@pytest.mark.parametrize("fail", ["refuse", "unreachable"])
def test_a_reload_failure_rolls_back(caddy, started, host, fail):  # noqa: F811
    issue(host, 1)
    before = files(caddy.live)
    caddy.fail = fail
    request(pem_config(host))
    tls_watch.handle_request()
    assert answer()["request_error"] in ("The proxy refused the certificate – the previous one stays active.",
                                         "The proxy could not be reached – the previous certificate stays active.")
    assert files(caddy.live) == before
    assert caddy.served == started and tls_settings.status()["source"] == "Self-signed default"


def test_unreadable_request_is_dropped(caddy, started):  # noqa: F811
    (caddy.live / tls_settings.REQUEST).write_text("{not json")
    tls_watch.handle_request()
    assert not (caddy.live / tls_settings.REQUEST).exists() and not (caddy.live / tls_settings.STATUS).exists()


def test_the_password_is_kept_for_renewals_but_never_logged_or_shown(caddy, started, host, caplog):  # noqa: F811
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(NAME, key)
    (host / "demo.p12").write_bytes(p12(key, cert, password=b"Pw-4-renewals"))
    config = {"mode": "pkcs12", "keystore": f"{host}/demo.p12", "password": "Pw-4-renewals"}
    caplog.set_level(logging.INFO)
    request(config)
    tls_watch.handle_request()
    assert caddy.served == cert
    assert json.loads((caddy.live / tls_setup.HOST_PATHS).read_text())["password"] == "Pw-4-renewals"
    assert stat.S_IMODE((caddy.live / tls_setup.HOST_PATHS).stat().st_mode) == 0o640
    info = tls_settings.status()
    assert info["host_paths"] == [f"{host}/demo.p12"] and "Pw-4-renewals" not in json.dumps(info)
    assert "Pw-4-renewals" not in caplog.text and b"Pw-4-renewals" not in (caddy.live / tls_settings.STATUS).read_bytes()


# --- the app's side of the handshake -------------------------------------------------------------------

@pytest.fixture
def watcher(caddy, started):  # noqa: F811
    """The watcher's request handling in a thread, as the tls-watch service runs it."""
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            tls_watch.handle_request()
            time.sleep(0.02)
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield
    stop.set()
    thread.join(5)


def test_request_host_waits_for_the_answer(caddy, watcher, host):  # noqa: F811
    cert, _ = issue(host, 1)
    tls_settings.request_host(pem_config(host))
    assert caddy.served == cert and tls_settings.status()["source"] == "From host path"
    assert stat.S_IMODE((caddy.live / tls_settings.STATUS).stat().st_mode) == 0o640


def test_request_host_reports_the_watchers_error(caddy, watcher, host):  # noqa: F811
    with pytest.raises(TLSError) as caught:
        tls_settings.request_host(pem_config(host))
    assert str(caught.value) == f"the certificate file {host}/live/{NAME}/fullchain.pem does not exist"


def test_request_host_without_a_watcher_times_out_and_withdraws(caddy, started, host, monkeypatch):  # noqa: F811
    issue(host, 1)
    monkeypatch.setattr(tls_settings, "ANSWER_TIMEOUT", 0.3)
    with pytest.raises(tls_settings.ApplyError) as caught:
        tls_settings.request_host(pem_config(host))
    assert str(caught.value) == ("The tls-watch service did not answer – the request was withdrawn. Check that the "
                                 "service runs, then try again.")
    assert not (caddy.live / tls_settings.REQUEST).exists()  # a watcher starting later does not apply it
    tls_watch.handle_request()
    assert caddy.served == started


def test_an_old_answer_is_not_taken_for_the_new_request(caddy, started, host, monkeypatch):  # noqa: F811
    (caddy.live / tls_settings.STATUS).write_text(json.dumps({"request": "old", "request_error": None}))
    monkeypatch.setattr(tls_settings, "ANSWER_TIMEOUT", 0.3)
    with pytest.raises(tls_settings.ApplyError, match="did not answer"):
        tls_settings.request_host(pem_config(host))


# --- renewals ------------------------------------------------------------------------------------------

@pytest.fixture
def applied(caddy, started, host):  # noqa: F811
    cert, _ = issue(host, 1)
    request(pem_config(host))
    tls_watch.handle_request()
    assert caddy.served == cert
    return cert


def test_a_renewal_is_applied(caddy, host, applied, caplog):  # noqa: F811
    caplog.set_level(logging.INFO)
    tls_watch.check()
    assert caddy.loads == 1  # unchanged files: no reload
    renewed, _ = issue(host, 2)
    tls_watch.check()
    assert caddy.served == renewed and caddy.loads == 2
    assert x509.load_pem_x509_certificates((caddy.live / "settings-cert.pem").read_bytes()) == [renewed]
    assert answer()["error"] is None and "renewed certificate from the host path applied" in caplog.text


@pytest.mark.parametrize("case", ["expired", "mismatch", "missing"])
def test_an_unusable_renewal_keeps_the_current_certificate(caddy, host, applied, caplog, case):  # noqa: F811
    if case == "missing":
        (host / "archive" / NAME / "fullchain1.pem").unlink()
    else:
        issue(host, 2, days=-1 if case == "expired" else 90)
        if case == "mismatch":
            (host / "archive" / NAME / "privkey2.pem").write_bytes(key_pem(ec.generate_private_key(ec.SECP256R1())))
    before = files(caddy.live)
    tls_watch.check()
    tls_watch.check()
    assert caddy.served == applied and caddy.loads == 1
    assert files(caddy.live) == before
    error = answer()["error"]
    assert error.startswith({"expired": "the certificate has expired",
                             "mismatch": "the private key does not belong to the certificate",
                             "missing": "the certificate file"}[case])
    assert caplog.text.count("stays as it is") == 1  # logged once, not every minute
    info = tls_settings.status()
    assert info["source"] == "From host path" and info["check_error"] == error
    issue(host, 3)  # fixed: applied, the error is gone
    tls_watch.check()
    assert caddy.loads == 2 and answer()["error"] is None and tls_settings.status()["check_error"] is None


def test_a_renewal_the_proxy_refuses_is_retried(caddy, host, applied):  # noqa: F811
    renewed, _ = issue(host, 2)
    caddy.fail = "unreachable"
    tls_watch.check()
    assert caddy.served == applied and "could not be reached" in answer()["error"]
    caddy.fail = None
    tls_watch.check()
    assert caddy.served == renewed and answer()["error"] is None


def test_check_without_host_paths_does_nothing(caddy, started):  # noqa: F811
    tls_watch.check()
    assert caddy.requests == [] and not (caddy.live / tls_settings.STATUS).exists()


def test_run_handles_requests_and_survives_a_broken_step(caddy, started, host, monkeypatch, caplog):  # noqa: F811
    cert, _ = issue(host, 1)
    monkeypatch.setattr(tls_watch, "POLL", 0)
    calls = []

    def broken():
        calls.append(1)
        raise RuntimeError("disk full")
    monkeypatch.setattr(tls_watch, "check", broken)
    request(pem_config(host))
    tls_watch.run(rounds=2)
    assert caddy.served == cert and calls == [1]  # the check ran once (then waits INTERVAL), the request was handled
    assert "TLS: broken failed" in caplog.text


# --- the last choice wins --------------------------------------------------------------------------------

def test_an_upload_replaces_the_host_paths(caddy, host, applied):  # noqa: F811
    key = ec.generate_private_key(ec.SECP256R1())
    uploaded = make_cert("upload.example.com", key)
    tls_settings.upload([uploaded], key)
    assert not (caddy.live / tls_setup.HOST_PATHS).exists() and not (caddy.live / tls_settings.STATUS).exists()
    assert tls_settings.status()["source"] == "Settings"
    issue(host, 2)  # a renewal of the old host path no longer counts
    tls_watch.check()
    assert caddy.served == uploaded


def test_host_paths_replace_an_upload(caddy, started, host):  # noqa: F811
    key = ec.generate_private_key(ec.SECP256R1())
    tls_settings.upload([make_cert("upload.example.com", key)], key)
    cert, _ = issue(host, 1)
    request(pem_config(host))
    tls_watch.handle_request()
    assert caddy.served == cert and tls_settings.status()["source"] == "From host path"


def test_reset_clears_the_host_paths(caddy, started, host, applied):  # noqa: F811
    tls_settings.reset()
    assert caddy.served == started and tls_settings.status()["source"] == "Self-signed default"
    assert not any((caddy.live / n).exists() for n in (tls_setup.HOST_PATHS, tls_settings.STATUS, "settings-cert.pem"))
    issue(host, 2)
    tls_watch.check()
    assert caddy.served == started


def test_the_lock_keeps_a_check_and_an_upload_apart(caddy, host, applied, monkeypatch):  # noqa: F811
    """An upload while a renewal check holds the lock waits for it – and then wins."""
    issue(host, 2)
    entered, release = threading.Event(), threading.Event()
    real_load = tls_setup.load_host

    def slow_load(config):
        entered.set()
        release.wait(5)
        return real_load(config)
    monkeypatch.setattr(tls_setup, "load_host", slow_load)
    checker = threading.Thread(target=tls_watch.check)
    checker.start()
    assert entered.wait(5)
    key = ec.generate_private_key(ec.SECP256R1())
    uploaded = make_cert("upload.example.com", key)
    uploader = threading.Thread(target=tls_settings.upload, args=([uploaded], key))
    uploader.start()
    uploader.join(0.3)
    assert uploader.is_alive()  # waits for the check
    release.set()
    checker.join(5)
    uploader.join(5)
    assert caddy.served == uploaded and not (caddy.live / tls_setup.HOST_PATHS).exists()


def test_the_lock_holds_across_processes(caddy, started):  # noqa: F811
    """tls-watch is another process (container): flock on the shared directory keeps an upload waiting."""
    holder = subprocess.Popen(
        [sys.executable, "-c", "import fcntl, os, sys; fd = os.open(sys.argv[1], os.O_RDONLY); "
         "fcntl.flock(fd, fcntl.LOCK_EX); print('locked', flush=True); sys.stdin.read()", str(caddy.live)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        key = ec.generate_private_key(ec.SECP256R1())
        uploaded = make_cert("upload.example.com", key)
        uploader = threading.Thread(target=tls_settings.upload, args=([uploaded], key))
        uploader.start()
        uploader.join(0.3)
        assert uploader.is_alive() and caddy.requests == []  # waits for the other process
    finally:
        holder.communicate("", timeout=10)
    uploader.join(5)
    assert caddy.served == uploaded


# --- the `tls` service at start ---------------------------------------------------------------------------

def test_start_reads_the_host_paths_again(caddy, host, applied, capsys):  # noqa: F811
    renewed, _ = issue(host, 2)  # renewed while the demonstrator was down
    assert tls_setup.main() == 0
    assert x509.load_pem_x509_certificates((caddy.live / "cert.pem").read_bytes()) == [renewed]
    assert x509.load_pem_x509_certificates((caddy.live / "settings-cert.pem").read_bytes()) == [renewed]
    assert "TLS: Settings certificate for demonstrator.example.com" in capsys.readouterr().out


def test_start_keeps_the_last_applied_pair_when_the_host_files_are_broken(caddy, host, applied, capsys):  # noqa: F811
    (host / "archive" / NAME / "fullchain1.pem").unlink()
    assert tls_setup.main() == 0
    assert x509.load_pem_x509_certificates((caddy.live / "cert.pem").read_bytes()) == [applied]
    err = capsys.readouterr().err
    assert "the certificate from the host path is not usable (the certificate file" in err
    assert "keeping the last one applied" in err


def test_start_without_host_directory_keeps_the_last_applied_pair(caddy, host, applied, capsys, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tls_setup, "HOST_DIR", "")
    assert tls_setup.main() == 0
    assert x509.load_pem_x509_certificates((caddy.live / "cert.pem").read_bytes()) == [applied]
    assert "no host directory is configured" in capsys.readouterr().err
