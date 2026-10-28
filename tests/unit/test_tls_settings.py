"""app/tls_settings.py – the HTTPS certificate set in Settings: checks of the upload, the live swap with Caddy's
reload (fake admin API), rollback when the reload fails, reset to the default, and what the page shows."""

import stat

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from cryptography import x509

from app import tls_settings, tls_setup
from app.tls_setup import TLSError
from tests.fakecaddy import caddy  # noqa: F401 – fixture
from tests.unit.test_tls_setup import key_pem, make_cert, pem


def p12(key, cert, extra=None, password: bytes | None = b"p12-pass") -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"demo", key, cert, extra, enc)


@pytest.fixture
def pair():
    key = ec.generate_private_key(ec.SECP256R1())
    return make_cert("upload.demo", key, sans=("upload.demo",)), key


def self_signed_default():
    """The installer's default: O=DTM Demonstrator self-signed."""
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives import hashes
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DTM Demonstrator self-signed"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "192.0.2.10")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=700))
            .sign(key, hashes.SHA256()))
    return cert, key


@pytest.fixture
def started(caddy, monkeypatch):  # noqa: F811
    """The live directory as the `tls` service leaves it: the default pair, served."""
    cert, key = self_signed_default()
    monkeypatch.setattr(tls_setup, "TARGET", caddy.live)
    tls_setup.write([cert], key, tls_setup.DEFAULT)
    tls_setup.write([cert], key)
    caddy.served = cert
    return cert


# --- parse ------------------------------------------------------------------------------------------

def test_parse_pem_pair_with_chain():
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = make_cert("Test CA", ca_key, ca=True, sans=())
    leaf = make_cert("upload.demo", key, ca, ca_key)
    chain, parsed = tls_settings.parse("pem", pem(leaf) + pem(ca), key_pem(key), b"", "")
    assert chain == [leaf, ca] and parsed.private_numbers() == key.private_numbers()


def test_parse_pkcs12(pair):
    cert, key = pair
    chain, _ = tls_settings.parse("pkcs12", b"", b"", p12(key, cert), "p12-pass")
    assert chain == [cert]


@pytest.mark.parametrize("mode,files,message", [
    ("pkcs12", "wrong-password", "the PKCS#12 file could not be opened – wrong password or not a PKCS#12 file"),
    ("pkcs12", "garbage-p12", "the PKCS#12 file could not be opened – wrong password or not a PKCS#12 file"),
    ("pem", "mismatch", "the private key does not belong to the certificate"),
    ("pem", "garbage-cert", "the certificate file is not a PEM certificate"),
    ("pem", "garbage-key", "the private key file is not a PEM private key"),
    ("pem", "encrypted-key", "the private key file is encrypted"),
    ("pem", "key-missing", "choose the certificate and the private key file"),
    ("pkcs12", "p12-missing", "choose the PKCS#12 file"),
    ("both", "ok", "choose PEM or PKCS#12"),
])
def test_parse_errors(pair, mode, files, message):
    cert, key = pair
    other = ec.generate_private_key(ec.SECP256R1())
    args = {"wrong-password": (b"", b"", p12(key, cert), "wrong"),
            "garbage-p12": (b"", b"", b"not a keystore", "p12-pass"),
            "mismatch": (pem(cert), key_pem(other), b"", ""),
            "garbage-cert": (b"not a certificate", key_pem(key), b"", ""),
            "garbage-key": (pem(cert), b"not a key", b"", ""),
            "encrypted-key": (pem(cert), key_pem(key, password=b"secret"), b"", ""),
            "key-missing": (pem(cert), b"", b"", ""),
            "p12-missing": (pem(cert), key_pem(key), b"", "p12-pass"),
            "ok": (pem(cert), key_pem(key), b"", "")}[files]
    with pytest.raises(TLSError) as caught:
        tls_settings.parse(mode, *args)
    assert str(caught.value).startswith(message)
    assert "p12-pass" not in str(caught.value) and "secret" not in str(caught.value)


def test_parse_refuses_a_too_large_file(pair):
    cert, key = pair
    with pytest.raises(TLSError, match="larger than 1 MB"):
        tls_settings.parse("pem", pem(cert) + b"\n" * tls_setup.MAX_SIZE, key_pem(key), b"", "")


def test_parse_refuses_an_expired_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(TLSError, match="the certificate has expired"):
        tls_settings.parse("pem", pem(make_cert("old.demo", key, days=-1)), key_pem(key), b"", "")


def test_parse_refuses_a_certificate_that_is_not_valid_yet():
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives import hashes
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "future.demo")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now + timedelta(days=2)).not_valid_after(now + timedelta(days=90))
            .sign(key, hashes.SHA256()))
    with pytest.raises(TLSError, match="not valid yet"):
        tls_settings.parse("pem", pem(cert), key_pem(key), b"", "")


# --- upload, reload, rollback --------------------------------------------------------------------------

def test_upload_applies_live_and_persists(caddy, started, pair):
    cert, key = pair
    tls_settings.upload([cert], key)
    assert caddy.served == cert and caddy.loads == 1
    get, post = caddy.requests
    assert (get.method, get.url.path, post.method, post.url.path) == ("GET", "/config/", "POST", "/load")
    assert post.headers["cache-control"] == "must-revalidate"
    for name in ("cert.pem", "settings-cert.pem"):
        assert x509.load_pem_x509_certificates((caddy.live / name).read_bytes()) == [cert]
    for name in ("key.pem", "settings-key.pem"):
        assert stat.S_IMODE((caddy.live / name).stat().st_mode) == 0o640
    assert x509.load_pem_x509_certificates((caddy.live / "default-cert.pem").read_bytes()) == [started]
    assert not list(caddy.live.glob(".*"))  # no backups or temp files left
    info = tls_settings.status()
    assert info["source"] == "Settings" and info["common_name"] == "upload.demo" and info["can_reset"]
    assert info["sans"] == ["DNS upload.demo"] and info["state"] == "ok"


def test_upload_reloads_with_the_running_config(caddy, started, pair):
    tls_settings.upload([pair[0]], pair[1])
    get, post = caddy.requests
    assert post.content == b'{"admin":{"listen":"unix//run/caddy-admin/admin.sock|0666"},"apps":{"http":{}}}'


@pytest.mark.parametrize("fail,message", [
    ("refuse", "The proxy refused the certificate – the previous one stays active."),
    ("unreachable", "The proxy could not be reached – the previous certificate stays active."),
])
def test_failed_reload_rolls_back(caddy, started, pair, fail, message):
    before = {p.name: p.read_bytes() for p in caddy.live.iterdir()}
    caddy.fail = fail
    with pytest.raises(tls_settings.ApplyError, match=message):
        tls_settings.upload([pair[0]], pair[1])
    assert {p.name: p.read_bytes() for p in caddy.live.iterdir()} == before  # exactly the previous files
    assert caddy.served == started
    assert tls_settings.status()["source"] == "Self-signed default"


def test_lost_answer_reloads_the_restored_files(caddy, started, pair):
    """Caddy took the new pair, but its answer never came: after the rollback Caddy must serve the old one again."""
    caddy.fail = "lost"
    with pytest.raises(tls_settings.ApplyError, match="could not be reached"):
        tls_settings.upload([pair[0]], pair[1])
    assert caddy.served == started and caddy.loads == 2


def test_replacing_a_settings_certificate_keeps_the_previous_on_failure(caddy, started, pair):
    first, first_key = pair
    tls_settings.upload([first], first_key)
    caddy.fail = "refuse"
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(tls_settings.ApplyError):
        tls_settings.upload([make_cert("second.demo", key)], key)
    assert x509.load_pem_x509_certificates((caddy.live / "settings-cert.pem").read_bytes()) == [first]
    assert tls_settings.status()["common_name"] == "upload.demo"


def test_unwritable_directory_reports_and_changes_nothing(caddy, started, pair, monkeypatch):
    def broken(*_args, **_kwargs):
        raise PermissionError("read-only")
    monkeypatch.setattr(tls_setup, "write_file", broken)
    with pytest.raises(tls_settings.ApplyError, match="could not be stored"):
        tls_settings.upload([pair[0]], pair[1])
    assert caddy.requests == [] and tls_settings.status()["source"] == "Self-signed default"
    assert (caddy.live / "key.pem").exists() and not (caddy.live / "settings-cert.pem").exists()


# --- reset ---------------------------------------------------------------------------------------------

def test_reset_goes_back_to_the_default(caddy, started, pair):
    tls_settings.upload([pair[0]], pair[1])
    tls_settings.reset()
    assert caddy.served == started
    assert not (caddy.live / "settings-cert.pem").exists() and not (caddy.live / "settings-key.pem").exists()
    info = tls_settings.status()
    assert info["source"] == "Self-signed default" and not info["can_reset"]


def test_failed_reset_keeps_the_settings_certificate(caddy, started, pair):
    tls_settings.upload([pair[0]], pair[1])
    caddy.fail = "refuse"
    with pytest.raises(tls_settings.ApplyError):
        tls_settings.reset()
    assert (caddy.live / "settings-cert.pem").exists() and caddy.served == pair[0]
    assert tls_settings.status()["source"] == "Settings"


def test_reset_without_a_default(caddy, started, pair):
    tls_settings.upload([pair[0]], pair[1])
    for name in tls_setup.DEFAULT:
        (caddy.live / name).unlink()
    with pytest.raises(tls_settings.ApplyError, match="No default certificate"):
        tls_settings.reset()
    assert caddy.served == pair[0] and caddy.loads == 1


# --- status --------------------------------------------------------------------------------------------

def test_status_of_an_env_certificate_close_to_expiry(caddy, monkeypatch):
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = make_cert("Corp CA", ca_key, ca=True, sans=())
    leaf = make_cert("demo.local", key, ca, ca_key, days=10, sans=("demo.local", "192.0.2.10"))
    monkeypatch.setattr(tls_setup, "TARGET", caddy.live)
    tls_setup.write([leaf, ca], key)
    info = tls_settings.status()
    assert (info["source"], info["common_name"], info["issuer"], info["state"]) == (".env", "demo.local", "Corp CA",
                                                                                  "soon")
    assert info["sans"] == ["DNS demo.local", "IP 192.0.2.10"] and info["days_left"] in (9, 10)
    assert info["sha256"].count(":") == 31 and not info["can_reset"]


def test_status_without_a_live_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_settings, "LIVE", tmp_path / "missing")
    assert tls_settings.status() is None


def test_real_admin_client_talks_to_the_unix_socket(monkeypatch, tmp_path):
    """No socket: the reload fails cleanly (the case of an install whose proxy has no admin socket)."""
    monkeypatch.setattr(tls_settings, "ADMIN_SOCKET", str(tmp_path / "admin.sock"))
    with pytest.raises(tls_settings.ApplyError, match="could not be reached"):
        tls_settings.reload()


def test_admin_client_uses_the_host_caddy_accepts_on_a_socket():
    with tls_settings.admin_client() as client:
        assert client.base_url == httpx.URL("http://127.0.0.1")
