"""app/tls_setup.py – the `tls` service: resolves the TLS files of .env (PEM pair, else PKCS#12) into
a checked PEM pair for Caddy, or stops with a clear message."""

import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from app import tls_setup

ROOT = Path(__file__).resolve().parents[2]


def make_cert(cn: str, key, issuer_cert=None, issuer_key=None, days: float = 90, sans=("demo.local",), ca=False):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder().subject_name(name)
               .issuer_name(issuer_cert.subject if issuer_cert else name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
               .not_valid_after(now + timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(s) if not s[0].isdigit() else x509.IPAddress(__import__("ipaddress").ip_address(s))
             for s in sans]), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key, password: bytes | None = None, fmt=serialization.PrivateFormat.PKCS8) -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, fmt, enc)


@pytest.fixture
def pki():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = make_cert("Test CA", ca_key, ca=True, sans=())
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = make_cert("demo.local", key, ca, ca_key, sans=("demo.local", "192.0.2.10"))
    return {"ca": ca, "ca_key": ca_key, "leaf": leaf, "key": key}


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    source, target = tmp_path / "in", tmp_path / "out"
    source.mkdir()
    monkeypatch.setattr(tls_setup, "SOURCE", source)
    monkeypatch.setattr(tls_setup, "TARGET", target)
    monkeypatch.delenv("TLS_PKCS12_PASSWORD", raising=False)
    # what compose mounts for an unset path: /dev/null (a character device, read as empty)
    for name in ("cert.pem", "key.pem", "keystore.p12"):
        (source / name).symlink_to("/dev/null")
    return source, target


def put(source: Path, name: str, data: bytes) -> None:
    (source / name).unlink()
    (source / name).write_bytes(data)


def run(capsys) -> tuple[int, str, str]:
    code = tls_setup.main()
    out = capsys.readouterr()
    return code, out.out, out.err


def written(target: Path):
    chain = x509.load_pem_x509_certificates((target / "cert.pem").read_bytes())
    key = serialization.load_pem_private_key((target / "key.pem").read_bytes(), None)
    return chain, key


def same_key(a, b) -> bool:
    der = lambda k: k.public_key().public_bytes(serialization.Encoding.DER,  # noqa: E731
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    return der(a) == der(b)


# --- PEM ---------------------------------------------------------------------------------------------

def test_pem_pair_with_chain(dirs, pki, capsys):
    source, target = dirs
    put(source, "cert.pem", pem(pki["leaf"]) + pem(pki["ca"]))
    put(source, "key.pem", key_pem(pki["key"], fmt=serialization.PrivateFormat.TraditionalOpenSSL))
    code, out, err = run(capsys)
    assert code == 0, err
    chain, key = written(target)
    assert chain == [pki["leaf"], pki["ca"]] and same_key(key, pki["key"])  # chain order kept
    assert (target / "key.pem").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")  # PKCS#8
    assert stat.S_IMODE((target / "cert.pem").stat().st_mode) == 0o644
    assert stat.S_IMODE((target / "key.pem").stat().st_mode) == 0o600
    assert not list(target.glob(".*.tmp"))  # atomic writes leave nothing behind
    valid = pki["leaf"].not_valid_after_utc.strftime("%Y-%m-%d")
    assert out.strip() == f"TLS: PEM certificate for demo.local, 192.0.2.10, valid until {valid}"
    assert "WARNING" not in err


def test_rsa_pem_pair(dirs, capsys):
    source, target = dirs
    key = rsa.generate_private_key(65537, 2048)
    cert = make_cert("rsa.demo", key, sans=("rsa.demo",))
    put(source, "cert.pem", pem(cert))
    put(source, "key.pem", key_pem(key))
    assert run(capsys)[0] == 0 and written(target)[0] == [cert]


def test_pem_wins_over_pkcs12(dirs, pki, capsys):
    source, target = dirs
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = make_cert("other.demo", other_key, sans=("other.demo",))
    put(source, "cert.pem", pem(pki["leaf"]))
    put(source, "key.pem", key_pem(pki["key"]))
    put(source, "keystore.p12", pkcs12.serialize_key_and_certificates(
        b"x", other_key, other, None, serialization.BestAvailableEncryption(b"pw")))
    code, out, _ = run(capsys)
    assert code == 0 and "TLS: PEM files are configured – TLS_PKCS12_FILE is ignored" in out
    assert written(target)[0] == [pki["leaf"]] and "TLS: PEM certificate for demo.local" in out


@pytest.mark.parametrize("present", ["cert.pem", "key.pem"])
def test_half_a_pem_pair_is_an_error(dirs, pki, capsys, present):
    source, target = dirs
    put(source, present, pem(pki["leaf"]) if present == "cert.pem" else key_pem(pki["key"]))
    code, out, err = run(capsys)
    assert code == 1 and err.strip() == ("TLS: set both TLS_CERT_FILE and TLS_KEY_FILE (or clear both to use "
                                         "TLS_PKCS12_FILE)")
    assert not target.exists() or not list(target.iterdir())  # nothing written for the proxy


def test_key_of_another_certificate_is_refused(dirs, pki, capsys):
    source, target = dirs
    put(source, "cert.pem", pem(pki["leaf"]))
    put(source, "key.pem", key_pem(ec.generate_private_key(ec.SECP256R1())))
    code, _, err = run(capsys)
    assert code == 1 and "the private key does not belong to the certificate" in err


def test_chain_in_the_wrong_order_is_refused(dirs, pki, capsys):
    source, _ = dirs
    put(source, "cert.pem", pem(pki["ca"]) + pem(pki["leaf"]))  # CA first
    put(source, "key.pem", key_pem(pki["key"]))
    code, _, err = run(capsys)
    assert code == 1 and "the server certificate must come first" in err


def test_encrypted_pem_key_gets_a_clear_message(dirs, pki, capsys):
    source, _ = dirs
    put(source, "cert.pem", pem(pki["leaf"]))
    put(source, "key.pem", key_pem(pki["key"], password=b"secret"))
    code, _, err = run(capsys)
    assert code == 1 and "TLS_KEY_FILE is encrypted" in err and "secret" not in err


@pytest.mark.parametrize("cert,key,message", [
    (b"not a certificate", None, "TLS_CERT_FILE is not a PEM certificate"),
    (None, b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "TLS_KEY_FILE is not a PEM private key"),  # gitleaks:allow – fake key
])
def test_garbage_pem_files(dirs, pki, capsys, cert, key, message):
    source, _ = dirs
    put(source, "cert.pem", cert or pem(pki["leaf"]))
    put(source, "key.pem", key or key_pem(pki["key"]))
    code, _, err = run(capsys)
    assert code == 1 and message in err


# --- PKCS#12 -----------------------------------------------------------------------------------------

def test_pkcs12_with_password_and_chain(dirs, pki, capsys, monkeypatch):
    source, target = dirs
    put(source, "keystore.p12", pkcs12.serialize_key_and_certificates(
        b"demo", pki["key"], pki["leaf"], [pki["ca"]], serialization.BestAvailableEncryption(b"p12-pass")))
    monkeypatch.setenv("TLS_PKCS12_PASSWORD", "p12-pass")
    code, out, err = run(capsys)
    assert code == 0, err
    chain, key = written(target)
    assert chain == [pki["leaf"], pki["ca"]] and same_key(key, pki["key"])
    assert out.startswith("TLS: PKCS#12 certificate for demo.local, 192.0.2.10, valid until ")
    assert "p12-pass" not in out + err


def test_pkcs12_without_password(dirs, pki, capsys):
    source, target = dirs
    put(source, "keystore.p12", pkcs12.serialize_key_and_certificates(
        None, pki["key"], pki["leaf"], None, serialization.NoEncryption()))
    assert run(capsys)[0] == 0 and written(target)[0] == [pki["leaf"]]


@pytest.mark.parametrize("password", ["wrong", ""])
def test_pkcs12_wrong_password(dirs, pki, capsys, monkeypatch, password):
    source, target = dirs
    put(source, "keystore.p12", pkcs12.serialize_key_and_certificates(
        b"demo", pki["key"], pki["leaf"], None, serialization.BestAvailableEncryption(b"right")))
    monkeypatch.setenv("TLS_PKCS12_PASSWORD", password)
    code, _, err = run(capsys)
    assert code == 1 and "wrong TLS_PKCS12_PASSWORD or not a PKCS#12 file" in err
    assert not (target / "key.pem").exists()


def test_pkcs12_without_key(dirs, pki, capsys):
    source, _ = dirs
    put(source, "keystore.p12", pkcs12.serialize_key_and_certificates(
        None, None, None, [pki["leaf"]], serialization.NoEncryption()))
    code, _, err = run(capsys)
    assert code == 1 and "holds no private key and certificate" in err


# --- nothing configured, expiry, renewal, the real module entry -----------------------------------------

def test_nothing_configured(dirs, capsys):
    _, target = dirs
    code, _, err = run(capsys)  # all three are /dev/null
    assert code == 1 and "no certificate configured" in err and not target.exists()


def test_dev_null_reads_as_empty(dirs):
    source, _ = dirs
    assert (source / "cert.pem").resolve() == Path("/dev/null") and tls_setup._read("cert.pem") == b""
    assert tls_setup._read("missing.pem") == b""


@pytest.mark.parametrize("days,warning", [(20, "expires soon"), (-1, "has expired"), (40, None)])
def test_expiry_warning(dirs, capsys, days, warning):
    source, target = dirs
    key = ec.generate_private_key(ec.SECP256R1())
    put(source, "cert.pem", pem(make_cert("demo.local", key, days=days)))
    put(source, "key.pem", key_pem(key))
    code, _, err = run(capsys)
    assert code == 0  # still served – the operator is warned
    if warning:
        assert f"TLS: WARNING – the certificate {warning}" in err
    else:
        assert "WARNING" not in err


def test_certificate_without_san_names_its_subject(dirs, capsys):
    source, _ = dirs
    key = ec.generate_private_key(ec.SECP256R1())
    put(source, "cert.pem", pem(make_cert("no-san.demo", key, sans=())))
    put(source, "key.pem", key_pem(key))
    code, out, _ = run(capsys)
    assert code == 0 and "certificate for CN=no-san.demo" in out


def test_renewal_replaces_the_files_in_place(dirs, pki, capsys):
    source, target = dirs
    put(source, "cert.pem", pem(pki["leaf"]))
    put(source, "key.pem", key_pem(pki["key"]))
    assert run(capsys)[0] == 0
    new_key = ec.generate_private_key(ec.SECP256R1())
    new = make_cert("demo.local", new_key, pki["ca"], pki["ca_key"])
    (source / "cert.pem").write_bytes(pem(new))
    (source / "key.pem").write_bytes(key_pem(new_key))
    assert run(capsys)[0] == 0
    chain, key = written(target)
    assert chain == [new] and same_key(key, new_key)


def test_module_entry_uses_the_env_dirs(tmp_path, pki):
    source, target = tmp_path / "src", tmp_path / "dst"
    source.mkdir()
    (source / "cert.pem").write_bytes(pem(pki["leaf"]))
    (source / "key.pem").write_bytes(key_pem(pki["key"]))
    env = {"PATH": os.environ["PATH"], "TLS_SOURCE_DIR": str(source), "TLS_TARGET_DIR": str(target)}
    result = subprocess.run([sys.executable, "-m", "app.tls_setup"], cwd=ROOT, env=env, capture_output=True,
                            text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("TLS: PEM certificate for demo.local") and (target / "key.pem").exists()
    (source / "key.pem").write_bytes(key_pem(ec.generate_private_key(ec.SECP256R1())))
    failed = subprocess.run([sys.executable, "-m", "app.tls_setup"], cwd=ROOT, env=env, capture_output=True,
                            text=True, timeout=60)
    assert failed.returncode == 1 and failed.stderr.startswith("TLS: the private key does not belong")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads a 0000 file anyway")
def test_unreadable_file_ends_with_a_clear_message(dirs, pki, capsys):
    source, target = dirs
    put(source, "cert.pem", pem(pki["leaf"]))
    put(source, "key.pem", key_pem(pki["key"]))
    (source / "key.pem").chmod(0)
    try:
        code, _, err = run(capsys)
    except PermissionError:
        pytest.fail("PermissionError escaped – the tls service would end with a traceback, not a message")
    finally:
        (source / "key.pem").chmod(0o600)
    assert code == 1 and err.startswith("TLS: ")
    assert "key.pem cannot be read" in err and "Traceback" not in err
    assert not (target / "key.pem").exists() and not (target / "cert.pem").exists()  # nothing half-written


def test_directory_instead_of_a_file_ends_with_a_clear_message(dirs, pki, capsys):
    source, target = dirs
    put(source, "cert.pem", pem(pki["leaf"]))
    (source / "key.pem").unlink()
    (source / "key.pem").mkdir()  # what docker mounts for a path that does not exist on the host
    code, _, err = run(capsys)
    assert code == 1 and err.startswith("TLS: ") and "key.pem is not a file" in err
    assert not (target / "cert.pem").exists()
