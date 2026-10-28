"""install.sh TLS handling: the self-signed default, its renewal, the migration of older installs,
--tls-cert/--tls-key and --tls-dir (TLS_HOST_DIR). The TLS block is extracted from install.sh (with the script's own .env helpers)
and run with bash and the real openssl in a temporary install directory – not re-implemented. The
pair it writes is then fed to app/tls_setup.py, the code the `tls` service runs at every start."""

import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests.unit.test_installer_options import installer  # noqa: F401 – fixture

INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"
BASH = shutil.which("bash")
OPENSSL = shutil.which("openssl")
ROOT = INSTALLER.parent


def _openssl3() -> bool:
    if not OPENSSL:
        return False
    return subprocess.run([OPENSSL, "version"], capture_output=True, text=True).stdout.startswith("OpenSSL 3")


needs_openssl = pytest.mark.skipif(not (BASH and _openssl3()), reason="needs bash and OpenSSL 3")


def _snippet() -> str:
    source = INSTALLER.read_text()
    helpers = re.search(r"^env_tmp=\"\"\n.*?^env_set\(\) \{ env_rewrite \"\$1\" \"\$2\"; \}$", source, re.M | re.S)
    block = re.search(r'^SELF_CERT=.*?^grep -q \'\^TLS_HOST_DIR=\' "\$env_file" \|\| env_set TLS_HOST_DIR ""$',
                      source, re.M | re.S)
    assert helpers and block, "install.sh changed – update the extraction"
    return (f'set -euo pipefail\ndie() {{ echo "ERROR: $*" >&2; exit 1; }}\n{helpers.group(0)}\n'
            f'mkdir -p "$INSTALL_DIR/tls"\n{block.group(0)}\n')


@pytest.fixture
def tls(tmp_path):
    install = tmp_path / "opt"
    install.mkdir()
    env_file = install / ".env"

    def run(env_lines: str = "", hosts: str = "demo.local 192.0.2.10", default_sni: str = "192.0.2.10",
            tls_mode: str = "", tls_cert: str = "", tls_key: str = "", tls_dir: str = "", keep_env: bool = False):
        if not keep_env:
            env_file.write_text(env_lines)
        env = {"PATH": os.environ["PATH"], "INSTALL_DIR": str(install), "env_file": str(env_file), "hosts": hosts,
               "default_sni": default_sni, "tls_mode": tls_mode, "tls_cert": tls_cert, "tls_key": tls_key,
               "tls_dir": tls_dir}
        result = subprocess.run([BASH, "-c", _snippet()], capture_output=True, text=True, timeout=60, env=env,
                                cwd=tmp_path)
        return result, dict(re.findall(r"^([A-Z_0-9]+)='(.*)'$", env_file.read_text(), re.M))

    run.install, run.env_file = install, env_file
    return run


def cert_of(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def sans(cert: x509.Certificate) -> list[str]:
    return [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]


def write_pair(directory: Path, org: str | None, days: float, names=("demo.local",)) -> x509.Certificate:
    """A pair as someone else (org=None) or an older installer run (org set) left it."""
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)] if org else []
    name = x509.Name([*attrs, x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    return cert


def tls_setup_accepts(cert: Path, key: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    source = tmp_path / "tls-in"
    shutil.rmtree(source, ignore_errors=True)
    source.mkdir()
    (source / "cert.pem").symlink_to(cert)
    (source / "key.pem").symlink_to(key)
    (source / "keystore.p12").symlink_to("/dev/null")
    env = {"PATH": os.environ["PATH"], "TLS_SOURCE_DIR": str(source), "TLS_TARGET_DIR": str(tmp_path / "tls-live")}
    return subprocess.run([sys.executable, "-m", "app.tls_setup"], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=60)


# --- the self-signed default ----------------------------------------------------------------------

@needs_openssl
def test_fresh_install_gets_a_self_signed_pair(tls, tmp_path):
    result, env = tls()
    assert result.returncode == 0, result.stderr
    assert env == {"TLS_CERT_FILE": "./tls/cert.pem", "TLS_KEY_FILE": "./tls/key.pem", "TLS_PKCS12_FILE": "",
                   "TLS_PKCS12_PASSWORD": "", "TLS_HOST_DIR": ""}
    cert_path, key_path = tls.install / "tls" / "cert.pem", tls.install / "tls" / "key.pem"
    cert = cert_of(cert_path)
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "DTM Demonstrator self-signed"
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "192.0.2.10"
    assert sans(cert) == ["demo.local", "192.0.2.10"]
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey) and cert.public_key().curve.name == "secp256r1"
    assert cert.not_valid_after_utc - datetime.now(timezone.utc) > timedelta(days=700)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600 and stat.S_IMODE(cert_path.stat().st_mode) == 0o644
    assert not list((tls.install / "tls").glob("*.new"))
    checked = tls_setup_accepts(cert_path, key_path, tmp_path)  # what the tls service does at every start
    assert checked.returncode == 0 and "TLS: PEM certificate for demo.local, 192.0.2.10" in checked.stdout


@needs_openssl
def test_update_keeps_a_fitting_pair(tls):
    tls()
    before = (tls.install / "tls" / "cert.pem").read_bytes()
    result, env = tls(keep_env=True)
    assert result.returncode == 0 and (tls.install / "tls" / "cert.pem").read_bytes() == before
    assert env["TLS_CERT_FILE"] == "./tls/cert.pem"


@needs_openssl
def test_new_hosts_renew_our_pair(tls):
    tls()
    result, _ = tls(keep_env=True, hosts="demo.local other.local 192.0.2.10")
    assert result.returncode == 0
    assert sans(cert_of(tls.install / "tls" / "cert.pem")) == ["demo.local", "other.local", "192.0.2.10"]


@needs_openssl
def test_our_pair_close_to_expiry_is_renewed(tls):
    write_pair(tls.install / "tls", "DTM Demonstrator self-signed", days=10, names=("demo.local",))
    result, _ = tls("TLS_CERT_FILE='./tls/cert.pem'\nTLS_KEY_FILE='./tls/key.pem'\n", hosts="demo.local")
    assert result.returncode == 0
    assert cert_of(tls.install / "tls" / "cert.pem").not_valid_after_utc - datetime.now(timezone.utc) > timedelta(days=700)


@needs_openssl
def test_a_foreign_pair_in_tls_is_never_overwritten(tls):
    """Someone put their own pair into ./tls (not ours): other hosts or expiry must not replace it."""
    theirs = write_pair(tls.install / "tls", None, days=5, names=("their.example",))
    result, env = tls("TLS_CERT_FILE='./tls/cert.pem'\nTLS_KEY_FILE='./tls/key.pem'\n", hosts="demo.local")
    assert result.returncode == 0 and cert_of(tls.install / "tls" / "cert.pem") == theirs


# --- migration of older installs (TLS_MODE) -------------------------------------------------------------

@needs_openssl
def test_old_custom_install_keeps_its_pair(tls, tmp_path):
    theirs = write_pair(tls.install / "tls", None, days=200, names=("demo.local",))
    result, env = tls("TLS_MODE='custom'\nSITE_HOSTS='demo.local'\n", hosts="demo.local other.local")
    assert result.returncode == 0, result.stderr
    assert cert_of(tls.install / "tls" / "cert.pem") == theirs  # not ours, not touched – even for new hosts
    assert "TLS_MODE" not in env and env["TLS_CERT_FILE"] == "./tls/cert.pem" and env["TLS_KEY_FILE"] == "./tls/key.pem"
    assert "SITE_HOSTS='demo.local'" in tls.env_file.read_text()  # other settings stay


@needs_openssl
def test_old_selfsigned_install_gets_a_pair(tls):
    result, env = tls("TLS_MODE='selfsigned'\n")
    assert result.returncode == 0 and "TLS_MODE" not in env
    assert "DTM Demonstrator self-signed" in cert_of(tls.install / "tls" / "cert.pem").subject.rfc4514_string()


@needs_openssl
def test_old_custom_install_without_files_gets_a_pair(tls):
    result, env = tls("TLS_MODE='custom'\n")
    assert result.returncode == 0 and env["TLS_CERT_FILE"] == "./tls/cert.pem"
    assert "DTM Demonstrator self-signed" in cert_of(tls.install / "tls" / "cert.pem").subject.rfc4514_string()


# --- --tls-cert / --tls-key / --tls selfsigned ------------------------------------------------------------

@needs_openssl
def test_own_pair_paths_go_to_env_as_absolute_paths(tls, tmp_path):
    own = tmp_path / "le"
    write_pair(own, None, days=90, names=("demo.example",))
    (tmp_path / "cwd").mkdir()
    result, env = tls(tls_cert="le/cert.pem", tls_key="le/key.pem")  # relative to the caller's directory
    assert result.returncode == 0, result.stderr
    assert env["TLS_CERT_FILE"] == str((own / "cert.pem").resolve())
    assert env["TLS_KEY_FILE"] == str((own / "key.pem").resolve())
    assert not (tls.install / "tls" / "cert.pem").exists()  # no self-signed pair needed
    # an update without options keeps them
    result, env = tls(keep_env=True)
    assert env["TLS_CERT_FILE"] == str((own / "cert.pem").resolve())


@needs_openssl
@pytest.mark.parametrize("problem,message", [
    ("missing", "--tls-cert and --tls-key need readable files"),
    ("not-a-cert", "is not a PEM certificate"),
    ("encrypted-key", "is not an unencrypted PEM private key"),
])
def test_bad_own_pair_is_refused(tls, tmp_path, problem, message):
    own = tmp_path / "own"
    write_pair(own, None, days=90)
    if problem == "not-a-cert":
        (own / "cert.pem").write_text("hello")
    if problem == "encrypted-key":
        key = serialization.load_pem_private_key((own / "key.pem").read_bytes(), None)
        (own / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.BestAvailableEncryption(b"pw")))
    cert = str(own / "cert.pem")
    key_path = str(own / ("nope.pem" if problem == "missing" else "key.pem"))
    result, env = tls("TLS_CERT_FILE='./tls/cert.pem'\n", tls_cert=cert, tls_key=key_path)
    assert result.returncode == 1 and message in result.stderr
    assert env.get("TLS_CERT_FILE") == "./tls/cert.pem"  # unchanged


@needs_openssl
def test_tls_selfsigned_resets_own_paths(tls, tmp_path):
    write_pair(tmp_path / "le", None, days=90)
    result, env = tls(f"TLS_CERT_FILE='{tmp_path}/le/cert.pem'\nTLS_KEY_FILE='{tmp_path}/le/key.pem'\n",
                      tls_mode="selfsigned")
    assert result.returncode == 0
    assert (env["TLS_CERT_FILE"], env["TLS_KEY_FILE"]) == ("./tls/cert.pem", "./tls/key.pem")
    assert "DTM Demonstrator self-signed" in cert_of(tls.install / "tls" / "cert.pem").subject.rfc4514_string()


@needs_openssl
def test_pkcs12_settings_are_kept(tls):
    lines = "TLS_CERT_FILE=''\nTLS_KEY_FILE=''\nTLS_PKCS12_FILE='/etc/ssl/demo.p12'\nTLS_PKCS12_PASSWORD='s3cret'\n"
    result, env = tls(lines)
    assert result.returncode == 0
    assert env == {"TLS_CERT_FILE": "", "TLS_KEY_FILE": "", "TLS_PKCS12_FILE": "/etc/ssl/demo.p12",
                   "TLS_PKCS12_PASSWORD": "s3cret", "TLS_HOST_DIR": ""}
    assert not (tls.install / "tls" / "cert.pem").exists()


# --- --tls-dir (TLS_HOST_DIR) ------------------------------------------------------------------------------

@needs_openssl
def test_tls_dir_is_written_and_kept_on_updates(tls, tmp_path):
    result, env = tls(tls_dir="/etc/digicert")
    assert result.returncode == 0, result.stderr
    assert env["TLS_HOST_DIR"] == "/etc/digicert"
    result, env = tls(keep_env=True)  # an update without the option keeps it
    assert result.returncode == 0 and env["TLS_HOST_DIR"] == "/etc/digicert"
    result, env = tls(keep_env=True, tls_dir="/srv-certs/acme")  # given again: replaced
    assert env["TLS_HOST_DIR"] == "/srv-certs/acme" and tls.env_file.read_text().count("TLS_HOST_DIR=") == 1


@needs_openssl
def test_hand_edited_tls_dir_is_never_overwritten(tls):
    result, env = tls("TLS_CERT_FILE='./tls/cert.pem'\nTLS_KEY_FILE='./tls/key.pem'\nTLS_HOST_DIR='/opt/acme'\n")
    assert result.returncode == 0 and env["TLS_HOST_DIR"] == "/opt/acme"


@pytest.mark.parametrize("value,message", [
    ("relative/dir", "--tls-dir needs an existing absolute directory: relative/dir"),
    ("/nonexistent-demo-dir/x", "--tls-dir needs an existing absolute directory: /nonexistent-demo-dir/x"),
    ("FILE", "--tls-dir needs an existing absolute directory"),
    ("/", "--tls-dir must be a directory like /etc/digicert"),
    ("/usr", "--tls-dir must be a directory like /etc/digicert"),
    ("/usr/bin", "--tls-dir must be a directory like /etc/digicert"),  # would cover the container's own files
    ("SPACE", "--tls-dir must be a directory like /etc/digicert"),
])
def test_tls_dir_is_validated_first(installer, tmp_path, value, message):  # noqa: F811
    if value == "FILE":
        value = str(tmp_path / "a-file")
        Path(value).write_text("x")
    if value == "SPACE":
        value = str(tmp_path / "with space")
        Path(value).mkdir()
    result, calls = installer("--version", "v0.1.0", "--tls-dir", value)
    assert result.returncode == 1 and f"ERROR: {message}" in result.stderr and calls == []


def test_valid_tls_dir_passes_validation(installer, tmp_path):  # noqa: F811
    (tmp_path / "acme" / "live").mkdir(parents=True)
    result, calls = installer("--version", "v0.1.0", "--tls-dir", str(tmp_path / "acme" / "live" / ".."))
    assert "ERROR" not in result.stderr
    assert calls[:1] == ["mkdir -p /opt/dtm-demonstrator"]  # reached the first system change


# --- option validation (before any system change) -------------------------------------------------------

@pytest.mark.parametrize("args,message", [
    (["--tls", "custom"], "--tls custom needs --tls-cert and --tls-key"),
    (["--tls", "internal"], "--tls must be selfsigned or custom"),
])
def test_tls_options_are_validated_first(installer, args, message):  # noqa: F811
    result, calls = installer("--version", "v0.1.0", *args)
    assert result.returncode == 1 and f"ERROR: {message}" in result.stderr and calls == []


def test_help_documents_the_tls_options():
    text = subprocess.run([BASH, str(INSTALLER), "--help"], capture_output=True, text=True, timeout=10).stdout
    assert re.search(r"^\s+--tls-cert PATH\s", text, re.M) and re.search(r"^\s+--tls-key PATH\s", text, re.M)
    assert re.search(r"^\s+--tls selfsigned\s", text, re.M) and "TLS_PKCS12_FILE" in text
    assert re.search(r"^\s+--tls-dir PATH\s+.*", text, re.M) and "TLS_HOST_DIR" in text


def test_installer_fetches_one_caddyfile_and_reapplies_tls_at_start():
    text = INSTALLER.read_text()
    assert 'fetch deploy/Caddyfile "$INSTALL_DIR/Caddyfile"' in text
    assert "Caddyfile.selfsigned" not in text and "Caddyfile.custom" not in text
    assert re.search(r"^ExecStart=.* up -d --force-recreate tls proxy$", text, re.M)
    assert 'chmod 700 "$INSTALL_DIR/tls" "$INSTALL_DIR/tls-host"' in text  # the .env sources: root only
    # the live directory is shared with the app's group, which swaps the certificate set in Settings
    assert 'chown "0:$APP_UID" "$INSTALL_DIR/tls-live" && chmod 770 "$INSTALL_DIR/tls-live"' in text
