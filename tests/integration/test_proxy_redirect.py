"""HTTP → HTTPS redirect against the real Caddy image (needs Docker; skipped without it).

The proxy container is started like compose starts it: the image, entrypoint, environment and
capabilities of the compose file, the deploy Caddyfile mounted read-only. Only plain HTTP is exercised –
no app container is needed for that."""

import datetime
import json
import os
import re
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
INSTALLER = DEPLOY.parent / "install.sh"
HOSTS = "demo.local 192.0.2.10"


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except subprocess.TimeoutExpired:
        return False


pytestmark = [pytest.mark.docker, pytest.mark.skipif(not _docker_available(), reason="Docker is not available")]


def _compose() -> dict:
    return yaml.safe_load((DEPLOY / "docker-compose.yml").read_text())


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _write_cert(directory: Path) -> None:
    """Throwaway self-signed pair where the tls service would put it (Caddy refuses to start without one)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.local")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("demo.local")]), critical=False)
            .sign(key, hashes.SHA256()))
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                          serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    # Test-only files, owned by the CI user: the container's root runs without CAP_DAC_OVERRIDE, so it can
    # read them only via the "other" bits – also on the directory, which pytest creates with 0700.
    # (Docker Desktop on macOS maps bind-mount ownership to the container user and hides this.)
    for path in directory.iterdir():
        path.chmod(0o644)
    directory.chmod(0o755)


@pytest.fixture(scope="module", params=["443", "8443"])
def proxy(request, tmp_path_factory):
    https_port = request.param
    proxy_service = _compose()["services"]["proxy"]
    tls_dir = tmp_path_factory.mktemp("tls")
    _write_cert(tls_dir)
    port, name = _free_port(), f"dtm-test-proxy-{uuid.uuid4().hex[:8]}"
    command = ["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:80",
               "-e", f"SITE_HOSTS={HOSTS}", "-e", "DEFAULT_SNI=192.0.2.10", "-e", f"HTTPS_PORT={https_port}",
               # --mount, not -v: a missing source fails instead of Docker creating a directory in the repo
               "--mount", f"type=bind,source={DEPLOY / 'Caddyfile'},target=/etc/caddy/Caddyfile,readonly",
               "--mount", f"type=bind,source={tls_dir},target=/tls,readonly",
               "--tmpfs", "/run/caddy-admin",  # compose: the caddy-admin volume holding the admin socket
               "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true",
               "--entrypoint", "/bin/sh", proxy_service["image"],
               "-c", proxy_service["entrypoint"][2].replace("$$", "$")]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=180)
        base, deadline = f"http://127.0.0.1:{port}", time.monotonic() + 30
        while True:
            try:
                httpx.get(base, timeout=1)
                break
            except httpx.TransportError:
                running = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                                         capture_output=True, text=True).stdout.strip()
                if running != "true" or time.monotonic() > deadline:
                    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
                    pytest.fail(f"proxy did not come up ({https_port}):\n{logs.stdout}{logs.stderr}")
                time.sleep(0.3)
        yield base, "" if https_port == "443" else f":{https_port}", https_port
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


def _get(base: str, host: str, path: str = "/") -> httpx.Response:
    return httpx.get(base + path, headers={"Host": host}, follow_redirects=False, timeout=5)


def test_known_host_name_redirects_with_path_and_query(proxy):
    base, suffix, _ = proxy
    response = _get(base, "demo.local", "/runs/42?tab=log&x=%2F")
    assert response.status_code == 302
    assert response.headers["location"] == f"https://demo.local{suffix}/runs/42?tab=log&x=%2F"


def test_known_ip_redirects(proxy):
    base, suffix, _ = proxy
    response = _get(base, "192.0.2.10")
    assert response.status_code == 302
    assert response.headers["location"] == f"https://192.0.2.10{suffix}/"


def test_port_in_host_header_is_replaced_by_https_port(proxy):
    """A browser on http://demo.local:8080/ must land on the HTTPS port, not on :8080."""
    base, suffix, _ = proxy
    response = _get(base, "demo.local:8080")
    assert response.status_code == 302
    assert response.headers["location"] == f"https://demo.local{suffix}/"


def test_post_is_redirected_too(proxy):
    """A temporary 302 (not a permanent, browser-cached redirect) – also for non-GET requests."""
    base, suffix, _ = proxy
    response = httpx.post(base + "/login", headers={"Host": "demo.local"}, data={"a": "b"}, timeout=5)
    assert response.status_code == 302
    assert response.headers["location"] == f"https://demo.local{suffix}/login"


@pytest.mark.parametrize("host", ["evil.example", "demo.local.evil.example", "sub.demo.local", "192.0.2.11"])
def test_unknown_host_gets_404_and_no_redirect(proxy, host):
    base, _, _ = proxy
    response = _get(base, host, "/x?next=https://evil.example")
    assert response.status_code == 404
    assert "location" not in response.headers
    # Fixed text: the Host header (attacker-controlled) is not reflected.
    assert response.text == "Unknown host name – use one of the configured addresses."
    assert host not in response.text and "evil" not in response.text


def test_path_cannot_redirect_to_another_host(proxy):
    base, suffix, _ = proxy
    response = _get(base, "demo.local", "//evil.example/")
    assert response.status_code == 302
    assert response.headers["location"].startswith(f"https://demo.local{suffix}/")


@pytest.mark.parametrize("host", ["demo.local", "evil.example"])
def test_no_server_header(proxy, host):
    base, _, _ = proxy
    assert "server" not in _get(base, host).headers


def _post_install_check(default_sni: str, port: str, http_port: str) -> subprocess.CompletedProcess:
    """install.sh's own redirect check (extracted, not re-implemented), run with the real curl."""
    block = re.search(r'^https_url=.*?does not redirect to \$https_url[^\n]*$', INSTALLER.read_text(), re.M | re.S)
    assert block, "install.sh changed – update the extraction"
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + block.group(0)], capture_output=True, text=True,
                          timeout=30, env={"PATH": os.environ["PATH"], "default_sni": default_sni, "port": port,
                                           "http_port": http_port})


@pytest.mark.skipif(not shutil.which("curl"), reason="curl not installed")
def test_installer_post_install_check_accepts_the_real_redirect(proxy):
    base, _, https_port = proxy
    for sni in ("192.0.2.10", "demo.local"):
        result = _post_install_check(sni, https_port, base.rsplit(":", 1)[1])
        assert result.returncode == 0 and "WARNING" not in result.stderr, result.stderr


@pytest.mark.skipif(not shutil.which("curl"), reason="curl not installed")
def test_installer_post_install_check_warns_on_wrong_answer(proxy):
    base, _, https_port = proxy
    wrong_port = "8443" if https_port == "443" else "443"  # expects a different HTTPS port than the proxy uses
    for sni, port in (("evil.example", https_port), ("demo.local", wrong_port)):
        result = _post_install_check(sni, port, base.rsplit(":", 1)[1])
        assert "WARNING: http://" in result.stderr and "does not redirect to" in result.stderr


def test_compose_publishes_http_port_from_env(tmp_path):
    """docker compose resolves HTTP_PORT (default 80) to the proxy's container port 80."""
    env_file = tmp_path / "empty.env"
    env_file.write_text("")
    base_env = {k: v for k, v in os.environ.items() if k not in {"HTTP_PORT", "HTTPS_PORT"}}
    base_env.update(DEMONSTRATOR_IMAGE="example/image:test", SITE_HOSTS=HOSTS, DEFAULT_SNI="192.0.2.10",
                    ADMIN_PASSWORD="x" * 16, JWT_SECRET="y" * 32)

    def config(**env) -> dict:
        result = subprocess.run(["docker", "compose", "-f", str(DEPLOY / "docker-compose.yml"), "--env-file",
                                 str(env_file), "config", "--format", "json"], capture_output=True, text=True,
                                timeout=60, env={**base_env, **env}, check=True)
        return json.loads(result.stdout)["services"]["proxy"]

    def published(proxy_service: dict) -> dict[int, str]:
        return {p["target"]: p["published"] for p in proxy_service["ports"]}

    default = config()
    assert published(default) == {80: "80", 443: "443"}
    assert default["environment"]["HTTPS_PORT"] == "443"
    custom = config(HTTP_PORT="8080", HTTPS_PORT="8443")
    assert published(custom) == {80: "8080", 443: "8443"}
    assert custom["environment"]["HTTPS_PORT"] == "8443"


def test_compose_resolves_the_tls_inputs(tmp_path):
    """docker compose turns unset TLS paths into /dev/null and keeps set ones; the PKCS#12 password
    defaults to empty."""
    env_file = tmp_path / "empty.env"
    env_file.write_text("")
    base_env = {k: v for k, v in os.environ.items() if not k.startswith("TLS_")}
    base_env.update(DEMONSTRATOR_IMAGE="example/image:test", SITE_HOSTS=HOSTS, DEFAULT_SNI="192.0.2.10",
                    ADMIN_PASSWORD="x" * 16, JWT_SECRET="y" * 32)

    def tls_service(**env) -> dict:
        result = subprocess.run(["docker", "compose", "-f", str(DEPLOY / "docker-compose.yml"), "--env-file",
                                 str(env_file), "config", "--format", "json"], capture_output=True, text=True,
                                timeout=60, env={**base_env, **env}, check=True)
        return json.loads(result.stdout)["services"]["tls"]

    def sources(service: dict) -> dict[str, str]:
        return {v["target"]: v["source"] for v in service["volumes"]}

    unset = tls_service()
    assert {t: s for t, s in sources(unset).items() if t.startswith("/tls-in")} == {
        "/tls-in/cert.pem": "/dev/null", "/tls-in/key.pem": "/dev/null", "/tls-in/keystore.p12": "/dev/null"}
    assert unset["environment"]["TLS_PKCS12_PASSWORD"] == ""
    assert unset["network_mode"] == "none" and unset["read_only"] is True
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    set_ = tls_service(TLS_CERT_FILE=str(cert), TLS_KEY_FILE=str(key), TLS_PKCS12_PASSWORD="pw")
    assert sources(set_)["/tls-in/cert.pem"] == str(cert) and sources(set_)["/tls-in/key.pem"] == str(key)
    assert sources(set_)["/tls-in/keystore.p12"] == "/dev/null" and set_["environment"]["TLS_PKCS12_PASSWORD"] == "pw"
    assert all(v.get("bind", {}).get("create_host_path") is False for v in set_["volumes"]
               if v["target"].startswith("/tls-in"))
