"""The `tls` service inside the real image, with the /tls-in mounts docker compose creates (needs Docker
and the image locally; skipped otherwise – the image is never pulled). An unset TLS path is bind-mounted
as the host's /dev/null, which is another node than the container's own /dev/null."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from tests.unit.test_tls_setup import key_pem, make_cert, pem

ROOT = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("TLS_TEST_IMAGE", "ghcr.io/danielstroehmann/dc-dtm-demonstrator:branch-dev")


def _image_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = [pytest.mark.docker, pytest.mark.skipif(not _image_available(), reason=f"Docker or {IMAGE} not available")]


def run_tls(cert: str, key: str, keystore: str) -> subprocess.CompletedProcess:
    """`python -m app.tls_setup` as compose runs it, with the working-tree app mounted over the image's."""
    mount = lambda source, target: ["--mount", f"type=bind,source={source},target={target},readonly"]
    command = ["docker", "run", "--rm", "--network", "none", "--user", "0", "--read-only", "--cap-drop", "ALL",
               "--tmpfs", "/tls", *mount(ROOT / "app", "/srv/app"), *mount(cert, "/tls-in/cert.pem"),
               *mount(key, "/tls-in/key.pem"), *mount(keystore, "/tls-in/keystore.p12"),
               IMAGE, "python", "-m", "app.tls_setup"]
    return subprocess.run(command, capture_output=True, text=True, timeout=300)


def test_pem_pair_with_unset_keystore(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "cert.pem").write_bytes(pem(make_cert("demo.local", key)))
    (tmp_path / "key.pem").write_bytes(key_pem(key))
    result = run_tls(tmp_path / "cert.pem", tmp_path / "key.pem", "/dev/null")
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("TLS: PEM certificate for demo.local")


def test_nothing_configured():
    result = run_tls("/dev/null", "/dev/null", "/dev/null")
    assert result.returncode == 1 and "no certificate configured" in result.stderr, result.stderr
