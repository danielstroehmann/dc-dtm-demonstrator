"""install.sh option handling, without root, Docker or any change to the machine.

The root check comes before the option validation, so the script runs with a stub `id` that reports
uid 0. Every command that could change the system is a tripwire stub: it records the call and aborts.
A rejected option must die with its message before any tripwire fires; an accepted one must get past
the validation and hit the first tripwire (`mkdir -p /opt/…`), which proves the harness can tell the two
apart.

The port settings ("must differ", the `ss` pre-flight check for a busy HTTP port) run only after Docker is
installed and the .env exists under the hard-coded /opt/dtm-demonstrator, which no non-root test can reach.
That block is extracted from install.sh and executed with bash together with the script's own env_get, a
stub `ss` and a stub `compose` – the code under test is not re-implemented."""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"
TRIPWIRES = ["mkdir", "curl", "docker", "apt-get", "systemctl", "rm", "install", "chmod", "chown", "touch", "mv",
             "cp", "tee", "ln", "openssl", "groupdel"]
BASH = shutil.which("bash")


def _executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def installer(tmp_path):
    bin_dir, calls = tmp_path / "bin", tmp_path / "calls.log"
    bin_dir.mkdir()
    real_id = shutil.which("id")
    _executable(bin_dir / "id", f'#!/bin/sh\nif [ "$1" = -u ]; then echo 0; else exec {real_id} "$@"; fi\n')
    for name in TRIPWIRES:
        _executable(bin_dir / name, f'#!/bin/sh\necho "{name} $*" >> "{calls}"\nexit 97\n')

    def run(*args: str) -> tuple[subprocess.CompletedProcess, list[str]]:
        result = subprocess.run([BASH, str(INSTALLER), *args], capture_output=True, text=True, timeout=20,
                                stdin=subprocess.DEVNULL, cwd=tmp_path,
                                env={"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path)})
        return result, calls.read_text().splitlines() if calls.exists() else []

    return run


@pytest.mark.parametrize("value", ["0", "65536", "abc", "-1", "80x", "8 0", "99999999999999999999"])
def test_invalid_http_port_is_rejected_before_any_system_change(installer, value):
    result, calls = installer("--version", "v0.1.0", "--http-port", value)
    assert result.returncode == 1
    assert f"ERROR: invalid HTTP port: {value}" in result.stderr
    assert calls == []


def test_missing_http_port_value_is_rejected(installer):
    result, calls = installer("--version", "v0.1.0", "--http-port")
    assert result.returncode != 0 and calls == []


@pytest.mark.parametrize("value", ["1", "80", "8080", "65535"])
def test_valid_http_port_passes_validation(installer, value):
    result, calls = installer("--version", "v0.1.0", "--http-port", value, "--port", "8443")
    assert "invalid" not in result.stderr
    assert calls[:1] == ["mkdir -p /opt/dtm-demonstrator"]  # reached the first system change


def test_help_lists_http_port():
    result = subprocess.run([BASH, str(INSTALLER), "--help"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert re.search(r"^\s+--http-port N\s+.*default 80", result.stdout, re.M)


# --- port settings block ("must differ", busy port, values kept in .env) ------------------------------


def _settings_snippet() -> str:
    source = INSTALLER.read_text()
    env_get = re.search(r"^env_get\(\) \{.*\}$", source, re.M)
    block = re.search(r'^port="\$\{port:-\$\(env_get HTTPS_PORT\)\}".*?'
                      r'die "port \$http_port is in use by another service – pass --http-port N"\nfi$', source, re.M | re.S)
    assert env_get and block, "install.sh changed – update the extraction"
    # compose stub: our proxy is running when PROXY_RUNNING is set (the real one asks Docker).
    return (f'set -euo pipefail\ndie() {{ echo "ERROR: $*" >&2; exit 1; }}\n{env_get.group(0)}\n'
            'compose() { echo "compose $*" >> "$CALLS"; [ -z "${PROXY_RUNNING:-}" ] || echo 4f2a9c; }\n'
            f'{block.group(0)}\necho "port=$port http_port=$http_port"\n')


@pytest.fixture
def settings(tmp_path):
    """Run the block; the stub `ss` reports a listener only for the ports in BUSY_PORTS."""
    bin_dir, calls = tmp_path / "bin", tmp_path / "calls.log"
    bin_dir.mkdir()
    _executable(bin_dir / "ss", '#!/bin/sh\necho "ss $*" >> "$CALLS"\n'
                                'for p in $BUSY_PORTS; do [ "$2" = "sport = :$p" ] && echo "LISTEN 0 4096 0.0.0.0:$p"; done\n'
                                'exit 0\n')

    def run(env_lines: str = "", port: str = "", http_port: str = "", busy: str = "", proxy_running: bool = False,
            path: str | None = None) -> tuple[subprocess.CompletedProcess, list[str]]:
        env_file = tmp_path / ".env"
        env_file.write_text(env_lines)
        calls.unlink(missing_ok=True)
        env = {"PATH": path or f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "env_file": str(env_file), "port": port,
               "http_port": http_port, "BUSY_PORTS": busy, "CALLS": str(calls)}
        if proxy_running:
            env["PROXY_RUNNING"] = "1"
        result = subprocess.run([BASH, "-c", _settings_snippet()], capture_output=True, text=True, timeout=10, env=env)
        return result, calls.read_text().splitlines() if calls.exists() else []

    return run


def test_defaults_are_443_and_80(settings):
    result, calls = settings()
    assert result.returncode == 0 and result.stdout.strip() == "port=443 http_port=80"
    assert calls == ["ss -Hltn sport = :80"]  # the HTTP port is probed before anything is published


def test_ports_are_kept_from_env_file(settings):
    result, _ = settings("HTTPS_PORT='8443'\nHTTP_PORT='8080'\n")
    assert result.returncode == 0 and result.stdout.strip() == "port=8443 http_port=8080"


def test_explicit_option_overrides_env_file(settings):
    result, _ = settings("HTTPS_PORT='8443'\nHTTP_PORT='8080'\n", http_port="8081")
    assert result.stdout.strip() == "port=8443 http_port=8081"


@pytest.mark.parametrize("env_lines, port, http_port", [
    ("", "8443", "8443"),                     # --port 8443 --http-port 8443
    ("", "80", ""),                           # --port 80 collides with the default HTTP port
    ("HTTPS_PORT='80'\n", "", ""),            # update of an install that used --port 80
    ("HTTP_PORT='8443'\n", "8443", ""),       # stored HTTP port collides with a new --port
])
def test_same_http_and_https_port_is_rejected(settings, env_lines, port, http_port):
    result, calls = settings(env_lines, port, http_port)
    assert result.returncode == 1
    assert "ERROR: HTTP and HTTPS port must differ" in result.stderr
    assert "port=" not in result.stdout and calls == []


def test_busy_http_port_on_fresh_install_is_rejected(settings):
    result, _ = settings(busy="80")
    assert result.returncode == 1
    assert "ERROR: port 80 is in use by another service – pass --http-port N" in result.stderr


def test_busy_port_is_not_confused_with_another_port(settings):
    result, _ = settings(busy="8080")
    assert result.returncode == 0 and result.stdout.strip() == "port=443 http_port=80"


def test_update_keeps_port_held_by_our_own_proxy(settings):
    result, calls = settings("HTTP_PORT='80'\n", busy="80", proxy_running=True)
    assert result.returncode == 0 and result.stdout.strip() == "port=443 http_port=80"
    assert "compose ps -q proxy" in calls


@pytest.mark.parametrize("env_lines, http_port, proxy_running", [
    ("HTTP_PORT='80'\n", "", False),          # stored port, but our proxy is not running: someone else has it
    ("HTTP_PORT='8080'\n", "80", True),       # our proxy holds 8080, the new port 80 belongs to someone else
    ("", "", True),                           # upgrade from a version without HTTP_PORT: not ours
])
def test_busy_port_not_held_by_our_proxy_is_rejected(settings, env_lines, http_port, proxy_running):
    result, _ = settings(env_lines, http_port=http_port, busy="80", proxy_running=proxy_running)
    assert result.returncode == 1
    assert "ERROR: port 80 is in use by another service" in result.stderr


@pytest.mark.skipif(not shutil.which("ss"), reason="real ss (iproute2) only on Linux – CI covers it")
def test_real_ss_detects_a_listening_port(settings):
    """The filter syntax against the real ss: a socket we hold open must count as busy."""
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        busy_port = str(sock.getsockname()[1])
        result, _ = settings(http_port=busy_port, path=os.environ["PATH"])
    assert result.returncode == 1
    assert f"ERROR: port {busy_port} is in use by another service" in result.stderr
