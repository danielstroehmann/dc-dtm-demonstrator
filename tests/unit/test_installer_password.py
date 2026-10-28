"""install.sh and the login password: nothing asked or written on install, an older ADMIN_PASSWORD removed only
once the app is healthy, and --reset-password.

As in test_installer_options: the blocks are extracted from install.sh and run with bash next to the script's own
env helpers; docker/compose/curl/openssl are stubs that record their calls – the code under test is not
re-implemented."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.unit.test_installer_options import _executable, installer  # noqa: F401 – fixture

INSTALLER = Path(__file__).resolve().parents[2] / "install.sh"
BASH = shutil.which("bash")
SOURCE = INSTALLER.read_text()
PRELUDE = 'set -euo pipefail\ndie() { echo "ERROR: $*" >&2; exit 1; }\ninfo() { echo "==> $*"; }\n'


def _extract(pattern: str) -> str:
    match = re.search(pattern, SOURCE, re.M | re.S)
    assert match, f"install.sh changed – update the extraction ({pattern[:40]}…)"
    return match.group(0)


HELPERS = _extract(r'^env_file="\$INSTALL_DIR/\.env"\n.*?^env_set\(\) \{ env_rewrite "\$1" "\$2"; \}$')
RESET = _extract(r"^if \$reset_password; then\n.*?^fi$")
SECRETS = _extract(r"^# Secrets: set once.*?^\[ -n \"\$\(env_get JWT_SECRET\)\" \] \|\| env_set JWT_SECRET .*?$")
TAIL = _extract(r'^info "Waiting for the demonstrator to become healthy"\n.*\Z')


def env_values(env_file: Path) -> dict[str, str]:
    return dict(re.findall(r"^([A-Z_0-9]+)='?(.*?)'?$", env_file.read_text(), re.M))


@pytest.fixture
def sh(tmp_path):
    """Runs a snippet with stub commands; COMPOSE_LOGS/HEALTH/LOGIN_PAGE steer the stubs."""
    install, bin_dir, calls = tmp_path / "opt", tmp_path / "bin", tmp_path / "calls.log"
    install.mkdir()
    bin_dir.mkdir()
    # seq: the wait loops give up after two tries instead of 60 – same outcome, without ~180 stub process starts
    for name in ("docker", "openssl", "curl", "sleep", "seq", "systemctl", "journalctl"):
        _executable(bin_dir / name, f'#!/bin/sh\necho "{name} $*" >> "$CALLS"\n' + {
            "docker": 'case "$1" in inspect) echo "$HEALTH" ;; compose) shift; '
                      'case "$*" in *" ps -q "*) [ -n "$APP_RUNNING" ] && echo 4f2a9c ;; '
                      '*" logs "*) cat "$COMPOSE_LOGS_FILE" ;; esac ;; esac\nexit 0\n',
            "openssl": 'case "$1" in rand) echo "rotated$$secret" ;; esac\nexit 0\n',
            "seq": 'echo 1; echo 2\n',
            "curl": 'case "$*" in *"/healthz"*) exit 0 ;; *"/login"*) printf "%s" "$LOGIN_PAGE"; exit 0 ;; '
                    '*) printf "302 https://192.0.2.10/"; exit 0 ;; esac\n',
        }.get(name, "exit 0\n"))
    env_file = install / ".env"

    def run(snippet: str, env_lines: str | None = "", **env) -> tuple[subprocess.CompletedProcess, list[str]]:
        if env_lines is None:
            env_file.unlink(missing_ok=True)
        else:
            env_file.write_text(env_lines)
        calls.unlink(missing_ok=True)
        # The log goes through a file: Linux caps a single environment string at 128 KB.
        logs_file = tmp_path / "compose.log"
        logs_file.write_text(env.pop("COMPOSE_LOGS", "") + "\n")
        variables = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "INSTALL_DIR": str(install),
                     "CALLS": str(calls), "HEALTH": "healthy", "APP_RUNNING": "1", "COMPOSE_LOGS_FILE": str(logs_file),
                     "LOGIN_PAGE": "", "hosts": "demo.local", "port": "443", "http_port": "80",
                     "default_sni": "192.0.2.10", "ref": "v9.9.9", "reset_password": "true"} | env
        script = (PRELUDE + 'compose() { docker compose --project-directory "$INSTALL_DIR" -p dtm-demonstrator "$@"; }\n'
                  'self_signed_by_us() { false; }\n' + HELPERS + "\n" + snippet + "\n")
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30, env=variables,
                                stdin=subprocess.DEVNULL, cwd=tmp_path)
        return result, calls.read_text().splitlines() if calls.exists() else []

    run.env_file = env_file
    return run


# --- fresh install / update: secrets block ------------------------------------------------------------


def test_fresh_install_writes_no_admin_password(sh):
    result, calls = sh(SECRETS, env_lines="")
    assert result.returncode == 0, result.stderr
    values = env_values(sh.env_file)
    assert "ADMIN_PASSWORD" not in values and re.fullmatch(r"rotated\d+secret", values["JWT_SECRET"])
    assert "password" not in result.stdout.lower()


def test_update_keeps_jwt_secret_and_does_not_touch_admin_password_before_start(sh):
    result, _ = sh(SECRETS, env_lines="ADMIN_PASSWORD='old-env-password'\nJWT_SECRET='kept'\n")
    assert result.returncode == 0
    assert env_values(sh.env_file) == {"ADMIN_PASSWORD": "old-env-password", "JWT_SECRET": "kept"}


def test_installer_never_prompts_for_a_password():
    """No (silent) password read anywhere in the install flow – the only tty reads are host names and confirmations."""
    assert not re.search(r"read\b[^\n]*-s\b", SOURCE)
    assert not re.search(r"(?i)(read|tty_read)[^\n]*password", SOURCE)


def test_install_flow_with_closed_stdin_reaches_system_changes_without_asking(installer):  # noqa: F811
    result, calls = installer("--version", "v0.1.0", "--yes")
    assert "password" not in (result.stdout + result.stderr).lower()
    assert calls[:1] == ["mkdir -p /opt/dtm-demonstrator"]


def test_compose_passes_an_optional_admin_password():
    compose = (INSTALLER.parent / "deploy" / "docker-compose.yml").read_text()
    assert re.search(r"^\s+ADMIN_PASSWORD: \$\{ADMIN_PASSWORD:-\}", compose, re.M)  # no warning when it is unset


# --- end of install: old ADMIN_PASSWORD, setup hint ---------------------------------------------------------

SETUP_PAGE = '<form method="post" action="/setup">'
LOGIN_PAGE = '<form method="post" action="/login">'


def test_old_password_is_removed_after_health_and_container_recreated(sh):
    result, calls = sh(TAIL, env_lines="ADMIN_PASSWORD='old-env-password'\nJWT_SECRET='kept'\n",
                       COMPOSE_LOGS="INFO demonstrator: login password taken over from ADMIN_PASSWORD",
                       LOGIN_PAGE=LOGIN_PAGE)
    assert result.returncode == 0, result.stderr
    assert env_values(sh.env_file) == {"JWT_SECRET": "kept"}
    assert "Login password: unchanged (now stored hashed by the app)" in result.stdout
    assert "WARNING" not in result.stderr and "not set yet" not in result.stdout
    up = [i for i, c in enumerate(calls) if "up -d app" in c]
    inspect = [i for i, c in enumerate(calls) if c.startswith("docker inspect")]
    assert up and inspect and up[0] > inspect[-1]  # recreated only after the health check
    assert oct(sh.env_file.stat().st_mode & 0o777) == "0o600"


def test_old_password_already_taken_over_reports_unchanged(sh):
    result, _ = sh(TAIL, env_lines="ADMIN_PASSWORD='old-env-password'\n",
                   COMPOSE_LOGS="INFO demonstrator: ADMIN_PASSWORD already taken over", LOGIN_PAGE=LOGIN_PAGE)
    assert result.returncode == 0 and "unchanged" in result.stdout and "WARNING" not in result.stderr
    assert "ADMIN_PASSWORD" not in env_values(sh.env_file)


def test_ignored_old_password_warns_and_points_to_reset(sh):
    result, _ = sh(TAIL, env_lines="ADMIN_PASSWORD='different'\n",
                   COMPOSE_LOGS="WARNING demonstrator: ADMIN_PASSWORD ignored: a login password is already set",
                   LOGIN_PAGE=LOGIN_PAGE)
    assert result.returncode == 0
    assert "WARNING: ADMIN_PASSWORD" in result.stderr and "--reset-password" in result.stderr
    assert "unchanged" not in result.stdout and "ADMIN_PASSWORD" not in env_values(sh.env_file)


@pytest.mark.parametrize("health", ["unhealthy", "starting", ""])
def test_old_password_stays_when_the_app_is_not_healthy(sh, health):
    result, calls = sh(TAIL, env_lines="ADMIN_PASSWORD='old-env-password'\n", HEALTH=health)
    assert result.returncode != 0 and "did not become healthy" in result.stderr
    assert env_values(sh.env_file)["ADMIN_PASSWORD"] == "old-env-password"
    assert not any("up -d app" in c for c in calls)


def test_old_password_stays_when_the_proxy_is_not_reachable(sh, tmp_path):
    curl = tmp_path / "bin" / "curl"
    curl.write_text('#!/bin/sh\necho "curl $*" >> "$CALLS"\nexit 7\n')
    result, _ = sh(TAIL, env_lines="ADMIN_PASSWORD='old-env-password'\n")
    assert result.returncode != 0 and "proxy is not reachable" in result.stderr
    assert env_values(sh.env_file)["ADMIN_PASSWORD"] == "old-env-password"


def test_fresh_install_says_set_the_password_now(sh):
    result, calls = sh(TAIL, env_lines="JWT_SECRET='s'\n", LOGIN_PAGE=SETUP_PAGE)
    assert result.returncode == 0
    assert "Login password: not set yet – open the URL now" in result.stdout
    assert not any("up -d app" in c for c in calls) and "unchanged" not in result.stdout


def test_unreachable_login_page_still_gives_a_hint(sh, tmp_path):
    curl = tmp_path / "bin" / "curl"
    curl.write_text('#!/bin/sh\necho "curl $*" >> "$CALLS"\ncase "$*" in *"/login"*) exit 7 ;; *"/healthz"*) exit 0 ;; '
                    '*) printf "302 https://192.0.2.10/"; exit 0 ;; esac\n')
    result, _ = sh(TAIL, env_lines="JWT_SECRET='s'\n")
    assert result.returncode == 0, result.stderr
    assert "Login password: if none is set yet, the first visit sets it" in result.stdout
    assert "not set yet" not in result.stdout


def test_ignored_warning_found_in_a_long_log(sh):
    """The log is captured before grep: a long log after the match must not turn the warning into "unchanged"."""
    long_log = "WARNING demonstrator: ADMIN_PASSWORD ignored: a login password is already set\n" + "x" * 200 + ("\nINFO filler" * 20000)
    result, _ = sh(TAIL, env_lines="ADMIN_PASSWORD='different'\n", COMPOSE_LOGS=long_log, LOGIN_PAGE=LOGIN_PAGE)
    assert result.returncode == 0 and "WARNING: ADMIN_PASSWORD" in result.stderr and "unchanged" not in result.stdout


def test_update_with_password_set_prints_no_setup_hint(sh):
    result, _ = sh(TAIL, env_lines="JWT_SECRET='s'\n", LOGIN_PAGE=LOGIN_PAGE)
    assert result.returncode == 0 and "Login password" not in result.stdout


# --- --reset-password -----------------------------------------------------------------------------------------


def test_reset_removes_password_rotates_secret_and_restarts(sh):
    result, calls = sh(RESET, env_lines="ADMIN_PASSWORD='old'\nJWT_SECRET='old-secret'\nHTTPS_PORT='443'\n")
    assert result.returncode == 0, result.stderr
    values = env_values(sh.env_file)
    assert "ADMIN_PASSWORD" not in values and values["JWT_SECRET"] != "old-secret" and values["HTTPS_PORT"] == "443"
    compose_calls = [c.split("dtm-demonstrator ", 1)[1] for c in calls if c.startswith("docker compose")]
    # The app is stopped before the hash is deleted and only started again with the new secret: no window in
    # which a stranger could set a password that survives the rotation.
    assert compose_calls == ["ps -q app", "stop app", "run --rm --no-deps -T app python -m app.reset_password",
                             "up -d app"]
    assert "Login password removed" in result.stdout


def test_reset_without_installation_is_refused(sh):
    result, calls = sh(RESET, env_lines=None)
    assert result.returncode != 0 and "no installation" in result.stderr and calls == []


def test_reset_with_app_not_running_changes_nothing(sh):
    result, calls = sh(RESET, env_lines="JWT_SECRET='old-secret'\n", APP_RUNNING="")
    assert result.returncode != 0 and "not running" in result.stderr
    assert env_values(sh.env_file) == {"JWT_SECRET": "old-secret"}
    assert not any("exec" in c or "up -d" in c for c in calls)


def test_reset_failure_restarts_the_app_and_changes_nothing(sh, tmp_path):
    docker = tmp_path / "bin" / "docker"
    docker.write_text('#!/bin/sh\necho "docker $*" >> "$CALLS"\ncase "$*" in *" ps -q "*) echo 4f2a9c ;; '
                      '*" run "*) exit 1 ;; esac\nexit 0\n')
    env_lines = "ADMIN_PASSWORD='old'\nJWT_SECRET='old-secret'\n"
    result, calls = sh(RESET, env_lines=env_lines)
    assert result.returncode != 0 and "reset failed – nothing changed" in result.stderr
    assert sh.env_file.read_text() == env_lines
    compose_calls = [c.split("dtm-demonstrator ", 1)[1] for c in calls if c.startswith("docker compose")]
    assert compose_calls[-1] == "start app" and not any(c.startswith("up -d") for c in compose_calls)


def test_reset_is_documented_in_help():
    result = subprocess.run([BASH, str(INSTALLER), "--help"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and re.search(r"^\s+--reset-password\s+\S", result.stdout, re.M)


def test_reset_mode_exits_before_any_install_step():
    reset_at, uninstall_at = SOURCE.index("if $reset_password; then"), SOURCE.index("if $uninstall; then")
    assert reset_at < uninstall_at and "exit 0" in RESET


# --- the minion instance name (several demonstrators on one Docker daemon) ---------------------------------

INSTANCE = _extract(r"^\[ -n \"\$\(env_get MINION_INSTANCE\)\" \] \|\| env_set MINION_INSTANCE .*?$")


def test_a_fresh_install_names_its_minions_once(sh):
    result, _ = sh(INSTANCE, env_lines="JWT_SECRET='kept'\n")
    assert result.returncode == 0, result.stderr
    name = env_values(sh.env_file)["MINION_INSTANCE"]
    assert re.fullmatch(r"[a-z0-9_-]{1,40}", name) and name.startswith("dtm-")  # what the launcher accepts


def test_an_update_keeps_the_instance_name(sh):
    result, _ = sh(INSTANCE, env_lines="JWT_SECRET='kept'\nMINION_INSTANCE='dtm-1a2b3c4d'\n")
    assert result.returncode == 0
    assert env_values(sh.env_file) == {"JWT_SECRET": "kept", "MINION_INSTANCE": "dtm-1a2b3c4d"}


def test_the_compose_file_hands_the_instance_name_to_the_launcher():
    import yaml
    compose = yaml.safe_load((INSTALLER.parent / "deploy" / "docker-compose.yml").read_text())
    assert compose["services"]["launcher"]["environment"]["MINION_INSTANCE"] == "${MINION_INSTANCE:-default}"
