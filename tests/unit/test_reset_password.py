"""`python -m app.reset_password` (run by install.sh --reset-password inside the app container)."""

import os
import subprocess
import sys
from pathlib import Path

from app.auth import PASSWORD_KEY, Auth
from app.store import Store
from tests.conftest import SECRET

ROOT = Path(__file__).resolve().parents[2]


def reset(data_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "app.reset_password"], capture_output=True, text=True, timeout=60,
                          cwd=ROOT, env={**os.environ, "DATA_DIR": str(data_dir)})


def test_reset_removes_only_the_password(tmp_path):
    store = Store(tmp_path / "demonstrator.db")
    Auth("the old password 1", SECRET, store=store)
    store.set_setting("other", "kept")
    store.save_connection(None, "Default", "one.nl.digicert.com", "acct", "key")
    result = reset(tmp_path)
    assert result.returncode == 0 and result.stdout.strip() == "login password removed"
    reopened = Store(tmp_path / "demonstrator.db")
    assert reopened.get_setting(PASSWORD_KEY) is None and reopened.get_setting("other") == "kept"
    assert len(reopened.connections()) == 1
    fresh = Auth(None, SECRET, store=reopened)
    assert not fresh.has_password() and not fresh.check_password("the old password 1")
    assert fresh.set_password("the next visitor 12")  # setup is possible again


def test_reset_without_a_password(tmp_path):
    Store(tmp_path / "demonstrator.db")
    result = reset(tmp_path)
    assert result.returncode == 0 and result.stdout.strip() == "no login password was set"
