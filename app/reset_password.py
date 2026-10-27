"""Removes the login password, so the next visitor sets a new one (install.sh --reset-password runs this
in the app container; the installer also rotates JWT_SECRET, which ends every session)."""

from .auth import PASSWORD_KEY
from .config import DATA_DIR
from .store import Store

if __name__ == "__main__":
    removed = Store(DATA_DIR / "demonstrator.db").delete_setting(PASSWORD_KEY)
    print("login password removed" if removed else "no login password was set")
