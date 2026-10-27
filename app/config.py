import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
# Build identity, set by the image build (CI build-args, or scripts/dev-up from git).
APP_VERSION = os.environ.get("APP_VERSION", "dev")
BUILD = {"version": APP_VERSION, "commit": os.environ.get("GIT_SHA") or None,
         "build_time": os.environ.get("BUILD_TIME") or None}
# Local development (scripts/dev-up): fuller build identity and the feedback overlay – the overlay's code is
# not part of the release image, so the flag alone never brings it into a release.
DEV_MODE = os.environ.get("DEV_MODE", "").lower() in ("1", "true")


def build_label(dev: bool) -> str:
    """Footer text: the version; dev builds add commit and build time so the author knows what is running."""
    parts = [f"Version {BUILD['version']}"]
    if dev:
        parts += [BUILD["commit"] or "no commit", f"built {BUILD['build_time']}" if BUILD["build_time"] else "no build time"]
    return " · ".join(parts)


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"environment variable {name} is required")
    return value
