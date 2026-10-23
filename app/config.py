import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
# Version shown in the UI; set by the image build (release tag or branch).
APP_VERSION = os.environ.get("APP_VERSION", "dev")


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"environment variable {name} is required")
    return value
