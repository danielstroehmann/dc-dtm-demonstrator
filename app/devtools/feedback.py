"""Feedback overlay backend (dev mode only): the author points at an element and comments on it.

Each item is one JSON file plus its screenshot PNG in data/feedback/; an agent works through the `open`
items and sets them to `done` with a note. File names are generated here – nothing from the request ever
becomes part of a path. Authentication and the same-origin check come from the app's middleware."""

import json
import logging
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile

log = logging.getLogger("demonstrator.feedback")
HERE = Path(__file__).parent
MAX_SCREENSHOT = 5 << 20  # one viewport at scale 1 is well below 1 MB
MAX_BODY = MAX_SCREENSHOT + (64 << 10)
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
# field: (required, max length)
FIELDS = {"comment": (True, 4000), "selector": (True, 1000), "component": (False, 300),
          "text": (False, 2000), "url": (True, 2000), "viewport": (True, 32)}
VIEWPORT = re.compile(r"\d{1,5}x\d{1,5}@\d{1,2}(\.\d{1,2})?")


def install(app: FastAPI, directory: Path, build: dict) -> None:
    app.mount("/devtools/static", StaticFiles(directory=HERE / "static"), name="devtools")

    @app.post("/feedback")
    async def save_feedback(request: Request):
        # Checked before the body is parsed: multipart parsing would otherwise spool any size to disk.
        length = request.headers.get("content-length", "")
        if not length.isdecimal() or int(length) > MAX_BODY:
            raise HTTPException(413, "Feedback too large or without Content-Length")
        form = await request.form(max_files=1, max_fields=len(FIELDS), max_part_size=8 << 10)
        values = {}
        for name, (required, limit) in FIELDS.items():
            value = form.get(name, "")
            if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
                raise HTTPException(400, f"Invalid feedback field: {name}")
            values[name] = value.strip()
        if not VIEWPORT.fullmatch(values["viewport"]):
            raise HTTPException(400, "Invalid feedback field: viewport")
        if not values["url"].startswith("/") or values["url"].startswith("//"):
            raise HTTPException(400, "Invalid feedback field: url")
        screenshot = form.get("screenshot")
        if not isinstance(screenshot, UploadFile):
            raise HTTPException(400, "Screenshot missing")
        png = await screenshot.read(MAX_SCREENSHOT + 1)
        if len(png) > MAX_SCREENSHOT or not png.startswith(PNG_MAGIC):
            raise HTTPException(400, "Screenshot must be a PNG of at most 5 MB")

        now = datetime.now(UTC)
        item_id = f"{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
        item = {
            "id": item_id, "status": "open", "note": None, "created": now.isoformat(timespec="seconds"),
            "comment": values["comment"],
            "element": {"selector": values["selector"], "component": values["component"], "text": values["text"]},
            "url": values["url"], "viewport": values["viewport"],
            "user_agent": request.headers.get("user-agent", "")[:300],
            "build": build, "screenshot": f"{item_id}.png",
        }
        directory.mkdir(parents=True, exist_ok=True)
        # The PNG first: a JSON item always has its screenshot. "x" never overwrites an existing item.
        with (directory / f"{item_id}.png").open("xb") as handle:
            handle.write(png)
        with (directory / f"{item_id}.json").open("x", encoding="utf-8") as handle:
            json.dump(item, handle, indent=2, ensure_ascii=False)
        log.info("feedback %s saved for %s", item_id, values["url"])
        return JSONResponse({"id": item_id}, status_code=201)
