"""Minion launcher (UC-8): the only service that reaches Docker, through the socket proxy. It builds every
container itself – the minion image, its own network, no mounts, no privileges, labelled with the run – from a few
checked values, and reads or removes only containers that carry its label. The web app talks to this service
instead of Docker, so a compromised app cannot start anything else (the proxy cannot check request bodies).

Run: uvicorn app.launcher:api --host 0.0.0.0 --port 8080"""

import json
import os
import re

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DOCKER = os.environ.get("MINION_DOCKER", "")  # the socket proxy, e.g. http://docker:2375
IMAGE = os.environ.get("MINION_IMAGE", "dtm-minion:latest")
NETWORK = os.environ.get("MINION_NETWORK", "dtm-minions")
API_VERSION = "/v1.44"  # Docker Engine 25+; Engine 29 refuses older versions by default
LABEL = "dtm-demonstrator.run"
RUN = re.compile(r"^[a-z0-9]{1,16}$")
NAME = re.compile(r"^robot-[a-z0-9]{1,16}-[a-z0-9-]{1,40}$")
CONTAINER = re.compile(r"^[0-9a-f]{12,64}$")
MAX_MINIONS = 50  # on this host, all runs together – the app allows 10 per run
ENV = {  # the only variables a minion gets, each with its shape
    "DTM_HOST": re.compile(r"^one(\.nl)?\.digicert\.com$"),
    "SERIAL": re.compile(r"^SN-[A-Z0-9]{1,16}-[0-9]{4}$"),
    "BOOT_POLICY": re.compile(r"^[A-Za-z0-9_-]{1,64}$"),
    "GROUP_ID": re.compile(r"^[A-Za-z0-9_-]{1,64}$"),
    "PASSCODE": re.compile(r"^[0-9a-f]{32}$"),
}

api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


class Minion(BaseModel):
    run_id: str
    name: str
    env: dict[str, str]


async def _call(method: str, path: str, expect: tuple[int, ...] = (200,), **kwargs) -> httpx.Response:
    if not DOCKER:
        raise HTTPException(503, "no minion runtime configured")
    try:
        async with httpx.AsyncClient(base_url=DOCKER + API_VERSION, timeout=30) as http:
            response = await http.request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Docker {method} {path.split('?')[0]} failed: {type(exc).__name__}") from exc
    if response.status_code not in expect:
        raise HTTPException(502, f"Docker {method} {path.split('?')[0]} returned {response.status_code}: "
                                 f"{response.text[:200]}")
    return response


async def _ours(container: str) -> dict:
    """The container's inspect data – only for a container this launcher created."""
    if not CONTAINER.fullmatch(container):
        raise HTTPException(404, "unknown container")
    info = (await _call("GET", f"/containers/{container}/json", (200, 404))).json()
    if "State" in info and (info.get("Config", {}).get("Labels") or {}).get(LABEL) is None:
        raise HTTPException(404, "unknown container")
    return info


@api.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


@api.get("/available")
async def available() -> dict:
    """Whether the minion image is built."""
    try:
        await _call("GET", f"/images/{IMAGE}/json")
        return {"available": True}
    except HTTPException:
        return {"available": False}


@api.post("/minions")
async def start(minion: Minion) -> dict:
    """Creates and starts one minion. Returns its container ID."""
    if not RUN.fullmatch(minion.run_id) or not NAME.fullmatch(minion.name):
        raise HTTPException(422, "unexpected run or minion name")
    if set(minion.env) - set(ENV) or not all(ENV[k].fullmatch(v) for k, v in minion.env.items()):
        raise HTTPException(422, "unexpected minion environment")
    running = await _call("GET", "/containers/json",
                          params={"all": 1, "filters": json.dumps({"label": [LABEL]})})
    if len(running.json()) >= MAX_MINIONS:
        raise HTTPException(429, f"at most {MAX_MINIONS} minions on this host")
    body = {"Image": IMAGE, "Env": [f"{k}={v}" for k, v in minion.env.items()], "Labels": {LABEL: minion.run_id},
            "HostConfig": {"NetworkMode": NETWORK, "Memory": 96 * 1024 * 1024, "NanoCpus": 500_000_000, "PidsLimit": 64,
                           "SecurityOpt": ["no-new-privileges:true"], "RestartPolicy": {"Name": "no"},
                           "LogConfig": {"Type": "json-file", "Config": {"max-size": "1m"}}}}
    created = await _call("POST", "/containers/create", (201,), params={"name": minion.name}, json=body)
    container = created.json()["Id"]
    try:
        await _call("POST", f"/containers/{container}/start", (204, 304))
    except HTTPException:  # a container that never ran is no use to anyone
        await _call("DELETE", f"/containers/{container}", (204, 404), params={"force": 1})
        raise
    return {"container": container}


@api.get("/minions/{container}")
async def state(container: str) -> dict:
    """Docker state and the last 400 log lines (with timestamps) of one minion."""
    info = await _ours(container)
    if "State" not in info:
        return {"status": "gone", "lines": []}
    logs = await _call("GET", f"/containers/{container}/logs",
                       params={"stdout": 1, "stderr": 1, "tail": 400, "timestamps": 1})
    return {"status": info["State"].get("Status", "unknown"), "lines": lines(logs.content)}


@api.delete("/runs/{run_id}")
async def remove_run(run_id: str) -> dict:
    """Removes every minion of the run (found by its label). Returns how many."""
    if not RUN.fullmatch(run_id):
        raise HTTPException(422, "unexpected run")
    listed = await _call("GET", "/containers/json",
                         params={"all": 1, "filters": json.dumps({"label": [f"{LABEL}={run_id}"]})})
    containers = [c for c in listed.json() if (c.get("Labels") or {}).get(LABEL) == run_id]
    for c in containers:
        await _call("DELETE", f"/containers/{c['Id']}", (204, 404), params={"force": 1})
    return {"removed": len(containers)}


def lines(raw: bytes) -> list[str]:
    """Docker multiplexes stdout/stderr without a TTY: 8-byte frame headers before each chunk."""
    out, i = b"", 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        out += raw[i + 8:i + 8 + size]
        i += 8 + size
    return out.decode(errors="replace").splitlines()
