"""Minions: one Docker container per simulated device, running DigiCert TrustEdge (UC-8). The app never reaches
Docker itself: it asks the minion launcher (app/launcher.py, its own service), which alone talks to the Docker
socket proxy and builds every container from a few checked values. Here: the launcher client and what the minion's
log tells about it (stage, firmware, the TrustEdge agent's lifecycle)."""

import os
import re
from datetime import datetime, timedelta, timezone

import httpx

LAUNCHER = os.environ.get("MINION_LAUNCHER", "")  # e.g. http://launcher:8080; empty: no minions
EVENT = re.compile(r'^\{"minion":"[^"]*","event":"([a-z_]+)"\}$')
FIRMWARE = re.compile(r'^\{"minion":"[^"]*","event":"firmware","version":([0-9]{1,4})\}$')


class MinionError(RuntimeError):
    pass


async def _call(method: str, path: str, timeout: float = 30, **kwargs) -> dict:
    if not LAUNCHER:
        raise MinionError("no minion runtime configured")
    try:
        async with httpx.AsyncClient(base_url=LAUNCHER, timeout=timeout) as http:
            response = await http.request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        raise MinionError(f"the minion launcher is not reachable ({type(exc).__name__})") from exc
    if response.status_code != 200:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = response.text[:200]
        raise MinionError(f"the minion launcher refused {method} {path}: {detail}")
    return response.json()


async def available() -> bool:
    """Whether minions can run here: the launcher answers and the minion image is built (short timeout – pages
    call this)."""
    if not LAUNCHER:
        return False
    try:
        return bool((await _call("GET", "/available", timeout=3))["available"])
    except MinionError:
        return False


async def start(run_id: str, name: str, env: dict[str, str]) -> str:
    """Creates and starts the device's container. Returns its ID."""
    return (await _call("POST", "/minions", json={"run_id": run_id, "name": name, "env": env}))["container"]


async def remove_run(run_id: str) -> int:
    """Removes every container of the run. Returns how many."""
    return (await _call("DELETE", f"/runs/{run_id}"))["removed"]


# The agent's lifecycle as its log shows it (TrustEdge 26.6, INFO level) – the latest matching line wins
AGENT = ((re.compile(r"Starting connection to MQTT endpoint"), "connecting"),
         (re.compile(r"Connected to endpoint|Connection established to MQTT"), "online"),
         (re.compile(r"Processing pending policies"), "checking for updates"),
         (re.compile(r"Processing certificate specification|Creating certificate request"), "requesting certificate"),
         (re.compile(r"Writing issued certificate"), "certificate received"),
         (re.compile(r"deployment progress message \(Downloading\)"), "downloading update"),
         (re.compile(r"deployment progress message \(Installing\)"), "installing update"),
         (re.compile(r"deployment progress message \(Installed\)"), "update installed"),
         (re.compile(r"Finished processing policy"), "online"),
         (re.compile(r"Terminating connection to MQTT endpoint"), "offline"))
CHECK_S = 10
ONLINE_S, OFFLINE_S = 100, 10  # observed defaults until the log shows a full cycle
STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)\S* (.*)$")


async def state(container: str) -> dict:
    """What the minion shows of itself: Docker state, its last reported event, its installed firmware version and
    the TrustEdge agent's lifecycle state with the time (UTC) it was entered."""
    seen = await _call("GET", f"/minions/{container}")
    if seen["status"] == "gone":
        return {"status": "gone", "event": None, "firmware": None, "agent": None, "since": None, "next_connect": None}
    lines = [m.groups() for line in seen["lines"] if (m := STAMP.match(line))]
    events = [m.group(1) for _, line in lines if (m := EVENT.match(line))]
    versions = [int(m.group(1)) for _, line in lines if (m := FIRMWARE.match(line))]
    agent = since = None
    connects, ends = [], []  # when the agent started connecting / terminated, to learn its cycle
    for stamp, line in lines:
        label = next((label for pattern, label in AGENT if pattern.search(line)), None)
        if label == "connecting":
            connects.append(_at(stamp))
        elif label and label.startswith("offline"):
            ends.append(_at(stamp))
        if label and label != agent:
            agent, since = label, stamp
    if agent == "checking for updates" and since and (
            datetime.now(timezone.utc) - datetime.fromisoformat(since + "+00:00")).total_seconds() > CHECK_S:
        agent = "online"  # nothing pending: the check leaves no further line
    status = seen["status"]
    running = status == "running"
    return {"status": status, "event": events[-1] if events else None, "firmware": versions[-1] if versions else None,
            "agent": agent if running else None, "since": since if running else None,
            "next_connect": _next_connect(connects, ends) if running else None}


def _at(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp + "+00:00")


def _next_connect(connects: list[datetime], ends: list[datetime]) -> str | None:
    """When the agent will connect next – learnt from its own cycle (TrustEdge keeps its own timing: about 100 s
    online and 10 s offline, whatever the configuration says). The latest observed durations count."""
    if not connects:
        return None
    online = next(((e - c).total_seconds() for c, e in zip(reversed(connects), reversed(ends)) if e > c), ONLINE_S)
    offline = next(((c - e).total_seconds() for e, c in zip(reversed(ends), reversed(connects)) if c > e), OFFLINE_S)
    last_connect, last_end = connects[-1], ends[-1] if ends else None
    start = last_end if last_end and last_end > last_connect else last_connect + timedelta(seconds=online)
    return (start + timedelta(seconds=offline)).strftime("%Y-%m-%dT%H:%M:%SZ")
