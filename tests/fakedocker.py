"""Fake Docker Engine API behind the socket proxy (UC-8 minions), as httpx MockTransport.

install() wires the whole chain: the app's minion client (app/minions.py) → the launcher service (app/launcher.py,
in-process via ASGI) → this fake Docker. Containers are kept in memory; their logs are served as Docker's multiplexed stream (8-byte frame
headers) with RFC 3339 timestamps, as `docker logs --timestamps` without a TTY. `on_start` lets a test
play the device's part (e.g. have the fake DTM issue its certificates) when the container starts."""

import json
import re
import uuid

import httpx

from app import launcher, minions


def frame(text: str, stream: int = 1) -> bytes:
    data = text.encode()
    return bytes([stream, 0, 0, 0]) + len(data).to_bytes(4, "big") + data


class Routed:
    """httpx as a module sees it, with every AsyncClient going through the given transport."""

    def __init__(self, transport):
        self._transport = transport

    def __getattr__(self, name):
        return getattr(httpx, name)

    def AsyncClient(self, **kwargs):  # noqa: N802 – mirrors httpx.AsyncClient
        return httpx.AsyncClient(transport=self._transport(), **kwargs)


class FakeDocker:
    def __init__(self):
        self.containers: dict[str, dict] = {}
        self.image_present = True
        self.fail_start = False
        self.filter_ignored = False  # a proxy that lists every container, whatever the filter says
        self.on_start = None  # callable(container dict)
        self.requests: list[httpx.Request] = []
        self.calls: list[tuple[str, str]] = []  # (action, container name or id)

    def install(self, monkeypatch) -> "FakeDocker":
        monkeypatch.setattr(launcher, "DOCKER", "http://docker:2375")
        monkeypatch.setattr(minions, "LAUNCHER", "http://launcher:8080")
        # self.handle is looked up per request – a test may replace it
        monkeypatch.setattr(launcher, "httpx", Routed(lambda: httpx.MockTransport(lambda r: self.handle(r))))
        monkeypatch.setattr(minions, "httpx", Routed(lambda: httpx.ASGITransport(app=launcher.api)))
        return self

    def add(self, name: str, run_id: str | None, status: str = "running", logs: list[tuple[str, str]] = ()) -> dict:
        """run_id None: a container the launcher did not create (no label)."""
        labels = {launcher.LABEL: run_id} if run_id is not None else {}
        container = {"Id": uuid.uuid4().hex, "name": name, "labels": labels, "status": status,
                     "logs": list(logs), "body": {}}
        self.containers[container["Id"]] = container
        return container

    def log(self, container_id: str, stamp: str, line: str) -> None:
        self.containers[container_id]["logs"].append((stamp, line))

    def running(self) -> list[dict]:
        return list(self.containers.values())

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix(launcher.API_VERSION)
        method = request.method
        if method == "GET" and (m := re.fullmatch(r"/images/(.+)/json", path)):
            self.calls.append(("image", m.group(1)))
            return httpx.Response(200, json={"Id": "sha256:x"}) if self.image_present else \
                httpx.Response(404, json={"message": "No such image"})
        if method == "POST" and path == "/containers/create":
            name = request.url.params.get("name")
            if any(c["name"] == name for c in self.containers.values()):
                return httpx.Response(409, json={"message": "Conflict. The container name is already in use"})
            body = json.loads(request.content)
            container = self.add(name, body.get("Labels", {}).get(launcher.LABEL), status="created")
            container["body"] = body
            self.calls.append(("create", name))
            return httpx.Response(201, json={"Id": container["Id"], "Warnings": []})
        if method == "GET" and path == "/containers/json":
            label = json.loads(request.url.params.get("filters") or "{}").get("label", [""])[0]
            listed = [c for c in self.containers.values()
                      if self.filter_ignored or f"{launcher.LABEL}={c['labels'].get(launcher.LABEL)}" == label
                      or (label == launcher.LABEL and launcher.LABEL in c["labels"])]  # label present, any value
            return httpx.Response(200, json=[{"Id": c["Id"], "Names": [f"/{c['name']}"], "Labels": c["labels"]}
                                             for c in listed])
        m = re.fullmatch(r"/containers/([0-9a-f]+)(/[a-z]+)?", path)
        container = self.containers.get(m.group(1)) if m else None
        action = (m.group(2) or "") if m else ""
        if m and method == "DELETE" and not action:
            self.calls.append(("delete", container["name"] if container else m.group(1)))
            if not container:
                return httpx.Response(404, json={"message": "No such container"})
            del self.containers[container["Id"]]
            return httpx.Response(204)
        if container is None:
            return httpx.Response(404, json={"message": "No such container"})
        if method == "POST" and action == "/start":
            self.calls.append(("start", container["name"]))
            if self.fail_start:
                return httpx.Response(500, json={"message": "cannot start"})
            container["status"] = "running"
            if self.on_start:
                self.on_start(container)
            return httpx.Response(204)
        if method == "GET" and action == "/json":
            return httpx.Response(200, json={"Id": container["Id"], "Config": {"Labels": container["labels"]},
                                             "State": {"Status": container["status"]}})
        if method == "GET" and action == "/logs":
            assert request.url.params.get("timestamps") == "1"
            return httpx.Response(200, content=b"".join(frame(f"{stamp} {line}\n", 1 + i % 2)
                                                        for i, (stamp, line) in enumerate(container["logs"])))
        return httpx.Response(404, json={"message": f"unexpected {method} {path}"})
