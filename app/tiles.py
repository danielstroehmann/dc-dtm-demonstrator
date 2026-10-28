"""Every use case shows its devices: up to WALL_FROM - 1 as large tiles (_device_tile.html), from WALL_FROM on as the
minion wall – one cell per device, coloured by its state. The Advanced use cases store their devices; for the others
each device is derived from the run's certificates (UC-4: one device that renews, UC-5: one device per passcode)."""

from .evergreen import common_names

WALL_FROM = 11
STATES = ("pending", "busy", "issued", "renewed", "failed", "revoked")
ADVANCED = ("uc06", "uc07", "uc08")


def _cert(c: dict, renewed: bool = False, renewed_from: bool = False) -> dict:
    """A certificate of the run's result in the shape DTM's device listing has (see devices.read_devices)."""
    return {"serial": c.get("serial"), "common_name": c.get("common_name"), "status": "issued",
            "valid_to": (c.get("not_after") or "")[:10], "renewed": renewed, "renewed_from": renewed_from}


def devices(run: dict) -> list[dict]:
    """The run's devices as tiles and wall show them – copies, never the stored dicts. While a run issues, its
    devices are not known yet: the wall shows one placeholder (name None) per device of the progress."""
    r, p, use_case = run.get("result") or {}, run["params"], run["use_case"]
    certificates = r.get("certificates") or []
    if use_case in ADVANCED:
        found = [dict(d) for d in r.get("devices") or []]
    elif use_case == "uc04":
        last = len(certificates) - 1
        found = [{"name": certificates[0]["common_name"], "issued": len(certificates),
                  "certificates": [_cert(c, i < last, i > 0) for i, c in enumerate(certificates)]}] if certificates else []
        if found and r.get("renewals"):
            found[0]["last"] = {"action": "Renewed", "seconds": r["renewals"][-1]["seconds"]}
    elif use_case == "uc05" and (r.get("provisioning") or run["status"] == "paused"):
        # one device per passcode, in the order the factory provisioned them
        by_cn = {c["common_name"]: c for c in certificates}
        found = [{"name": cn, "issued": int(cn in by_cn), "certificates": [_cert(by_cn[cn])] if cn in by_cn else []}
                 for cn in common_names(run["id"], p["protocol"], p["count"], use_case)]
    else:
        found = [{"name": c["common_name"], "issued": 1, "certificates": [_cert(c)]} for c in certificates]
    progress = run.get("progress") or {}
    if run["status"] == "running" and progress.get("total") and len(found) < progress["total"] and use_case not in ADVANCED:
        found += [{"name": None, "issued": 0, "certificates": []} for _ in range(progress["total"] - len(found))]
    busy = set(r.get("busy") or [])
    if use_case == "uc04" and run["status"] == "renewing":
        busy |= {d["name"] for d in found}
    for d in found:
        d["busy"] = d["name"] in busy
    return found


def state(run: dict, d: dict, index: int = 0) -> str:
    """One of STATES – the wall's colour of the device."""
    if d.get("busy"):
        return "busy"
    if run.get("cleanup_status") == "done":
        return "revoked"
    current = [c for c in d.get("certificates") or [] if c.get("status") == "issued"]
    if not current:
        if d.get("certificates"):
            return "revoked"
        if d["name"] is None and index < ((run.get("progress") or {}).get("done") or 0):
            return "issued"  # issued while the run goes on – the wall turns green as the batch fills up
        return "failed" if run["status"] in ("failed", "interrupted") else "pending"
    renewals = [x for x in (run.get("result") or {}).get("renewals") or [] if x.get("device") == d["name"]]
    if renewals and renewals[-1].get("failed"):
        return "failed"
    return "renewed" if any(c.get("renewed_from") for c in d["certificates"]) else "issued"


def wall(run: dict, found: list[dict]) -> dict:
    """The wall's cells and counters. Cells step down in size above 1000 so 2000 fit on a desktop screen."""
    cells = [d | {"state": state(run, d, i)} | _identity(d) for i, d in enumerate(found)]
    counts = {s: sum(1 for c in cells if c["state"] == s) for s in STATES}
    small = len(cells) > 1000
    size, gap = (10, 3) if small else (14, 4)
    columns = min(80 if small else 60, len(cells))
    rows = -(-len(cells) // columns)
    pitch = size + gap
    return {"cells": cells, "counts": {s: n for s, n in counts.items() if n}, "size": size, "pitch": pitch,
            "columns": columns, "width": columns * pitch - gap, "height": rows * pitch - gap}


def serial_key(serial: str | None) -> str:
    """One spelling per serial: upper case without leading zeros – how the saved PEMs are named
    (format(n, "X")). DTM lists serials in either case and may pad them with zeros."""
    return (serial or "").upper().lstrip("0") or ("0" if serial else "")


def short(serial: str | None) -> str:
    """First and last three hex digits – enough to tell a device's certificates apart."""
    serial = (serial or "").upper()  # DTM lists hex serials in either case
    return f"{serial[:3]}…{serial[-3:]}" if len(serial) > 8 else serial


def cert_state(c: dict) -> str:
    if c.get("status") != "issued":
        return c.get("status") or "unknown"
    return "renewed" if c.get("renewed") else "active"


def certificates(run: dict, d: dict) -> list[dict]:
    """The device's certificates as tile and detail view list them: newest first (UC-8: bootstrap, operational),
    each with its state and a compact label for the detail view's picker."""
    listed = d.get("certificates") or []
    listed = sorted(listed, key=lambda c: c.get("role") or "") if run["use_case"] == "uc08" else listed[::-1]
    out = []
    for c in listed:
        state = cert_state(c)
        parts = [c["role"].capitalize() if c.get("role") else None, short(c.get("serial")), state]
        out.append(c | {"state": state, "short": short(c.get("serial")), "label": " · ".join(p for p in parts if p)})
    return out


def _identity(d: dict) -> dict:
    """What a wall cell tells on hover (name, CN, short serial, validity) and is searched by (full serial)."""
    certificates = d.get("certificates") or []
    current = [c for c in certificates if c.get("status") == "issued" and not c.get("renewed")]
    cert = (current or certificates or [{}])[-1]
    serial, cn = cert.get("serial") or "", cert.get("common_name")
    parts = [d["name"], cn if cn != d["name"] else None, short(serial), f"until {cert['valid_to']}" if cert.get("valid_to") else None]
    return {"serial": serial, "tip": " · ".join(p for p in parts if p)}
