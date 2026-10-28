"""UC-8 – TrustEdge managed devices (Advanced license). Real Docker containers simulate devices running DigiCert
TrustEdge. The factory creates each device in DTM (name + serial number) and gives it nothing but an individual
one-time passcode bound to its serial number. In the field the minion enrolls a long-lived bootstrap
certificate via EST (CN = serial number), loads its bootstrap configuration via mTLS and starts the TrustEdge
agent, which fetches the operational certificate over MQTT (CN = device name) and renews it itself before it expires
(TrustEdge has no command to renew on demand – so there is no renewal per click).

Verified end to end on US 2026-10-27. On NL the agent's request for the operational certificate is not
answered (reported to DTM) – the use case is offered for US connections only."""

import asyncio
import os
import secrets
import time
from pathlib import Path

from . import dtm, enrollment, firmware, minions
from .apicalls import ApiCalls
from .devices import DEVICE_DESCRIPTION, DeviceError, commit, device_action, device_dir, device_of, identity
from .dtm import DTMClient, DTMError
from .evergreen import LIST, by_name, common_names, create_division, prefix, use_profile
from .store import Store, now

MAX_DEVICES = 10  # each device is a running container with an agent
FIELD_TIMEOUT_S = 300  # bootstrap enrollment + configuration + agent connect + operational certificate
POLL_S = 3.0
PLATFORM = "one.digicert.com"


def supported(host: str) -> bool:
    return host == PLATFORM


async def run(store: Store, client: DTMClient, run_id: str, run_dir: Path) -> None:
    run_ = store.get_run(run_id)
    p = run_["params"] | {"use_case": run_["use_case"]}
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    api = ApiCalls()
    variables = {"DTM_HOST": p["dtm_host"], "DTM_ACCOUNT_ID": p["account_id"], "ICA_ID": p["ca_id"]}
    result: dict = {"api_calls": api.calls, "api_variables": variables}
    store.update_run(run_id, status="running")
    base = prefix(run_id, p["use_case"])
    try:
        division_id = await create_division(client, api, store, run_id, p["use_case"], variables, log)
        log(f"Creating authentication policy {base}-auth")
        auth_policy_id = await api.timed(
            "Create an authentication policy for the devices' passcodes", "POST", enrollment.AUTH_POLICY_PATH,
            client.create_auth_policy(f"{base}-auth"),
            spec={"method": "POST", "path": enrollment.AUTH_POLICY_PATH, "body_file": "auth-policy.json",
                  "json": {"name": "{RUN_NAME}-auth", "account_id": "{DTM_ACCOUNT_ID}"},
                  "capture": {"var": "AUTH_POLICY_ID", "jq": ".id", "ps": "$r.id"}}, phase="setup")
        store.add_object(run_id, "auth_policy", auth_policy_id, f"{base}-auth")
        variables["AUTH_POLICY_ID"] = auth_policy_id

        # Bootstrap: evergreen, EST with the passcode, only for devices of the group
        profile_id = await use_profile(client, api, store, run_id, p["use_case"], dtm.PROFILE_EVERGREEN, variables, log)
        boot = await _policy(client, api, store, run_id, f"{base}-boot-policy", "BOOT_POLICY_ID",
                             "Create the bootstrap policy (EST + passcode, only for devices of the group)",
                             dtm.enrollment_policy_body(name="{n}", division_id=division_id, profile_id=profile_id,
                                                        ica_id=p["ca_id"], key_type="P_256",
                                                        auth_policy_id=auth_policy_id, protocol="est",
                                                        device_group=True), variables, log)
        # Operational: short-lived, the TrustEdge agent applies it over MQTT
        profile_id = await use_profile(client, api, store, run_id, p["use_case"], dtm.PROFILE_RENEWAL, variables, log)
        operational = await _policy(client, api, store, run_id, f"{base}-op-policy", "OP_POLICY_ID",
                                    "Create the operational policy (TrustEdge agent, CN = device name)",
                                    dtm.trustedge_policy_body(name="{n}", division_id=division_id,
                                                              profile_id=profile_id, ica_id=p["ca_id"],
                                                              auth_policy_id=auth_policy_id), variables, log)
        group_name = f"{base}-group"
        log(f"Creating device group {group_name} – bootstrap (serial number) and operational (device name)")
        body = dtm.trustedge_group_body(group_name, division_id, p["account_id"], boot, operational, auth_policy_id)
        group_id = await api.timed(
            "Create the device group (bootstrap: serial number → CN, operational: device name → CN)", "POST",
            dtm.DEVICE_GROUPS, client.create_device_group(group_name, division_id, "", "", body=body),
            spec={"method": "POST", "path": dtm.DEVICE_GROUPS, "body_file": "device-group.json",
                  "json": dtm.trustedge_group_body("{RUN_NAME}-group", "{DIVISION_ID}", "{DTM_ACCOUNT_ID}",
                                                   "{BOOT_POLICY_ID}", "{OP_POLICY_ID}", "{AUTH_POLICY_ID}")},
            phase="setup")
        api.add("Look up the device group ID by its name", "GET", dtm.DEVICE_GROUPS, None, phase="setup",
                spec={"method": "GET", "path": dtm.DEVICE_GROUPS, "query": LIST,
                      "capture": by_name("GROUP_ID", "{RUN_NAME}-group")})
        store.add_object(run_id, "device_group", group_id, group_name)
        variables["GROUP_ID"] = group_id
        log("DTM is configured for this run", "success")
        result |= {"division": f"{base}-division", "group": group_name, "identity": "Serial number"}

        await _factory(client, api, store, run_id, run_dir, group_id, auth_policy_id, p, log, result)
        _seed_field_steps(api)
        first = result["devices"][0]
        variables |= {"DEVICE_NAME": first["name"], "SERIAL": first["serial"],
                      "PASSCODE": "<the device's passcode from the factory>"}
        result["renewals"] = []
        if p.get("pause"):
            log("The devices are registered in DTM with a passcode each – start each IoT minion from its tile", "success")
        else:
            store.update_run(run_id, result=result)  # each device commits onto the stored result
            started_wall, names = time.time(), [d["name"] for d in result["devices"]]
            try:
                for done, name in enumerate(names):
                    store.update_run(run_id, progress={"label": f"Starting {len(names)} IoT minions in the field",
                                                       "started": started_wall, "total": len(names), "done": done})
                    await _field(store, client, run_id, run_dir, name, log)
            finally:
                result = store.get_run(run_id)["result"]
        try:  # the firmware catalogue the run page offers – not needed for the run itself
            await firmware.refresh(store, client)
        except DTMError as exc:
            log(f"Could not read the firmware catalogue: {exc}")
        store.update_run(run_id, status="completed", result=result, progress=None, finished_at=now())
        log("Run completed", "success")
    except (DTMError, ValueError, minions.MinionError) as exc:
        log(f"Run failed: {exc}", "error")
        store.update_run(run_id, status="failed", error=str(exc), progress=None, finished_at=now(), result=result)
    except Exception as exc:  # keep the run visible as failed instead of silently dying
        log(f"Run failed unexpectedly: {type(exc).__name__}", "error")
        store.update_run(run_id, status="failed", error=type(exc).__name__, progress=None, finished_at=now(),
                         result=result)
        raise


async def _policy(client: DTMClient, api: ApiCalls, store: Store, run_id: str, name: str, var: str, purpose: str,
                  body: dict, variables: dict, log) -> str:
    log(f"Creating certificate policy {name}")
    real = {"certificate_policy": body["certificate_policy"] | {"name": name}}
    shown = {"certificate_policy": body["certificate_policy"] | {
        "name": name.replace(prefix_of(name), "{RUN_NAME}"), "division_id": "{DIVISION_ID}",
        "certificate_profile_id": "{PROFILE_ID}", "ica_id": "{ICA_ID}", "authentication_policy_id": "{AUTH_POLICY_ID}"}}
    policy_id = await api.timed(purpose, "POST", dtm.POLICIES, client.create_device_policy(body=real),
                                spec={"method": "POST", "path": dtm.POLICIES, "body_file": "policy.json", "json": shown},
                                phase="setup")
    api.add("Look up the policy ID by its name", "GET", dtm.POLICIES, None, phase="setup",
            spec={"method": "GET", "path": dtm.POLICIES, "query": LIST,
                  "capture": by_name(var, shown["certificate_policy"]["name"])})
    store.add_object(run_id, "policy", policy_id, name)
    variables[var] = policy_id
    return policy_id


def prefix_of(name: str) -> str:
    return name.rsplit("-", 2)[0]  # robot-<run>-uc08 of robot-<run>-uc08-boot-policy


async def _factory(client: DTMClient, api: ApiCalls, store: Store, run_id: str, run_dir: Path, group_id: str,
                   auth_policy_id: str, p: dict, log, result: dict) -> None:
    """Per device: register it in DTM with its serial number, create its one-time passcode bound to that serial
    number – the only thing the device takes from the factory (kept in the run dir until the field start)."""
    names = common_names(run_id, "iot-minion", p["count"], p["use_case"])
    base = prefix(run_id, p["use_case"])
    log(f"Factory: registering {len(names)} device(s) – each gets only a one-time passcode")
    devices, create_s, passcode_s, started_wall = [], 0.0, 0.0, time.time()
    for done, name in enumerate(names, 1):
        device, created, passcoded = await _register(client, store, run_id, run_dir, group_id, auth_policy_id, done,
                                                     name, base)
        create_s, passcode_s = create_s + created, passcode_s + passcoded
        devices.append(device)
        result |= {"devices": devices, "certificate_total": 0}
        store.update_run(run_id, result=result, progress={
            "label": f"Factory: registering {len(names)} devices", "started": started_wall, "total": len(names),
            "done": done})
    api.add("Name the device and draw its serial number", "LOCAL", "openssl", None, spec={"command": {
        "bash": 'export DEVICE_NAME="${RUN_NAME}-iot-minion-0001"\nexport SERIAL="SN-$(openssl rand -hex 4 | tr a-f A-F)-0001"\n'
                'export PASSCODE="$(openssl rand -hex 16)"',
        "powershell": '$env:DEVICE_NAME = "$env:RUN_NAME-iot-minion-0001"\n'
                      '$env:SERIAL = "SN-$((openssl rand -hex 4).ToUpper())-0001"\n$env:PASSCODE = openssl rand -hex 16'}})
    api.add("Register the device with its serial number (once per device)", "POST", f"{dtm.DEVICES}/enroll",
            round(create_s, 2), count=len(devices),
            spec={"method": "POST", "path": f"{dtm.DEVICES}/enroll", "body_file": "device.json",
                  "json": dtm.device_body("{DEVICE_NAME}", "{DTM_ACCOUNT_ID}", "{GROUP_ID}", DEVICE_DESCRIPTION,
                                          "serial_number", "{SERIAL}")})
    api.add("Create the device's one-time passcode, bound to its serial number", "POST", enrollment.PASSCODE_PATH,
            round(passcode_s, 2), count=len(devices),
            spec={"method": "POST", "path": enrollment.PASSCODE_PATH, "body_file": "passcode.json",
                  "json": dtm.passcode_body("{RUN_NAME}-passcode-0001", "{DTM_ACCOUNT_ID}", "{AUTH_POLICY_ID}",
                                            "{PASSCODE}", "{SERIAL}")})
    result["factory"] = {"duration_s": round(create_s + passcode_s, 2), "create_s": round(create_s, 2),
                         "passcode_s": round(passcode_s, 2),
                         "per_certificate_s": round((create_s + passcode_s) / len(devices), 3)}
    store.update_run(run_id, result=result, progress=None)
    log(f"{len(devices)} device(s) registered – each holds only its passcode", "success")


async def _register(client: DTMClient, store: Store, run_id: str, run_dir: Path, group_id: str, auth_policy_id: str,
                    number: int, name: str, base: str) -> tuple[dict, float, float]:
    """One device from the factory: registered in DTM with its serial number, plus its one-time passcode bound to
    that serial number (kept in the run dir until the field start). Returns (device, register s, passcode s)."""
    serial = identity(run_id, number, "serial")
    start = time.monotonic()
    device_id = await client.enroll_device(name, group_id, DEVICE_DESCRIPTION, "serial_number", serial)
    if not dtm.SAFE_ID.fullmatch(str(device_id)):
        raise DeviceError(f"DTM returned an unusable device ID for {name}")
    store.add_object(run_id, "device", device_id, name)
    created = time.monotonic()
    passcode = secrets.token_hex(16)
    made = await client.create_passcode(f"{base}-passcode-{number:04d}", auth_policy_id, passcode, serial)
    store.add_object(run_id, "passcode", made["id"], f"{base}-passcode-{number:04d}")
    _write_secret(device_dir(run_dir, name), "passcode", passcode.encode())
    return ({"name": name, "identity": name, "serial": serial, "id": device_id, "issued": 0, "certificate_id": None,
             "stage": "factory"}, created - start, time.monotonic() - created)


ADDING = "adding"  # marks a device being added in the run's busy list


async def add_device(store: Store, client: DTMClient, run_id: str, run_dir: Path) -> None:
    """Per click: one more IoT minion from the factory – registered with its passcode, started from its tile."""
    await device_action(store, run_id, ADDING, "Adding an IoT minion",
                        lambda log: _add(store, client, run_id, run_dir, log))


async def _add(store: Store, client: DTMClient, run_id: str, run_dir: Path, log) -> None:
    run_ = store.get_run(run_id)
    number = len(run_["result"]["devices"]) + 1
    if number > MAX_DEVICES:
        raise ValueError(f"at most {MAX_DEVICES} IoT minions per run")
    groups, auth = store.objects(run_id, "device_group"), store.objects(run_id, "auth_policy")
    if not groups or not auth:
        raise ValueError("the run has no device group or authentication policy any more")
    base = prefix(run_id, run_["use_case"])
    name = f"{base}-iot-minion-{number:04d}"
    log(f"Factory: registering {name} – it gets only a one-time passcode")
    device, created, passcoded = await _register(client, store, run_id, run_dir, groups[0]["dtm_id"],
                                                 auth[0]["dtm_id"], number, name, base)

    def added(r: dict) -> None:
        r["devices"].append(device)
        for call in r["api_calls"]:
            if call["purpose"].startswith(("Register the device", "Create the device's one-time passcode")):
                call["count"] = call.get("count", 1) + 1
    commit(store, run_id, added)
    log(f"{name} registered in {created + passcoded:.1f}s – start it from its tile", "success")


def _write_secret(folder: Path, name: str, data: bytes) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    with os.fdopen(os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as handle:
        handle.write(data)


def _seed_field_steps(api: ApiCalls) -> None:
    api.add("Build the IoT minion image (DigiCert TrustEdge from its public release)", "LOCAL", "docker", None,
            phase="setup", spec={"command": {"bash": minions_build(), "powershell": minions_build()}})
    api.add("Start the IoT minion: bootstrap via EST, configuration via mTLS, TrustEdge agent", "LOCAL", "docker", None,
            phase="field", spec={"command": {
                "bash": 'docker run -d --name "${DEVICE_NAME}" -e DTM_HOST="${DTM_HOST}" -e SERIAL="${SERIAL}" \\\n'
                        '  -e BOOT_POLICY="${BOOT_POLICY_ID}" -e GROUP_ID="${GROUP_ID}" -e PASSCODE="${PASSCODE}" dtm-minion',
                "powershell": 'docker run -d --name "$env:DEVICE_NAME" -e DTM_HOST="$env:DTM_HOST" -e SERIAL="$env:SERIAL" `\n'
                              '  -e BOOT_POLICY="$env:BOOT_POLICY_ID" -e GROUP_ID="$env:GROUP_ID" -e PASSCODE="$env:PASSCODE" dtm-minion'}})
    api.add("Follow the IoT minion (bootstrap, configured, agent – then the operational certificate)", "LOCAL", "docker",
            None, phase="field", spec={"command": {"bash": 'docker logs -f "${DEVICE_NAME}"',
                                                   "powershell": 'docker logs -f "$env:DEVICE_NAME"'}})
    api.add("Read the certificates filed under the device", "GET", f"{dtm.DEVICES}/certificates", None, phase="field",
            spec={"method": "GET", "path": f"{dtm.DEVICES}/certificates", "query": "device_id={DEVICE_ID}"})


def minions_build() -> str:
    return ("# minion/ of the demonstrator's repository: Dockerfile + entrypoint.sh\n"
            "docker build -t dtm-minion minion/")


START_STAGGER_S = 5  # Start all: the minions start one after the other – not every DTM call at once


def startable(device: dict) -> bool:
    """A device whose minion can start: not started, not enrolled, not acting (tiles.devices)."""
    return bool(device["name"]) and not device.get("container") and not device.get("issued") and not device["busy"]


async def enroll(store: Store, client: DTMClient, run_id: str, run_dir: Path, name: str, delay: float = 0) -> None:
    """Per click: the device goes into the field – its minion starts (after delay: Start all staggers them)."""
    async def act(log):
        await asyncio.sleep(delay)
        await _field(store, client, run_id, run_dir, name, log)
    await device_action(store, run_id, name, "Field start", act)


async def _field(store: Store, client: DTMClient, run_id: str, run_dir: Path, name: str, log) -> None:
    """Starts the device's minion and follows it until DTM lists the operational certificate under the device."""
    run_ = store.get_run(run_id)
    p, device = run_["params"], device_of(run_["result"], name)
    policies = {o["name"].rsplit("-", 2)[-2]: o["dtm_id"] for o in store.objects(run_id, "policy")}
    groups = store.objects(run_id, "device_group")
    secret = device_dir(run_dir, name) / "passcode"
    if "boot" not in policies or not groups or not secret.is_file():
        raise DeviceError("the run has no bootstrap policy, device group or passcode for this device any more")
    log(f"{name}: starting its IoT minion – TrustEdge enrolls the bootstrap certificate with the passcode")
    started = time.monotonic()
    container = await minions.start(run_id, name, {
        "DTM_HOST": p["dtm_host"], "SERIAL": device["serial"], "BOOT_POLICY": policies["boot"],
        "GROUP_ID": groups[0]["dtm_id"], "PASSCODE": secret.read_text()})
    # recorded before the passcode goes: a restart in between must not leave a running minion nobody knows
    commit(store, run_id, lambda r: device_of(r, name).update(container=container, stage="starting"))
    secret.unlink()  # one-time: the device has it now
    stage, certificates = "starting", []
    while time.monotonic() - started < FIELD_TIMEOUT_S:
        await asyncio.sleep(POLL_S)
        seen = await minions.state(container)
        status, stage = seen["status"], seen["event"] or stage
        certificates = _certificates(await client.device_certificates(device["id"], quiet=True), device)
        commit(store, run_id, lambda r, s=stage, c=certificates, w=seen: device_of(r, name).update(
            stage=s, certificates=c, agent=w["agent"], agent_since=w["since"], next_connect=w["next_connect"],
            **({"firmware": w["firmware"]} if w["firmware"] else {})))
        if any(c["role"] == "operational" for c in certificates):
            break
        if status in ("exited", "dead", "gone"):
            raise DeviceError(f"{name}: the IoT minion stopped ({stage})")
    else:
        raise DeviceError(f"{name}: no operational certificate within {FIELD_TIMEOUT_S // 60} minutes ({stage})")
    seconds = time.monotonic() - started

    def done(r: dict) -> None:
        d = device_of(r, name)
        d |= {"issued": 1, "stage": "operational", "enroll_s": round(seconds, 1),
              "last": {"action": "Operational", "seconds": round(seconds, 1)}}
        r["certificate_total"] = sum(len(x.get("certificates") or []) for x in r["devices"])
        enrolled = [x["enroll_s"] for x in r["devices"] if x.get("enroll_s") is not None]
        r |= {"duration_s": round(sum(enrolled), 1), "median_s": sorted(enrolled)[len(enrolled) // 2]}
        for call in r["api_calls"]:
            if call.get("phase") == "field" and call["purpose"].startswith("Start the IoT minion"):
                call["count"] = len(enrolled)
    commit(store, run_id, done)
    log(f"{name}: operational certificate after {seconds:.0f}s – fetched by the TrustEdge agent over MQTT", "success")


def _certificates(records: list[dict], device: dict) -> list[dict]:
    """The device's certificates with their role: bootstrap (CN = serial number) or operational (CN = name)."""
    roles = {device["serial"]: "bootstrap", device["name"]: "operational"}
    return [{"serial": r.get("serial_number"), "common_name": r.get("common_name"),
             "role": roles.get(r.get("common_name"), "other"), "status": str(r.get("status", "")).lower(),
             "valid_to": str(r.get("valid_to", ""))[:10], "renewed": bool(r.get("is_renewed")),
             "renewed_from": bool(r.get("renewed_from_certificate_id"))} for r in records]
