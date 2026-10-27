"""UC-6 – managed devices (Advanced license). In the factory each device is created in DTM with an
inventory attribute – a fictitious serial number or MAC address – and gets its first certificate via the
REST API, EST or CMPv2 (API key, passcode or factory certificate). The certificate does not carry the
device name: its CN is the hardware identity, and DTM files it under the right device through the group's
attribute mapping. In the field the devices renew per click – via the REST API (the backend renews) or,
with the factory's protocol, the device itself with its current certificate.

Every request goes to the device-group variant of the endpoint – only that one files the certificate
under the device. Verified live on NL 2026-10-26."""

import asyncio
import hashlib
import statistics
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from . import certs, dtm, enrollment, minions
from .apicalls import ApiCalls
from .dtm import DTMClient, DTMError
from .evergreen import LIST, by_name, common_names, create_division, keygen_command, prefix, rates, use_profile
from .store import Store, now

PROTOCOLS = {"rest": "REST API", "est": "EST", "cmpv2": "CMPv2"}
AUTHS = {"apikey": "API key", "passcode": "Passcode", "certificate": "Factory certificate"}
IDENTITIES = {"serial": ("Serial number", "serial_number"), "mac": ("MAC address", "mac_address")}
MAX_DEVICES = 100
MAX_RENEWALS = 5  # per device – each renewal consumes DTM requests (the route checks it)
ESTIMATE_DEVICES = 1000
LIST_RETRIES = 5  # the device's certificate list lags a moment behind an issuance
DEVICE_DESCRIPTION = "dc-dtm-demonstrator run – safe to delete"
CURRENT_JQ = ('[.records[] | select((.status | ascii_upcase) == "ISSUED" and (.is_renewed | not))] '
              "| if length == 1 then .[0].certificate_id else empty end")
CURRENT_PS = ('$(if (($m = @($r.records | Where-Object { $_.status -eq "ISSUED" -and -not $_.is_renewed })).Count -eq 1) '
              '{ $m[0].certificate_id })')
# The replayed steps draw their own identity – never one of a run
IDENTITY_COMMAND = {
    "serial": {"bash": 'export IDENTITY="SN-$(openssl rand -hex 4 | tr a-f A-F)-0001"',
               "powershell": '$env:IDENTITY = "SN-$((openssl rand -hex 4).ToUpper())-0001"'},
    "mac": {"bash": "export IDENTITY=\"02:$(openssl rand -hex 5 | sed 's/../&:/g; s/:$//')\"",
            "powershell": '$env:IDENTITY = "02:" + ((openssl rand -hex 5) -replace "(..)(?!$)", \'$1:\')'},
}


class DeviceError(ValueError):
    pass


def check_choice(protocol: str, auth: str, field: str, identity: str) -> str | None:
    """The form's answers – None when they fit together, else what is wrong."""
    if protocol not in PROTOCOLS or auth not in AUTHS or field not in PROTOCOLS or identity not in IDENTITIES:
        return "Select the factory protocol, the authentication, the field renewal and the identity."
    if auth == "apikey" and protocol != "rest":
        return "An API key works only with the REST API."
    return None  # any field protocol: the policy carries the factory's and the field's method


def identity(run_id: str, number: int, kind: str) -> str:
    """The device's fictitious hardware identity – deterministic and unique per run and device. MAC
    addresses come from the locally administered range (02:…), never a manufacturer's OUI."""
    if kind == "serial":
        return f"SN-{run_id.upper()}-{number:04d}"
    run = hashlib.sha256(run_id.encode()).digest()[:2]
    return "02:" + ":".join(f"{b:02x}" for b in (*run, number >> 16 & 0xFF, number >> 8 & 0xFF, number & 0xFF))


def device_dir(run_dir: Path, name: str) -> Path:
    """The simulated device's key and certificate (EST/CMPv2 field renewal) – removed by the rollback."""
    return run_dir / "devices" / name


def _check(response: dict, device: dict) -> dict:
    """A REST answer must be for exactly this device and carry its identity – DTM files a REST request
    under the named device whatever the CN says (verified live), so the identity is checked here."""
    pem = response.get("pem") if isinstance(response, dict) else None
    if not pem:
        raise DeviceError(f"DTM response for {device['name']} contains no certificate")
    info = certs.parse_pem_certificate(pem)
    if (response.get("device") or {}).get("id") != device["id"]:
        raise DeviceError(f"DTM did not file the certificate of {device['name']} under the device")
    _same_identity(info, device)
    if not dtm.SAFE_ID.fullmatch(str(response.get("certificate_id") or "")):
        raise DeviceError(f"DTM returned no usable certificate ID for {device['name']}")
    return info | {"certificate_id": response["certificate_id"]}


def _same_identity(info: dict, device: dict) -> None:
    if info["common_name"] != device["identity"]:
        raise DeviceError(f"certificate of {device['name']} carries {info['common_name']!r} instead of its "
                          f"identity {device['identity']!r}")


async def read_devices(client: DTMClient, devices: list[dict], quiet: bool = False) -> None:
    """What DTM files under each device – read back after every change (the list lags a moment). Every
    certificate under a device must carry that device's identity, the current one included."""
    for device in devices:
        records: list[dict] = []
        for attempt in range(LIST_RETRIES):
            records = await client.device_certificates(device["id"], quiet=quiet)
            if len(records) >= device["issued"]:
                break
            await asyncio.sleep(1 + attempt)
        if len(records) < device["issued"]:
            raise DeviceError(f"DTM lists {len(records)} of {device['issued']} certificate(s) under {device['name']}")
        wrong = [r.get("common_name") for r in records if r.get("common_name") != device["identity"]]
        if wrong:
            raise DeviceError(f"{device['name']} holds certificates of another identity: {wrong[:2]}")
        device["certificates"] = [
            {"serial": r.get("serial_number"), "common_name": r.get("common_name"),
             "status": str(r.get("status", "")).lower(), "valid_to": str(r.get("valid_to", ""))[:10],
             "renewed": bool(r.get("is_renewed")), "renewed_from": bool(r.get("renewed_from_certificate_id"))}
            for r in records]
        current = [r for r in records if str(r.get("status", "")).upper() == "ISSUED" and not r.get("is_renewed")]
        if len(current) == 1 and dtm.SAFE_ID.fullmatch(str(current[0].get("certificate_id") or "")):
            device["certificate_id"] = current[0]["certificate_id"]


async def _current_certificate(client: DTMClient, device_id: str) -> str | None:
    """The device's certificate DTM would renew next: issued and not renewed yet."""
    records = [r for r in await client.device_certificates(device_id)
               if str(r.get("status", "")).upper() == "ISSUED" and not r.get("is_renewed")]
    found = records[0].get("certificate_id") if len(records) == 1 else None
    return found if dtm.SAFE_ID.fullmatch(str(found or "")) else None


def _stats(times: list[float], keygen: float) -> dict:
    duration = sum(times)
    return {"duration_s": round(duration, 2), **rates(duration, len(times)),
            "median_s": round(statistics.median(times), 3), "keygen_s": round(keygen, 2),
            **({"estimate_min": round(statistics.median(times) * ESTIMATE_DEVICES / 60, 1),
                "estimate_devices": ESTIMATE_DEVICES} if len(times) > 1 else {})}


async def run(store: Store, client: DTMClient, run_id: str, run_dir: Path) -> None:
    run_ = store.get_run(run_id)
    p = run_["params"] | {"use_case": run_["use_case"]}
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    api = ApiCalls()
    variables = {"DTM_HOST": p["dtm_host"], "DTM_ACCOUNT_ID": p["account_id"], "ICA_ID": p["ca_id"]}
    if p["auth"] == "passcode":
        variables["PASSCODE"] = "<choose a passcode, 6–64 characters>"
    result: dict = {"api_calls": api.calls, "api_variables": variables}
    store.update_run(run_id, status="running")
    base = prefix(run_id, p["use_case"])
    protocol, auth = p["protocol"], p["auth"]
    label, attribute = IDENTITIES[p["identity"]]
    try:
        division_id = await create_division(client, api, store, run_id, p["use_case"], variables, log)
        protocols = (protocol, p["field"])  # the policy carries both methods
        credential = (None, None, None, None)
        if auth != "apikey" or p["field"] != "rest":  # the device renews itself: its policy needs an auth policy
            credential = await enrollment.setup_credentials(client, api, store, run_id, base, protocol, auth,
                                                            variables, log, field=auth == "apikey")
        auth_policy_id = credential[0]
        spec = dtm.PROFILE_RENEWAL_CMP if "cmpv2" in protocols else dtm.PROFILE_RENEWAL
        profile_id = await use_profile(client, api, store, run_id, p["use_case"], spec, variables, log)

        policy_id, cmp_id, ca_chain_pem, group_id = await setup_group(
            client, api, store, run_id, base, division_id, profile_id, p, protocols, auth_policy_id, attribute, variables, log)
        log("DTM is configured for this run", "success")
        result |= {"division": f"{base}-division", "policy": f"{base}-policy", "group": f"{base}-group", "cmp_id": cmp_id,
                   "identity": label}

        with tempfile.TemporaryDirectory(prefix="dtm-uc06-") as tmp:
            station = None
            if auth != "apikey":
                station = enrollment.Station(p["dtm_host"], protocol, auth, policy_id, cmp_id, credential[1],
                                             credential[2], credential[3], Path(tmp), ca_chain_pem, group_id)
            try:
                result |= await _register(client, api, store, run_id, run_dir, station, policy_id, group_id, p,
                                          ca_chain_pem, log, result)
            finally:
                if station:
                    await station.aclose()
        first = result["devices"][0]
        # The first device's values – the renewal steps replay on their own, too
        variables |= {"DEVICE_NAME": first["name"], "IDENTITY": first["identity"], "DEVICE_ID": first["id"]}
        result["renewals"] = []
        _seed_renewal_steps(api, p)
        store.update_run(run_id, status="completed", result=result, progress=None, finished_at=now())
        log("Run completed", "success")
    except (DTMError, ValueError) as exc:
        log(f"Run failed: {exc}", "error")
        store.update_run(run_id, status="failed", error=str(exc), progress=None, finished_at=now(), result=result)
    except Exception as exc:  # keep the run visible as failed instead of silently dying
        log(f"Run failed unexpectedly: {type(exc).__name__}", "error")
        store.update_run(run_id, status="failed", error=type(exc).__name__, progress=None, finished_at=now(),
                         result=result)
        raise


async def setup_group(client: DTMClient, api: ApiCalls, store: Store, run_id: str, base: str, division_id: str,
                      profile_id: str, p: dict, protocols: tuple[str, ...], auth_policy_id: str | None, attribute: str, variables: dict,
                      log, also: tuple[str, ...] = ()) -> tuple[str, str | None, str, str]:
    """The run's certificate policy (only for devices of a group) and its device group, whose mapping files a
    certificate under the device by attribute → common name. UC-6 and UC-7.
    Returns (policy ID, CMPv2 endpoint ID, CA chain PEM, group ID)."""
    policy_name = f"{base}-policy"
    methods = " + ".join(dict.fromkeys(PROTOCOLS[x] for x in protocols))
    log(f"Creating certificate policy {policy_name} ({methods}, device group required, {p['ca_name']})")
    args = {"profile_id": profile_id, "ica_id": p["ca_id"], "key_type": p["key_type"], "protocols": protocols}
    shown = args | {"profile_id": "{PROFILE_ID}", "ica_id": "{ICA_ID}",
                    "auth_policy_id": "{AUTH_POLICY_ID}" if auth_policy_id else None}
    body = dtm.device_policy_body(name="{RUN_NAME}-policy", division_id="{DIVISION_ID}", **shown)
    policy_id = await api.timed(
        f"Create the certificate policy ({methods}, only for devices of a group)", "POST", dtm.POLICIES,
        client.create_device_policy(name=policy_name, division_id=division_id, auth_policy_id=auth_policy_id, **args),
        spec={"method": "POST", "path": dtm.POLICIES, "body_file": "policy.json", "json": body}, phase="setup")
    api.add("Look up the policy ID by its name", "GET", dtm.POLICIES, None,
            spec={"method": "GET", "path": dtm.POLICIES, "query": LIST,
                  "capture": by_name("POLICY_ID", "{RUN_NAME}-policy")}, phase="setup")
    store.add_object(run_id, "policy", policy_id, policy_name)
    variables["POLICY_ID"] = policy_id
    cmp_id, ca_chain_pem = await enrollment.read_endpoint(client, api, policy_id,
                                                          "cmpv2" if "cmpv2" in protocols else protocols[0], variables)

    group_name = f"{base}-group"
    log(f"Creating device group {group_name} – policy assigned, {attribute} → common name")
    group_id = await api.timed(
        f"Create the device group (policy assigned, {attribute} → common name)", "POST", dtm.DEVICE_GROUPS,
        client.create_device_group(group_name, division_id, policy_id, attribute, also),
        spec={"method": "POST", "path": dtm.DEVICE_GROUPS, "body_file": "device-group.json",
              "json": dtm.device_group_body("{RUN_NAME}-group", "{DIVISION_ID}", "{DTM_ACCOUNT_ID}", "{POLICY_ID}",
                                            attribute, also)},
        phase="setup")
    api.add("Look up the device group ID by its name", "GET", dtm.DEVICE_GROUPS, None,
            spec={"method": "GET", "path": dtm.DEVICE_GROUPS, "query": LIST,
                  "capture": by_name("GROUP_ID", "{RUN_NAME}-group")}, phase="setup")
    store.add_object(run_id, "device_group", group_id, group_name)
    variables["GROUP_ID"] = group_id
    return policy_id, cmp_id, ca_chain_pem, group_id


async def _register(client: DTMClient, api: ApiCalls, store: Store, run_id: str, run_dir: Path, station,
                    policy_id: str, group_id: str, p: dict, ca_chain_pem: str, log, partial: dict) -> dict:
    """Per device, one after another: key + CSR (CN = identity) → create the device with its identity
    (the factory's MES, API) → its first certificate (REST with the API key, or the station's protocol)."""
    names = common_names(run_id, "minion", p["count"], p["use_case"])
    protocol, attribute = p["protocol"], IDENTITIES[p["identity"]][1]
    keeps_key = p["field"] in ("est", "cmpv2")  # the device renews itself in the field
    log(f"Registering {len(names)} device(s) one by one – {PROTOCOLS[protocol]} ({AUTHS[p['auth']].lower()}); "
        f"the certificate carries the {attribute}, not the device name")
    started_wall = time.time()
    devices, issued, times, keygen = [], [], [], 0.0
    create_s = issue_s = 0.0
    outcome = "error"
    try:
        for done, name in enumerate(names, 1):
            device = {"name": name, "identity": identity(run_id, done, p["identity"]), "issued": 1,
                      "certificate_id": None}
            start = time.monotonic()
            key_pem, csr = await asyncio.to_thread(certs.device_request, device["identity"], p["key_type"])
            keygen += time.monotonic() - start
            start = time.monotonic()
            device["id"] = await client.enroll_device(name, group_id, DEVICE_DESCRIPTION, attribute, device["identity"])
            if not dtm.SAFE_ID.fullmatch(str(device["id"])):
                raise DeviceError(f"DTM returned an unusable device ID for {name}")
            store.add_object(run_id, "device", device["id"], name)
            created = time.monotonic()
            if station:
                station.device_id = device["id"]
                info = await station.enroll(device["identity"], key_pem, csr)
                _same_identity(info, device)
            else:
                csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
                info = _check(await client.issue_device_certificate(policy_id, group_id, device["id"],
                                                                    device["identity"], csr_pem), device)
                device["certificate_id"] = info["certificate_id"]
            end = time.monotonic()
            create_s, issue_s = create_s + created - start, issue_s + end - created
            times.append(end - start)
            if keeps_key:
                enrollment._save_device(run_dir, key_pem, info["pem"], device_dir(run_dir, name))
                if p["field"] == "cmpv2":  # the key update's answers are signed by the issuing CA
                    (device_dir(run_dir, name) / "ca-chain.pem").write_text(ca_chain_pem)
            certs.save_certificates(run_dir, [info])  # moves the PEM into a file
            issued.append(info | {"device": name})
            devices.append(device)
            # Stored at once: a run that breaks off later still shows (and counts) what DTM issued
            partial |= {"devices": devices, "certificates": issued, "certificate_total": len(issued)}
            store.update_run(run_id, result=partial, progress={"label": f"Registering {len(names)} devices one by one",
                                                               "started": started_wall, "total": len(names), "done": done})
        outcome = "ok"
    finally:
        _record_registration_steps(api, p, round(create_s, 2), round(issue_s, 2), outcome,
                                   len(devices) + (outcome != "ok"))
    log(f"{len(devices)} device(s) registered in {sum(times):.1f}s", "success")
    # EST/CMPv2 answer with the certificate only – the device's own list is the proof of the mapping
    await api.timed("Read the certificates filed under the device", "GET", f"{dtm.DEVICES}/certificates",
                    read_devices(client, devices),
                    spec={"method": "GET", "path": f"{dtm.DEVICES}/certificates", "query": "device_id={DEVICE_ID}"})
    log("DTM filed every certificate under its device – by the identity, not the name", "success")
    return {**_stats(times, keygen), "create_s": round(create_s, 2), "issue_s": round(issue_s, 2),
            "devices": devices, "certificates": issued, "certificate_total": len(issued)}


def _record_registration_steps(api: ApiCalls, p: dict, create_s: float, issue_s: float, outcome: str,
                               count: int) -> None:
    attribute = IDENTITIES[p["identity"]][1]
    naming = IDENTITY_COMMAND[p["identity"]]
    api.add("Name the device and draw its identity (CN ≠ device name)", "LOCAL", "openssl", None, spec={"command": {
        "bash": 'export DEVICE_NAME="${RUN_NAME}-minion-0001"\n' + naming["bash"],
        "powershell": '$env:DEVICE_NAME = "$env:RUN_NAME-minion-0001"\n' + naming["powershell"]}})
    api.add(f"Create the device with its {attribute} (once per device)", "POST", f"{dtm.DEVICES}/enroll", create_s,
            outcome, count=count,
            spec={"method": "POST", "path": f"{dtm.DEVICES}/enroll", "body_file": "device.json",
                  "json": dtm.device_body("{DEVICE_NAME}", "{DTM_ACCOUNT_ID}", "{GROUP_ID}", DEVICE_DESCRIPTION,
                                          attribute, "{IDENTITY}"),
                  "capture": {"var": "DEVICE_ID", "jq": ".device_id", "ps": "$r.device_id"}})
    if p["auth"] != "apikey":  # the station's protocol, on the device-group endpoint
        for step in enrollment.enroll_steps(p["protocol"], p["auth"], "{IDENTITY}", p["key_type"], group=True):
            took = issue_s if step["kind"] == "call" else None
            api.add(step["purpose"], step["method"], step["path"], took, outcome if took is not None else "ok",
                    count=count if took is not None else 1, spec={"command": step["command"]}, phase=step["phase"])
        return
    api.add("Generate the device key and CSR (CN = identity)", "LOCAL", "openssl", None,
            spec={"command": keygen_command("{IDENTITY}", p["key_type"])})
    api.add("Request the certificate for the device (once per device)", "POST", dtm.CERTIFICATES, issue_s, outcome,
            count=count,
            spec={"method": "POST", "path": dtm.CERTIFICATES, "body_file": "certificate.json",
                  "json": dtm.device_certificate_body("{POLICY_ID}", "{GROUP_ID}", "{DEVICE_ID}", "{IDENTITY}", "{CSR}"),
                  "output": "certificate.json.out"})
    api.add("Extract the certificate (local)", "LOCAL", "jq", None, spec={"command": {
        "bash": "jq -r .pem certificate.json.out > device.crt",
        "powershell": "(Get-Content certificate.json.out -Raw | ConvertFrom-Json).pem | Set-Content device.crt"}})


def _seed_renewal_steps(api: ApiCalls, p: dict) -> None:
    """The renewal block of the reproducible steps, untimed; every round adds its count and time."""
    if p["field"] != "rest":  # the device itself, with its current certificate, on the device-group endpoint
        if p["field"] == "cmpv2" and p["protocol"] != "cmpv2":  # the factory's steps did not build it
            api.add("Build ca-chain.pem from the policy", "LOCAL", "openssl", None, phase="setup",
                    spec={"command": {"bash": enrollment.CA_CHAIN_BASH, "powershell": enrollment.CA_CHAIN_PS}})
        for step in enrollment.renew_steps(p["field"], "{IDENTITY}", p["key_type"], group=True):
            api.add(step["purpose"], step["method"], step["path"], None, count=0 if step["kind"] == "call" else 1,
                    spec={"command": step["command"]}, phase="renewal")
        return
    command = keygen_command("{IDENTITY}", p["key_type"])
    api.add("Generate a new key and CSR on the device", "LOCAL", "openssl", None, phase="renewal",
            spec={"command": {k: v.replace("device.key", "device-new.key") for k, v in command.items()}})
    api.add("Look up the device's current certificate", "GET", f"{dtm.DEVICES}/certificates", None, phase="renewal",
            spec={"method": "GET", "path": f"{dtm.DEVICES}/certificates", "query": "device_id={DEVICE_ID}",
                  "capture": {"var": "CERT_ID", "jq": CURRENT_JQ, "ps": CURRENT_PS, "retry": True}})
    api.add("Renew the device's current certificate", "PUT", f"{dtm.CERTIFICATES}/{{CERT_ID}}/renew", None,
            count=0, phase="renewal",
            spec={"method": "PUT", "path": f"{dtm.CERTIFICATES}/{{CERT_ID}}/renew", "body_file": "renew.json",
                  "json": {"csr": "{CSR}"}, "output": "renew.json.out"})
    api.add("Switch to the new key and certificate (local)", "LOCAL", "jq", None, phase="renewal", spec={"command": {
        "bash": "jq -r .pem renew.json.out > device.crt && mv device-new.key device.key",
        "powershell": "(Get-Content renew.json.out -Raw | ConvertFrom-Json).pem | Set-Content device.crt\n"
                      "Move-Item -Force device-new.key device.key"}})


def count_step(calls: list[dict], phase: str, seconds: float, count: int) -> None:
    """A per-device action adds its count and time to the phase's timed step(s) of the reproducible steps."""
    for call in calls:
        if call.get("phase") == phase and call["method"] in ("PUT", "POST"):
            call["count"] += count
            call["seconds"] = round((call["seconds"] or 0) + seconds, 2)


def renewals_of(result: dict, name: str) -> int:
    """Renewal attempts of one device – the route and the tile use the same limit."""
    return sum(1 for r in result.get("renewals") or [] if r.get("device") == name)


def commit(store: Store, run_id: str, change) -> dict:
    """Read, change and write the run's result without an await in between – devices act concurrently, each
    task commits only its own device's changes onto the latest result."""
    result = store.get_run(run_id)["result"]
    change(result)
    store.update_run(run_id, result=result)
    return result


def device_of(result: dict, name: str) -> dict:
    return next(d for d in result["devices"] if d["name"] == name)


async def device_action(store: Store, run_id: str, name: str, label: str, act) -> None:
    """One device, per click (the route marked it busy). Devices act independently; whatever happens, the
    device is no longer busy afterwards."""
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    try:
        await act(log)
    except (DTMError, ValueError, OSError, minions.MinionError) as exc:
        log(f"{label} of {name} failed: {exc}", "error")
    except Exception as exc:
        log(f"{label} of {name} failed unexpectedly: {type(exc).__name__}", "error")
        raise
    finally:
        commit(store, run_id, lambda r: r.update(busy=[n for n in r.get("busy") or [] if n != name]))


async def renew(store: Store, client: DTMClient, run_id: str, run_dir: Path, name: str) -> None:
    """Per click: one device renews with a new key – timed."""
    await device_action(store, run_id, name, "Renewal",
                        lambda log: _renew(store, client, run_id, run_dir, name, log))


async def _renew_one(client: DTMClient, p: dict, result: dict, run_dir: Path, policy_id: str, group_id: str,
                     device: dict, log) -> tuple[dict, float, float]:
    """One device: (certificate info, round trip, key generation)."""
    start = time.monotonic()
    key_pem, csr = await asyncio.to_thread(certs.device_request, device["identity"], p["key_type"])
    keygen = time.monotonic() - start
    field = p["field"]
    if field == "rest":
        # DTM knows which certificate is current – also after a round that broke off midway
        current = await _current_certificate(client, device["id"]) or device["certificate_id"]
        if not current:
            raise DeviceError(f"DTM lists no current certificate for {device['name']}")
        start = time.monotonic()
        response = await client.renew_certificate(current, csr.public_bytes(serialization.Encoding.PEM).decode())
        seconds = time.monotonic() - start
        return _check(response, device), seconds, keygen
    folder = device_dir(run_dir, device["name"])
    info, retry, seconds = None, "", 0.0
    for attempt in range(1, enrollment.RENEW_ATTEMPTS + 1):
        if field == "cmpv2":
            info, retry, seconds = await enrollment._renew_cmp(p, result, run_dir, key_pem, folder, group_id)
        else:
            info, retry, seconds = await enrollment._renew_est(p, policy_id, run_dir, csr, folder, group_id)
        if info or not retry or attempt == enrollment.RENEW_ATTEMPTS:
            break
        log(f"{device['name']}: DTM does not accept the new certificate yet – retrying in "
            f"{enrollment.RENEW_RETRY_S:g}s", "wait")
        await asyncio.sleep(enrollment.RENEW_RETRY_S)
    if not info:
        raise DeviceError(retry)
    _same_identity(info, device)
    return info | {"_key": key_pem}, seconds, keygen


async def _renew(store: Store, client: DTMClient, run_id: str, run_dir: Path, name: str, log) -> None:
    run_ = store.get_run(run_id)
    p, result = run_["params"], run_["result"]  # a snapshot – changes are committed onto the latest result
    device = device_of(result, name)
    policies, groups = store.objects(run_id, "policy"), store.objects(run_id, "device_group")
    if not policies or not groups:
        raise DeviceError("the run has no certificate policy or device group any more")
    policy_id, group_id = policies[0]["dtm_id"], groups[0]["dtm_id"]
    log(f"Renewing {name} via {PROTOCOLS[p['field']]} – new key, same identity")
    seconds, ok = None, False
    try:
        info, seconds, _keygen = await _renew_one(client, p, result, run_dir, policy_id, group_id, device, log)
        key_pem, pem = info.pop("_key", None), info["pem"]
        certs.save_certificates(run_dir, [info])

        def issued(r: dict) -> None:  # stored at once: a later failure must not lose what DTM already issued
            d = device_of(r, name)
            d["issued"] += 1
            d["certificate_id"] = info.get("certificate_id") or d["certificate_id"]
            d["last"] = {"action": "Renewed", "seconds": round(seconds, 2)}
            r["certificates"].append(info | {"device": name})
            r["certificate_total"] = len(r["certificates"])
            count_step(r["api_calls"], "renewal", seconds, 1)
            device.update(d)
        commit(store, run_id, issued)
        if key_pem:  # only now the device switches to the new pair – the result knows the certificate
            enrollment._save_device(run_dir, key_pem, pem, device_dir(run_dir, name))
        await read_devices(client, [device])  # the new certificate must be filed under the same device
        commit(store, run_id, lambda r: device_of(r, name).update(certificates=device["certificates"],
                                                                  certificate_id=device["certificate_id"]))
        ok = True
    finally:
        # Every attempt counts against the limit, a broken one too – a device that always fails must not
        # consume DTM requests without end
        commit(store, run_id, lambda r: r.setdefault("renewals", []).append(
            {"device": name, "seconds": round(seconds or 0, 2), "at": now(), **({} if ok else {"failed": True})}))
    log(f"{name} renewed in {seconds:.2f}s – filed under the same device; the previous certificate stays valid "
        "until the rollback", "success")
