"""UC-7 – Retrofit managed devices (Advanced license). The manufacturer runs its own PKI outside DTM: in the
factory every device gets an unmanaged device-ID certificate (CN = serial number) from the manufacturer's
ICA and is registered in DTM with its name and serial number. The ICA is stored in DTM as trust anchor of
the run's authentication policy, so in the field every device with a device-ID certificate from it enrolls
via EST or CMPv2 for a managed certificate – CN = its device name, 6 months, renewable per click. DTM files
it under the device through the group's mapping device_name → common name.

DTM does not reject a request whose CN is not a device name (verified live on NL 2026-10-27) – the
devices choose the name themselves; the run checks every answer against it."""

import asyncio
import os
import tempfile
import time
from pathlib import Path

from . import certs, dtm, enrollment
from .apicalls import ApiCalls
from .devices import (DEVICE_DESCRIPTION, DeviceError, _same_identity, _stats, commit, count_step, device_action,
                      device_dir, device_of, identity, read_devices, setup_group)
from .dtm import DTMClient, DTMError
from .evergreen import common_names, create_division, prefix, use_profile
from .store import Store, now

PROTOCOLS = {"est": "EST", "cmpv2": "CMPv2"}

# The manufacturer's PKI as the replayed setup builds it – root → device-ID ICA, ECDSA P-256
PKI_BASH = (
    'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mfr-root.key -out mfr-root.crt \\\n'
    '  -days 1095 -subj "/O=Fictitious Manufacturer/CN=${RUN_NAME}-manufacturer-root" \\\n'
    '  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" -addext "keyUsage=critical,keyCertSign,cRLSign"\n'
    'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mfr-ica.key -out mfr-ica.csr \\\n'
    '  -subj "/O=Fictitious Manufacturer/CN=${RUN_NAME}-device-id-ica"\n'
    "openssl x509 -req -in mfr-ica.csr -CA mfr-root.crt -CAkey mfr-root.key -out mfr-ica.crt -days 730 \\\n"
    "  -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\\nkeyUsage=critical,keyCertSign,cRLSign')\n"
    "export ICA_PEM=\"$(awk '{printf \"%s\\\\n\", $0}' mfr-ica.crt)\"")
PKI_PS = (
    'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mfr-root.key -out mfr-root.crt `\n'
    '  -days 1095 -subj "/O=Fictitious Manufacturer/CN=$env:RUN_NAME-manufacturer-root" `\n'
    '  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" -addext "keyUsage=critical,keyCertSign,cRLSign"\n'
    'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout mfr-ica.key -out mfr-ica.csr `\n'
    '  -subj "/O=Fictitious Manufacturer/CN=$env:RUN_NAME-device-id-ica"\n'
    'Set-Content mfr-ica.ext "basicConstraints=critical,CA:TRUE,pathlen:0`nkeyUsage=critical,keyCertSign,cRLSign"\n'
    "openssl x509 -req -in mfr-ica.csr -CA mfr-root.crt -CAkey mfr-root.key -out mfr-ica.crt -days 730 "
    "-extfile mfr-ica.ext\n"
    '$env:ICA_PEM = (Get-Content mfr-ica.crt -Raw).Replace("`r", "").Replace("`n", "\\n")')
# The device-ID certificate lands in factory.crt/factory.key – the enrollment steps authenticate with those
DEVICE_ID_BASH = (
    'export DEVICE_NAME="${RUN_NAME}-device-0001"\n'
    'export SERIAL="SN-$(openssl rand -hex 4 | tr a-f A-F)-0001"\n'
    'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout factory.key -out device-id.csr \\\n'
    '  -subj "/O=Fictitious Manufacturer/CN=${SERIAL}"\n'
    "openssl x509 -req -in device-id.csr -CA mfr-ica.crt -CAkey mfr-ica.key -out device-id.crt -days 365 \\\n"
    "  -extfile <(printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature\\n"
    "extendedKeyUsage=clientAuth')\n"
    "cat device-id.crt mfr-ica.crt > factory.crt")
DEVICE_ID_PS = (
    '$env:DEVICE_NAME = "$env:RUN_NAME-device-0001"\n'
    '$env:SERIAL = "SN-$((openssl rand -hex 4).ToUpper())-0001"\n'
    'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout factory.key -out device-id.csr `\n'
    '  -subj "/O=Fictitious Manufacturer/CN=$env:SERIAL"\n'
    'Set-Content device-id.ext "basicConstraints=critical,CA:FALSE`nkeyUsage=critical,digitalSignature`n'
    'extendedKeyUsage=clientAuth"\n'
    "openssl x509 -req -in device-id.csr -CA mfr-ica.crt -CAkey mfr-ica.key -out device-id.crt -days 365 "
    "-extfile device-id.ext\n"
    "Get-Content device-id.crt, mfr-ica.crt | Set-Content factory.crt")


def _save_pki(run_dir: Path, pki: dict) -> None:
    """The manufacturer's root and ICA (key included, 0600) – demo material of the run, never shown or
    downloadable, removed by the rollback."""
    folder = run_dir / "manufacturer"
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    (folder / "root.pem").write_text(pki["root"])
    (folder / "ica.pem").write_text(pki["ica"])
    with os.fdopen(os.open(folder / "ica.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as handle:
        handle.write(pki["ica_key"])


async def run(store: Store, client: DTMClient, run_id: str, run_dir: Path) -> None:
    run_ = store.get_run(run_id)
    p = run_["params"] | {"use_case": run_["use_case"]}
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    api = ApiCalls()
    variables = {"DTM_HOST": p["dtm_host"], "DTM_ACCOUNT_ID": p["account_id"], "ICA_ID": p["ca_id"]}
    result: dict = {"api_calls": api.calls, "api_variables": variables}
    store.update_run(run_id, status="running")
    base = prefix(run_id, p["use_case"])
    protocol = p["protocol"]
    try:
        division_id = await create_division(client, api, store, run_id, p["use_case"], variables, log)
        log("The manufacturer's own PKI: root and device-ID ICA, outside DTM")
        pki = await asyncio.to_thread(certs.manufacturer_ca, base)
        _save_pki(run_dir, pki)
        api.add("Create the manufacturer's root and device-ID ICA (outside DTM)", "LOCAL", "openssl", None,
                spec={"command": {"bash": PKI_BASH, "powershell": PKI_PS}}, phase="setup")

        log(f"Creating authentication policy {base}-auth")
        auth_policy_id = await api.timed(
            "Create an authentication policy for the field", "POST", enrollment.AUTH_POLICY_PATH,
            client.create_auth_policy(f"{base}-auth"),
            spec={"method": "POST", "path": enrollment.AUTH_POLICY_PATH, "body_file": "auth-policy.json",
                  "json": {"name": "{RUN_NAME}-auth", "account_id": "{DTM_ACCOUNT_ID}"},
                  "capture": {"var": "AUTH_POLICY_ID", "jq": ".id", "ps": "$r.id"}}, phase="setup")
        store.add_object(run_id, "auth_policy", auth_policy_id, f"{base}-auth")
        variables["AUTH_POLICY_ID"] = auth_policy_id
        ica_name = f"{base}-device-id-ica"
        log(f"Storing the device-ID ICA {ica_name} as trust anchor of the authentication policy")
        anchor = await api.timed(
            "Store the device-ID ICA as trust anchor of the authentication policy", "POST", dtm.AUTH_CA,
            client.create_auth_ca(auth_policy_id, pki["ica"]),
            spec={"method": "POST", "path": dtm.AUTH_CA, "body_file": "auth-ca.json",
                  "json": {"authentication_policy_id": "{AUTH_POLICY_ID}", "ca_body_pem": "{ICA_PEM}",
                           "account_id": "{DTM_ACCOUNT_ID}"}}, phase="setup")
        # DTM names the entry after the CA's common name – ours, so the rollback's prefix check holds
        store.add_object(run_id, "auth_ca", anchor["id"], ica_name)

        spec = dtm.PROFILE_RENEWAL_CMP if protocol == "cmpv2" else dtm.PROFILE_RENEWAL
        profile_id = await use_profile(client, api, store, run_id, p["use_case"], spec, variables, log)
        policy_id, cmp_id, ca_chain_pem, group_id = await setup_group(
            client, api, store, run_id, base, division_id, profile_id, p, (protocol,), auth_policy_id, "device_name",
            variables, log, also=("serial_number",))
        log("DTM is configured for this run", "success")
        result |= {"division": f"{base}-division", "policy": f"{base}-policy", "group": f"{base}-group",
                   "cmp_id": cmp_id, "identity": "Device name"}

        (run_dir / "ca-chain.pem").write_text(ca_chain_pem)  # public: the issuing CA signs CMPv2 answers
        await _provision(client, api, store, run_id, run_dir, group_id, p, pki, log, result)
        first = result["devices"][0]
        # The first device's values – the field and renewal steps replay on their own, too
        variables |= {"DEVICE_NAME": first["name"], "SERIAL": first["serial"], "DEVICE_ID": first["id"]}
        result["renewals"] = []
        _seed_field_steps(api, p)
        if p.get("pause"):  # every device enrolls from its tile, per click
            log("The devices are registered in DTM – show them and the trust anchor in the portal, then enroll each "
                "device from its tile", "success")
        else:
            log(f"Field enrollment of {len(result['devices'])} device(s) via {PROTOCOLS[protocol]} – authenticated by "
                "the device-ID certificate, CN = device name")
            store.update_run(run_id, result=result)  # each device commits onto the stored result
            started_wall, names = time.time(), [d["name"] for d in result["devices"]]
            try:
                for done, name in enumerate(names):
                    store.update_run(run_id, progress={"label": f"Field enrollment of {len(names)} devices",
                                                       "started": started_wall, "total": len(names), "done": done})
                    await _enroll(store, client, run_id, run_dir, name, log)
            finally:  # what the devices committed – also for a run that fails midway
                result = store.get_run(run_id)["result"]
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


async def _provision(client: DTMClient, api: ApiCalls, store: Store, run_id: str, run_dir: Path, group_id: str,
                     p: dict, pki: dict, log, result: dict) -> None:
    """The factory, per device: device-ID certificate (CN = serial) from the manufacturer's ICA → register the
    device in DTM with its name and serial number. The device keeps its device-ID credential (run dir, 0600)."""
    names = common_names(run_id, "device", p["count"], p["use_case"])
    log(f"Factory: {len(names)} device(s) get a device-ID certificate (CN = serial number) and are registered "
        "in DTM by name")
    started_wall = time.time()
    devices, times, keygen, create_s = [], [], 0.0, 0.0
    outcome = "error"
    try:
        for done, name in enumerate(names, 1):
            device = {"name": name, "identity": name, "serial": identity(run_id, done, "serial"), "issued": 0,
                      "certificate_id": None}
            start = time.monotonic()
            cert_pem, key_pem = await asyncio.to_thread(certs.device_id_certificate, device["serial"], pki["ica"],
                                                        pki["ica_key"])
            _save_device_id(device_dir(run_dir, name), cert_pem, key_pem)
            keygen += time.monotonic() - start
            created = time.monotonic()
            device["id"] = await client.enroll_device(name, group_id, DEVICE_DESCRIPTION, "serial_number",
                                                      device["serial"])
            if not dtm.SAFE_ID.fullmatch(str(device["id"])):
                raise DeviceError(f"DTM returned an unusable device ID for {name}")
            store.add_object(run_id, "device", device["id"], name)
            create_s += time.monotonic() - created
            times.append(time.monotonic() - start)
            devices.append(device)
            result |= {"devices": devices, "certificate_total": 0}
            store.update_run(run_id, result=result, progress={
                "label": f"Factory: registering {len(names)} devices", "started": started_wall, "total": len(names),
                "done": done})
        outcome = "ok"
    finally:
        count = len(devices) + (outcome != "ok")
        api.add("Device-ID certificate from the manufacturer's ICA (CN = serial number)", "LOCAL", "openssl", None,
                spec={"command": {"bash": DEVICE_ID_BASH, "powershell": DEVICE_ID_PS}})
        api.add("Register the device with its name and serial number (once per device)", "POST",
                f"{dtm.DEVICES}/enroll", round(create_s, 2), outcome, count=count,
                spec={"method": "POST", "path": f"{dtm.DEVICES}/enroll", "body_file": "device.json",
                      "json": dtm.device_body("{DEVICE_NAME}", "{DTM_ACCOUNT_ID}", "{GROUP_ID}", DEVICE_DESCRIPTION,
                                              "serial_number", "{SERIAL}"),
                      "capture": {"var": "DEVICE_ID", "jq": ".device_id", "ps": "$r.device_id"}})
    result["factory"] = {**_stats(times, keygen), "create_s": round(create_s, 2)}
    store.update_run(run_id, result=result, progress=None)
    log(f"{len(devices)} device(s) leave the factory with a device-ID certificate – no managed certificate yet",
        "success")


def _save_device_id(folder: Path, cert_pem: str, key_pem: bytes) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    for file, data in (("device-id.crt", cert_pem.encode()), ("device-id.key", key_pem)):
        with os.fdopen(os.open(folder / file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as handle:
            handle.write(data)


def _seed_field_steps(api: ApiCalls, p: dict) -> None:
    """The field enrollment and renewal blocks of the reproducible steps, untimed; every device adds its count
    and time."""
    for step in enrollment.enroll_steps(p["protocol"], "certificate", "{DEVICE_NAME}", p["key_type"], group=True):
        api.add(step["purpose"], step["method"], step["path"], None, count=0 if step["kind"] == "call" else 1,
                spec={"command": step["command"]}, phase="setup" if "ca-chain" in step["purpose"] else "field")
    api.add("Read the certificates filed under the device", "GET", f"{dtm.DEVICES}/certificates", None, phase="field",
            spec={"method": "GET", "path": f"{dtm.DEVICES}/certificates", "query": "device_id={DEVICE_ID}"})
    for step in enrollment.renew_steps(p["protocol"], "{DEVICE_NAME}", p["key_type"], group=True):
        api.add(step["purpose"], step["method"], step["path"], None, count=0 if step["kind"] == "call" else 1,
                spec={"command": step["command"]}, phase="renewal")


async def enroll(store: Store, client: DTMClient, run_id: str, run_dir: Path, name: str) -> None:
    """Per click: one device enrolls in the field."""
    await device_action(store, run_id, name, "Field enrollment",
                        lambda log: _enroll(store, client, run_id, run_dir, name, log))


async def _enroll(store: Store, client: DTMClient, run_id: str, run_dir: Path, name: str, log) -> None:
    """One device in the field: new key + CSR (CN = device name) → EST/CMPv2 on the device-group endpoint,
    authenticated by its device-ID certificate → the managed certificate, filed under the device. Devices
    enroll concurrently – the changes are committed onto the latest result."""
    run_ = store.get_run(run_id)
    p, result = run_["params"], run_["result"]
    device = device_of(result, name)
    policies, groups = store.objects(run_id, "policy"), store.objects(run_id, "device_group")
    if not policies or not groups:
        raise DeviceError("the run has no certificate policy or device group any more")
    folder = device_dir(run_dir, name)
    credential = ((folder / "device-id.crt").read_text(), (folder / "device-id.key").read_bytes())
    start = time.monotonic()
    key_pem, csr = await asyncio.to_thread(certs.device_request, name, p["key_type"])
    keygen = time.monotonic() - start
    with tempfile.TemporaryDirectory(prefix="dtm-uc07-") as tmp:
        station = enrollment.Station(p["dtm_host"], p["protocol"], "certificate", policies[0]["dtm_id"],
                                     result.get("cmp_id"), None, None, credential, Path(tmp),
                                     (run_dir / "ca-chain.pem").read_text(), groups[0]["dtm_id"])
        try:
            start = time.monotonic()
            info = await station.enroll(name, key_pem, csr)
            seconds = time.monotonic() - start
        finally:
            await station.aclose()
    _same_identity(info, device)
    enrollment._save_device(run_dir, key_pem, info["pem"], folder)
    if p["protocol"] == "cmpv2":  # the key update's answers are signed by the issuing CA
        (folder / "ca-chain.pem").write_text((run_dir / "ca-chain.pem").read_text())
    certs.save_certificates(run_dir, [info])  # moves the PEM into a file

    def enrolled(r: dict) -> None:  # stored at once: a later failure must not lose the certificate
        d = device_of(r, name)
        d |= {"issued": 1, "enroll_s": round(seconds, 3), "keygen_s": round(keygen, 3),
              "last": {"action": "Enrolled", "seconds": round(seconds, 2)}}
        certificates = r.setdefault("certificates", [])
        certificates.append(info | {"device": name})
        r["certificate_total"] = len(certificates)
        done = [x for x in r["devices"] if x.get("enroll_s") is not None]
        r |= _stats([x["enroll_s"] for x in done], sum(x["keygen_s"] for x in done))
        count_step(r["api_calls"], "field", seconds, 1)
        device.update(d)
    commit(store, run_id, enrolled)
    # EST/CMPv2 answer with the certificate only – the device's own list is the proof of the mapping
    await read_devices(client, [device])
    commit(store, run_id, lambda r: device_of(r, name).update(certificates=device["certificates"],
                                                              certificate_id=device["certificate_id"]))
    log(f"{name} enrolled in {seconds:.2f}s – DTM filed the managed certificate under the device", "success")
