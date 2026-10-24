"""Evergreen device IDs for factory provisioning – UC-1 (DTM generates the keys) and UC-2 (the
factory generates keys and CSRs). Same flow: single or batch, via API or in the DTM web UI."""

import asyncio
import io
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import certs, dtm
from .apicalls import ApiCalls
from .dtm import DTMClient, DTMError
from .store import Store, now


@dataclass(frozen=True)
class UseCase:
    title: str
    summary: str
    key_generation: str  # "server_side" (DTM creates the key pairs) or "client_side" (factory CSRs)
    tags: tuple[str, ...] = ()


USE_CASES = {
    "uc01": UseCase(
        "Evergreen Device IDs for Factory Provisioning",
        "The manufacturer generates keys and certificates in advance, so nothing can go wrong on the production "
        "line and no connection to the CA is needed during manufacturing. DTM generates the key pairs server-side "
        "and issues long-lived device certificates – individually or as a batch, via API (with time measurement) "
        "or in the DTM web UI. The demonstrator shows what DTM returns and rolls everything back afterwards.",
        "server_side", ("Server-side keys", "Single · Batch", "API · Web UI")),
    "uc02": UseCase(
        "Evergreen Device IDs with Factory-Generated Keys",
        "Like UC-1, but the factory generates each key pair itself and sends only a CSR – the private key never "
        "leaves the factory. DTM signs long-lived device certificates individually or as a batch, via API (with "
        "time measurement) or in the DTM web UI.",
        "client_side", ("Factory CSR", "Single · Batch", "API · Web UI")),
    "uc03": UseCase(
        "Evergreen Device IDs via Enrollment Protocols",
        "The factory station enrolls a device itself over EST, CMPv2, SCEP or the REST API and authenticates "
        "with a passcode or its own client certificate. The request is timed and extrapolated to a production run.",
        "client_side", ("EST · CMPv2 · SCEP · REST", "Passcode · Factory certificate", "Single device")),
    "uc04": UseCase(
        "Evergreen Device ID with Renewal in the Field",
        "One device is enrolled in the factory via EST and later renews its certificate in the field with a "
        "click – authenticated by the certificate it already holds. No device group, so the Essentials license "
        "is enough.",
        "client_side", ("EST", "Single device", "Renewal per click")),
}
# The home page offers UC-1..UC-3 as one guided entry; the answers resolve to one of them.
GUIDE = UseCase(
    "Evergreen Device IDs",
    "Long-lived device certificates for the factory – answer a few questions and the run shows the matching "
    "flow end to end.",
    "client_side", ("Server-side or factory keys", "Batch · Single", "REST · EST · CMPv2 · SCEP"))
CATALOG = {"evergreen": GUIDE, "uc04": USE_CASES["uc04"]}


def resolve_guide(key_location: str, mode: str, protocol: str, auth: str) -> tuple[str, str, str]:
    """Guide answers → (use case, protocol, auth). Single always means one certificate."""
    if mode == "batch":
        return ("uc01" if key_location == "server" else "uc02"), "", ""
    if key_location == "server":
        return "uc01", "", ""
    if protocol == "rest" and auth == "apikey":  # the factory calls the management API itself
        return "uc02", "", ""
    return "uc03", protocol, auth


DIVISION_DESCRIPTION = "dc-dtm-demonstrator run – safe to delete"
# Verified up to 1000 (≈2 min issuance); every certificate consumes a license and slows cleanup.
MAX_BATCH = 2_000
POLL_INTERVAL = 0.5
STORY_INTERVAL = 5.0
# DTM key type for the policy, derived from the issuing CA's algorithm.
KEY_TYPES = {"ecdsa": "P_256", "rsa": "RSA_2048"}

# Shown one after another while DTM works on a batch – the wait is part of the story.
WAIT_STORY = {
    "server_side": (
        "DTM generates a {key_type} key pair per device on the server side",
        "Each certificate is signed by the issuing CA {ca_name}",
        "DTM registers every certificate for its lifecycle (renewal, revocation, audit)",
        "The result is packed and encrypted to our one-time RSA key (CMS envelope)",
    ),
    "client_side": (
        "DTM checks each CSR's signature – proof that the factory holds the private key",
        "Each certificate is signed by the issuing CA {ca_name}",
        "DTM registers every certificate for its lifecycle (renewal, revocation, audit)",
        "No private key travels – the result contains certificates only",
    ),
}

DIVISION_PATH = "/devicetrustmanager/api/v4/division"
RZONE_PATH = "/devicetrustmanager/api/v4/rendezvous-zone"
POLICY_PATH = "/devicetrustmanager/certificate-configuration-service/api/v2/certificate-policy"
SINGLE_PATH = "/devicetrustmanager/certificate-issuance-service/api/v2/certificate"
JOBS_PATH = "/devicetrustmanager/certificate-batch-service/api/v1/jobs"
ENC_CERT_COMMAND = ('openssl req -x509 -newkey rsa:3072 -nodes -keyout enc.key -out enc.crt -days 30 '
                    '-subj "/CN=batch-encryption"')
DECRYPT_COMMAND = "openssl cms -decrypt -inform DER -in result.p7m -recip enc.crt -inkey enc.key -out result.zip"


def prefix(run_id: str, use_case: str) -> str:
    return f"robot-{run_id}-{use_case}"


def common_names(run_id: str, mode: str, count: int, use_case: str) -> list[str]:
    return [f"{prefix(run_id, use_case)}-{mode}-{i:04d}" for i in range(1, count + 1)]


def batch_zip(names: list[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("batch.csv", "subject.common_name\n" + "".join(f"{n}\n" for n in names))
    return buffer.getvalue()


def csr_zip(csrs: dict[str, str]) -> bytes:
    """One <common name>.csr file per device – what the factory uploads."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for cn, csr in csrs.items():
            archive.writestr(f"{cn}.csr", csr)
    return buffer.getvalue()


def _make_csrs(names: list[str], key_type: str) -> tuple[dict[str, str], float]:
    start = time.monotonic()
    return {cn: certs.factory_csr(cn, key_type) for cn in names}, time.monotonic() - start


async def factory_csrs(names: list[str], key_type: str, log) -> tuple[dict[str, str], float]:
    """The factory's key pairs and CSRs. CPU-bound (RSA ≈ 25 ms per key), so it runs in a thread –
    the event loop keeps serving the UI meanwhile."""
    log(f"Factory generates {len(names)} key pair(s) and CSR(s)")
    csrs, seconds = await asyncio.to_thread(_make_csrs, names, key_type)
    log(f"{len(names)} CSR(s) ready in {seconds:.2f}s – the private keys stay in the factory", "success")
    return csrs, seconds


def keygen_command(cn: str, key_type: str) -> dict:
    """Per-dialect local step: key + CSR, and the CSR as a JSON-ready variable for the request body."""
    new_key = "rsa:2048" if key_type.upper().startswith("RSA") else "ec -pkeyopt ec_paramgen_curve:P-256"
    openssl = f'openssl req -new -newkey {new_key} -nodes -keyout device.key -out device.csr -subj "/CN={cn}"'
    return {
        "bash": openssl + "\nexport CSR=\"$(awk '{printf \"%s\\\\n\", $0}' device.csr)\"",
        "powershell": openssl + '\n$env:CSR = (Get-Content device.csr -Raw).Replace("`r", "").Replace("`n", "\\n")',
    }


def rates(seconds: float, count: int) -> dict:
    if seconds <= 0 or count <= 0:
        return {}
    return {"per_certificate_s": round(seconds / count, 3), "per_minute": round(count / seconds * 60)}


async def create_division(client: DTMClient, api: ApiCalls, store: Store, run_id: str, use_case: str,
                          variables: dict, log) -> str:
    """The run's own division – every DTM object of the run lives in it (shared by all use cases)."""
    division_name = f"{prefix(run_id, use_case)}-division"
    log(f"Creating division {division_name}")
    rzone_id = await api.timed("Find a rendezvous zone for the division", "GET", RZONE_PATH,
                               client.rendezvous_zone(), spec={"method": "GET", "path": RZONE_PATH}, phase="setup")
    division_id = await api.timed(
        "Create a division for this run (the response has no ID)", "POST", DIVISION_PATH,
        client.create_division(division_name, DIVISION_DESCRIPTION, rzone_id),
        spec={"method": "POST", "path": DIVISION_PATH, "body_file": "division.json",
              "json": dtm.division_body(division_name, DIVISION_DESCRIPTION, "{DTM_ACCOUNT_ID}", rzone_id)},
        phase="setup")
    api.add("Look up the division ID by its name", "GET", DIVISION_PATH, None,
            spec={"method": "GET", "path": DIVISION_PATH}, phase="setup")
    variables["DIVISION_ID"] = division_id
    store.add_object(run_id, "division", division_id, division_name)
    return division_id


async def use_shared_profile(client: DTMClient, api: ApiCalls, spec: dtm.ProfileSpec, variables: dict, log) -> str:
    """The purpose's shared profile (validity etc.) – created by the first run, reused afterwards."""
    validity = f"{spec.value} {spec.unit}"
    profile_id, how = await api.timed(
        f"Find the shared profile {spec.name} ({validity}) – created once, reused by every run", "GET",
        dtm.PROFILES, client.shared_profile(spec), spec={"method": "GET", "path": dtm.PROFILES}, phase="setup")
    log({"created": "Created", "enabled": "Enabled again"}.get(how, "Using")
        + f" the shared certificate profile {spec.name} ({validity}) – DTM keeps it permanently")
    variables["PROFILE_ID"] = profile_id
    return profile_id


async def run(store: Store, client: DTMClient, run_id: str, run_dir: Path) -> None:
    run_ = store.get_run(run_id)
    p = run_["params"] | {"use_case": run_["use_case"],
                          "key_generation": USE_CASES[run_["use_case"]].key_generation}
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    api = ApiCalls()
    # Variables for the copyable command-line snippets; IDs are added as DTM hands them out.
    variables = {"DTM_HOST": p["dtm_host"], "DTM_ACCOUNT_ID": p["account_id"]}
    result: dict = {"api_calls": api.calls, "api_variables": variables}
    store.update_run(run_id, status="running")
    try:
        division_id = await create_division(client, api, store, run_id, p["use_case"], variables, log)

        profile_id = await use_shared_profile(client, api, dtm.PROFILE_EVERGREEN, variables, log)
        policy_name = f"{prefix(run_id, p['use_case'])}-policy"
        log(f"Creating certificate policy {policy_name} ({p['key_type']}, issuing CA {p['ca_name']})")
        policy_args = {"profile_id": profile_id, "ica_id": p["ca_id"], "key_type": p["key_type"],
                       "require_approval": bool(p.get("approval")), "key_generation": p["key_generation"]}
        keys_by = "server-side keys" if p["key_generation"] == "server_side" else "client-side keys (CSR)"
        policy_id = await api.timed(
            f"Create the certificate policy (single + batch, {keys_by})", "POST", POLICY_PATH,
            client.create_policy(name=policy_name, division_id=division_id, **policy_args),
            spec={"method": "POST", "path": POLICY_PATH, "body_file": "policy.json",
                  "json": dtm.policy_body(name=policy_name, division_id="{DIVISION_ID}", **policy_args
                                          | {"profile_id": "{PROFILE_ID}"})},
            phase="setup")
        api.add("Look up the policy ID by its name", "GET", POLICY_PATH, None,
                spec={"method": "GET", "path": POLICY_PATH}, phase="setup")
        variables["POLICY_ID"] = policy_id
        store.add_object(run_id, "policy", policy_id, policy_name)
        log("DTM is configured for this run", "success")

        result |= {"division": f"{prefix(run_id, p['use_case'])}-division", "policy": policy_name}
        if p["variant"] == "webui":
            result |= await _prepare_portal(run_id, p, run_dir, log)
            store.update_run(run_id, status="waiting", result=result)
            log("Setup done – continue in the DTM portal", "success")
            return
        if p["mode"] == "single":
            result |= await _single(client, api, store, run_id, policy_id, p, log)
        else:
            result |= await _batch(client, api, store, run_id, policy_id, p, run_dir, variables, log)
        certs.save_certificates(run_dir, result.get("certificates") or [])
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


async def _single(client: DTMClient, api: ApiCalls, store: Store, run_id: str, policy_id: str, p: dict,
                  log) -> dict:
    """Individual requests, one after another – the statistics cover all of them."""
    names = common_names(run_id, "single", p["count"], p["use_case"])
    client_side = p["key_generation"] == "client_side"
    csrs, keygen_s = {}, None
    if client_side:
        csrs, keygen_s = await factory_csrs(names, p["key_type"], log)
        api.add("Generate the device key and CSR (local, per device)", "LOCAL", "openssl", None,
                spec={"command": keygen_command(names[0], p["key_type"])})
    log(f"Requesting {len(names)} certificate(s) one by one – "
        + ("DTM signs each CSR" if client_side else "DTM generates each key pair"))
    started_wall, start = time.time(), time.monotonic()
    issued, private_keys, shown = [], 0, None
    next_note = start + STORY_INTERVAL
    outcome = "error"
    try:
        for done, cn in enumerate(names, 1):
            response = await client.issue_single(policy_id, cn, csrs.get(cn))
            pem = response.get("pem") if isinstance(response, dict) else None
            if not pem:
                raise ValueError(f"DTM response for {cn} contains no certificate")
            issued.append(certs.parse_pem_certificate(pem))
            private_keys += bool(response.get("private_key"))
            if shown is None:  # DTM's answer for the first request, never the private key
                shown = {k: v for k, v in response.items()
                         if k in ("certificate_id", "certificate_request_id", "status", "result", "certificate_status",
                                  "serial_number", "common_name", "valid_from", "valid_to")}
            store.update_run(run_id, progress={"label": f"Requesting {len(names)} certificates one by one",
                                               "started": started_wall, "total": len(names), "done": done})
            if time.monotonic() >= next_note and done < len(names):
                elapsed = time.monotonic() - start
                log(f"{done} of {len(names)} issued – {done / elapsed * 60:.0f} per minute so far", "wait")
                next_note = time.monotonic() + STORY_INTERVAL
        outcome = "ok"
    finally:
        purpose = ("Send the CSR, receive the certificate (once per device)" if client_side
                   else "Request a certificate with a server-generated key (once per certificate)")
        api.add(purpose, "POST", SINGLE_PATH, time.monotonic() - start, outcome,
                count=len(issued) + (outcome != "ok"),
                spec={"method": "POST", "path": SINGLE_PATH, "body_file": "certificate.json",
                      "json": dtm.single_body("{POLICY_ID}", names[0], "{CSR}" if client_side else None),
                      "output": "certificate.json.out"})
    duration = time.monotonic() - start
    log(f"{len(issued)} certificate(s) issued in {duration:.1f}s", "success")
    return {"duration_s": round(duration, 2), **rates(duration, len(issued)), "response": shown,
            "keygen_s": None if keygen_s is None else round(keygen_s, 2),
            "private_keys_returned": private_keys, "certificates": issued, "certificate_total": len(issued)}


async def _batch(client: DTMClient, api: ApiCalls, store: Store, run_id: str, policy_id: str, p: dict,
                 run_dir: Path, variables: dict, log) -> dict:
    pre = prefix(run_id, p["use_case"])
    names = common_names(run_id, "batch", p["count"], p["use_case"])
    client_side = p["key_generation"] == "client_side"
    run_dir.mkdir(parents=True, exist_ok=True)
    keygen_s = cert_pem = key_pem = None
    upload = {"method": "POST", "path": f"{JOBS_PATH}/certificate-enroll"}
    if client_side:
        store.update_run(run_id, progress={"label": f"Factory generates {len(names)} key pairs", "started": time.time()})
        csrs, keygen_s = await factory_csrs(names, p["key_type"], log)
        payload, artifact = csr_zip(csrs), "csrs.zip"
        api.add("Generate key + CSR per device (example: first device) – or use csrs.zip from the Payload", "LOCAL",
                "openssl", None, spec={"command": keygen_command(names[0], p["key_type"])})
        upload |= {"form": dtm.csr_batch_fields(f"{pre}-batch", "{POLICY_ID}"),
                   "files": {"data": "@csrs.zip;type=application/zip"}}
    else:
        payload, artifact = batch_zip(names), "batch.zip"
        cert_pem, key_pem = certs.encryption_keypair(f"{pre}-encryption")
        api.add("Create a one-time RSA key pair DTM encrypts the result to (local)", "LOCAL", "openssl", None,
                spec={"command": ENC_CERT_COMMAND})
        upload |= {"form": dtm.batch_fields(f"{pre}-batch", "{POLICY_ID}", p["key_type"]),
                   "files": {"encryption_certificate": "<enc.crt", "data": "@batch.zip;type=application/zip"}}
    (run_dir / artifact).write_bytes(payload)  # offered for download, to replay the call manually
    log(f"Uploading a ZIP with {len(names)} " + ("CSRs" if client_side else "certificate requests (CSV)"))
    store.update_run(run_id, progress={"label": f"Uploading {len(names)} certificate requests", "started": time.time()})
    job = await api.timed(
        "Upload the batch (multipart: " + ("CSR files" if client_side else "CSV") + " in a ZIP)", "POST",
        f"{JOBS_PATH}/certificate-enroll",
        client.submit_batch(name=f"{pre}-batch", policy_id=policy_id, payload=payload, key_type=p["key_type"],
                            encryption_cert_pem=None if client_side else cert_pem.decode()),
        spec=upload)
    upload_done = time.monotonic()  # measurement starts when the upload call has returned
    job_id = job["id"]
    variables["JOB_ID"] = job_id
    store.add_object(run_id, "batch_job", job_id, f"{pre}-batch")
    log(f"Batch job {job_id} accepted – the clock is running", "success")

    approval_s = None
    deadline = upload_done + max(600, len(names) * 2)
    status, done, polls, poll_seconds = None, None, 0, 0.0
    stories, story, next_story = WAIT_STORY[p["key_generation"]], 0, upload_done + STORY_INTERVAL
    started_wall = time.time()
    try:
        while True:
            poll_start = time.monotonic()
            job = await client.batch_job(job_id, quiet=True)
            polls += 1
            poll_seconds += time.monotonic() - poll_start
            if (job.get("status"), job.get("success_items")) != (status, done):
                if job.get("status") != status:
                    log(f"Job status: {job.get('status')}")
                status, done = job.get("status"), job.get("success_items")
                store.update_run(run_id, progress={
                    "label": f"DTM is issuing {len(names)} certificates", "status": status,
                    "started": started_wall, "total": len(names), "done": done})
            if status in ("completed", "failed", "rejected"):
                break
            if p.get("approval") and approval_s is None and status == "pending_approval":  # verified live
                log("Approval required – approving via API (the request/approve round trip)")
                await api.timed("Approve the batch job", "PUT", f"{JOBS_PATH}/{{JOB_ID}}/approve",
                                client.approve_batch(job_id),
                                spec={"method": "PUT", "path": f"{JOBS_PATH}/{{JOB_ID}}/approve", "json": {},
                                      "body_file": "empty.json"})
                approval_s = round(time.monotonic() - upload_done, 2)
                log(f"Approved after {approval_s}s", "success")
            if time.monotonic() >= next_story and status != "pending_approval":
                progress = f" – {done} of {len(names)} issued so far" if done else ""
                log(stories[story % len(stories)].format(**p) + progress, "wait")
                story += 1
                next_story = time.monotonic() + STORY_INTERVAL
            if time.monotonic() > deadline:
                raise ValueError(f"batch job did not complete within {deadline - upload_done:.0f}s")
            await asyncio.sleep(POLL_INTERVAL)
    finally:  # also shown when the job failed or timed out
        api.add(f"Poll the job status (every {POLL_INTERVAL:g}s) until it is completed", "GET",
                f"{JOBS_PATH}/{{JOB_ID}}", poll_seconds, count=polls,
                spec={"method": "GET", "path": f"{JOBS_PATH}/{{JOB_ID}}"})
    measured = time.monotonic() - upload_done
    if status != "completed":
        raise ValueError(f"batch job ended with status {status}")
    log(f"Batch completed after {measured:.2f}s – {len(names)} certificates", "success")

    result_path = f"{JOBS_PATH}/{{JOB_ID}}/download/result"
    if client_side:  # certificates only – nothing secret, so DTM sends a plain ZIP
        store.update_run(run_id, progress={"label": "Downloading the result", "started": time.time()})
        inner = await api.timed("Download the result (ZIP with the certificates)", "GET", result_path,
                                client.batch_result(job_id),
                                spec={"method": "GET", "path": result_path, "output": "result.zip"})
    else:
        store.update_run(run_id, progress={"label": "Downloading and decrypting the result", "started": time.time()})
        envelope = await api.timed("Download the encrypted result (CMS envelope)", "GET", result_path,
                                   client.batch_result(job_id),
                                   spec={"method": "GET", "path": result_path, "output": "result.p7m"})
        api.add("Decrypt the result with the one-time key (local)", "LOCAL", "openssl", None,
                spec={"command": DECRYPT_COMMAND})
        inner = certs.decrypt_result(envelope, cert_pem, key_pem)
    issued, keys = certs.parse_batch_zip(inner)
    log(f"Result: {len(issued)} certificates" + (f", {keys} private keys (not displayed)" if keys else ""), "success")
    # Rates exclude the approval round trip – they describe DTM's issuing speed.
    issuing = measured - (approval_s or 0)
    return {"duration_s": round(measured, 2), **rates(issuing, len(issued)), "approval_s": approval_s,
            "server_processing_ms": job.get("processing_time"),
            "success_items": job.get("success_items"), "failed_items": job.get("failed_items"),
            "certificates": issued, "certificate_total": len(issued),
            "keygen_s": None if keygen_s is None else round(keygen_s, 2),
            "private_keys_returned": keys, "artifact": artifact}


async def _prepare_portal(run_id: str, p: dict, run_dir: Path, log) -> dict:
    names = common_names(run_id, p["mode"], p["count"], p["use_case"])
    result = {}
    if p["mode"] == "single":
        result["portal_values"] = ({"Common name": names[0]} if len(names) == 1
                                   else {"Common names": f"{names[0]} … {names[-1]}"})
    run_dir.mkdir(parents=True, exist_ok=True)
    if p["key_generation"] == "client_side":  # the portal needs the factory's CSRs
        csrs, _ = await factory_csrs(names, p["key_type"], log)
        (run_dir / "csrs.zip").write_bytes(csr_zip(csrs))
        return result | {"artifact": "csrs.zip"}
    if p["mode"] == "batch":
        (run_dir / "batch.zip").write_bytes(batch_zip(names))
        log(f"Batch upload file with {p['count']} entries ready for download", "success")
        return result | {"artifact": "batch.zip"}
    return result
