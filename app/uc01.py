"""UC-1 – evergreen certificates in manufacturing (server-side keys, single or batch)."""

import asyncio
import io
import time
import zipfile
from pathlib import Path

from . import certs
from .dtm import DTMClient, DTMError
from .store import Store, now

USE_CASE = "uc01"
MAX_BATCH = 10_000
POLL_INTERVAL = 0.5
SHOWN_CERTIFICATES = 50
# DTM key type for the policy, derived from the issuing CA's algorithm.
KEY_TYPES = {"ecdsa": "P_256", "rsa": "RSA_2048"}


def prefix(run_id: str) -> str:
    return f"robot-{run_id}-{USE_CASE}"


def common_names(run_id: str, mode: str, count: int) -> list[str]:
    return [f"{prefix(run_id)}-{mode}-{i:04d}" for i in range(1, count + 1)]


def batch_zip(names: list[str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("batch.csv", "subject.common_name\n" + "".join(f"{n}\n" for n in names))
    return buffer.getvalue()


async def run(store: Store, client: DTMClient, run_id: str, run_dir: Path) -> None:
    run_ = store.get_run(run_id)
    p = run_["params"]
    log = lambda msg, level="info": store.add_event(run_id, msg, level)  # noqa: E731
    store.update_run(run_id, status="running")
    try:
        division_name = f"{prefix(run_id)}-division"
        log(f"Creating division {division_name}")
        division_id = await client.create_division(division_name, "dc-dtm-demonstrator run – safe to delete")
        store.add_object(run_id, "division", division_id, division_name)

        policy_name = f"{prefix(run_id)}-policy"
        log(f"Creating certificate policy {policy_name} ({p['key_type']}, issuing CA {p['ca_name']})")
        policy_id = await client.create_policy(
            name=policy_name, division_id=division_id, profile_id=p["profile_id"], ica_id=p["ca_id"],
            key_type=p["key_type"], require_approval=bool(p.get("approval")))
        store.add_object(run_id, "policy", policy_id, policy_name)

        result = {"division": division_name, "policy": policy_name}
        if p["variant"] == "webui":
            result |= await _prepare_portal(run_id, p, run_dir, log)
            store.update_run(run_id, status="waiting", result=result)
            log("Setup done – continue in the DTM portal")
            return
        if p["mode"] == "single":
            result |= await _single(client, run_id, policy_id, log)
        else:
            result |= await _batch(client, store, run_id, policy_id, p, log)
        store.update_run(run_id, status="completed", result=result, finished_at=now())
        log("Run completed")
    except (DTMError, ValueError) as exc:
        log(f"Run failed: {exc}", "error")
        store.update_run(run_id, status="failed", error=str(exc), finished_at=now())
    except Exception as exc:  # keep the run visible as failed instead of silently dying
        log(f"Run failed unexpectedly: {type(exc).__name__}", "error")
        store.update_run(run_id, status="failed", error=type(exc).__name__, finished_at=now())
        raise


async def _single(client: DTMClient, run_id: str, policy_id: str, log) -> dict:
    cn = common_names(run_id, "single", 1)[0]
    log(f"Requesting certificate {cn} (server-side key)")
    start = time.monotonic()
    response = await client.issue_single(policy_id, cn)
    duration = time.monotonic() - start
    pem = response.get("pem") if isinstance(response, dict) else None
    if not pem:
        raise ValueError("DTM response contains no certificate")
    log(f"Certificate issued in {duration:.1f}s")
    # Show DTM's answer, but never the private key.
    shown = {k: v for k, v in response.items()
             if k in ("certificate_id", "certificate_request_id", "status", "result", "certificate_status",
                      "serial_number", "common_name", "valid_from", "valid_to")}
    return {"duration_s": round(duration, 2), "response": shown,
            "private_key_returned": bool(response.get("private_key")),
            "certificates": [certs.parse_pem_certificate(pem)], "certificate_total": 1}


async def _batch(client: DTMClient, store: Store, run_id: str, policy_id: str, p: dict, log) -> dict:
    names = common_names(run_id, "batch", p["count"])
    cert_pem, key_pem = certs.encryption_keypair(f"{prefix(run_id)}-encryption")
    log(f"Uploading batch of {len(names)} certificate requests")
    job = await client.submit_batch(name=f"{prefix(run_id)}-batch", policy_id=policy_id, key_type=p["key_type"],
                                    csv_zip=batch_zip(names), encryption_cert_pem=cert_pem.decode())
    upload_done = time.monotonic()  # measurement starts when the upload call has returned
    job_id = job["id"]
    store.add_object(run_id, "batch_job", job_id, f"{prefix(run_id)}-batch")
    log(f"Batch job {job_id} created – measuring until DTM reports it completed")

    approval_s = None
    deadline = upload_done + max(600, len(names) * 2)
    status = None
    while True:
        job = await client.batch_job(job_id)
        if job.get("status") != status:
            status = job.get("status")
            log(f"t+{time.monotonic() - upload_done:.1f}s job status: {status}")
        if status in ("completed", "failed", "rejected"):
            break
        if p.get("approval") and approval_s is None and "approv" in str(status).lower():
            log("Approval required – approving via API")
            await client.approve_batch(job_id)
            approval_s = round(time.monotonic() - upload_done, 2)
            log(f"Approved after {approval_s}s")
        if time.monotonic() > deadline:
            raise ValueError(f"batch job did not complete within {deadline - upload_done:.0f}s")
        await asyncio.sleep(POLL_INTERVAL)
    measured = round(time.monotonic() - upload_done, 2)
    if status != "completed":
        raise ValueError(f"batch job ended with status {status}")
    log(f"Batch completed after {measured}s (DTM processing time {job.get('processing_time')} ms)")

    envelope = await client.batch_result(job_id)
    inner = certs.decrypt_result(envelope, cert_pem, key_pem)
    issued, keys = certs.parse_batch_zip(inner)
    log(f"Result decrypted: {len(issued)} certificates, {keys} private keys (not displayed)")
    return {"duration_s": measured, "approval_s": approval_s,
            "server_processing_ms": job.get("processing_time"),
            "success_items": job.get("success_items"), "failed_items": job.get("failed_items"),
            "certificates": issued[:SHOWN_CERTIFICATES], "certificate_total": len(issued),
            "private_keys_returned": keys}


async def _prepare_portal(run_id: str, p: dict, run_dir: Path, log) -> dict:
    if p["mode"] == "single":
        return {"portal_values": {"Common name": common_names(run_id, "single", 1)[0]}}
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "batch.zip").write_bytes(batch_zip(common_names(run_id, "batch", p["count"])))
    log(f"Batch upload file with {p['count']} entries ready for download")
    return {"artifact": "batch.zip"}
