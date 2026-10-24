"""Rollback of everything a run created. Order matters: wait for batch jobs → certificates →
policies → authentication objects (UC-3) → division (deleting a division does not cascade, R-2)."""

import asyncio
import shutil
import time
from pathlib import Path

from . import evergreen
from .dtm import AUTH_KINDS, DTMClient, DTMError
from .store import Store

REVOKE_PARALLEL = 16
MAX_PASSES = 30
CONFIRM_DELAY_S = 3.0
IDLE_BACKOFF_S = 5.0
JOB_WAIT_S = 1800
HEARTBEAT_S = 1.5  # a cleanup must never look frozen during a demo
TERMINAL_JOB_STATES = {"completed", "failed", "rejected"}


class Heartbeat:
    """Logs the current cleanup state at least every HEARTBEAT_S and mirrors it into the run's
    progress card, so long revocations stay visible."""

    def __init__(self, store: Store, run_id: str, log):
        self.store, self.run_id, self.log = store, run_id, log
        self.phase, self.total, self.revoked, self.already, self.retry = "Preparing the cleanup", 0, 0, 0, 0
        self.started = time.time()
        self._task: asyncio.Task | None = None

    def set(self, phase: str, total: int = 0) -> None:
        self.phase, self.total, self.revoked, self.already, self.retry = phase, total, 0, 0, 0

    def count(self, outcome: str) -> None:
        if outcome == "revoked":
            self.revoked += 1
        elif outcome == "already":
            self.already += 1
        else:
            self.retry += 1

    def message(self) -> str:
        if not self.total:
            return self.phase
        done = self.revoked + self.already + self.retry
        return (f"{self.phase}: {done} of {self.total} done – {self.revoked} revoked, {self.already} already revoked"
                + (f", {self.retry} to retry" if self.retry else ""))

    async def _beat(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_S)
            self.log(self.message(), "wait")
            self.store.update_run(self.run_id, progress={
                "label": self.phase, "started": self.started, "total": self.total or None,
                "done": (self.revoked + self.already + self.retry) if self.total else None})

    def __enter__(self):
        self._task = asyncio.create_task(self._beat())
        return self

    def __exit__(self, *_exc):
        self._task.cancel()
        self.store.update_run(self.run_id, progress=None)


async def revoke_all(client: DTMClient, policy_id: str, log, expected: int = 0, beat: Heartbeat | None = None) -> None:
    """Failsafe mass revoke (R-4): short timeouts, passes until no issued certificate is left.
    All certificates under the policy are revoked – the policy belongs to the run, so this also
    covers certificates issued in the DTM portal under a different name.
    `expected`: certificates the run knows it issued – an empty issued list only counts once at
    least that many are listed as revoked (the lists are eventually consistent)."""
    semaphore = asyncio.Semaphore(REVOKE_PARALLEL)

    async def one(cert_id: str) -> str:
        async with semaphore:
            outcome = await client.revoke(cert_id)
        if beat:
            beat.count(outcome)
        return outcome

    idle_passes = 0
    for attempt in range(1, MAX_PASSES + 1):
        if beat:
            beat.set("Loading the list of issued certificates from DTM")
        issued = await client.issued_certificates(policy_id)
        if not issued:
            # The issued list lags behind; confirm before the policy gets deleted.
            if beat:
                beat.set("Confirming that DTM lists no issued certificate any more")
            await asyncio.sleep(CONFIRM_DELAY_S)
            issued = await client.issued_certificates(policy_id)
            if not issued and await client.count_certificates(policy_id, "revoked") >= expected:
                return
        if not issued:
            log("Issued list empty, but not all known certificates are listed as revoked yet – waiting", "wait")
            await asyncio.sleep(IDLE_BACKOFF_S * attempt)
            continue
        log(f"Revocation pass {attempt}: {len(issued)} certificates still issued")
        if beat:
            beat.set(f"Revoking certificates (pass {attempt})", len(issued))
        outcomes = await asyncio.gather(*(one(c["id"]) for c in issued), return_exceptions=True)
        auth_errors = [o for o in outcomes if isinstance(o, DTMError) and o.status in (401, 403)]
        if auth_errors:
            raise auth_errors[0]
        revoked = outcomes.count("revoked")
        retry = len(outcomes) - revoked - outcomes.count("already")
        log(f"Pass {attempt}: {revoked} revoked, {outcomes.count('already')} already revoked, {retry} to retry")
        # No progress (list lag or congestion): wait longer before the next pass.
        idle_passes = idle_passes + 1 if revoked == 0 or retry > len(issued) / 2 else 0
        if idle_passes:
            if beat:
                beat.set("Waiting for DTM to catch up – its lists are eventually consistent")
            await asyncio.sleep(IDLE_BACKOFF_S * idle_passes)
    raise DTMError(f"certificates still issued after {MAX_PASSES} revocation passes")


async def wait_for_jobs(store: Store, client: DTMClient, run_id: str, log) -> None:
    """A batch job may still be issuing (run timed out or app restarted) – revoking now would
    miss certificates issued afterwards."""
    for job in store.objects(run_id, "batch_job"):
        deadline = time.monotonic() + JOB_WAIT_S
        while True:
            try:
                status = (await client.batch_job(job["dtm_id"], quiet=True)).get("status")
            except DTMError as exc:
                if exc.status == 404:  # jobs expire after 30 days – nothing left to wait for
                    break
                raise
            if status in TERMINAL_JOB_STATES:
                break
            if status == "pending_approval":
                # Never approved (approve failed or the app restarted) – reject so it ends.
                log(f"Rejecting batch job {job['dtm_id']} that is still waiting for approval")
                await client.reject_batch(job["dtm_id"])
            elif time.monotonic() > deadline:
                raise DTMError(f"batch job {job['dtm_id']} still {status} – try the cleanup again later")
            else:
                log(f"Waiting for batch job {job['dtm_id']} ({status}) to finish before revoking", "wait")
            await asyncio.sleep(10)


async def discover(store: Store, client: DTMClient, run_id: str, log) -> None:
    """Merge objects found by their exact run names into the ledger – a create may have
    succeeded in DTM although the run never recorded it (crash, lookup failure)."""
    run = store.get_run(run_id)
    base = evergreen.prefix(run_id, run["use_case"])
    lookups = [("division", f"{base}-division", client.division_ids),
               ("policy", f"{base}-policy", client.policy_ids)]
    if run["use_case"] == "uc03":  # the factory's credential lives in its own authentication policy
        credential = ("auth_certificate", "factory") if run["params"].get("auth") == "certificate" else ("passcode", "passcode")
        lookups += [(kind, f"{base}-{suffix}", lambda n, k=kind: client.auth_object_ids(k, n))
                    for kind, suffix in (credential, ("auth_policy", "auth"))]
    for kind, name, lookup in lookups:
        known = {o["dtm_id"] for o in store.objects(run_id, kind)}
        for dtm_id in await lookup(name):
            if dtm_id not in known:
                log(f"Found unrecorded {kind} {name} – adding it to the cleanup")
                store.add_object(run_id, kind, dtm_id, name)


async def cleanup(store: Store, client: DTMClient, run_id: str, mode: str, run_dir: Path) -> None:
    """mode 'full' restores the account; mode 'certificates' only revokes (keeps the configuration)."""
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    expected_prefix = f"robot-{run_id}-"
    store.update_run(run_id, cleanup_mode=mode, cleanup_status="running")
    try:
        with Heartbeat(store, run_id, log) as beat:
            await discover(store, client, run_id, log)
            for obj in store.objects(run_id):
                # Ledger entries are ours by construction; the name check guards against corruption.
                if not obj["name"].startswith(expected_prefix):
                    raise DTMError(f"refusing to touch {obj['kind']} {obj['name']!r}: outside run prefix")
            beat.set("Checking that no batch job is still issuing")
            await wait_for_jobs(store, client, run_id, log)
            result = store.get_run(run_id).get("result") or {}
            for policy in store.objects(run_id, "policy"):
                log(f"Revoking certificates of policy {policy['name']}")
                await revoke_all(client, policy["dtm_id"], log, expected=result.get("certificate_total") or 0,
                                 beat=beat)
            if mode == "full":
                for policy in store.objects(run_id, "policy"):
                    log(f"Deleting certificate policy {policy['name']}")
                    beat.set(f"Deleting certificate policy {policy['name']} and verifying it is gone")
                    await client.delete_policy(policy["dtm_id"])
                    store.mark_removed(run_id, "policy", policy["dtm_id"])
                for kind in AUTH_KINDS:  # credentials first, their authentication policy last
                    for obj in store.objects(run_id, kind):
                        log(f"Deleting {kind.replace('_', ' ')} {obj['name']}")
                        beat.set(f"Deleting {kind.replace('_', ' ')} {obj['name']} and verifying it is gone")
                        await client.delete_auth_object(kind, obj["dtm_id"])
                        store.mark_removed(run_id, kind, obj["dtm_id"])
                for division in store.objects(run_id, "division"):
                    log(f"Deleting division {division['name']}")
                    beat.set(f"Deleting division {division['name']} and verifying it is gone")
                    await client.delete_division(division["dtm_id"])
                    store.mark_removed(run_id, "division", division["dtm_id"])
                shutil.rmtree(run_dir, ignore_errors=True)
            store.update_run(run_id, cleanup_status="done")
            log("Cleanup done" + (" – account restored" if mode == "full" else " – configuration kept"), "success")
    except DTMError as exc:
        log(f"Cleanup failed: {exc}", "error")
        store.update_run(run_id, cleanup_status="failed")
    except Exception as exc:
        log(f"Cleanup failed unexpectedly: {type(exc).__name__}", "error")
        store.update_run(run_id, cleanup_status="failed")
        raise
