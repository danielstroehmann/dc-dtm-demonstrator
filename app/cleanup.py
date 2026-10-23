"""Rollback of everything a run created. Order matters: certificates → policies → division
(deleting a division does not cascade, R-2)."""

import asyncio
import shutil
from pathlib import Path

from .dtm import DTMClient, DTMError
from .store import Store

REVOKE_PARALLEL = 16
MAX_PASSES = 30
BACKOFF_S = 10.0
CONFIRM_DELAY_S = 3.0


async def revoke_all(client: DTMClient, policy_id: str, log) -> None:
    """Failsafe mass revoke (R-4): short timeouts, passes until no issued certificate is left."""
    semaphore = asyncio.Semaphore(REVOKE_PARALLEL)

    async def one(cert_id: str) -> str:
        async with semaphore:
            return await client.revoke(cert_id)

    for attempt in range(1, MAX_PASSES + 1):
        issued = await client.issued_certificates(policy_id)
        if not issued:
            # The issued list lags behind; confirm before the policy gets deleted.
            await asyncio.sleep(CONFIRM_DELAY_S)
            issued = await client.issued_certificates(policy_id)
            if not issued:
                return
        log(f"Revocation pass {attempt}: {len(issued)} certificates still issued")
        outcomes = await asyncio.gather(*(one(c["id"]) for c in issued))
        timeouts = outcomes.count("timeout")
        log(f"Pass {attempt}: {outcomes.count('revoked')} revoked, {outcomes.count('already')} already revoked, "
            f"{timeouts} timed out")
        if timeouts > len(issued) / 2:
            await asyncio.sleep(BACKOFF_S)
    raise DTMError(f"certificates still issued after {MAX_PASSES} revocation passes")


async def cleanup(store: Store, client: DTMClient, run_id: str, mode: str, run_dir: Path) -> None:
    """mode 'full' restores the account; mode 'certificates' only revokes (keeps the configuration)."""
    log = lambda msg, level="info": store.add_event(run_id, msg, level)  # noqa: E731
    expected_prefix = f"robot-{run_id}-"
    store.update_run(run_id, cleanup_mode=mode, cleanup_status="running")
    try:
        for obj in store.objects(run_id):
            # Ledger entries are ours by construction; the name check guards against corruption.
            if not obj["name"].startswith(expected_prefix):
                raise DTMError(f"refusing to touch {obj['kind']} {obj['name']!r}: outside run prefix")
        for policy in store.objects(run_id, "policy"):
            log(f"Revoking certificates of policy {policy['name']}")
            await revoke_all(client, policy["dtm_id"], log)
        if mode == "full":
            for policy in store.objects(run_id, "policy"):
                log(f"Deleting certificate policy {policy['name']}")
                await client.delete_policy(policy["dtm_id"])
                store.mark_removed(run_id, "policy", policy["dtm_id"])
            for division in store.objects(run_id, "division"):
                log(f"Deleting division {division['name']}")
                await client.delete_division(division["dtm_id"])
                store.mark_removed(run_id, "division", division["dtm_id"])
        shutil.rmtree(run_dir, ignore_errors=True)
        store.update_run(run_id, cleanup_status="done")
        log("Cleanup done" + (" – account restored" if mode == "full" else " – configuration kept"))
    except DTMError as exc:
        log(f"Cleanup failed: {exc}", "error")
        store.update_run(run_id, cleanup_status="failed")
    except Exception as exc:
        log(f"Cleanup failed unexpectedly: {type(exc).__name__}", "error")
        store.update_run(run_id, cleanup_status="failed")
        raise
