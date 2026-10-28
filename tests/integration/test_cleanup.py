"""Cleanup against the stateful fake DTM: order, modes, failsafe revoke passes, guards."""

import re

import httpx
import pytest

from app import cleanup
from tests.fakedtm import FakeDTM
from tests.integration.test_uc01_flow import start


async def do_cleanup(store, fake: FakeDTM, run_id: str, mode: str, tmp_path):
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, run_id, mode, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


def deletes_in_order(fake: FakeDTM) -> list[str]:
    return [n for n in fake.route_order() if n in ("revoke", "policy_delete", "division_delete")]


async def test_full_cleanup_order_and_result(store, fake, tmp_path):
    await start(store, fake, "c1", tmp_path, mode="batch", count=5)
    fake.calls.clear()
    run = await do_cleanup(store, fake, "c1", "full", tmp_path)
    assert run["cleanup_status"] == "done" and run["cleanup_mode"] == "full", store.events("c1")
    order = deletes_in_order(fake)
    # certificates → policy → division (R-2: deleting a division does not cascade)
    assert order == ["revoke"] * 5 + ["policy_delete", "division_delete"]
    assert fake.issued() == [] and fake.policies == {} and fake.divisions == {}
    assert store.objects("c1", "policy") == [] and store.objects("c1", "division") == []
    assert fake.violations == []


async def test_certificates_mode_keeps_policy_division_and_artifact(store, fake, tmp_path):
    await start(store, fake, "c2", tmp_path, mode="single")
    run_dir = tmp_path / "runs" / "c2"
    serial = store.get_run("c2")["result"]["certificates"][0]["serial"]
    pem_file = run_dir / "certificates" / f"{serial}.pem"
    assert pem_file.is_file()  # the run saved the issued certificate for download
    (run_dir / "batch.zip").write_bytes(b"artifact")
    run = await do_cleanup(store, fake, "c2", "certificates", tmp_path)
    assert run["cleanup_status"] == "done" and run["cleanup_mode"] == "certificates"
    assert pem_file.is_file()  # certificates-only cleanup keeps the downloads (the run's result stays)
    assert fake.issued() == []
    assert len(fake.policies) == 1 and len(fake.divisions) == 1
    assert "policy_delete" not in fake.route_order() and "division_delete" not in fake.route_order()
    assert (run_dir / "batch.zip").exists()
    # a later full rollback still removes the configuration and the run directory
    run = await do_cleanup(store, fake, "c2", "full", tmp_path)
    assert run["cleanup_status"] == "done" and fake.policies == {} and fake.divisions == {}
    assert not run_dir.exists()


async def test_webui_certificates_issued_in_portal_are_revoked(store, fake, tmp_path):
    await start(store, fake, "c3", tmp_path, variant="webui", mode="batch", count=2)
    policy_id = next(iter(fake.policies))
    fake._new_certificate(policy_id, "robot-c3-uc01-batch-0001")
    fake._new_certificate(policy_id, "typed-differently-in-portal")
    run = await do_cleanup(store, fake, "c3", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert fake.issued() == [] and fake.policies == {}


async def test_revoke_passes_survive_timeouts_and_list_lag(store, fake, tmp_path):
    await start(store, fake, "c4", tmp_path, mode="batch", count=4)
    ids = [c["id"] for c in fake.issued()]
    fake.revoke_plan = {ids[0]: ["timeout"], ids[1]: ["timeout_completed"], ids[2]: ["status503"]}
    run = await do_cleanup(store, fake, "c4", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("c4")
    assert fake.issued() == [] and fake.policies == {}
    messages = " | ".join(e["message"] for e in store.events("c4"))
    assert "Pass 1: 1 revoked, 0 already revoked, 3 to retry" in messages
    assert "already revoked" in messages
    assert "Pass 2: 2 revoked, 1 already revoked, 0 to retry" in messages


async def test_confirmation_relist_catches_late_certificates(store, fake, tmp_path):
    await start(store, fake, "c5", tmp_path, mode="single")
    hidden = fake.issued()[0]["id"]
    fake.issued_list_hidden = {hidden}  # first listing lags: looks empty
    run = await do_cleanup(store, fake, "c5", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert fake.certificates[hidden]["status"] == "REVOKED"
    assert deletes_in_order(fake)[:1] == ["revoke"]


async def test_revocation_parallelism_is_bounded(store, fake, tmp_path):
    await start(store, fake, "c6", tmp_path, mode="batch", count=40)
    fake.revoke_delay = 0.01
    run = await do_cleanup(store, fake, "c6", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert 1 < fake.revoke_max_in_flight <= cleanup.REVOKE_PARALLEL


async def test_gives_up_after_max_passes(store, fake, tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup, "MAX_PASSES", 3)
    await start(store, fake, "c7", tmp_path, mode="single")
    cert_id = fake.issued()[0]["id"]
    fake.revoke_plan = {cert_id: ["timeout"] * 10}
    run = await do_cleanup(store, fake, "c7", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert fake.route_order().count("revoke") == 3
    assert "policy_delete" not in fake.route_order()  # never delete a policy with issued certificates
    assert any("after 3 revocation passes" in e["message"] for e in store.events("c7"))


async def test_idle_passes_back_off_increasingly(store, fake, tmp_path, monkeypatch, fast_timing):
    monkeypatch.setattr(cleanup, "IDLE_BACKOFF_S", 5.0)
    await start(store, fake, "c8", tmp_path, mode="single")
    cert_id = fake.issued()[0]["id"]
    fake.revoke_plan = {cert_id: ["timeout", "timeout", "ok"]}
    fast_timing.clear()
    run = await do_cleanup(store, fake, "c8", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert [s for s in fast_timing if s >= 5] == [5.0, 10.0]


async def test_refuses_ledger_objects_outside_run_prefix(store, fake, tmp_path):
    await start(store, fake, "c9", tmp_path, mode="single")
    store.add_object("c9", "policy", "IOT_foreign", "customer-production-policy")
    fake.calls.clear()
    run = await do_cleanup(store, fake, "c9", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert deletes_in_order(fake) == []
    assert any("outside run prefix" in e["message"] for e in store.events("c9"))


async def test_prefix_of_other_run_is_outside(store, fake, tmp_path):
    # run "c1" must not touch objects of run "c10" even though the ids share a prefix
    await start(store, fake, "c1", tmp_path, mode="single")
    store.add_object("c1", "division", "d-x", "robot-c10-uc01-division")
    run = await do_cleanup(store, fake, "c1", "full", tmp_path)
    assert run["cleanup_status"] == "failed"


async def test_policy_delete_failure_marks_failed_and_keeps_division(store, fake, tmp_path):
    await start(store, fake, "d1", tmp_path, mode="single")
    fake.fail["policy_delete"] = httpx.Response(400, text="<!doctype html><html>error</html>")
    run = await do_cleanup(store, fake, "d1", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert "division_delete" not in fake.route_order()
    assert len(fake.divisions) == 1
    assert any("(HTML error page)" in e["message"] and e["level"] == "error" for e in store.events("d1"))
    # retry after DTM recovered
    del fake.fail["policy_delete"]
    run = await do_cleanup(store, fake, "d1", "full", tmp_path)
    assert run["cleanup_status"] == "done" and fake.divisions == {} and fake.policies == {}


async def test_discover_finds_unrecorded_division(store, fake, tmp_path, monkeypatch):
    # The create succeeded in DTM but the lookup never saw it (list lag beyond the retries).
    fake.division_list_lag = 10
    run = await start(store, fake, "o1", tmp_path)
    assert run["status"] == "failed" and "found 0" in run["error"]
    assert store.objects("o1") == [] and len(fake.divisions) == 1
    for d in fake.divisions.values():
        d["hidden"] = 0
    run = await do_cleanup(store, fake, "o1", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert fake.divisions == {}


async def test_discover_ignores_similar_names(store, fake, tmp_path):
    await start(store, fake, "o2", tmp_path, mode="single")
    # objects of other runs/humans with similar names must survive
    fake.divisions["foreign"] = {"id": "foreign", "name": "robot-o2-uc01-division-copy", "hidden": 0}
    fake.divisions["foreign2"] = {"id": "foreign2", "name": "robot-o22-uc01-division", "hidden": 0}
    run = await do_cleanup(store, fake, "o2", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert set(fake.divisions) == {"foreign", "foreign2"}


async def test_waits_for_running_batch_job_before_revoking(store, fake, tmp_path):
    fake.job_steps = ["in_progress"] * 3 + ["completed"]
    await start(store, fake, "j1", tmp_path, mode="batch", count=2, approval=False)
    # Simulate a run that was interrupted while the job was still running.
    job = next(iter(fake.jobs.values()))
    job.update(status="in_progress", steps=["in_progress", "in_progress", "completed"], issued=[])
    for c in list(fake.certificates.values()):
        del fake.certificates[c["id"]]
    run = await do_cleanup(store, fake, "j1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("j1")
    assert len(job["issued"]) == 2  # certificates issued while waiting ...
    assert fake.issued() == []      # ... are revoked as well
    assert any("Waiting for batch job" in e["message"] for e in store.events("j1"))


async def test_cleanup_waits_through_transient_failed_job_status(store, fake, tmp_path):
    fake.job_steps = ["in_progress", "completed"]
    await start(store, fake, "j1f", tmp_path, mode="batch", count=2, approval=False)
    # Interrupted run; DTM then reports "failed" once while the job keeps issuing.
    job = next(iter(fake.jobs.values()))
    job.update(status="in_progress", steps=["failed", "in_progress", "completed"], issued=[])
    for c in list(fake.certificates.values()):
        del fake.certificates[c["id"]]
    fake.calls.clear()
    run = await do_cleanup(store, fake, "j1f", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("j1f")
    assert job["status"] == "completed" and len(job["issued"]) == 2  # issued after the transient failed ...
    assert fake.issued() == []                                         # ... and revoked
    order = fake.route_order()
    assert order.count("job") == 3 and order.index("revoke") > max(i for i, n in enumerate(order) if n == "job")
    assert any("(failed) to finish before revoking" in e["message"] for e in store.events("j1f"))


async def test_cleanup_proceeds_after_persistent_failed_job_status(store, fake, tmp_path):
    fake.job_steps = ["in_progress", "completed"]
    await start(store, fake, "j1p", tmp_path, mode="batch", count=2, approval=False)
    job = next(iter(fake.jobs.values()))
    job.update(status="in_progress", steps=["failed"] * 100)
    fake.calls.clear()
    run = await do_cleanup(store, fake, "j1p", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("j1p")
    assert fake.route_order().count("job") == 2  # failed confirmed on the second check, no endless wait
    assert fake.issued() == [] and fake.policies == {} and fake.divisions == {}


async def test_cleanup_rejects_job_stuck_in_pending_approval(store, fake, tmp_path):
    fake.fail["approve"] = httpx.Response(500, json={"error": "approval service down"})
    run = await start(store, fake, "j2", tmp_path, mode="batch", count=2, approval=True)
    assert run["status"] == "failed"
    job = next(iter(fake.jobs.values()))
    assert job["status"] == "pending_approval"
    run = await do_cleanup(store, fake, "j2", "full", tmp_path)
    assert run["cleanup_status"] == "done", [e["message"] for e in store.events("j2")][-3:]
    assert job["status"] == "rejected" and len(fake.names("reject")) == 1
    assert job["issued"] == [] and fake.certificates == {}
    assert fake.policies == {} and fake.divisions == {}
    assert fake.route_order().index("reject") < fake.route_order().index("policy_delete")


async def test_cleanup_with_expired_batch_job(store, fake, tmp_path):
    await start(store, fake, "j3", tmp_path, mode="batch", count=1)
    fake.jobs.clear()  # expired → 404 entity_not_found
    run = await do_cleanup(store, fake, "j3", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert fake.issued() == [] and fake.policies == {}


async def test_job_lookup_errors_other_than_404_fail_the_cleanup(store, fake, tmp_path):
    await start(store, fake, "j4", tmp_path, mode="batch", count=1)
    fake.fail["job"] = httpx.Response(500, json={"error": "batch service down"})
    run = await do_cleanup(store, fake, "j4", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert "revoke" not in fake.route_order() and len(fake.policies) == 1


async def test_job_wait_times_out(store, fake, tmp_path, monkeypatch):
    fake.job_steps = ["in_progress", "completed"]
    await start(store, fake, "j5", tmp_path, mode="batch", count=1)
    job = next(iter(fake.jobs.values()))
    job.update(status="in_progress", steps=["in_progress"] * 1000)
    monkeypatch.setattr(cleanup, "JOB_WAIT_S", 0.0)
    run = await do_cleanup(store, fake, "j5", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert any("still in_progress" in e["message"] for e in store.events("j5"))
    assert len(fake.policies) == 1  # nothing deleted while the job may still issue


async def test_job_wait_deadline_gives_a_failed_status_its_second_check(store, fake, tmp_path, monkeypatch):
    fake.job_steps = ["in_progress", "completed"]
    await start(store, fake, "j5f", tmp_path, mode="batch", count=1)
    job = next(iter(fake.jobs.values()))
    job.update(status="in_progress", steps=["failed", "completed"], issued=[])
    for c in list(fake.certificates.values()):
        del fake.certificates[c["id"]]
    monkeypatch.setattr(cleanup, "JOB_WAIT_S", 0.0)  # the deadline has passed at the first check
    run = await do_cleanup(store, fake, "j5f", "full", tmp_path)
    assert run["cleanup_status"] == "done", [e["message"] for e in store.events("j5f")][-3:]
    assert len(job["issued"]) == 1 and fake.issued() == []


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_error_aborts_revocation_immediately(store, fake, tmp_path, status):
    await start(store, fake, "a1", tmp_path, mode="batch", count=3)
    for cert in fake.issued():
        fake.revoke_plan[cert["id"]] = [f"status{status}"] * 50
    run = await do_cleanup(store, fake, "a1", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert fake.route_order().count("cert_list") == 1  # one pass only, not MAX_PASSES
    assert "policy_delete" not in fake.route_order()
    assert any(f"returned {status}" in e["message"] for e in store.events("a1"))


async def test_empty_issued_list_waits_for_revoked_count(store, fake, tmp_path):
    await start(store, fake, "l1", tmp_path, mode="batch", count=3)
    for cert in fake.certificates.values():
        cert["status"] = "REVOKED"   # revoked already (e.g. earlier pass) ...
    fake.revoked_count_lag = 2       # ... but the revoked listing has not caught up yet
    run = await do_cleanup(store, fake, "l1", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert any("not all known certificates are listed as revoked" in e["message"] for e in store.events("l1"))
    order = fake.route_order()
    revoked_checks = [i for i, (n, _) in enumerate(fake.calls) if n == "cert_list"]
    assert len(revoked_checks) >= 2 * 3  # issued + confirm + revoked count, repeated until consistent
    assert order.index("policy_delete") > revoked_checks[-1]


async def test_policy_is_kept_while_known_certificates_are_not_confirmed_revoked(store, fake, tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup, "MAX_PASSES", 3)
    await start(store, fake, "l2", tmp_path, mode="batch", count=2)
    for cert in fake.certificates.values():
        cert["status"] = "REVOKED"
    fake.revoked_count_lag = 1000
    run = await do_cleanup(store, fake, "l2", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert len(fake.policies) == 1 and "policy_delete" not in fake.route_order()


async def test_unexpected_error_marks_failed_and_propagates(store, fake, tmp_path, monkeypatch):
    await start(store, fake, "u1", tmp_path, mode="single")

    async def broken(self, policy_id):
        raise RuntimeError("bug")

    monkeypatch.setattr("app.dtm.DTMClient.issued_certificates", broken)
    with pytest.raises(RuntimeError):
        await do_cleanup(store, fake, "u1", "full", tmp_path)
    assert store.get_run("u1")["cleanup_status"] == "failed"
    assert any("failed unexpectedly: RuntimeError" in e["message"] for e in store.events("u1"))


async def test_non_json_response_fails_cleanup_cleanly(store, fake, tmp_path):
    await start(store, fake, "u2", tmp_path, mode="single")
    fake.fail["cert_list"] = httpx.Response(200, text="not json at all")
    run = await do_cleanup(store, fake, "u2", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert any("non-JSON" in e["message"] for e in store.events("u2"))
    assert len(fake.policies) == 1


async def test_cleanup_log_levels(store, fake, tmp_path):
    await start(store, fake, "lv", tmp_path, mode="single")
    before = len(store.events("lv"))
    await do_cleanup(store, fake, "lv", "full", tmp_path)
    events = store.events("lv")[before:]
    assert {e["level"] for e in events} <= {"step", "success", "wait", "error", "api"}
    assert events[-1]["level"] == "success" and events[-1]["message"].startswith("Cleanup done")


# --- heartbeat --------------------------------------------------------------------------------

def spy_progress(store, monkeypatch) -> list:
    seen = []
    original = store.update_run

    def update_run(run_id, **fields):
        if "progress" in fields:
            seen.append(fields["progress"])
        return original(run_id, **fields)

    monkeypatch.setattr(store, "update_run", update_run)
    return seen


def beats(store, run_id, since=0):
    return [e for e in store.events(run_id)[since:] if e["level"] == "wait"]


async def test_heartbeat_during_slow_revoke_pass(store, fake, tmp_path, monkeypatch):
    import asyncio
    monkeypatch.setattr(cleanup, "HEARTBEAT_S", 0.05)
    monkeypatch.setattr(cleanup, "REVOKE_PARALLEL", 1)  # one at a time → a slow, observable pass
    await start(store, fake, "h1", tmp_path, mode="batch", count=6)
    ids = [c["id"] for c in fake.issued()]
    fake.revoke_plan = {ids[0]: ["timeout"]}  # one retry in pass 1
    fake.revoke_delay = 0.06
    before = len(store.events("h1"))
    seen = spy_progress(store, monkeypatch)
    started = asyncio.get_running_loop().time()
    run = await do_cleanup(store, fake, "h1", "full", tmp_path)
    elapsed = asyncio.get_running_loop().time() - started
    assert run["cleanup_status"] == "done"
    messages = [e["message"] for e in beats(store, "h1", before)]
    # at least one heartbeat per HEARTBEAT_S while the cleanup ran
    assert len(messages) >= int(elapsed / 0.05) - 2, (len(messages), elapsed)
    pass1 = [m for m in messages if m.startswith("Revoking certificates (pass 1): ")]
    assert pass1, messages
    counts = [tuple(map(int, re.search(r"(\d+) of (\d+) done – (\d+) revoked, (\d+) already revoked", m).groups()))
              for m in pass1]
    assert all(total == 6 and 0 <= done - revoked - already <= 1 and done <= 6
               for done, total, revoked, already in counts)
    assert any(done >= 1 for done, *_ in counts)
    assert [c[0] for c in counts] == sorted(c[0] for c in counts)  # monotonically increasing
    assert any(", 1 to retry" in m for m in pass1)  # the timed-out revoke is reported
    # progress mirrors the heartbeat and is cleared at the end
    revoke_progress = [p for p in seen if p and p["label"].startswith("Revoking certificates (pass 1)")]
    assert revoke_progress and all(p["total"] == 6 and 0 <= p["done"] <= 6 for p in revoke_progress)
    assert seen[-1] is None and store.get_run("h1")["progress"] is None


async def test_heartbeat_interval_does_not_include_its_own_writes(store, monkeypatch):
    """Slow database writes (a busy host) must not stretch the interval: 'sleep, then write' gave a beat every
    HEARTBEAT_S + write time – 6 instead of 10 beats here."""
    import asyncio
    import time as clock
    monkeypatch.setattr(cleanup, "HEARTBEAT_S", 0.05)
    monkeypatch.setattr(store, "update_run", lambda *_a, **_k: clock.sleep(0.03))  # blocks the loop, like SQLite
    beats = []
    with cleanup.Heartbeat(store, "x", lambda message, _kind: beats.append(message)):
        await asyncio.get_running_loop().run_in_executor(None, clock.sleep, 0.5)  # asyncio.sleep is instant here
    assert 8 <= len(beats) <= 11, len(beats)


async def test_heartbeat_phases_and_counts_are_exact(store, fake, tmp_path, monkeypatch):
    beat = cleanup.Heartbeat(store, "x", lambda *_: None)
    beat.set("Revoking certificates (pass 2)", 5)
    for outcome in ("revoked", "revoked", "already", "retry"):
        beat.count(outcome)
    assert beat.message() == "Revoking certificates (pass 2): 4 of 5 done – 2 revoked, 1 already revoked, 1 to retry"
    beat.set("Deleting division robot-x-uc01-division and verifying it is gone")
    assert beat.message() == "Deleting division robot-x-uc01-division and verifying it is gone"
    assert "to retry" not in beat.message()
    beat.set("Revoking certificates (pass 1)", 3)
    beat.count("revoked")
    assert beat.message() == "Revoking certificates (pass 1): 1 of 3 done – 1 revoked, 0 already revoked"


async def test_heartbeat_stops_and_progress_clears_after_success(store, fake, tmp_path):
    import asyncio
    await start(store, fake, "h2", tmp_path, mode="single")
    fake.revoke_delay = 0.2
    await do_cleanup(store, fake, "h2", "full", tmp_path)
    assert store.get_run("h2")["progress"] is None
    count = len(store.events("h2"))
    assert store.events("h2")[-1]["message"].startswith("Cleanup done")
    await asyncio.sleep(0.2)  # several heartbeat intervals (patched asyncio.sleep honours HEARTBEAT_S only)
    for _ in range(4):
        await asyncio.sleep(cleanup.HEARTBEAT_S)
    assert len(store.events("h2")) == count  # task cancelled: no events after the end
    assert store.get_run("h2")["progress"] is None
    assert not [t for t in asyncio.all_tasks() if "_beat" in repr(t.get_coro()) and not t.done()]


async def test_heartbeat_stops_and_progress_clears_after_failure(store, fake, tmp_path, monkeypatch):
    import asyncio
    await start(store, fake, "h3", tmp_path, mode="single")
    fake.revoke_delay = 0.15
    fake.fail["policy_delete"] = httpx.Response(400, text="<html>no</html>")
    run = await do_cleanup(store, fake, "h3", "full", tmp_path)
    assert run["cleanup_status"] == "failed" and run["progress"] is None
    count = len(store.events("h3"))
    for _ in range(4):
        await asyncio.sleep(cleanup.HEARTBEAT_S)
    assert len(store.events("h3")) == count
    assert not [t for t in asyncio.all_tasks() if "_beat" in repr(t.get_coro()) and not t.done()]


async def test_heartbeat_stops_after_unexpected_exception(store, fake, tmp_path, monkeypatch):
    import asyncio
    await start(store, fake, "h4", tmp_path, mode="single")

    async def broken(self, policy_id):
        await asyncio.sleep(cleanup.HEARTBEAT_S * 3)
        raise RuntimeError("bug")

    monkeypatch.setattr("app.dtm.DTMClient.issued_certificates", broken)
    with pytest.raises(RuntimeError):
        await do_cleanup(store, fake, "h4", "full", tmp_path)
    assert store.get_run("h4")["progress"] is None
    count = len(store.events("h4"))
    for _ in range(4):
        await asyncio.sleep(cleanup.HEARTBEAT_S)
    assert len(store.events("h4")) == count


async def test_quick_cleanup_is_not_flooded_with_heartbeats(store, fake, tmp_path):
    await start(store, fake, "h5", tmp_path, mode="single")
    before = len(store.events("h5"))
    await do_cleanup(store, fake, "h5", "full", tmp_path)
    assert len(beats(store, "h5", before)) <= 3



async def test_heartbeat_names_the_slow_issued_listing(store, fake, tmp_path, monkeypatch):
    from tests.fakedtm import _real_sleep
    monkeypatch.setattr(cleanup, "HEARTBEAT_S", 0.03)
    await start(store, fake, "h6", tmp_path, mode="batch", count=2)
    original = fake._list_certs

    async def slow(request):
        await _real_sleep(0.15)
        return original(request)

    fake.router.routes["cert_list"].side_effect = fake._wrap("cert_list", slow)
    before = len(store.events("h6"))
    run = await do_cleanup(store, fake, "h6", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    messages = [e["message"] for e in beats(store, "h6", before)]
    loading = [m for m in messages if m.startswith("Loading the list of issued certificates from DTM")]
    assert len(loading) >= 3, messages
    stale = [m for m in messages if m.startswith("Checking that no batch job")]
    assert len(stale) <= 1, messages  # the job check is quick; the slow part is reported as listing


SHORT_PHASES = {"Preparing", "Checking jobs", "Listing certs", "Revoking", "Confirming", "Waiting for DTM",
                "Other policies", "Deleting policy", "Deleting profile", "Deleting passcode", "Deleting credential",
                "Deleting auth", "Deleting division", "Deleting trust anchor", "Removing minions",
                "Aborting deployment"}


async def test_heartbeat_mirrors_a_short_phase_name(store, fake, tmp_path, monkeypatch):
    """Every progress the runs list may show carries a short phase name from the agreed set, next to
    the full label (the tooltip)."""
    monkeypatch.setattr(cleanup, "HEARTBEAT_S", 0.001)
    await start(store, fake, "h1", tmp_path, mode="batch", count=3)
    fake.revoke_delay = 0.01
    seen = []
    original = store.update_run

    def spy(run_id, **fields):
        if fields.get("progress"):
            seen.append(fields["progress"])
        return original(run_id, **fields)
    monkeypatch.setattr(store, "update_run", spy)
    run = await do_cleanup(store, fake, "h1", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert seen and all(p["short"] in SHORT_PHASES and p["label"] for p in seen), {p["short"] for p in seen}
    assert "Revoking" in {p["short"] for p in seen}
    assert store.get_run("h1")["progress"] is None  # cleared at the end


def test_short_names_cover_every_credential_kind():
    from app.dtm import AUTH_KINDS
    assert set(cleanup.AUTH_SHORT) == set(AUTH_KINDS) | {"auth_ca"} and set(cleanup.AUTH_SHORT.values()) <= SHORT_PHASES
    assert list(cleanup.AUTH_SHORT)[-1] == "auth_policy"  # trust anchor and credentials before their policy


def test_heartbeat_keeps_the_last_short_name():
    beat = cleanup.Heartbeat(None, "x", lambda *a: None)
    assert beat.short == "Preparing"
    beat.set("Deleting certificate policy p", short="Deleting policy")
    beat.set("Something without a short name")
    assert (beat.phase, beat.short) == ("Something without a short name", "Deleting policy")
