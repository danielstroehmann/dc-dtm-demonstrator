"""Web UI runs: the certificates are ordered by hand in the DTM portal, so the rollback must find
what the app never recorded – portal batch jobs under the run's policy, and certificates with the
run's device names that were ordered under another policy by mistake. Never touch anything else."""

import httpx
import pytest

from app import cleanup, evergreen
from tests.fakedtm import FakeDTM
from tests.integration.test_cleanup import do_cleanup
from tests.integration.test_uc01_flow import start

OTHER_POLICY = "IOT_someone-elses-policy"


def issue(fake: FakeDTM, policy_id: str, cn: str, account: str | None = None) -> dict:
    record, _cert, _key = fake._new_certificate(policy_id, cn)
    if account:
        record["account_id"] = account
    return record


def cn_searches(fake: FakeDTM) -> list[str]:
    return [r.url.params["common_name"] for r in fake.requests if "common_name" in r.url.params]


async def portal_run(store, fake, tmp_path, run_id="p1", mode="batch", count=3):
    run = await start(store, fake, run_id, tmp_path, variant="webui", mode=mode, count=count)
    assert run["status"] == "waiting", run["error"]
    (policy,) = store.objects(run_id, "policy")
    fake.calls.clear()
    fake.requests.clear()
    return policy["dtm_id"], evergreen.common_names(run_id, mode, count, "uc01")


def portal_job(fake: FakeDTM, job_id: str, policy_id: str, status: str, steps=(), names=(), account=None) -> dict:
    job = {"id": job_id, "name": "typed in the portal", "policy_id": policy_id, "status": status, "steps": list(steps),
           "approved": False, "issued": [], "names": list(names)}
    if account:
        job["account_id"] = account
    fake.jobs[job_id] = job
    return job


async def test_portal_job_waiting_for_approval_is_rejected_before_revoking(store, fake, tmp_path):
    policy_id, names = await portal_run(store, fake, tmp_path)
    portal_job(fake, "pj-wait", policy_id, "pending_approval", names=names)
    issued = [issue(fake, policy_id, n) for n in names[:2]]  # ordered in the portal, approved earlier
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert fake.jobs["pj-wait"]["status"] == "rejected"
    order = fake.route_order()
    assert order.index("reject") < order.index("revoke")  # rejected first – it cannot issue any more
    assert all(c["status"] == "REVOKED" for c in issued)
    messages = [e["message"] for e in store.events("p1")]
    assert "Found 1 batch job(s) started in the DTM portal under the run's policy" in messages
    assert fake.violations == []


async def test_portal_job_still_issuing_is_waited_for(store, fake, tmp_path):
    policy_id, names = await portal_run(store, fake, tmp_path)
    portal_job(fake, "pj-run", policy_id, "in_progress", steps=["in_progress", "in_progress", "completed"], names=names)
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert fake.jobs["pj-run"]["status"] == "completed" and len(fake.jobs["pj-run"]["issued"]) == 3
    # the certificates the job issued after the cleanup started are revoked, too
    assert all(fake.certificates[r["id"]]["status"] == "REVOKED" for r, _c, _k in fake.jobs["pj-run"]["issued"])
    assert fake.issued() == []
    assert any("Waiting for batch job pj-run" in e["message"] for e in store.events("p1"))


async def test_jobs_of_other_policies_or_accounts_are_untouched(store, fake, tmp_path):
    policy_id, names = await portal_run(store, fake, tmp_path)
    portal_job(fake, "pj-other-policy", OTHER_POLICY, "pending_approval")
    portal_job(fake, "pj-other-account", policy_id, "pending_approval", account="another-account")
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert fake.jobs["pj-other-policy"]["status"] == fake.jobs["pj-other-account"]["status"] == "pending_approval"
    assert fake.names("reject") == [] and fake.names("job") == []
    assert not any("started in the DTM portal" in e["message"] for e in store.events("p1"))


async def test_stray_under_another_policy_is_revoked_foreign_and_other_names_are_not(store, fake, tmp_path):
    policy_id, names = await portal_run(store, fake, tmp_path)
    stray = issue(fake, OTHER_POLICY, names[1])
    foreign = issue(fake, OTHER_POLICY, names[1], account="another-account")  # same CN, other account
    unrelated = issue(fake, OTHER_POLICY, "robot-p10-uc01-batch-0002")  # another run's device
    own = issue(fake, policy_id, names[0])
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert stray["status"] == own["status"] == "REVOKED"
    assert foreign["status"] == unrelated["status"] == "ISSUED"
    assert sorted(cn_searches(fake)) == sorted(names)  # ≤ 20 devices: every name, nothing else
    revoked = fake.names("revoke")
    assert stray["id"] in revoked and revoked.count(own["id"]) == 1  # own policy: by revoke_all only
    assert any("issued under another policy" in e["message"] for e in store.events("p1"))


async def test_clean_portal_run_logs_nothing_found(store, fake, tmp_path):
    await portal_run(store, fake, tmp_path, mode="single", count=1)
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert cn_searches(fake) == ["robot-p1-uc01-single-0001"]
    assert "No certificate with the run's device names outside its policy" in [e["message"] for e in store.events("p1")]


async def test_large_batch_sample_only_when_clean(store, fake, tmp_path):
    await portal_run(store, fake, tmp_path, count=25)
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done"
    names = evergreen.common_names("p1", "batch", 25, "uc01")
    sample = names[:cleanup.STRAY_SAMPLE] + names[-cleanup.STRAY_SAMPLE:]
    assert cn_searches(fake) == sample  # 20 lookups, not 25 – the middle is skipped


async def test_large_batch_full_search_once_the_sample_finds_a_stray(store, fake, tmp_path):
    _policy_id, names = await portal_run(store, fake, tmp_path, count=25)
    in_sample, in_middle = issue(fake, OTHER_POLICY, names[-1]), issue(fake, OTHER_POLICY, names[12])
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done"
    assert in_sample["status"] == in_middle["status"] == "REVOKED"
    assert sorted(cn_searches(fake)) == sorted(names)  # each name once: sample + the rest
    assert len(cn_searches(fake)) == 25


async def test_large_batch_stray_only_in_the_middle_is_not_searched(store, fake, tmp_path):
    """Documents the trade-off (DTM load): a stray that only sits in the unsampled middle of a large
    batch is not found by this cleanup."""
    _policy_id, names = await portal_run(store, fake, tmp_path, count=25)
    middle = issue(fake, OTHER_POLICY, names[12])
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done"
    assert middle["status"] == "ISSUED" and names[12] not in cn_searches(fake)


async def test_api_runs_never_search_by_name(store, fake, tmp_path):
    await start(store, fake, "a1", tmp_path, mode="batch", count=2)
    stray = issue(fake, OTHER_POLICY, "robot-a1-uc01-batch-0001")
    fake.requests.clear()
    run = await do_cleanup(store, fake, "a1", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert cn_searches(fake) == [] and stray["status"] == "ISSUED"
    assert fake.names("jobs_list") == []  # nobody orders in the portal for an API run – no job list either


async def test_stray_revoke_that_keeps_failing_fails_the_cleanup(store, fake, tmp_path):
    policy_id, names = await portal_run(store, fake, tmp_path)
    stray = issue(fake, OTHER_POLICY, names[0])
    fake.revoke_plan[stray["id"]] = ["status503"] * 3
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert fake.names("revoke").count(stray["id"]) == 3 and stray["status"] == "ISSUED"
    assert any(f"could not revoke {names[0]}" in e["message"] for e in store.events("p1"))
    assert fake.policies  # stopped before the policy was deleted – nothing left half done


async def test_stray_revoke_recovers_within_three_attempts(store, fake, tmp_path):
    _policy_id, names = await portal_run(store, fake, tmp_path)
    stray = issue(fake, OTHER_POLICY, names[0])
    fake.revoke_plan[stray["id"]] = ["status503", "status502"]
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert stray["status"] == "REVOKED" and fake.names("revoke").count(stray["id"]) == 3


# --- the client filters itself: DTM ignores a policy filter on jobs, and lists span policies ---------

async def test_client_filters_jobs_and_certificates_by_account(fake):
    portal_job(fake, "j1", "IOT_a", "completed")
    portal_job(fake, "j2", "IOT_b", "completed")
    portal_job(fake, "j3", "IOT_a", "completed", account="another-account")
    mine = issue(fake, "IOT_x", "robot-z1-uc01-single-0001")
    issue(fake, "IOT_y", "robot-z1-uc01-single-0001", account="another-account")
    issue(fake, "IOT_x", "robot-z1-uc01-single-00010")
    client = fake.client()
    try:
        assert [j["id"] for j in await client.batch_jobs_of({"IOT_a"})] == ["j1"]
        assert await client.batch_jobs_of(set()) == []
        assert [c["id"] for c in await client.certificates_named("robot-z1-uc01-single-0001")] == [mine["id"]]
    finally:
        await client.aclose()
    assert fake.violations == []


@pytest.mark.parametrize("count", [101, 250])
async def test_jobs_list_is_paged(fake, count):
    for i in range(count):
        portal_job(fake, f"j{i:03d}", "IOT_a", "completed")
    client = fake.client()
    try:
        assert len(await client.batch_jobs_of({"IOT_a"})) == count
    finally:
        await client.aclose()
    assert len(fake.names("jobs_list")) == count // 100 + 1


async def test_jobs_list_error_fails_the_cleanup(store, fake, tmp_path):
    await portal_run(store, fake, tmp_path)
    fake.fail["jobs_list"] = httpx.Response(500, json={"error": "down"})
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "failed" and fake.policies and fake.names("revoke") == []


async def test_stray_search_leaves_the_runs_own_policies_to_revoke_all(store, fake, tmp_path):
    """Called directly (revoke_all normally ran before): certificates under the run's own policies
    are not strays – only those under other policies are revoked here."""
    policy_id, names = await portal_run(store, fake, tmp_path)
    own, stray = issue(fake, policy_id, names[0]), issue(fake, OTHER_POLICY, names[0])
    events = []
    client = fake.client()
    try:
        await cleanup.revoke_portal_strays(client, store.get_run("p1"), {policy_id}, lambda m, level="step": events.append(m))
    finally:
        await client.aclose()
    assert own["status"] == "ISSUED" and stray["status"] == "REVOKED"
    assert fake.names("revoke") == [stray["id"]]



async def test_enrollment_runs_never_list_jobs_or_search(store, enroll_net, cmp_openssl, tmp_path):
    from tests.integration import test_uc03_flow
    run = await test_uc03_flow.start(store, enroll_net, "e1", tmp_path, count=1)
    assert run["status"] == "completed", run["error"]
    enroll_net.calls.clear()
    enroll_net.requests.clear()
    run = await do_cleanup(store, enroll_net, "e1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("e1")[-5:]
    assert enroll_net.names("jobs_list") == [] and cn_searches(enroll_net) == []


async def test_webui_run_that_failed_at_policy_creation_does_not_search(store, fake, tmp_path):
    fake.fail["policy_create"] = httpx.Response(400, json={"errors": [{"message": "nope"}]})
    run = await start(store, fake, "f1", tmp_path, variant="webui", mode="batch", count=2)
    assert run["status"] == "failed" and store.objects("f1", "policy") == []
    del fake.fail["policy_create"]
    # another run (same ID earlier, or a person) owns certificates with these names
    theirs = [issue(fake, OTHER_POLICY, n) for n in evergreen.common_names("f1", "batch", 2, "uc01")]
    fake.calls.clear()
    fake.requests.clear()
    run = await do_cleanup(store, fake, "f1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("f1")[-5:]
    assert cn_searches(fake) == [] and fake.names("jobs_list") == [] and fake.names("revoke") == []
    assert all(c["status"] == "ISSUED" for c in theirs)


async def test_webui_run_that_never_reached_the_portal_step_does_not_search(store, fake, tmp_path):
    policy_id, names = await portal_run(store, fake, tmp_path)
    store.update_run("p1", status="failed")  # e.g. failed while preparing the upload file
    theirs = issue(fake, OTHER_POLICY, names[0])
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert cn_searches(fake) == [] and theirs["status"] == "ISSUED"
    assert fake.names("jobs_list")  # its own policy is still checked for portal jobs


async def test_retried_cleanup_after_policy_deletion_still_excludes_the_own_policy(store, fake, tmp_path):
    policy_id, names = await portal_run(store, fake, tmp_path)
    fake.fail["division_delete"] = httpx.Response(500, json={"error": "down"})
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "failed" and policy_id not in fake.policies  # policy already gone
    del fake.fail["division_delete"]
    stray = issue(fake, OTHER_POLICY, names[0])
    leftover = issue(fake, policy_id, names[1])  # listed under the deleted own policy
    fake.requests.clear()
    fake.calls.clear()
    run = await do_cleanup(store, fake, "p1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert sorted(cn_searches(fake)) == sorted(names)  # still searched – the deleted policy counts as own
    assert stray["status"] == "REVOKED" and leftover["status"] == "ISSUED"
    assert fake.names("revoke") == [stray["id"]]


@pytest.mark.parametrize("created_at", ["2020-01-01T00:00:00Z", None, "", "yesterday"])
async def test_older_or_undated_certificate_with_the_runs_name_stays(store, fake, tmp_path, created_at):
    _policy_id, names = await portal_run(store, fake, tmp_path)
    older = issue(fake, OTHER_POLICY, names[0])
    older["created_at"] = created_at  # issued before this run existed (an earlier run with this ID)
    newer = issue(fake, OTHER_POLICY, names[1])
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert older["status"] == "ISSUED" and newer["status"] == "REVOKED"
    assert fake.names("revoke") == [newer["id"]]


async def test_certificate_from_the_runs_first_second_counts(store, fake, tmp_path):
    _policy_id, names = await portal_run(store, fake, tmp_path)
    stray = issue(fake, OTHER_POLICY, names[0])
    stray["created_at"] = store.get_run("p1")["created_at"].replace("+00:00", "Z")  # same second
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done" and stray["status"] == "REVOKED"


def _relative(store, run_id: str, minutes: float, zone: str = "Z") -> str:
    """A DTM-style timestamp relative to the run's start (zone "" = no time zone, as DTM might send)."""
    from datetime import datetime, timedelta
    started = datetime.fromisoformat(store.get_run(run_id)["created_at"])
    return (started + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S") + zone


async def test_certificate_date_without_time_zone_is_utc(store, fake, tmp_path):
    _policy_id, names = await portal_run(store, fake, tmp_path)
    naive = issue(fake, OTHER_POLICY, names[0])
    naive["created_at"] = _relative(store, "p1", 1, zone="")  # e.g. "2026-10-25T07:32:33"
    old_naive = issue(fake, OTHER_POLICY, names[1])
    old_naive["created_at"] = _relative(store, "p1", -60, zone="")
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)  # no TypeError
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert naive["status"] == "REVOKED" and old_naive["status"] == "ISSUED"


@pytest.mark.parametrize("minutes,revoked", [(-3, True), (-4.9, True), (-10, False), (-60 * 24, False)])
async def test_clock_skew_tolerance_before_the_run_start(store, fake, tmp_path, minutes, revoked):
    assert cleanup.CLOCK_SKEW.total_seconds() == 300
    _policy_id, names = await portal_run(store, fake, tmp_path)
    cert = issue(fake, OTHER_POLICY, names[0])
    cert["created_at"] = _relative(store, "p1", minutes)
    run = await do_cleanup(store, fake, "p1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done", store.events("p1")[-5:]
    assert cert["status"] == ("REVOKED" if revoked else "ISSUED")
