"""NL (one.nl.digicert.com): every run creates its own certificate profile, records it and the full
rollback deletes it again – DTM there allows that once no policy uses the profile. US keeps the
shared profiles (tests/integration/test_shared_profiles.py). See dtm.PLATFORMS."""

import pytest

from app import cleanup, dtm, evergreen, snippets
from app.dtm import DTMError
from tests.fakedtm import ACCOUNT_ID, HOST, NL_HOST, RSA_CA_ID, FakeDTM, renews_anytime
from tests.integration import test_uc01_flow, test_uc02_flow, test_uc03_flow, test_uc04_flow
from tests.integration.test_cleanup import do_cleanup
from tests.integration.test_replayable_steps import assert_replayable


@pytest.fixture
def fake() -> FakeDTM:  # this module runs against the NL platform (also for enroll_net, cmp_openssl …)
    return FakeDTM(host=NL_HOST)


RSA = {"ca_id": RSA_CA_ID, "ca_name": "Fake RSA ICA", "key_type": "RSA_2048"}
# (flow module, use case, overrides, the purpose's settings the run's own profile must carry)
CASES = {
    "uc01-single": (test_uc01_flow, "uc01", {}, dtm.PROFILE_EVERGREEN),
    "uc01-batch": (test_uc01_flow, "uc01", {"mode": "batch", "count": 2, "approval": True}, dtm.PROFILE_EVERGREEN),
    "uc02-batch": (test_uc02_flow, "uc02", {"mode": "batch", "count": 2}, dtm.PROFILE_EVERGREEN),
    "uc03-est": (test_uc03_flow, "uc03", {"protocol": "est", "count": 1}, dtm.PROFILE_EVERGREEN),
    "uc03-rest-cert": (test_uc03_flow, "uc03", {"protocol": "rest", "auth": "certificate", "count": 1},
                       dtm.PROFILE_EVERGREEN),
    "uc03-scep": (test_uc03_flow, "uc03", {"protocol": "scep", "count": 1, **RSA}, dtm.PROFILE_EVERGREEN),
    "uc03-cmpv2": (test_uc03_flow, "uc03", {"protocol": "cmpv2", "count": 1}, dtm.PROFILE_EVERGREEN_CMP),
    "uc04-est": (test_uc04_flow, "uc04", {"protocol": "est"}, dtm.PROFILE_RENEWAL),
    "uc04-cmpv2": (test_uc04_flow, "uc04", {"protocol": "cmpv2"}, dtm.PROFILE_RENEWAL_CMP),
}


def settings(profile: dict) -> tuple:
    """The fake's own reading of a profile: validity, bare public key, renewal at any time."""
    entries = {e["key"]: e["value"] for e in profile["body"]}
    return (entries["validity.duration_unit"], int(entries["validity.duration_value"]),
            bool(profile.get("allow_bare_public_key")), renews_anytime(profile))


async def nl_run(store, fake, tmp_path, case: str, run_id: str = "n1"):
    flow, _uc, overrides, _spec = CASES[case]
    run = await flow.start(store, fake, run_id, tmp_path, dtm_host=NL_HOST, **overrides)
    assert run["status"] == "completed", (case, run["error"])
    return run


@pytest.mark.parametrize("case", list(CASES))
async def test_nl_run_creates_records_and_rolls_back_its_own_profile(store, fake, enroll_net, cmp_openssl,
                                                                    scep_client, tmp_path, case):
    _flow, use_case, _overrides, spec = CASES[case]
    run = await nl_run(store, fake, tmp_path, case)
    name = f"robot-n1-{use_case}-profile"
    (ledger,) = store.objects("n1", "profile")
    assert ledger["name"] == name
    profile = fake.profile(name)
    assert profile["id"] == ledger["dtm_id"] == run["result"]["api_variables"]["PROFILE_ID"]
    assert (profile["status"], profile["account_id"]) == ("ACTIVE", ACCOUNT_ID)
    unit, value, bare, anytime = settings(profile)
    assert (unit, value, bare) == (spec.unit, spec.value, spec.bare_key)
    assert anytime or not spec.renew_anytime  # renewal at any time is required for UC-4 (copied as is otherwise)
    (policy_obj,) = store.objects("n1", "policy")
    assert fake.policies[policy_obj["dtm_id"]]["certificate_profile_id"] == profile["id"]
    # no shared profile on NL – not looked up, not created
    assert all(not p["name"].startswith(("robot-evergreen", "robot-renewal")) for p in fake.profiles)
    assert fake.names("profile_enable") == [] and fake.names("profile_undelete") == []
    # the copy comes from the account's client profile (its template)
    assert fake.created_profiles[-1]["certificate_template_id"] == "tpl-client"
    assert any(e["message"].startswith(f"Creating certificate profile {name}") for e in store.events("n1"))

    cmp_openssl.sync_to_dtm()
    scep_client.sync_to_dtm()
    fake.calls.clear()
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("n1")[-5:]
    assert profile["status"] == "DELETED" and store.objects("n1", "profile") == []
    order = [n for n in fake.route_order() if n.endswith("_delete")]
    # policies first (DTM refuses to delete a used profile), then the profile, then auth objects/division
    assert order.index("policy_delete") < order.index("profile_delete") < order.index("division_delete")
    assert all(order.index("profile_delete") < order.index(n) for n in order if n.startswith(("passcode", "auth_")))
    assert order.count("profile_delete") == 1 and fake.violations == []


async def test_certificates_only_cleanup_keeps_the_profile(store, fake, tmp_path):
    await nl_run(store, fake, tmp_path, "uc01-single")
    (ledger,) = store.objects("n1", "profile")
    run = await do_cleanup(store, fake, "n1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done"
    assert fake.profile("robot-n1-uc01-profile")["status"] == "ACTIVE" and fake.names("profile_delete") == []
    assert store.objects("n1", "profile") == [ledger]  # the full rollback later still deletes it
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "done" and fake.profile("robot-n1-uc01-profile")["status"] == "DELETED"


async def test_discover_finds_an_unrecorded_profile(store, fake, tmp_path, monkeypatch):
    """The create succeeded in DTM, but the run never recorded it (crash): found by its exact name."""
    original = store.add_object
    monkeypatch.setattr(store, "add_object", lambda run_id, kind, *a: None if kind == "profile" else
                        original(run_id, kind, *a))
    await nl_run(store, fake, tmp_path, "uc01-single")
    monkeypatch.setattr(store, "add_object", original)
    assert store.objects("n1", "profile") == []
    other = dict(fake.profile("robot-n1-uc01-profile"), id="profile-other-run", name="robot-n10-uc01-profile")
    fake.profiles.append(other)  # a similar name of another run is not ours
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("n1")[-5:]
    assert fake.profile("robot-n1-uc01-profile")["status"] == "DELETED" and other["status"] == "ACTIVE"
    assert any("Found unrecorded profile robot-n1-uc01-profile" in e["message"] for e in store.events("n1"))


async def test_mismatching_run_profile_is_deleted_and_the_run_fails(store, fake, tmp_path):
    fake.template_validity_cap["tpl-client"] = ("years", 1)  # the template caps the validity silently
    run = await test_uc01_flow.start(store, fake, "n2", tmp_path, dtm_host=NL_HOST)
    assert run["status"] == "failed" and "did not accept the settings" in run["error"]
    assert "the profile was deleted" in run["error"]
    created = fake.profile("robot-n2-uc01-profile")
    assert created["status"] == "DELETED" and fake.names("profile_delete") == [created["id"]]
    assert fake.policies == {}  # no policy on a wrong profile
    run = await do_cleanup(store, fake, "n2", "full", tmp_path)
    assert run["cleanup_status"] == "done" and fake.divisions == {}


async def test_nl_reproducible_steps_create_the_profile_and_capture_its_id(store, fake, enroll_net, cmp_openssl,
                                                                          tmp_path):
    for run_id, case in (("r1", "uc01-single"), ("r3", "uc03-cmpv2"), ("r4", "uc04-cmpv2")):
        run = await nl_run(store, fake, tmp_path, case, run_id)
        cmp_openssl.sync_to_dtm()
        assert_replayable(run, fake)
        calls = run["result"]["api_calls"]
        (step,) = [c for c in calls if c["path"] == dtm.PROFILES]
        assert (step["method"], step["phase"]) == ("POST", "setup")
        assert step["purpose"].startswith("Create the certificate profile for this run (")
        assert step["spec"]["capture"] == {"var": "PROFILE_ID", "jq": ".id", "ps": "$r.id"}
        body = step["spec"]["json"]
        assert body["name"] == "{RUN_NAME}-profile" and body["account_id"] == "{DTM_ACCOUNT_ID}"
        # the recorded body is what the client posted, once the variables are filled in
        posted = fake.created_profiles[-1]
        variables = run["result"]["api_variables"]
        filled = snippets.tokenize(posted, variables["RUN_NAME"]) | {"account_id": "{DTM_ACCOUNT_ID}"}
        assert body == filled
        # the policy step uses the captured ID
        assert calls.index(step) < next(i for i, c in enumerate(calls) if c["method"] == "POST"
                                        and c["path"].endswith("certificate-policy"))


async def test_nl_delete_refused_while_a_policy_uses_the_profile(fake):
    """The fake models NL: a profile in use cannot be deleted; once its policy is gone it can."""
    from dataclasses import replace
    spec = replace(dtm.PROFILE_EVERGREEN, name="robot-d1-uc01-profile")
    client = fake.client()
    try:
        profile_id = await client.create_run_profile(spec, await client.run_profile_body(spec))
        fake.policies["IOT_x"] = {"id": "IOT_x", "certificate_profile_id": profile_id}
        with pytest.raises(DTMError, match="referenced by a certificate management policy"):
            await client.delete_profile(profile_id)
        assert await client.profile_ids(spec.name) == [profile_id]
        del fake.policies["IOT_x"]
        await client.delete_profile(profile_id)
        assert await client.profile_ids(spec.name) == []
    finally:
        await client.aclose()
    assert fake.profile(spec.name)["status"] == "DELETED"


# --- US stays shared; other hosts are refused ---------------------------------------------------------

async def test_us_run_uses_the_shared_profile_and_never_deletes_it(store, tmp_path):
    us = FakeDTM(host=HOST)
    run = await test_uc01_flow.start(store, us, "u1", tmp_path)
    assert run["status"] == "completed"
    assert store.objects("u1", "profile") == [] and us.profile("robot-u1-uc01-profile") is None
    shared = us.profile(dtm.PROFILE_EVERGREEN.name)
    assert shared["status"] == "ACTIVE" and run["result"]["api_variables"]["PROFILE_ID"] == shared["id"]
    (step,) = [c for c in run["result"]["api_calls"] if c["path"] == dtm.PROFILES]
    assert step["method"] == "GET"  # the shared lookup, not a create
    # a profile with the per-run name (e.g. from elsewhere) is never adopted on US
    us.profiles.append(dict(shared, id="profile-lookalike", name="robot-u1-uc01-profile"))
    run = await do_cleanup(store, us, "u1", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert us.names("profile_delete") == [] and shared["status"] == "ACTIVE"
    assert us.profile("robot-u1-uc01-profile")["status"] == "ACTIVE"


async def test_us_refuses_to_delete_a_profile_a_deleted_policy_used(store, tmp_path):
    us = FakeDTM(host=HOST)
    run = await test_uc01_flow.start(store, us, "u2", tmp_path)
    assert run["status"] == "completed"
    await do_cleanup(store, us, "u2", "full", tmp_path)
    assert us.policies == {}
    client = us.client()
    try:
        with pytest.raises(DTMError):  # why US needs shared profiles
            await client.delete_profile(us.profile(dtm.PROFILE_EVERGREEN.name)["id"])
    finally:
        await client.aclose()


async def test_unsupported_host_fails_the_run_but_never_blocks_its_rollback(store, tmp_path):
    other = FakeDTM(host="dtm.example.com")
    run = await test_uc01_flow.start(store, other, "x1", tmp_path, dtm_host="dtm.example.com")
    assert run["status"] == "failed" and "unsupported DTM platform dtm.example.com" in run["error"]
    assert other.created_profiles == [] and other.policies == {}
    run = await do_cleanup(store, other, "x1", "full", tmp_path)  # discover must not raise on the host
    assert run["cleanup_status"] == "done", store.events("x1")[-5:]
    assert other.divisions == {}


def test_profile_mode():
    assert dtm.profile_mode(NL_HOST) == "per_run" and dtm.profile_mode(HOST) == "shared"
    for host in ("dtm.example.com", "one.digicert.com.evil", "", "ONE.DIGICERT.COM"):
        with pytest.raises(DTMError, match="unsupported DTM platform"):
            dtm.profile_mode(host)
    assert cleanup.PLATFORMS is dtm.PLATFORMS
    assert evergreen.prefix("n1", "uc01") + "-profile" == "robot-n1-uc01-profile"


async def test_nl_renewal_profile_allows_renewal_even_if_the_base_does_not(store, fake, enroll_net, tmp_path):
    base = next(p for p in fake.profiles if p["id"] == "profile-client")
    for entry in base["body"]:
        if entry["key"] == "renewal_settings.renew_valid_cert":
            entry["value"] = "dont_allow"
    assert not renews_anytime(base)
    run = await nl_run(store, fake, tmp_path, "uc04-est")
    assert renews_anytime(fake.profile("robot-n1-uc04-profile"))
    run = await test_uc04_flow.renew(store, "n1", tmp_path)  # DTM accepts the renewal on the run's profile
    assert run["status"] == "completed" and len(run["result"]["renewals"]) == 1, store.events("n1")[-3:]


async def test_profile_of_a_run_that_failed_at_policy_creation_is_rolled_back(store, fake, tmp_path):
    import httpx
    fake.fail["policy_create"] = httpx.Response(400, json={"errors": [{"message": "nope"}]})
    run = await test_uc01_flow.start(store, fake, "n3", tmp_path, dtm_host=NL_HOST)
    assert run["status"] == "failed" and [o["kind"] for o in store.objects("n3", "profile")] == ["profile"]
    run = await do_cleanup(store, fake, "n3", "full", tmp_path)
    assert run["cleanup_status"] == "done" and fake.profile("robot-n3-uc01-profile")["status"] == "DELETED"


# --- deleting the run's profile is idempotent; a refusal is a failed cleanup with the reason ------------

async def test_rollback_after_the_profile_was_deleted_in_the_portal(store, fake, tmp_path):
    await nl_run(store, fake, tmp_path, "uc01-single")
    profile = fake.profile("robot-n1-uc01-profile")
    fake.delete_profile(profile)  # someone deleted it meanwhile – DTM answers the delete with 404
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("n1")[-5:]
    assert fake.names("profile_delete") == [profile["id"]] and profile["status"] == "DELETED"
    assert store.objects("n1", "profile") == [] and fake.divisions == {}


async def test_rollback_when_dtm_answers_400_for_an_already_deleted_profile(store, fake, tmp_path):
    import httpx
    await nl_run(store, fake, tmp_path, "uc01-single")
    profile = fake.profile("robot-n1-uc01-profile")
    fake.delete_profile(profile)
    fake.fail["profile_delete"] = httpx.Response(400, json={"errors": [{"message": "profile is already deleted"}]})
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("n1")[-5:]


async def test_retry_after_a_cleanup_that_failed_after_the_profile_delete(store, fake, tmp_path):
    import httpx
    await nl_run(store, fake, tmp_path, "uc01-single")
    fake.fail["division_delete"] = httpx.Response(500, json={"error": "down"})
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert fake.profile("robot-n1-uc01-profile")["status"] == "DELETED"
    del fake.fail["division_delete"]
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("n1")[-5:]
    assert fake.divisions == {} and fake.names("profile_delete").count(
        fake.profile("robot-n1-uc01-profile")["id"]) == 1  # not deleted twice – it left the ledger


async def test_profile_still_in_use_fails_the_cleanup_with_the_reason(store, fake, tmp_path):
    await nl_run(store, fake, tmp_path, "uc01-single")
    profile = fake.profile("robot-n1-uc01-profile")
    (own_policy,) = fake.policies.values()  # another policy (not the run's) uses the run's profile
    fake.policies["IOT_someone-else"] = dict(own_policy, id="IOT_someone-else", name="someone-elses-policy")
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert profile["status"] == "ACTIVE" and store.objects("n1", "profile") != []
    failure = next(e["message"] for e in store.events("n1") if e["message"].startswith("Cleanup failed"))
    assert f"profile {profile['id']} still exists after delete" in failure
    assert "referenced by a certificate management policy" in failure
    assert fake.divisions  # stopped before the division – retried later
    del fake.policies["IOT_someone-else"]
    run = await do_cleanup(store, fake, "n1", "full", tmp_path)
    assert run["cleanup_status"] == "done" and profile["status"] == "DELETED"


async def test_mismatch_and_failing_delete_keep_the_settings_message(store, fake, tmp_path):
    import httpx
    fake.template_validity_cap["tpl-client"] = ("years", 1)
    fake.fail["profile_delete"] = httpx.Response(500, json={"errors": [{"message": "backend down"}]})
    run = await test_uc01_flow.start(store, fake, "n4", tmp_path, dtm_host=NL_HOST)
    assert run["status"] == "failed"
    assert run["error"].startswith("DTM did not accept the settings of robot-n4-uc01-profile (5 years)")
    assert "; deleting the profile failed: " in run["error"] and "the profile was deleted" not in run["error"]
    assert fake.profile("robot-n4-uc01-profile")["status"] == "ACTIVE" and fake.policies == {}
    # the rollback finds the left-over profile by its name and deletes it
    del fake.fail["profile_delete"]
    run = await do_cleanup(store, fake, "n4", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("n4")[-5:]
    assert fake.profile("robot-n4-uc01-profile")["status"] == "DELETED"
