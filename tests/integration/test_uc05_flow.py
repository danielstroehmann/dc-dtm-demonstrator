"""UC-5 – passcode-bound device certificates: the factory provisions one one-time passcode per device,
bound to the device's common name (usage limit 1, registered value), and the device enrolls in the
field via EST or CMPv2 – against the stateful fake DTM, which enforces both rules like DTM does
(verified live): usage limit first, every request counts as a use, then the registered common name."""

import json

import pytest

from app import dtm, enrollment, evergreen, snippets
from tests.fakedtm import ACCOUNT_ID, HOST, NL_HOST, FakeDTM
from tests.integration.test_cleanup import do_cleanup
from tests.integration.test_uc01_flow import assert_rates
from tests.integration.test_uc03_flow import params as uc03_params

UC = "uc05"


def params(**overrides) -> dict:
    base = {"protocol": "est", "auth": "passcode", "mode": "single", "count": 1, "checks": True}
    return uc03_params(**(base | overrides))


async def start(store, fake: FakeDTM, run_id: str, tmp_path, **overrides):
    store.create_run(run_id, UC, params(dtm_host=fake.host, **overrides))
    client = fake.client(on_call=lambda msg: store.add_event(run_id, f"API {msg}", "api"))
    try:
        await enrollment.run(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


def passcodes(fake: FakeDTM, prefix: str) -> dict[str, dict]:
    return {o["name"]: o for o in fake.auth_objects["passcode"].values() if o["name"].startswith(prefix)}


def batch(count: int) -> dict:
    return {"mode": "batch", "count": count} if count > 1 else {}


@pytest.mark.parametrize("checks", [True, False])
@pytest.mark.parametrize("count", [1, 3])
@pytest.mark.parametrize("protocol", ["est", "cmpv2"])
async def test_uc05_provisions_bound_passcodes_and_enrolls_in_the_field(store, enroll_net, cmp_openssl, tmp_path,
                                                                        protocol, count, checks):
    fake = enroll_net
    run = await start(store, fake, "u5", tmp_path, protocol=protocol, checks=checks, **batch(count))
    assert run["status"] == "completed", run["error"]
    r = run["result"]
    names = evergreen.common_names("u5", protocol, count, UC)
    assert [c["common_name"] for c in r["certificates"]] == names and r["certificate_total"] == count
    assert r["bound_cn"] == names[0]
    # one passcode per device, bound to exactly that device's name, each used exactly once
    own = passcodes(fake, "robot-u5-uc05-passcode-0")
    assert sorted(own) == [f"robot-u5-uc05-passcode-{i:04d}" for i in range(1, count + 1)]
    for i, cn in enumerate(names, 1):
        record = own[f"robot-u5-uc05-passcode-{i:04d}"]
        assert record["body"]["usage_limit"] == 1 and record["registered_cn"] == cn
        assert record["body"]["registered_values"] == [
            {"certificate_field": "subject.common_name", "matcher": "equals", "value": cn}]
        # used once – check 1's second try is refused at the limit and not counted beyond it
        assert fake.passcode_usage(record) == 1, (cn, fake.passcode_usage(record))
    # provisioning statistics
    prov = r["provisioning"]
    # the fake answers in well under a millisecond – rounded to 3 decimals the median may be 0.0 (CI)
    assert prov["count"] == count and prov["median_s"] >= 0
    assert_rates(prov, count, prov["duration_s"], slack=0.005)
    assert ("estimate_devices" in prov) == ("estimate_min" in prov) == (count > 1)
    assert ("estimate_devices" in r) == (count > 1)  # the enrollment estimate only for several devices
    # the ledger: auth policy, every passcode (and the check's), policy, division – no profile on US
    kinds = sorted(o["kind"] for o in store.objects("u5"))
    assert kinds == sorted(["auth_policy", "division", "policy"] + ["passcode"] * (count + checks))
    # phases: setup, factory provisioning (recurring), field enrollment
    calls = r["api_calls"]
    (create,) = [c for c in calls if c["path"] == enrollment.PASSCODE_PATH]
    assert (create["phase"], create["count"], create["method"]) == ("recurring", count, "POST")
    assert create["purpose"] == "Create the device's one-time passcode, bound to its common name"
    field = [c for c in calls if c["phase"] == "field"]
    assert field and sum(c["method"] == "POST" for c in field) == 1
    assert next(c for c in field if c["method"] == "POST")["count"] == count
    assert {c["phase"] for c in calls} == {"setup", "recurring", "field"}
    if checks:
        one, two, three = r["checks"]
        assert one["ok"] and "Passcode has reached its usage limit" in one["outcome"]
        assert two["ok"] and "Invalid registered value provided in attribute: subject.common_name" in two["outcome"]
        assert three["ok"] and three["outcome"].startswith("usage 1 of 1")
        check = passcodes(fake, "robot-u5-uc05-passcode-check")["robot-u5-uc05-passcode-check"]
        # a device outside the batch – never one of the run's own names
        assert check["registered_cn"] == evergreen.common_names("u5", protocol, count + 1, UC)[-1]
        assert check["registered_cn"] not in names
    else:
        assert "checks" not in r and not passcodes(fake, "robot-u5-uc05-passcode-check")
    # nothing but the run's devices got certificates
    cmp_openssl.sync_to_dtm()
    assert sorted(c["common_name"] for c in fake.issued()) == names
    # the full rollback removes every passcode, the auth policy, the policy and the division
    run = await do_cleanup(store, fake, "u5", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("u5")[-5:]
    assert all(o["status"] == "DELETED" for o in fake.auth_objects["passcode"].values())
    assert all(o["status"] == "DELETED" for o in fake.auth_objects["auth_policy"].values())
    assert fake.issued() == [] and fake.policies == {} and fake.divisions == {}
    assert fake.violations == []


@pytest.mark.parametrize("protocol", ["est", "cmpv2"])
async def test_uc05_on_nl_has_its_own_profile(store, tmp_path, monkeypatch, protocol):
    from tests import conftest
    nl = FakeDTM(host=NL_HOST)
    enroll_net = conftest.enroll_net.__wrapped__(monkeypatch, nl)
    cmp = conftest.FakeOpenSSL(tmp_path / "nl-bin", nl)
    monkeypatch.setenv("PATH", f"{cmp.bin_dir}:{__import__('os').environ['PATH']}")
    run = await start(store, enroll_net, "n5", tmp_path, protocol=protocol, **batch(2))
    assert run["status"] == "completed", run["error"]
    spec = dtm.PROFILE_EVERGREEN_CMP if protocol == "cmpv2" else dtm.PROFILE_EVERGREEN
    (profile_obj,) = store.objects("n5", "profile")
    profile = nl.profile("robot-n5-uc05-profile")
    assert profile["id"] == profile_obj["dtm_id"] and bool(profile.get("allow_bare_public_key")) == spec.bare_key
    cmp.sync_to_dtm()
    run = await do_cleanup(store, nl, "n5", "full", tmp_path)
    assert run["cleanup_status"] == "done" and profile["status"] == "DELETED"


@pytest.mark.parametrize("protocol", ["est", "cmpv2"])
async def test_a_dtm_that_wrongly_accepts_is_shown_and_rolled_back(store, enroll_net, cmp_openssl, tmp_path,
                                                                    protocol):
    enroll_net.passcode_rules = False  # neither the usage limit nor the registered name hold
    run = await start(store, enroll_net, "w5", tmp_path, protocol=protocol)
    assert run["status"] == "completed", run["error"]
    one, two, three = run["result"]["checks"]
    assert (one["ok"], one["outcome"]) == (False, "issued – the usage limit did not hold")
    assert (two["ok"], two["outcome"]) == (False, "issued – the registered common name did not hold")
    assert three["ok"]
    assert any(e["level"] == "error" and "did not hold" in e["message"] for e in store.events("w5"))
    cmp_openssl.sync_to_dtm()
    issued = sorted(c["common_name"] for c in enroll_net.issued())
    assert issued == sorted(["robot-w5-uc05-%s-0001" % protocol] * 2 + ["robot-w5-uc05-wrong-name"])
    run = await do_cleanup(store, enroll_net, "w5", "certificates", tmp_path)
    assert run["cleanup_status"] == "done" and enroll_net.issued() == []  # the extra ones are revoked, too


async def test_issued_certificate_with_another_name_fails_the_run(store, enroll_net, tmp_path, monkeypatch):
    original = enroll_net._new_certificate
    monkeypatch.setattr(enroll_net, "_new_certificate",
                        lambda oid, cn, key=None: original(oid, cn + "-renamed", key))
    run = await start(store, enroll_net, "m5", tmp_path, checks=False)
    assert run["status"] == "failed" and "certificates carry other names than their passcodes" in run["error"]
    run = await do_cleanup(store, enroll_net, "m5", "full", tmp_path)
    assert run["cleanup_status"] == "done" and enroll_net.issued() == []


async def test_each_device_uses_its_own_passcode(store, enroll_net, tmp_path):
    """The fake rejects a passcode for any other name – a run that handed device 2 the passcode of
    device 1 could not complete; and every request carried a different passcode."""
    run = await start(store, enroll_net, "d5", tmp_path, checks=False, **batch(3))
    assert run["status"] == "completed", run["error"]
    import base64
    sent = [base64.b64decode(r.headers["authorization"][6:]).decode() for r in enroll_net.enroll_requests]
    own = passcodes(enroll_net, "robot-d5-uc05-passcode-")
    by_secret = {o["body"]["passcode"]: o["registered_cn"] for o in own.values()}
    assert len(set(sent)) == 3 and [by_secret[s] for s in sent] == evergreen.common_names("d5", "est", 3, UC)


async def test_discover_finds_unrecorded_passcodes_by_prefix_only(store, enroll_net, tmp_path, monkeypatch):
    original = store.add_object
    monkeypatch.setattr(store, "add_object", lambda run_id, kind, *a: None if kind == "passcode" else
                        original(run_id, kind, *a))
    run = await start(store, enroll_net, "u5", tmp_path, **batch(2))
    monkeypatch.setattr(store, "add_object", original)
    assert run["status"] == "completed" and store.objects("u5", "passcode") == []
    # another run's look-alike (run ID "u50"): same leading characters, different prefix
    client = enroll_net.client()
    try:
        auth_policy = next(iter(enroll_net.auth_objects["auth_policy"]))
        other = await client.create_passcode("robot-u50-uc05-passcode-0001", auth_policy, "x" * 16, "robot-u50-x")
    finally:
        await client.aclose()
    enroll_net.calls.clear()
    run = await do_cleanup(store, enroll_net, "u5", "certificates", tmp_path)
    assert run["cleanup_status"] == "done"
    found = [e["message"] for e in store.events("u5") if e["message"].startswith("Found unrecorded passcode")]
    assert sorted(found) == sorted(f"Found unrecorded passcode robot-u5-uc05-passcode-{s} – adding it to the cleanup"
                                   for s in ("0001", "0002", "check"))
    ids = {o["id"] for n, o in passcodes(enroll_net, "robot-u5-uc05-passcode-").items()}
    assert {o["dtm_id"] for o in store.objects("u5", "passcode")} == ids and other["id"] not in ids
    assert enroll_net.names("passcode_list") and len(enroll_net.names("passcode_list")) == 1  # one list call
    enroll_net.auth_objects["passcode"][other["id"]]["status"] = "ACTIVE"
    run = await do_cleanup(store, enroll_net, "u5", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("u5")[-5:]
    assert enroll_net.auth_objects["passcode"][other["id"]]["status"] == "ACTIVE"  # not ours – untouched
    assert all(o["status"] == "DELETED" for n, o in passcodes(enroll_net, "robot-u5-uc05-").items())


# --- reproducible steps --------------------------------------------------------------------------

@pytest.mark.parametrize("protocol,count", [("est", 1), ("cmpv2", 3)])
async def test_uc05_steps_are_replayable(store, enroll_net, cmp_openssl, tmp_path, protocol, count):
    from tests.integration.test_api_call_elements import assert_one_request_per_element
    from tests.integration.test_replayable_steps import assert_replayable
    run = await start(store, enroll_net, "r5", tmp_path, protocol=protocol, **batch(count))
    assert run["status"] == "completed", run["error"]
    assert_replayable(run, enroll_net)
    assert assert_one_request_per_element(run) == len([c for c in run["result"]["api_calls"] if c.get("spec")])
    calls = run["result"]["api_calls"]
    (create,) = [c for c in calls if c["path"] == enrollment.PASSCODE_PATH]
    body = create["spec"]["json"]
    assert body == dtm.passcode_body("{RUN_NAME}-passcode-0001", "{DTM_ACCOUNT_ID}", "{AUTH_POLICY_ID}", "{PASSCODE}",
                                     f"{{RUN_NAME}}-{protocol}-0001")
    assert body["usage_limit"] == 1
    variables = run["result"]["api_variables"]
    text = json.dumps([c["spec"] for c in calls])
    assert "robot-r5-" not in text and variables["PASSCODE"].startswith("<")  # the secret is never recorded
    for p in passcodes(enroll_net, "robot-r5-").values():
        assert p["body"]["passcode"] not in snippets.script(variables, calls, "curl")
    # the field block is its own script that keeps what the factory steps set in this shell
    field = snippets.script(variables, calls, "curl", "field")
    assert field.startswith('[ -n "${ZSH_VERSION:-}" ] && setopt interactivecomments\n[ -n "${DTM_API_KEY:-}" ] ||')
    assert ("openssl cmp -cmd ir" if protocol == "cmpv2" else "simpleenroll") in field


def test_passcode_body():
    assert dtm.passcode_body("n", ACCOUNT_ID, "ap", "secret") == {
        "name": "n", "account_id": ACCOUNT_ID, "authentication_policy_id": "ap", "enable_username_for_passcode": False,
        "passcode": "secret"}
    bound = dtm.passcode_body("n", ACCOUNT_ID, "ap", "secret", "robot-x-uc05-est-0001")
    assert bound["usage_limit"] == 1 and bound["registered_values"] == [
        {"certificate_field": "subject.common_name", "matcher": "equals", "value": "robot-x-uc05-est-0001"}]
    assert HOST != NL_HOST



async def test_discovered_passcodes_keep_their_own_names(store, enroll_net, tmp_path, monkeypatch):
    original = store.add_object
    monkeypatch.setattr(store, "add_object", lambda run_id, kind, *a: None if kind == "passcode" else
                        original(run_id, kind, *a))
    await start(store, enroll_net, "u6", tmp_path, checks=False, **batch(2))
    monkeypatch.setattr(store, "add_object", original)
    await do_cleanup(store, enroll_net, "u6", "certificates", tmp_path)
    assert sorted(o["name"] for o in store.objects("u6", "passcode")) == [
        "robot-u6-uc05-passcode-0001", "robot-u6-uc05-passcode-0002"]


async def test_each_cmpv2_device_uses_its_own_passcode(store, enroll_net, cmp_openssl, tmp_path):
    """CMPv2: the MAC secret must belong to the -ref (the fake checks it) – each of 3 devices sends
    its own reference with its own secret, bound to its own name."""
    import hashlib
    run = await start(store, enroll_net, "c5", tmp_path, protocol="cmpv2", checks=False, **batch(3))
    assert run["status"] == "completed", run["error"]
    own = sorted(passcodes(enroll_net, "robot-c5-uc05-passcode-").values(), key=lambda o: o["name"])
    calls = [c for c in cmp_openssl.calls() if c["issued"]]
    refs = [c["argv"][c["argv"].index("-ref") + 1] for c in calls]
    subjects = [c["argv"][c["argv"].index("-subject") + 1] for c in calls]
    assert refs == [o["alternate_id"] for o in own] and len(set(refs)) == 3
    assert subjects == [f"/CN={o['registered_cn']}" for o in own]
    published = json.loads((cmp_openssl.bin_dir / "config.json").read_text())["passcodes"]
    assert all(published[o["alternate_id"]]["secret_sha256"] == hashlib.sha256(o["body"]["passcode"].encode()).hexdigest()
               for o in own)


async def test_cmp_fake_rejects_a_secret_of_another_reference(store, enroll_net, cmp_openssl, tmp_path, monkeypatch):
    """The CMP fake can fail: DTM holds another secret than the station sends for that -ref."""
    original = dtm.DTMClient.create_passcode

    async def create_passcode(self, name, auth_policy_id, passcode, common_name=None):
        return await original(self, name, auth_policy_id, passcode + "-other", common_name)
    monkeypatch.setattr(dtm.DTMClient, "create_passcode", create_passcode)
    run = await start(store, enroll_net, "x5", tmp_path, protocol="cmpv2", checks=False)
    assert run["status"] == "failed" and "MAC verification failed" in run["error"]


async def test_failing_policy_creates_no_passcode(store, enroll_net, tmp_path):
    import httpx
    enroll_net.fail["policy_create"] = httpx.Response(400, json={"errors": [{"message": "nope"}]})
    run = await start(store, enroll_net, "f5", tmp_path, **batch(2))
    assert run["status"] == "failed"
    assert enroll_net.names("passcode_create") == [] and store.objects("f5", "passcode") == []
    assert not [c for c in run["result"]["api_calls"] if c["path"] == enrollment.PASSCODE_PATH]
    del enroll_net.fail["policy_create"]
    run = await do_cleanup(store, enroll_net, "f5", "full", tmp_path)
    assert run["cleanup_status"] == "done" and enroll_net.divisions == {}
    assert all(o["status"] == "DELETED" for o in enroll_net.auth_objects["auth_policy"].values())


async def test_passcodes_come_after_policy_setup(store, enroll_net, cmp_openssl, tmp_path):
    run = await start(store, enroll_net, "o5", tmp_path, protocol="cmpv2", checks=False)
    order = enroll_net.route_order()
    assert order.index("policy_create") < order.index("policy_get") < order.index("passcode_create")
    calls = run["result"]["api_calls"]
    paths = [c["path"] for c in calls]
    # after every DTM setup call (local setup steps of the protocol may follow)
    assert paths.index(enrollment.PASSCODE_PATH) > max(i for i, c in enumerate(calls)
                                                       if c["phase"] == "setup" and c["method"] != "LOCAL")
    ref_step = next(c for c in calls if c["purpose"] == "Extract the passcode reference (CMPv2 sender ID)")
    assert ref_step["phase"] == "recurring" and calls.index(ref_step) == paths.index(enrollment.PASSCODE_PATH) + 1


async def test_provision_counts_create_attempts_only(store, enroll_net, cmp_openssl, tmp_path, monkeypatch):
    """A passcode DTM created but answered without a usable reference: one attempt, error; the
    passcode is in the ledger and the rollback removes it."""
    original = dtm.DTMClient.create_passcode

    async def no_reference(self, *args):
        created = await original(self, *args)
        return created | {"alternate_id": None}
    monkeypatch.setattr(dtm.DTMClient, "create_passcode", no_reference)
    run = await start(store, enroll_net, "a5", tmp_path, protocol="cmpv2", checks=False, **batch(3))
    assert run["status"] == "failed" and "no usable passcode reference" in run["error"]
    (step,) = [c for c in run["result"]["api_calls"] if c["path"] == enrollment.PASSCODE_PATH]
    assert (step["count"], step["outcome"]) == (1, "error")
    assert len(store.objects("a5", "passcode")) == 1
    run = await do_cleanup(store, enroll_net, "a5", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert all(o["status"] == "DELETED" for o in enroll_net.auth_objects["passcode"].values())


@pytest.mark.parametrize("protocol", ["est", "cmpv2"])
async def test_checks_that_cannot_reach_dtm_are_inconclusive(store, enroll_net, cmp_openssl, tmp_path, monkeypatch,
                                                             protocol):
    import httpx
    original = enrollment._passcode_checks

    async def outage(*args, **kwargs):  # DTM's enrollment endpoint fails after the real enrollment
        enroll_net.enroll_fail = httpx.Response(503, text="Service Unavailable")
        cmp_openssl.fail_with("transfer error: connection reset by peer")
        return await original(*args, **kwargs)
    monkeypatch.setattr(enrollment, "_passcode_checks", outage)
    run = await start(store, enroll_net, "i5", tmp_path, protocol=protocol)
    assert run["status"] == "completed", run["error"]
    one, two, three = run["result"]["checks"]
    for row in (one, two):
        assert row["ok"] is False and row["outcome"].startswith("inconclusive – "), row
        assert "issued" not in row["outcome"]
    assert three["check"] == "Passcode usage afterwards" and three["expected"] == "used up"
    assert (three["ok"], three["outcome"]) == (False, "usage 0 of 1")  # the request never reached the passcode
    for row in (one, two):  # the full error stays available (tooltip), the outcome is DTM's message only
        assert row["detail"].startswith(("EST returned 503", "CMPv2 request rejected"))
        assert row["outcome"] == "inconclusive – " + enrollment.dtm_message(row["detail"])


@pytest.mark.parametrize("protocol", ["est", "cmpv2"])
async def test_real_rejections_count_and_usage_is_reported(store, enroll_net, cmp_openssl, tmp_path, protocol):
    run = await start(store, enroll_net, "j5", tmp_path, protocol=protocol)
    one, two, three = run["result"]["checks"]
    assert (one["ok"], one["outcome"]) == (True, "Passcode has reached its usage limit")
    assert (two["ok"], two["outcome"]) == (True, "Invalid registered value provided in attribute: subject.common_name")
    for row in (one, two):
        assert row["detail"] != row["outcome"] and row["outcome"] in row["detail"]  # full text kept as detail
        assert ("returned 400" if protocol == "est" else "PKIStatus: rejection") in row["detail"]
    assert three == {"check": "Passcode usage afterwards", "expected": "used up", "ok": True,
                     "outcome": "usage 1 of 1 – the rejected request used it up, this device could not enroll any more"}


async def test_a_failing_check_does_not_fail_the_run(store, enroll_net, tmp_path, monkeypatch):
    import httpx
    original = enrollment._passcode_checks

    async def broken(*args, **kwargs):  # the check passcode cannot be created
        enroll_net.fail["passcode_create"] = httpx.Response(500, json={"errors": [{"message": "down"}]})
        return await original(*args, **kwargs)
    monkeypatch.setattr(enrollment, "_passcode_checks", broken)
    run = await start(store, enroll_net, "k5", tmp_path)
    assert run["status"] == "completed", run["error"]
    (row,) = run["result"]["checks"]
    assert row["check"] == "Checks" and row["ok"] is False and row["outcome"].startswith("could not run – ")
    assert run["result"]["certificate_total"] == 1
    assert (tmp_path / "runs" / "k5" / "certificates").is_dir()  # the certificates are saved


async def test_passcode_of_another_account_with_the_runs_prefix_is_untouched(store, enroll_net, tmp_path, monkeypatch):
    original = store.add_object
    monkeypatch.setattr(store, "add_object", lambda run_id, kind, *a: None if kind == "passcode" else
                        original(run_id, kind, *a))
    await start(store, enroll_net, "v5", tmp_path, checks=False)
    monkeypatch.setattr(store, "add_object", original)
    foreign = {"id": "foreign-passcode", "name": "robot-v5-uc05-passcode-0009", "status": "ACTIVE",
               "account_id": "0a1b2c3d-0000-4000-8000-00000000b002",
               "body": {"passcode": "x" * 16, "authentication_policy_id": "elsewhere"}}
    enroll_net.auth_objects["passcode"]["foreign-passcode"] = foreign
    run = await do_cleanup(store, enroll_net, "v5", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("v5")[-5:]
    assert foreign["status"] == "ACTIVE" and "foreign-passcode" not in enroll_net.names("passcode_delete")
    assert [o["name"] for o in store.objects("v5", "passcode", include_removed=True)] == ["robot-v5-uc05-passcode-0001"]


async def test_batch_labels(store, enroll_net, tmp_path):
    await start(store, enroll_net, "b5", tmp_path, checks=False, **batch(3))
    messages = [e["message"] for e in store.events("b5")]
    assert "Enrolling 3 devices one after another via EST (passcode)" in messages
    assert any(m.startswith("3 devices enrolled – ") and m.endswith("s per request") for m in messages)


@pytest.mark.parametrize("protocol,reason,detail", [("est", "invalid passcode", "returned 401"),
                                                    ("cmpv2", "MAC verification failed", "PKIStatus: rejection")])
async def test_rejection_for_another_reason_does_not_count(store, enroll_net, cmp_openssl, tmp_path, monkeypatch,
                                                            protocol, reason, detail):
    """Both checks get a real rejection – but for a wrong passcode, not for the rule they test: DTM
    holds other secrets than the station sends (EST: 401 invalid passcode; CMPv2: MAC check)."""
    original_checks, original_create = enrollment._passcode_checks, dtm.DTMClient.create_passcode

    async def create_passcode(self, name, auth_policy_id, passcode, common_name=None):
        return await original_create(self, name, auth_policy_id, passcode + "-other", common_name)

    async def wrong_secrets(*args, **kwargs):
        for record in enroll_net.auth_objects["passcode"].values():  # device 0001's passcode no longer matches
            record["body"]["passcode"] += "-rotated"
        cmp_openssl.publish_passcodes()
        monkeypatch.setattr(dtm.DTMClient, "create_passcode", create_passcode)  # nor does the check's
        return await original_checks(*args, **kwargs)
    monkeypatch.setattr(enrollment, "_passcode_checks", wrong_secrets)
    run = await start(store, enroll_net, "q5", tmp_path, protocol=protocol)
    assert run["status"] == "completed", run["error"]
    one, two, three = run["result"]["checks"]
    for row in (one, two):
        assert row["ok"] is False and row["outcome"] == f"rejected for another reason – {reason}", row
        assert detail in row["detail"]
        assert "reached its usage limit" not in row["outcome"] and "Invalid registered value" not in row["outcome"]
    assert (three["ok"], three["outcome"]) == (False, "usage 0 of 1")  # refused before the passcode was used
    cmp_openssl.sync_to_dtm()
    assert len(enroll_net.issued()) == 1  # only the real device


def test_check_reason_patterns():
    assert enrollment.USAGE_LIMIT.search("EST returned 400: Passcode has reached its usage limit")
    assert enrollment.USAGE_LIMIT.search('StatusString: "Protection is not valid"')
    assert enrollment.REGISTERED_VALUE.search("Invalid registered value provided in attribute: subject.common_name")
    for other in ("EST returned 401: invalid passcode", 'StatusString: "MAC verification failed"'):
        assert not enrollment.USAGE_LIMIT.search(other) and not enrollment.REGISTERED_VALUE.search(other)



def test_dtm_message():
    est = 'EST request failed: EST returned 400: {"errors":[{"code":"invalid_input","message":"Passcode has reached its usage limit"}]}'
    assert enrollment.dtm_message(est) == "Passcode has reached its usage limit"
    cmp = ('CMPv2 request rejected: CMP error: request rejected by server:PKIStatus: rejection; StatusString: '
           '"Invalid registered value provided in attribute: subject.common_name"; PKIFailureInfo: badRequest')
    assert enrollment.dtm_message(cmp) == "Invalid registered value provided in attribute: subject.common_name"
    for plain in ("EST returned 503: Service Unavailable", "usage 1 of 1", "CMPv2 request timed out", ""):
        assert enrollment.dtm_message(plain) == plain
    assert enrollment.dtm_message('{"errors":[{"code":"x", "message" : "spaced"}]}') == "spaced"


async def test_timeline_wording(store, enroll_net, tmp_path):
    await start(store, enroll_net, "t5", tmp_path)
    messages = [e["message"] for e in store.events("t5")]
    assert "Rejected as expected: Passcode has reached its usage limit" in messages
    assert "Rejected as expected: Invalid registered value provided in attribute: subject.common_name" in messages
    assert not any(" enrolled in " in m for m in messages)  # a single device: only the summary line
    await start(store, enroll_net, "t6", tmp_path, checks=False, **batch(2))
    per_device = [m for m in (e["message"] for e in store.events("t6")) if " enrolled in " in m]
    assert [m.split(" enrolled in ")[0] for m in per_device] == evergreen.common_names("t6", "est", 2, UC)


# --- the pause before the field: the presenter shows the passcodes in DTM, then starts the enrollment ---

async def until(predicate, what: str):
    """Waits on the run task inside the same loop – asyncio.sleep is instant in mocked tests, so the
    number of turns is bounded instead of the time."""
    import asyncio
    for _ in range(20000):
        if value := predicate():
            return value
        await asyncio.sleep(0)
    raise AssertionError(f"timed out waiting for {what}")


def run_in_background(store, fake: FakeDTM, run_id: str, tmp_path, **overrides):
    import asyncio
    return asyncio.create_task(start(store, fake, run_id, tmp_path, **overrides))


def paused(store, run_id):
    return lambda: (r := store.get_run(run_id)) and r["status"] == "paused" and r


def ended(store, run_id):
    return lambda: (r := store.get_run(run_id)) and r["status"] in ("completed", "failed") and r


async def test_without_pause_the_run_never_stops(store, enroll_net, tmp_path, monkeypatch):
    statuses = []
    original = store.update_run
    monkeypatch.setattr(store, "update_run", lambda rid, **f: statuses.append(f.get("status")) or original(rid, **f))
    run = await start(store, enroll_net, "q5", tmp_path, pause=False, checks=False)
    assert run["status"] == "completed", run["error"]
    assert "paused" not in statuses
    assert not any("Field enrollment started" in e["message"] for e in store.events("q5"))


@pytest.mark.parametrize("protocol,count", [("est", 1), ("cmpv2", 2)])
async def test_pause_waits_with_the_passcodes_in_dtm_until_the_field_starts(store, enroll_net, cmp_openssl, tmp_path,
                                                                           protocol, count):
    task = run_in_background(store, enroll_net, "z5", tmp_path, protocol=protocol, pause=True, **batch(count))
    run = await until(paused(store, "z5"), "the pause")
    names = evergreen.common_names("z5", protocol, count, UC)
    # the factory step is done: one bound passcode per device, unused; nothing enrolled yet
    own = passcodes(enroll_net, "robot-z5-uc05-passcode-0")
    assert sorted(o["registered_cn"] for o in own.values()) == sorted(names)
    assert all(enroll_net.passcode_usage(o) == 0 for o in own.values())
    assert enroll_net.enroll_requests == []
    cmp_openssl.sync_to_dtm()
    assert enroll_net.issued() == []
    # the result so far is saved (the page shows the policy), nothing is in progress
    assert run["result"]["policy"] == "robot-z5-uc05-policy" and run["result"]["provisioning"]["count"] == count
    assert run["progress"] is None and not task.done()
    events = [e["message"] for e in store.events("z5")]
    assert any(m.startswith("Passcodes are in DTM") for m in events)
    assert not any("Field enrollment started" in m for m in events)
    # still waiting after many more polls
    import asyncio
    for _ in range(200):
        await asyncio.sleep(0)
    assert store.get_run("z5")["status"] == "paused" and not task.done()
    # the presenter clicks: paused → running, the run enrolls and completes like without the pause
    assert store.claim_status("z5", "paused", "running")
    run = await asyncio.wait_for(task, 30)
    assert run["status"] == "completed", run["error"]
    r = run["result"]
    assert [c["common_name"] for c in r["certificates"]] == names
    assert [c["ok"] for c in r["checks"]] == [True, True, True]
    assert all(enroll_net.passcode_usage(o) == 1 for o in own.values())
    events = [e["message"] for e in store.events("z5")]
    assert events.index("Field enrollment started") > next(
        i for i, m in enumerate(events) if m.startswith("Passcodes are in DTM"))
    cmp_openssl.sync_to_dtm()
    assert sorted(c["common_name"] for c in enroll_net.issued()) == sorted(names)
    run = await do_cleanup(store, enroll_net, "z5", "full", tmp_path)
    assert run["cleanup_status"] == "done" and enroll_net.violations == []


async def test_rollback_during_the_pause_ends_the_run_and_removes_the_passcodes(store, enroll_net, tmp_path,
                                                                                 monkeypatch):
    import asyncio
    updates = []
    original = store.update_run
    monkeypatch.setattr(store, "update_run", lambda rid, **f: updates.append(f) or original(rid, **f))
    task = run_in_background(store, enroll_net, "r5", tmp_path, pause=True, **batch(2))
    await until(paused(store, "r5"), "the pause")
    assert len(passcodes(enroll_net, "robot-r5-uc05-passcode-0")) == 2
    cleanup_run = await do_cleanup(store, enroll_net, "r5", "full", tmp_path)
    run = await asyncio.wait_for(task, 30)
    assert run["status"] == "failed" and run["error"] == "rolled back before the field enrollment"
    assert run["finished_at"]
    # the run task neither logs its end nor resets the progress – the cleanup's heartbeat owns both
    (failed,) = [u for u in updates if u.get("status") == "failed"]
    assert "progress" not in failed
    assert not any(e["message"].startswith("Run failed") for e in store.events("r5"))
    assert cleanup_run["cleanup_status"] == "done", store.events("r5")[-5:]
    assert store.get_run("r5")["cleanup_status"] == "done"
    assert enroll_net.enroll_requests == [] and enroll_net.issued() == []
    assert all(o["status"] == "DELETED" for o in enroll_net.auth_objects["passcode"].values())
    assert enroll_net.policies == {} and enroll_net.divisions == {} and enroll_net.violations == []


async def test_pause_ends_after_the_time_limit(store, enroll_net, tmp_path, monkeypatch):
    import asyncio
    import time as real_time
    clock = {"offset": 0.0}

    class Time:
        def __getattr__(self, name):
            return getattr(real_time, name)

        @staticmethod
        def monotonic():
            return real_time.monotonic() + clock["offset"]

    monkeypatch.setattr(enrollment, "time", Time())
    monkeypatch.setattr(enrollment, "PAUSE_MAX_S", 120)
    task = run_in_background(store, enroll_net, "t5", tmp_path, pause=True)
    await until(paused(store, "t5"), "the pause")
    for _ in range(50):
        await asyncio.sleep(0)
    assert store.get_run("t5")["status"] == "paused"  # within the limit it keeps waiting
    clock["offset"] = 121
    run = await asyncio.wait_for(task, 30)
    assert run["status"] == "failed"
    assert run["error"] == "the field enrollment was not started within 2 minutes"
    assert enroll_net.enroll_requests == []
    run = await do_cleanup(store, enroll_net, "t5", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert all(o["status"] == "DELETED" for o in enroll_net.auth_objects["passcode"].values())


def test_production_pause_limit_is_an_hour():
    assert enrollment.PAUSE_MAX_S == 3600 and enrollment.PAUSE_POLL_S > 0


async def test_deleting_the_run_during_the_pause_ends_the_task_quietly(store, enroll_net, tmp_path):
    import asyncio
    task = run_in_background(store, enroll_net, "x5", tmp_path, pause=True)
    await until(paused(store, "x5"), "the pause")
    store.delete_run("x5")
    assert await asyncio.wait_for(task, 30) is None  # no exception, nothing recreated
    assert store.get_run("x5") is None and enroll_net.enroll_requests == []
