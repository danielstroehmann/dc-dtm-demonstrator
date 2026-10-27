"""Shared certificate profiles per account against the
stateful fake DTM: find, enable, create once, races, mismatches, template caps, foreign accounts,
retire – and that runs use the right one and never put it into the cleanup ledger."""

import asyncio

import httpx
import pytest

from app import dtm
from app.dtm import DTMError
from tests.fakedtm import ACCOUNT_ID, OTHER_ACCOUNT_ID, PROFILE_ID, FakeDTM, _profile

EVERGREEN, CMP, RENEWAL = dtm.PROFILE_EVERGREEN, dtm.PROFILE_EVERGREEN_CMP, dtm.PROFILE_RENEWAL


async def call(fake: FakeDTM, method: str, *args):
    client = fake.client()
    try:
        return await getattr(client, method)(*args)
    finally:
        await client.aclose()


def shared(fake: FakeDTM, spec, unit="years", value=5, status="ACTIVE", account_id=ACCOUNT_ID, **extra) -> dict:
    """A profile of that name as an earlier run (or someone else) left it."""
    profile = _profile(f"existing-{spec.name}-{account_id[-4:]}", spec.name, "tpl-client",
                       "anytime" if spec.renew_anytime else None, account_id)
    for entry in profile["body"]:
        if entry["key"] == "validity.duration_unit":
            entry["value"] = unit
        if entry["key"] == "validity.duration_value":
            entry["value"] = value
    profile |= {"status": status, "allow_bare_public_key": spec.bare_key} | extra
    fake.profiles.append(profile)
    return profile


def writes(fake: FakeDTM) -> list[str]:
    return [n for n in fake.route_order() if n.startswith("profile_") and n != "profile_get"]


# --- find or create ----------------------------------------------------------------------------

@pytest.mark.parametrize("spec", [EVERGREEN, CMP, RENEWAL])
async def test_created_once_then_used(fake, spec):
    profile_id, how = await call(fake, "shared_profile", spec)
    assert how == "created"
    created = fake.profile(spec.name)
    assert created["id"] == profile_id and created["status"] == "ACTIVE" and created["account_id"] == ACCOUNT_ID
    (body,) = fake.created_profiles
    assert body["certificate_template_id"] == "tpl-client"  # copied from the basic client profile
    assert fake.names("profile_get") == [PROFILE_ID]
    entries = {e["key"]: e["value"] for e in created["body"]}
    assert (entries["validity.duration_unit"], entries["validity.duration_value"]) == (spec.unit, spec.value)
    assert created["allow_bare_public_key"] is spec.bare_key
    assert (entries.get("renewal_settings.renew_valid_cert") == "anytime") == (spec.renew_anytime or
                                                                               "renewal_settings.renew_valid_cert"
                                                                               in entries)
    fake.calls.clear()
    assert await call(fake, "shared_profile", spec) == (profile_id, "used")
    assert writes(fake) == [] and len(fake.created_profiles) == 1
    assert fake.violations == []


async def test_base_profile_choice(fake):
    """Prefers an own, active, non-robot profile with "client" in its name; never a foreign one."""
    fake.profiles = [p for p in fake.profiles if p["id"] != PROFILE_ID]
    fake.profiles.insert(0, _profile("profile-foreign-client", "Foreign client profile", "tpl-foreign", None,
                                     OTHER_ACCOUNT_ID))
    fake.profiles.insert(0, _profile("profile-robot-client", "robot-x-client-profile", "tpl-robot", None))
    fake.profiles.append(_profile("profile-iot-client", "IoT client", "tpl-iot", None))
    await call(fake, "shared_profile", EVERGREEN)
    assert fake.names("profile_get") == ["profile-iot-client"]
    assert fake.created_profiles[0]["certificate_template_id"] == "tpl-iot"


async def test_base_profile_falls_back_to_the_first_own_active_one(fake):
    fake.profiles = [p for p in fake.profiles if "client" not in p["name"].lower()]
    await call(fake, "shared_profile", EVERGREEN)
    assert fake.names("profile_get") == ["profile-server"]  # first own ACTIVE, INACTIVE "Old" skipped


async def test_no_base_profile(fake):
    fake.profiles = [p for p in fake.profiles if p.get("account_id") != ACCOUNT_ID or p["status"] != "ACTIVE"]
    with pytest.raises(DTMError, match="no active certificate profile to copy"):
        await call(fake, "shared_profile", EVERGREEN)
    assert fake.created_profiles == []


async def test_base_without_template_is_refused(fake):
    fake.fail["profile_get"] = lambda request: httpx.Response(200, json={"id": PROFILE_ID, "body": []})
    with pytest.raises(DTMError, match="cannot be copied"):
        await call(fake, "shared_profile", EVERGREEN)
    assert fake.created_profiles == []


@pytest.mark.parametrize("status", ["DISABLED", "INACTIVE"])
async def test_retired_profile_is_enabled_again(fake, status):
    old = shared(fake, EVERGREEN, status=status)
    assert await call(fake, "shared_profile", EVERGREEN) == (old["id"], "enabled")
    assert old["status"] == "ACTIVE" and fake.names("profile_enable") == [old["id"]]
    assert fake.created_profiles == []


async def test_active_preferred_over_retired_duplicate(fake):
    shared(fake, EVERGREEN, status="DISABLED")
    active = shared(fake, EVERGREEN, status="ACTIVE", id="second")
    assert await call(fake, "shared_profile", EVERGREEN) == ("second", "used")
    assert writes(fake) == []
    assert active["status"] == "ACTIVE"


# Deleted in the portal: DTM hides the profile but keeps its name reserved (verified live) – restore it.

async def test_deleted_shared_profile_is_restored_not_recreated(fake):
    old = shared(fake, EVERGREEN)
    fake.delete_profile(old)
    assert fake.profile(EVERGREEN.name)["status"] == "DELETED"
    assert await call(fake, "shared_profile", EVERGREEN) == (old["id"], "restored")
    assert old["status"] == "ACTIVE" and fake.names("profile_undelete") == [old["id"]]
    assert fake.names("profile_create") == [] and fake.created_profiles == []
    assert writes(fake) == ["profile_undelete"]
    lists = [r.url.params.get("status") for r in fake.requests if r.url.path == dtm.PROFILES and r.method == "GET"]
    assert lists == [None, "DELETED", None]  # look, find it among the deleted, look again


async def test_deleted_and_retired_profile_is_restored_and_enabled(fake):
    old = shared(fake, CMP, status="DISABLED")
    fake.delete_profile(old)
    assert await call(fake, "shared_profile", CMP) == (old["id"], "restored")
    assert old["status"] == "ACTIVE"
    assert writes(fake) == ["profile_undelete", "profile_enable"] and fake.created_profiles == []


@pytest.mark.parametrize("spec,changes", [(EVERGREEN, {"value": 1}), (EVERGREEN, {"unit": "months"}),
                                          (CMP, {"allow_bare_public_key": False})])
async def test_deleted_profile_with_other_settings_stays_deleted(fake, spec, changes):
    """The deleted record is checked first: a mismatching profile is neither restored nor replaced."""
    old = shared(fake, spec, **changes)
    fake.delete_profile(old)
    with pytest.raises(DTMError) as error:
        await call(fake, "shared_profile", spec)
    assert str(error.value) == (f"profile {spec.name} was deleted with other settings – restore it in the DTM portal, "
                                "then fix or rename it")
    assert writes(fake) == [] and fake.created_profiles == []  # no undelete, no create, no enable
    assert old["status"] == "DELETED"


async def test_deleted_profile_of_another_account_is_ignored(fake):
    foreign = shared(fake, EVERGREEN, account_id=OTHER_ACCOUNT_ID)
    fake.delete_profile(foreign)
    profile_id, how = await call(fake, "shared_profile", EVERGREEN)
    assert how == "created" and profile_id != foreign["id"]
    assert fake.names("profile_undelete") == [] and foreign["status"] == "DELETED"
    assert fake.profile(EVERGREEN.name)["id"] == profile_id


async def test_deleted_profile_of_another_name_is_ignored(fake):
    other = shared(fake, CMP)
    fake.delete_profile(other)
    _profile_id, how = await call(fake, "shared_profile", EVERGREEN)
    assert how == "created" and fake.names("profile_undelete") == [] and other["status"] == "DELETED"


async def test_no_deleted_record_creates_as_before(fake):
    profile_id, how = await call(fake, "shared_profile", EVERGREEN)
    assert how == "created" and fake.names("profile_undelete") == []
    lists = [r.url.params.get("status") for r in fake.requests if r.url.path == dtm.PROFILES and r.method == "GET"]
    assert lists == [None, "DELETED"] and fake.profile(EVERGREEN.name)["id"] == profile_id


async def test_fake_keeps_deleted_names_reserved(fake):
    """The fake models the live behaviour the app relies on: a new profile of a deleted name is refused."""
    old = shared(fake, EVERGREEN)
    fake.delete_profile(old)
    client = fake.client()
    try:
        response = await client._request("POST", dtm.PROFILES, expect=(400,),
                                         json=dtm.shared_profile_body(fake.profiles[0], EVERGREEN, ACCOUNT_ID))
    finally:
        await client.aclose()
    assert f"Certificate profile with name {EVERGREEN.name} already exists" in response.text
    assert old["id"] not in [p["id"] for p in await call(fake, "_profiles")]  # hidden from the normal list


async def test_string_values_from_dtm_still_match(fake):
    old = shared(fake, EVERGREEN, unit="Years", value="5")
    assert await call(fake, "shared_profile", EVERGREEN) == (old["id"], "used")


@pytest.mark.parametrize("spec,changes", [
    (EVERGREEN, {"value": 1}),
    (EVERGREEN, {"unit": "months"}),
    (CMP, {"allow_bare_public_key": False}),
    (EVERGREEN, {"status": "DISABLED", "value": 2}),  # a retired, wrong one is not enabled either
])
async def test_own_profile_with_other_settings_is_never_used_or_changed(fake, spec, changes):
    import copy
    old = shared(fake, spec, **changes)
    before = copy.deepcopy(old)
    with pytest.raises(DTMError, match="exists with other settings – fix or rename it"):
        await call(fake, "shared_profile", spec)
    assert writes(fake) == [] and old == before


async def test_renewal_profile_without_renew_anytime_is_a_mismatch(fake):
    old = shared(fake, RENEWAL, unit="months", value=6)
    next(e for e in old["body"] if e["key"] == "renewal_settings.renew_valid_cert")["value"] = "dont_allow"
    with pytest.raises(DTMError, match="exists with other settings"):
        await call(fake, "shared_profile", RENEWAL)


async def test_foreign_account_profile_of_that_name_is_ignored(fake):
    import copy
    foreign = shared(fake, EVERGREEN, account_id=OTHER_ACCOUNT_ID, value=1)  # mismatching on purpose
    before = copy.deepcopy(foreign)
    profile_id, how = await call(fake, "shared_profile", EVERGREEN)
    assert how == "created" and profile_id != foreign["id"]
    assert foreign == before and not any(oid == foreign["id"] for _n, oid in fake.calls)
    assert fake.profile(EVERGREEN.name)["account_id"] == ACCOUNT_ID


async def test_race_with_another_installation(fake):
    """Create answers 400 because someone else just created it – look again and use theirs."""
    def other_installation_first(request):
        if not fake.profile(EVERGREEN.name):
            shared(fake, EVERGREEN, id="theirs")
        return None  # the fake then refuses the duplicate name with 400
    fake.fail["profile_create"] = other_installation_first
    assert await call(fake, "shared_profile", EVERGREEN) == ("theirs", "used")
    assert [p["id"] for p in fake.profiles if p["name"] == EVERGREEN.name] == ["theirs"]


async def test_create_refused_for_another_reason(fake):
    fake.fail["profile_create"] = httpx.Response(400, json={"errors": [{"message": "template not allowed"}]})
    with pytest.raises(DTMError, match="could not create profile robot-evergreen-5y-profile: .*template not allowed"):
        await call(fake, "shared_profile", EVERGREEN)
    assert fake.names("profile_create") == [""] and not fake.profile(EVERGREEN.name)


async def test_template_cap_disables_the_new_profile_and_stops(fake):
    fake.template_validity_cap["tpl-client"] = ("years", 1)
    with pytest.raises(DTMError, match=r"did not accept the settings of robot-evergreen-5y-profile \(5 years\) – "
                                       r"the template of Basic client certificate profile may limit them"):
        await call(fake, "shared_profile", EVERGREEN)
    created = fake.profile(EVERGREEN.name)
    assert created["status"] == "DISABLED" and fake.names("profile_disable") == [created["id"]]
    # the next run does not silently enable the wrong one
    with pytest.raises(DTMError, match="exists with other settings"):
        await call(fake, "shared_profile", EVERGREEN)
    assert created["status"] == "DISABLED" and fake.names("profile_enable") == []


async def test_concurrent_calls_create_once(fake):
    results = await asyncio.gather(*(call(fake, "shared_profile", EVERGREEN) for _ in range(3)))
    assert sorted(how for _id, how in results) == ["created", "used", "used"]
    assert len({profile_id for profile_id, _how in results}) == 1 and len(fake.created_profiles) == 1


# --- status and retire -------------------------------------------------------------------------

async def test_status(fake):
    assert await call(fake, "shared_profile_status") == {s.name: "missing" for s in dtm.SHARED_PROFILES}
    shared(fake, EVERGREEN)
    shared(fake, CMP, status="DISABLED")
    shared(fake, RENEWAL, account_id=OTHER_ACCOUNT_ID, unit="months", value=6)  # not ours
    missing = {s.name: "missing" for s in dtm.SHARED_PROFILES}
    assert await call(fake, "shared_profile_status") == missing | {EVERGREEN.name: "ACTIVE", CMP.name: "DISABLED"}
    assert writes(fake) == []


@pytest.mark.parametrize("status,listed", [("ACTIVE", "ACTIVE"), ("DISABLED", None), (None, None)])
async def test_status_lists_the_legacy_profile_only_while_active(fake, status, listed):
    from tests.fakedtm import OTHER_ACCOUNT_ID as other
    if status:
        fake.profiles.append(_profile("legacy-cmp", "robot-uc03-cmp-profile", "tpl-client", None) | {"status": status})
    fake.profiles.append(_profile("legacy-foreign", "robot-uc03-cmp-profile", "tpl-x", None, other))  # not ours
    result = await call(fake, "shared_profile_status")
    assert result.get("robot-uc03-cmp-profile") == listed
    assert [n for n in result if n != "robot-uc03-cmp-profile"] == [s.name for s in dtm.SHARED_PROFILES]


async def test_retire_disables_ours_only(fake):
    ours = shared(fake, EVERGREEN)
    retired = shared(fake, CMP, status="DISABLED")
    legacy = _profile("legacy-cmp", "robot-uc03-cmp-profile", "tpl-client", None)
    foreign = shared(fake, RENEWAL, account_id=OTHER_ACCOUNT_ID, unit="months", value=6)
    fake.profiles.append(legacy)
    fake.calls.clear()
    status = await call(fake, "retire_shared_profiles")
    assert status == {s.name: "missing" for s in dtm.SHARED_PROFILES} | {EVERGREEN.name: "DISABLED",
                                                                        CMP.name: "DISABLED"}
    assert ours["status"] == retired["status"] == legacy["status"] == "DISABLED"
    assert foreign["status"] == "ACTIVE"
    assert sorted(fake.names("profile_disable")) == sorted([ours["id"], legacy["id"]])  # no needless PUTs
    assert fake.route_order().count("profiles") == 1  # one listing, the status comes from it
    assert next(p for p in fake.profiles if p["id"] == PROFILE_ID)["status"] == "ACTIVE"  # base untouched
    # a later run enables it again
    assert await call(fake, "shared_profile", EVERGREEN) == (ours["id"], "enabled")


# --- runs use the right one; never in the ledger, never deleted --------------------------------

async def test_engines_use_the_right_profile_and_never_record_or_delete_it(store, enroll_net, cmp_openssl,
                                                                           scep_client, tmp_path):
    from app import cleanup
    from tests.integration import test_uc01_flow, test_uc02_flow, test_uc03_flow, test_uc04_flow
    fake = enroll_net
    runs = {"a1": test_uc01_flow.start(store, fake, "a1", tmp_path),
            "a2": test_uc02_flow.start(store, fake, "a2", tmp_path),
            "a3": test_uc03_flow.start(store, fake, "a3", tmp_path, protocol="est"),
            "a4": test_uc03_flow.start(store, fake, "a4", tmp_path, protocol="cmpv2"),
            "a5": test_uc03_flow.start(store, fake, "a5", tmp_path, protocol="scep", ca_id="ca-rsa-ica",
                                       ca_name="Fake RSA ICA", key_type="RSA_2048"),
            "a6": test_uc04_flow.start(store, fake, "a6", tmp_path)}
    expected = {"a1": EVERGREEN, "a2": EVERGREEN, "a3": EVERGREEN, "a4": CMP, "a5": EVERGREEN, "a6": RENEWAL}
    for run_id, coro in runs.items():
        run = await coro
        assert run["status"] == "completed", (run_id, run["error"])
        (policy_obj,) = store.objects(run_id, "policy")
        policy = fake.policies[policy_obj["dtm_id"]]
        assert policy["certificate_profile_id"] == fake.profile(expected[run_id].name)["id"], run_id
        assert run["result"]["api_variables"]["PROFILE_ID"] == policy["certificate_profile_id"]
        assert not any("profile" in o["kind"] or o["name"].startswith("robot-evergreen")
                       or o["name"].startswith("robot-renewal") for o in store.objects(run_id))
    assert sorted(b["name"] for b in fake.created_profiles) == sorted(s.name for s in (EVERGREEN, CMP, RENEWAL))
    messages = [e["message"] for r in runs for e in store.events(r)]
    assert sum(m.startswith("Created the shared certificate profile") for m in messages) == 3
    assert sum(m.startswith("Using the shared certificate profile") for m in messages) == 3
    assert all("DTM keeps it permanently" in m for m in messages if "shared certificate profile" in m)
    cmp_openssl.sync_to_dtm()
    scep_client.sync_to_dtm()
    for run_id in runs:
        client = fake.client()
        try:
            await cleanup.cleanup(store, client, run_id, "full", tmp_path / "runs" / run_id)
        finally:
            await client.aclose()
        assert store.get_run(run_id)["cleanup_status"] == "done", store.events(run_id)
    assert {fake.profile(s.name)["status"] for s in (EVERGREEN, CMP, RENEWAL)} == {"ACTIVE"}
    assert not any(n.startswith("profile_") and n not in ("profile_get", "profile_create") for n in fake.route_order())
    assert fake.violations == []  # a profile delete would hit an unmodelled endpoint


async def test_run_stops_cleanly_when_the_profile_is_unusable(store, fake, tmp_path):
    from tests.integration import test_uc01_flow
    shared(fake, EVERGREEN, value=3)
    run = await test_uc01_flow.start(store, fake, "x1", tmp_path)
    assert run["status"] == "failed" and "exists with other settings – fix or rename it" in run["error"]
    assert fake.policies == {} and len(fake.divisions) == 1  # the division is in the ledger for the rollback
    assert [o["kind"] for o in store.objects("x1")] == ["division"]


@pytest.mark.parametrize("before", ["ACTIVE", "DISABLED"])
async def test_run_restores_a_deleted_shared_profile_and_says_so(store, fake, tmp_path, before):
    from tests.integration import test_uc01_flow
    old = shared(fake, EVERGREEN, status=before)
    fake.delete_profile(old)
    run = await test_uc01_flow.start(store, fake, "rs1", tmp_path)
    assert run["status"] == "completed", run["error"]
    (policy_obj,) = store.objects("rs1", "policy")
    assert fake.policies[policy_obj["dtm_id"]]["certificate_profile_id"] == old["id"] and old["status"] == "ACTIVE"
    assert fake.created_profiles == [] and fake.names("profile_undelete") == [old["id"]]
    assert fake.names("profile_enable") == ([old["id"]] if before == "DISABLED" else [])
    messages = [e["message"] for e in store.events("rs1")]
    assert (f"Restored the shared certificate profile {EVERGREEN.name} (5 years) – DTM keeps it permanently"
            in messages)
    assert not any(m.startswith(("Using the shared", "Created the shared", "Enabled again the shared"))
                   for m in messages)


async def test_run_fails_cleanly_on_a_deleted_profile_with_other_settings(store, fake, tmp_path):
    from tests.integration import test_uc01_flow
    old = shared(fake, EVERGREEN, value=2)
    fake.delete_profile(old)
    run = await test_uc01_flow.start(store, fake, "rs2", tmp_path)
    assert run["status"] == "failed" and "was deleted with other settings" in run["error"]
    assert old["status"] == "DELETED" and fake.created_profiles == [] and fake.policies == {}



async def test_restored_profile_not_listed_yet_is_a_clear_error(fake, monkeypatch):
    """Undelete answers 204, but the list still lags: a clear DTMError, nothing created."""
    old = shared(fake, EVERGREEN)
    fake.delete_profile(old)
    monkeypatch.setattr(fake, "_undelete_profile", lambda request, oid: httpx.Response(204))
    fake._register()  # the routes bind the handler at registration
    with pytest.raises(DTMError) as error:
        await call(fake, "shared_profile", EVERGREEN)
    assert str(error.value) == f"profile {EVERGREEN.name} was restored but is not listed yet – start the run again"
    assert fake.names("profile_undelete") == [old["id"]] and fake.created_profiles == []
    assert old["status"] == "DELETED"


async def test_undelete_refused_because_another_installation_restored_it(store, fake, tmp_path):
    """Between our look and our undelete someone else restored it: DTM answers 400, the next look
    finds the ACTIVE profile and the run goes on with it."""
    from tests.integration import test_uc01_flow
    old = shared(fake, EVERGREEN)
    fake.delete_profile(old)
    original = fake._list_profiles

    def list_then_restore(request):
        response = original(request)
        if request.url.params.get("status") == "DELETED":
            old["status"] = old.pop("status_before_delete")  # the other installation's undelete
        return response

    fake._list_profiles = list_then_restore
    fake._register()
    run = await test_uc01_flow.start(store, fake, "ud1", tmp_path)
    assert run["status"] == "completed", run["error"]
    assert fake.names("profile_undelete") == [old["id"]]  # ours was refused (not deleted any more)
    (policy_obj,) = store.objects("ud1", "policy")
    assert fake.policies[policy_obj["dtm_id"]]["certificate_profile_id"] == old["id"]
    assert fake.created_profiles == [] and old["status"] == "ACTIVE"


async def test_deleted_list_record_with_another_status_is_not_undeleted(fake, monkeypatch):
    """Should the status filter ever be ignored, only records really marked DELETED are restored."""
    import copy
    odd = shared(fake, EVERGREEN, id="odd-status")
    fake.profiles.remove(odd)  # only the DELETED listing returns it – with a status that is not DELETED
    retired_elsewhere = copy.deepcopy(odd) | {"status": "DISABLED"}
    original = fake._list_profiles

    def unfiltered(request):
        if request.url.params.get("status") == "DELETED":
            return fake._page(request, [retired_elsewhere])  # name matches, status does not
        return original(request)

    fake._list_profiles = unfiltered
    fake._register()
    profile_id, how = await call(fake, "shared_profile", EVERGREEN)
    assert how == "created" and fake.names("profile_undelete") == [] and profile_id != "odd-status"
