"""UC-6 – managed devices: each device is created in DTM with a fictitious hardware identity (serial number
or MAC address) and gets its certificate – CN = identity, not the device name – filed under it through the
group's attribute mapping. Factory via REST (API key, passcode, factory certificate), EST or CMPv2 on the
device-group endpoints; renewal per click via REST or the factory's protocol. Against the stateful fake
DTM (the facts verified live on NL), the fake openssl and the
station's routed httpx client."""

import json
import re

import httpx
import pytest
from cryptography import x509

from app import cleanup, devices, dtm, enrollment, evergreen, snippets
from tests.fakedtm import ACCOUNT_ID, ECDSA_CA_ID, NL_HOST, OTHER_ACCOUNT_ID, FakeDTM, _error
from tests.integration import test_replayable_steps
from tests.integration.test_uc03_flow import all_snippets

UC = "uc06"
# (factory protocol, authentication, field renewal)
COMBOS = [("rest", "apikey", "rest"), ("rest", "passcode", "rest"), ("rest", "certificate", "rest"),
          ("est", "passcode", "est"), ("est", "certificate", "est"), ("est", "passcode", "rest"),
          ("cmpv2", "passcode", "cmpv2"), ("cmpv2", "certificate", "cmpv2"), ("cmpv2", "certificate", "rest"),
          # one policy, two protocols (verified live): the field's protocol independent of the factory's
          ("rest", "apikey", "est"), ("rest", "apikey", "cmpv2"), ("est", "passcode", "cmpv2"),
          ("cmpv2", "passcode", "est"), ("rest", "certificate", "est")]
METHOD = {"rest": "SINGLE", "est": "EST", "cmpv2": "CMP_V2"}
NET = ("enroll_net", "cmp_openssl")  # the station's protocols – unused (and harmless) with the API key


def params(fake: FakeDTM, **overrides) -> dict:
    return {"dtm_host": fake.host, "account_id": ACCOUNT_ID, "variant": "api", "mode": "single", "count": 1,
            "ca_id": ECDSA_CA_ID, "ca_name": "Fake ECDSA ICA", "key_type": "P_256", "approval": False,
            "protocol": "rest", "auth": "apikey", "field": "rest", "identity": "serial"} | overrides


async def start(store, fake: FakeDTM, run_id: str, tmp_path, **overrides) -> dict:
    store.create_run(run_id, UC, params(fake, **overrides))
    client = fake.client(on_call=lambda msg: store.add_event(run_id, f"API {msg}", "api"))
    try:
        await devices.run(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


async def renew(store, fake: FakeDTM, run_id: str, tmp_path) -> dict:
    assert store.claim_status(run_id, "completed", "renewing")  # what POST /runs/{id}/renew does first
    client = fake.client()
    try:
        await devices.renew(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


async def do_cleanup(store, fake: FakeDTM, run_id: str, mode: str, tmp_path) -> dict:
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, run_id, mode, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


def names(run_id: str, count: int) -> list[str]:
    return [f"robot-{run_id}-uc06-minion-{i:04d}" for i in range(1, count + 1)]


def filed(fake: FakeDTM, device_id: str) -> list[dict]:
    return [c for c in fake.certificates.values() if c.get("device_id") == device_id]


def events(store, run_id) -> str:
    return "\n".join(e["message"] for e in store.events(run_id))


def run_devices(fake: FakeDTM) -> list[dict]:
    return sorted((d for d in fake.devices.values() if d["name"].startswith("robot-")), key=lambda d: d["name"])


# --- identity and form choices (unit level) ------------------------------------------------------------

def test_identity_serial_and_mac():
    assert devices.identity("ab12", 1, "serial") == "SN-AB12-0001"
    assert devices.identity("ab12", 42, "serial") == "SN-AB12-0042"
    macs = [devices.identity("ab12", n, "mac") for n in (1, 2, 256, 65536)]
    for mac in macs:
        assert re.fullmatch(r"02(:[0-9a-f]{2}){5}", mac), mac
        first = int(mac[:2], 16)
        assert first & 0b10 and not first & 0b1  # locally administered, unicast – never a vendor OUI
    assert len(set(macs)) == 4 and macs[0].endswith(":00:00:01") and macs[2].endswith(":00:01:00")
    assert devices.identity("ab12", 1, "mac") == macs[0]  # deterministic
    assert devices.identity("ab13", 1, "mac") != macs[0]  # unique per run


@pytest.mark.parametrize("protocol,auth,field,identity,ok", [
    ("rest", "apikey", "rest", "serial", True), ("est", "passcode", "est", "mac", True),
    ("est", "certificate", "rest", "serial", True), ("cmpv2", "passcode", "cmpv2", "serial", True),
    ("est", "apikey", "est", "serial", False),        # an API key works only with REST
    ("cmpv2", "apikey", "rest", "serial", False),
    ("est", "passcode", "cmpv2", "serial", True),     # one policy carries both protocols
    ("rest", "apikey", "est", "mac", True), ("rest", "apikey", "cmpv2", "serial", True),
    ("cmpv2", "certificate", "est", "serial", True),
    ("scep", "passcode", "rest", "serial", False), ("rest", "basic", "rest", "serial", False),
    ("rest", "apikey", "scep", "serial", False), ("rest", "apikey", "rest", "imei", False),
])
def test_check_choice(protocol, auth, field, identity, ok):
    assert (devices.check_choice(protocol, auth, field, identity) is None) is ok


# --- happy paths over every factory / field combination ------------------------------------------------

@pytest.mark.parametrize("protocol,auth,field", COMBOS)
async def test_devices_get_certificates_with_their_identity(store, enroll_net, cmp_openssl, tmp_path,
                                                            protocol, auth, field):
    fake = enroll_net
    run = await start(store, fake, "m1", tmp_path, mode="batch", count=2, protocol=protocol, auth=auth, field=field)
    assert run["status"] == "completed", (run["error"], events(store, "m1"))
    r = run["result"]
    assert fake.violations == []

    (group,) = fake.device_groups.values()
    assert group["name"] == "robot-m1-uc06-group" and group["attributes"] == ["serial_number"]
    (policy,) = fake.policies.values()
    assert policy["require_device_group_for_enroll"] is True
    assert policy["certificate_management_methods"] == list(dict.fromkeys([METHOD[protocol], METHOD[field]]))
    for method, section in (("SINGLE", "single_cert_request_parameters"), ("CMP_V2", "cmp_request_parameters")):
        assert (section in policy) is (method in policy["certificate_management_methods"]), section
    # the device authenticates in the field with its certificate – an authentication policy is needed
    # even with the API key in the factory, but no credential then
    assert ("authentication_policy_id" in policy) is (auth != "apikey" or field != "rest")
    profile = next(p for p in fake.profiles if p["id"] == policy["certificate_profile_id"])
    assert profile.get("allow_bare_public_key", False) is ("cmpv2" in (protocol, field))
    (assignment,) = group["policies"]
    assert (assignment["policy_id"], assignment["status"]) == (policy["id"], "ACTIVE")
    assert assignment["device_field_mappings"] == [{"key": "serial_number", "field": "subject.common_name"}]

    # DTM: exactly the run's devices (no Device-<uuid> created by an unmatched identity), each with
    # its identity as attribute and exactly one certificate whose CN is that identity – not the name
    assert len(fake.devices) == 2 and [d["name"] for d in run_devices(fake)] == names("m1", 2)
    for number, device in enumerate(run_devices(fake), 1):
        ident = f"SN-M1-{number:04d}"
        assert device["attributes"] == [{"key": "serial_number", "value": ident}]
        (cert,) = filed(fake, device["id"])
        assert cert["common_name"] == ident != device["name"] and cert["status"] == "ISSUED"
        if protocol != "rest":  # mapped by the attribute (verified live: ENROLLED → REGISTERED)
            assert device["device_status"] == "REGISTERED"

    # the run page shows both side by side
    assert [d["name"] for d in r["devices"]] == names("m1", 2)
    for number, d in enumerate(r["devices"], 1):
        assert d["identity"] == f"SN-M1-{number:04d}"
        (listed,) = d["certificates"]
        (cert,) = filed(fake, d["id"])
        assert listed["common_name"] == d["identity"] and listed["serial"] == cert["serial_number"]
        assert listed["status"] == "issued" and d["certificate_id"] == cert["id"]
    assert r["certificate_total"] == 2 and r["renewals"] == [] and "estimate_min" in r
    assert r["identity"] == "Serial number"

    # certificates for download, never keys in the run data; the device key only where the device renews itself
    folder = tmp_path / "runs" / "m1"
    assert sorted(p.stem for p in (folder / "certificates").iterdir()) == sorted(c["serial"] for c in r["certificates"])
    assert "PRIVATE KEY" not in json.dumps(run) + events(store, "m1")
    for name in names("m1", 2):
        device_dir = devices.device_dir(folder, name)
        assert device_dir.exists() is (field != "rest"), name
        if field != "rest":
            assert (device_dir / "device.pem").stat().st_mode & 0o777 == 0o600
            assert (device_dir / "ca-chain.pem").exists() is (field == "cmpv2")
    ledger = {(o["kind"], o["name"]) for o in store.objects("m1")}
    assert {n for k, n in ledger if k == "device"} == set(names("m1", 2))
    kinds = {k for k, _ in ledger}
    assert ("auth_policy" in kinds) is (auth != "apikey" or field != "rest")
    assert ("passcode" in kinds) is (auth == "passcode") and ("auth_certificate" in kinds) is (auth == "certificate")
    assert len(fake.active_auth("passcode") + fake.active_auth("auth_certificate")) == (auth != "apikey")


async def test_mac_identity(store, fake, tmp_path):
    run = await start(store, fake, "m2", tmp_path, identity="mac")
    assert run["status"] == "completed", run["error"]
    (group,) = fake.device_groups.values()
    assert group["attributes"] == ["mac_address"]
    assert group["policies"][0]["device_field_mappings"] == [{"key": "mac_address", "field": "subject.common_name"}]
    (device,) = fake.devices.values()
    mac = devices.identity("m2", 1, "mac")
    assert device["attributes"] == [{"key": "mac_address", "value": mac}]
    assert [c["common_name"] for c in filed(fake, device["id"])] == [mac]
    assert run["result"]["identity"] == "MAC address"


async def test_group_lookup_and_list_lag_are_retried(store, fake, tmp_path):
    fake.device_group_list_lag = dtm.LOOKUP_RETRIES - 1
    fake.device_cert_list_lag = 2  # total already counts, records not yet (verified live)
    run = await start(store, fake, "m3", tmp_path)
    assert run["status"] == "completed", run["error"]
    assert len(run["result"]["devices"][0]["certificates"]) == 1
    assert fake.route_order().count("device_certificates") == 3


# --- the identity check: DTM files a REST request under the named device whatever the CN says ----------

async def test_rest_certificate_with_another_cn_fails_the_run(store, fake, tmp_path):
    fake.single_cn_override = "SN-SOMEONE-ELSE"  # DTM files it under the device anyway (device_id wins)
    run = await start(store, fake, "c1", tmp_path)
    assert run["status"] == "failed" and "instead of its identity 'SN-C1-0001'" in run["error"]
    run = await do_cleanup(store, fake, "c1", "full", tmp_path)  # what DTM issued is revoked anyway
    assert run["cleanup_status"] == "done" and fake.issued() == [] and fake.active_devices() == []


async def test_certificate_filed_under_another_device_fails_the_run(store, fake, tmp_path):
    fake.device_answer_override = {"id": "someone-elses-device", "name": "x", "new_device": False}
    run = await start(store, fake, "c2", tmp_path, mode="batch", count=2)
    assert run["status"] == "failed" and "did not file the certificate" in run["error"]
    assert len(fake.devices) == 1  # stopped at the first device


async def test_device_without_its_certificate_fails_the_run(store, fake, tmp_path):
    fake.device_cert_list_lag = devices.LIST_RETRIES + 5  # DTM never lists it under the device
    run = await start(store, fake, "c3", tmp_path)
    assert run["status"] == "failed" and "lists 0 of 1 certificate(s)" in run["error"]
    assert fake.route_order().count("device_certificates") == devices.LIST_RETRIES


async def test_foreign_identity_under_the_device_fails_the_run(store, fake, tmp_path):
    def plant(request):  # another certificate shows up under the device before it is read
        for device in fake.devices.values():
            record, _c, _k = fake._new_certificate(next(iter(fake.policies)), "SN-INTRUDER-0001")
            record["device_id"] = device["id"]
        fake.fail.pop("device_certificates")
    fake.fail["device_certificates"] = plant
    run = await start(store, fake, "c4", tmp_path)
    assert run["status"] == "failed" and "holds certificates of another identity" in run["error"]
    assert "SN-INTRUDER-0001" in run["error"]


@pytest.mark.parametrize("protocol", ["est", "cmpv2"])
async def test_device_without_matching_identity_is_detected(store, enroll_net, cmp_openssl, tmp_path, monkeypatch,
                                                            protocol):
    """EST/CMPv2 map by the attribute – a device whose attribute does not match gets nothing; DTM files the
    certificate under a new Device-<uuid> in the group instead (verified live). The run must notice, and
    the rollback must remove the stray device too (it is in the run's group)."""
    fake = enroll_net
    real = dtm.device_body
    monkeypatch.setattr(dtm, "device_body", lambda *a: real(*a[:-1], "SN-MISMATCH"))
    run = await start(store, fake, "c5", tmp_path, protocol=protocol, auth="passcode", field="rest")
    assert run["status"] == "failed" and "lists 0 of 1 certificate(s)" in run["error"]
    (stray,) = [d for d in fake.devices.values() if d["name"].startswith("Device-")]
    assert [c["common_name"] for c in filed(fake, stray["id"])] == ["SN-C5-0001"]
    run = await do_cleanup(store, fake, "c5", "full", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "c5")
    assert fake.active_devices() == [] and fake.issued() == []


async def test_plain_cmp_path_would_not_file_under_the_device(store, enroll_net, cmp_openssl, tmp_path, monkeypatch):
    """Verified live: the plain CMPv2 path issues without filing – the device-group path is what matters."""
    monkeypatch.setattr(enrollment, "cmp_path", lambda alternative_id, group_id=None:
                        enrollment.CMP_PATH.format(alternative_id=alternative_id))
    run = await start(store, enroll_net, "c6", tmp_path, protocol="cmpv2", auth="passcode", field="rest")
    assert run["status"] == "failed" and "lists 0 of 1 certificate(s)" in run["error"]


async def test_dtm_refusing_the_device_fails_with_its_message(store, fake, tmp_path):
    """An Essentials-only account: DTM refuses the device – the run shows DTM's error."""
    fake.fail["device_enroll"] = _error(403, "feature not licensed")
    run = await start(store, fake, "c7", tmp_path)
    assert run["status"] == "failed" and "feature not licensed" in run["error"]
    assert store.objects("c7", "device") == [] and len(store.objects("c7", "device_group")) == 1


async def test_group_assignment_without_status_is_refused(store, fake, tmp_path, monkeypatch):
    """Verified live: DTM refuses a policy assignment without status – the run fails at the group step."""
    real = dtm.device_group_body

    def without_status(*args):
        body = real(*args)
        del body["policies"][0]["status"]
        return body
    monkeypatch.setattr(dtm, "device_group_body", without_status)
    run = await start(store, fake, "c8", tmp_path)
    assert run["status"] == "failed" and "Policy assignment status is required" in run["error"]
    assert fake.devices == {}


async def test_group_that_never_shows_up_fails_and_is_found_by_the_rollback(store, fake, tmp_path):
    fake.device_group_list_lag = dtm.LOOKUP_RETRIES
    run = await start(store, fake, "c9", tmp_path)
    assert run["status"] == "failed" and "not found by its name" in run["error"]
    assert store.objects("c9", "device_group") == []
    run = await do_cleanup(store, fake, "c9", "full", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "c9")
    assert "Found unrecorded device_group robot-c9-uc06-group" in events(store, "c9")
    assert [g["status"] for g in fake.device_groups.values()] == ["DELETED"]


# --- renewal -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("protocol,auth,field", [("rest", "apikey", "rest"), ("est", "passcode", "est"),
                                                 ("est", "certificate", "est"), ("cmpv2", "passcode", "cmpv2"),
                                                 ("cmpv2", "certificate", "rest"), ("rest", "apikey", "est"),
                                                 ("rest", "apikey", "cmpv2"), ("est", "passcode", "cmpv2"),
                                                 ("cmpv2", "passcode", "est")])
async def test_renewal_rounds_land_under_the_same_devices(store, enroll_net, cmp_openssl, tmp_path,
                                                          protocol, auth, field):
    fake = enroll_net
    await start(store, fake, "r1", tmp_path, mode="batch", count=2, protocol=protocol, auth=auth, field=field)
    before = {d["id"]: d for d in store.get_run("r1")["result"]["devices"]}
    pems = {n: (devices.device_dir(tmp_path / "runs" / "r1", n) / "device.pem").read_bytes()
            for n in names("r1", 2) if field != "rest"}
    await renew(store, fake, "r1", tmp_path)
    run = await renew(store, fake, "r1", tmp_path)
    assert run["status"] == "completed" and run["progress"] is None, events(store, "r1")
    r = run["result"]
    assert len(r["renewals"]) == 2 and r["certificate_total"] == 6
    assert "Renewal failed" not in events(store, "r1")
    for d in r["devices"]:
        assert d["id"] in before and d["issued"] == 3 and len(d["certificates"]) == 3
        assert {c["common_name"] for c in d["certificates"]} == {d["identity"]}
        records = filed(fake, d["id"])
        assert {c["common_name"] for c in records} == {d["identity"]} and len(records) == 3
        # verified live: the renewals land under the same device, recorded with the field's method
        assert [c["enrollment_method"] for c in records] == [METHOD[protocol]] + [METHOD[field]] * 2
    assert len(fake.devices) == 2  # no device was created on the way
    if field == "rest":
        # verified live: the old certificates are marked renewed and stay ISSUED
        for d in r["devices"]:
            assert sum(c["renewed"] for c in d["certificates"]) == 2 and d["certificate_id"] == filed(fake, d["id"])[-1]["id"]
    else:  # the device switched to its new key and certificate
        for name, pem in pems.items():
            now = (devices.device_dir(tmp_path / "runs" / "r1", name) / "device.pem").read_bytes()
            assert now != pem and now.count(b"BEGIN PRIVATE KEY") == 1
    calls = [c for c in r["api_calls"] if c.get("phase") == "renewal" and c["method"] in ("PUT", "POST")]
    assert calls and all(c["count"] == 4 for c in calls)
    assert len(list((tmp_path / "runs" / "r1" / "certificates").iterdir())) == 6


async def test_failed_renewal_keeps_what_dtm_issued_and_frees_the_run(store, fake, tmp_path):
    await start(store, fake, "r2", tmp_path, mode="batch", count=2)
    seen = []

    def second_fails(request):
        seen.append(request)
        return _error(500, "upstream trouble") if len(seen) == 2 else None
    fake.fail["renew"] = second_fails
    run = await renew(store, fake, "r2", tmp_path)
    assert run["status"] == "completed" and run["progress"] is None
    assert "Renewal failed" in events(store, "r2")
    r = run["result"]
    # the broken round counts against the limit; the first device's new certificate is recorded
    assert [x.get("failed") for x in r["renewals"]] == [True] and r["renewals"][0]["devices"] == 1
    assert r["certificate_total"] == 3
    del fake.fail["renew"]
    run = await renew(store, fake, "r2", tmp_path)
    assert [x.get("failed") for x in run["result"]["renewals"]] == [True, None], events(store, "r2")
    assert run["result"]["certificate_total"] == 5


async def test_renewal_after_a_timed_out_renewal_continues(store, fake, tmp_path):
    """DTM completed a renewal although the client gave up: the old certificate can no longer be renewed
    (renew_allowed false) – the next round must renew the certificate DTM lists as current."""
    run = await start(store, fake, "r3", tmp_path)
    (device,) = run["result"]["devices"]

    def completed_server_side(request):
        old = fake.certificates[device["certificate_id"]]
        record, _cert, _key = fake._new_certificate(old["policy_id"], old["common_name"])
        record |= {"device_id": device["id"], "renewed_from": old["id"]}
        old["is_renewed"] = True
        raise httpx.ReadTimeout("fake timeout", request=request)
    fake.fail["renew"] = completed_server_side
    run = await renew(store, fake, "r3", tmp_path)
    assert run["status"] == "completed" and "Renewal failed" in events(store, "r3")
    del fake.fail["renew"]
    run = await renew(store, fake, "r3", tmp_path)
    assert [x.get("failed") for x in run["result"]["renewals"]] == [True, None], events(store, "r3")
    assert len(filed(fake, device["id"])) == 3


async def test_renewal_with_another_cn_is_reported(store, fake, tmp_path):
    await start(store, fake, "r4", tmp_path)
    fake.device_answer_override = {"id": "other", "name": "other"}
    run = await renew(store, fake, "r4", tmp_path)
    assert run["status"] == "completed" and [x.get("failed") for x in run["result"]["renewals"]] == [True]
    assert "did not file the certificate" in events(store, "r4")


async def test_renewal_without_group_any_more_is_reported(store, fake, tmp_path):
    await start(store, fake, "r5", tmp_path)
    (group,) = store.objects("r5", "device_group")
    store.mark_removed("r5", "device_group", group["dtm_id"])
    run = await renew(store, fake, "r5", tmp_path)
    assert run["status"] == "completed" and "no certificate policy or device group" in events(store, "r5")
    assert "renew" not in fake.route_order()


# --- rollback ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("platform", ["us", "nl"])
async def test_full_rollback_order_api_key(store, fake, tmp_path, platform):
    fake = FakeDTM(host=NL_HOST) if platform == "nl" else fake
    await start(store, fake, "d1", tmp_path, mode="batch", count=2)
    await renew(store, fake, "d1", tmp_path)
    assert len(fake.issued()) == 4  # renewed certificates stay ISSUED (verified live)
    run = await do_cleanup(store, fake, "d1", "full", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "d1")
    assert fake.issued() == [] and fake.violations == []
    assert fake.active_devices() == [] and [g["status"] for g in fake.device_groups.values()] == ["DELETED"]
    assert fake.policies == {} and fake.divisions == {} and store.objects("d1") == []
    order = fake.route_order()
    last_revoke = max(i for i, n in enumerate(order) if n == "revoke")
    device_deletes = [i for i, n in enumerate(order) if n == "device_delete"]
    group_delete = order.index("device_group_delete")
    assert len(device_deletes) == 2
    assert last_revoke < min(device_deletes) and max(device_deletes) < group_delete < order.index("policy_delete")
    assert order.index("device_disable") < min(device_deletes) and order.index("device_group_disable") < group_delete
    assert not (tmp_path / "runs" / "d1").exists()


@pytest.mark.parametrize("protocol,auth,field", [("est", "passcode", "est"), ("cmpv2", "certificate", "cmpv2")])
async def test_full_rollback_with_credentials_and_device_keys(store, enroll_net, cmp_openssl, tmp_path,
                                                              protocol, auth, field):
    fake = enroll_net
    await start(store, fake, "d2", tmp_path, protocol=protocol, auth=auth, field=field)
    await renew(store, fake, "d2", tmp_path)
    assert (devices.device_dir(tmp_path / "runs" / "d2", names("d2", 1)[0]) / "device.pem").exists()
    if protocol == "cmpv2":
        cmp_openssl.sync_to_dtm()
    run = await do_cleanup(store, fake, "d2", "full", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "d2")
    assert fake.issued() == [] and fake.active_devices() == [] and fake.policies == {}
    kind = "passcode" if auth == "passcode" else "auth_certificate"
    assert fake.active_auth(kind) == [] and fake.active_auth("auth_policy") == []
    order = fake.route_order()
    assert order.index("device_group_delete") < order.index("policy_delete") < order.index("auth_policy_delete")
    assert not (tmp_path / "runs" / "d2").exists()  # the simulated devices' keys are gone


async def test_revoke_only_keeps_devices_and_group(store, fake, tmp_path):
    await start(store, fake, "d3", tmp_path)
    run = await do_cleanup(store, fake, "d3", "certificates", tmp_path)
    assert run["cleanup_status"] == "done" and fake.issued() == []
    assert len(fake.active_devices()) == 1 and [g["status"] for g in fake.device_groups.values()] == ["ACTIVE"]
    assert "device_delete" not in fake.route_order()


async def test_rollback_of_an_already_deleted_device_is_idempotent(store, fake, tmp_path):
    run = await start(store, fake, "d4", tmp_path)
    (device,) = run["result"]["devices"]
    fake.devices[device["id"]]["status"] = "DELETED"  # e.g. deleted in the portal
    run = await do_cleanup(store, fake, "d4", "full", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "d4")
    assert "device_delete" not in fake.route_order()


@pytest.mark.parametrize("filter_ignored", [False, True])
async def test_unrecorded_devices_are_discovered_foreign_ones_are_not(store, fake, tmp_path, filter_ignored):
    run = await start(store, fake, "d5", tmp_path)
    group_id = run["result"]["api_variables"]["GROUP_ID"]
    fake.device_list_ignores_group = filter_ignored  # the client checks membership on each record, too
    base = {"device_group_id": group_id, "status": "ACTIVE", "device_status": "ENROLLED",
            "operational_status": "ENABLED", "description": "", "attributes": []}
    # a device the run created but never recorded (crash between create and ledger) …
    fake.devices["lost"] = base | {"id": "lost", "name": "robot-d5-uc06-minion-0002", "account_id": ACCOUNT_ID}
    # … one a replayed step or an unmatched EST identity created in the run's group …
    fake.devices["replayed"] = base | {"id": "replayed", "name": "Device-0f8e2b1c-3d4a-4b5c-8d9e-1a2b3c4d5e6f",
                                       "account_id": ACCOUNT_ID}
    # … a device a human put into the run's group under a name of their own …
    fake.devices["human"] = base | {"id": "human", "name": "lab-printer-7", "account_id": ACCOUNT_ID}
    # … one that only looks like DTM's own name …
    fake.devices["fakeauto"] = base | {"id": "fakeauto", "name": "Device-1234", "account_id": ACCOUNT_ID}
    # … one of another account in the list (the device endpoints ignore account_id) …
    fake.devices["foreign"] = base | {"id": "foreign", "name": "robot-d5-uc06-minion-0003",
                                      "account_id": OTHER_ACCOUNT_ID}
    # … and devices of this account in another group – even with the run's name
    fake.devices["stranger"] = base | {"id": "stranger", "name": "someone-device", "account_id": ACCOUNT_ID,
                                       "device_group_id": "other-group"}
    fake.devices["lookalike"] = base | {"id": "lookalike", "name": "robot-d5-uc06-minion-0004",
                                        "account_id": ACCOUNT_ID, "device_group_id": "other-group"}
    fake.device_groups["foreign-group"] = {"id": "foreign-group", "name": "robot-d5-uc06-group",
                                           "account_id": OTHER_ACCOUNT_ID, "status": "ACTIVE", "hidden": 0,
                                           "policies": [], "division_id": "x", "attributes": []}
    run = await do_cleanup(store, fake, "d5", "full", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "d5")
    assert "Found unrecorded device robot-d5-uc06-minion-0002" in events(store, "d5")
    assert fake.devices["lost"]["status"] == fake.devices["replayed"]["status"] == "DELETED"
    untouched = {"foreign", "stranger", "lookalike", "human", "fakeauto"}
    assert {fake.devices[i]["status"] for i in untouched} == {"ACTIVE"}
    assert fake.device_groups["foreign-group"]["status"] == "ACTIVE"
    touched = {oid for name, oid in fake.calls if name.startswith(("device_", "device_group_"))}
    assert not touched & (untouched | {"foreign-group"})


async def test_rollback_refuses_a_device_of_another_account(store, fake, tmp_path):
    await start(store, fake, "d6", tmp_path)
    fake.devices["foreign"] = {"id": "foreign", "name": "robot-d6-uc06-minion-0009", "account_id": OTHER_ACCOUNT_ID,
                               "device_group_id": "elsewhere", "status": "ACTIVE", "operational_status": "ENABLED"}
    store.add_object("d6", "device", "foreign", "robot-d6-uc06-minion-0009")
    run = await do_cleanup(store, fake, "d6", "full", tmp_path)
    assert run["cleanup_status"] == "failed" and "another account" in events(store, "d6")
    assert fake.devices["foreign"]["status"] == "ACTIVE"
    assert ("device_disable", "foreign") not in fake.calls and ("device_delete", "foreign") not in fake.calls


def test_run_device_names():
    assert dtm.run_device("robot-d1-uc06-minion-0001", "robot-d1-")
    assert dtm.run_device("Device-0f8e2b1c-3d4a-4b5c-8d9e-1a2b3c4d5e6f", "robot-d1-")
    for name in ("robot-d10-uc06-minion-0001", "lab-printer-7", "Device-1234", "device-0f8e2b1c-3d4a-4b5c-8d9e-1a2b3c4d5e6f",
                 "Device-0f8e2b1c-3d4a-4b5c-8d9e-1a2b3c4d5e6f-x", "x-Device-0f8e2b1c-3d4a-4b5c-8d9e-1a2b3c4d5e6f"):
        assert not dtm.run_device(name, "robot-d1-"), name


async def test_device_list_record_naming_another_group_is_not_returned(fake):
    """A record that lists its groups must name the run's group – even with the run's name."""
    fake.device_list_ignores_group = True
    base = {"status": "ACTIVE", "account_id": ACCOUNT_ID, "device_group_id": "g-run"}
    fake.devices["member"] = base | {"id": "member", "name": "robot-d8-uc06-minion-0001",
                                     "device_groups": [{"id": "g-run"}]}
    fake.devices["other"] = base | {"id": "other", "name": "robot-d8-uc06-minion-0002",
                                    "device_groups": [{"id": "g-other"}]}
    client = fake.client()
    try:
        found = await client.device_ids("g-run", "robot-d8-uc06-minion-")
    finally:
        await client.aclose()
    assert found == [("member", "robot-d8-uc06-minion-0001")]


async def test_rollback_refuses_a_ledger_device_with_a_foreign_name(store, fake, tmp_path):
    run = await start(store, fake, "d9", tmp_path)
    group_id = run["result"]["api_variables"]["GROUP_ID"]
    fake.devices["human"] = {"id": "human", "name": "lab-printer-7", "account_id": ACCOUNT_ID,
                             "device_group_id": group_id, "status": "ACTIVE", "operational_status": "ENABLED"}
    store.add_object("d9", "device", "human", "lab-printer-7")  # a corrupted ledger row
    run = await do_cleanup(store, fake, "d9", "full", tmp_path)
    assert run["cleanup_status"] == "failed" and "outside run prefix" in events(store, "d9")
    assert fake.devices["human"]["status"] == "ACTIVE"
    assert not {n for n, oid in fake.calls if oid == "human" and n.startswith("device_")}
    assert "device_delete" not in fake.route_order()  # refused before anything is deleted


async def test_rollback_refuses_a_group_of_another_account(store, fake, tmp_path):
    await start(store, fake, "d7", tmp_path)
    fake.device_groups["foreign-group"] = {"id": "foreign-group", "name": "robot-d7-uc06-group",
                                           "account_id": OTHER_ACCOUNT_ID, "status": "ACTIVE", "hidden": 0,
                                           "policies": [], "division_id": "x", "attributes": []}
    store.add_object("d7", "device_group", "foreign-group", "robot-d7-uc06-group")
    run = await do_cleanup(store, fake, "d7", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert fake.device_groups["foreign-group"]["status"] == "ACTIVE"
    assert not {("device_group_disable", "foreign-group"), ("device_group_delete", "foreign-group")} & set(fake.calls)


# --- reproducible steps --------------------------------------------------------------------------------

@pytest.mark.parametrize("protocol,auth,field", COMBOS)
async def test_steps_render_and_replay(store, enroll_net, cmp_openssl, tmp_path, protocol, auth, field):
    fake = enroll_net
    await start(store, fake, "s1", tmp_path, mode="batch", count=2, protocol=protocol, auth=auth, field=field)
    run = await renew(store, fake, "s1", tmp_path)
    assert run["status"] == "completed", events(store, "s1")
    text = all_snippets(run)
    for var in ("GROUP_ID", "DEVICE_ID", "DEVICE_NAME", "IDENTITY") + (("CERT_ID",) if field == "rest" else ()):
        assert f"${var}" in text or f"${{{var}}}" in text, var
        assert f"$env:{var}" in text, var
    assert not re.findall(r"(?<![$\w:])\{(GROUP_ID|DEVICE_ID|CERT_ID|DEVICE_NAME|IDENTITY)\}", text)
    calls = run["result"]["api_calls"]
    captured = [c["spec"]["capture"]["var"] for c in calls if (c.get("spec") or {}).get("capture")]
    assert "GROUP_ID" in captured and "DEVICE_ID" in captured
    assert ("CERT_ID" in captured) is (field == "rest")  # the current certificate is read from DTM first
    commands = json.dumps([c["spec"] for c in calls if c.get("spec")])
    if protocol == "est":
        assert "/device-group/${GROUP_ID}/simpleenroll" in text
    if protocol == "cmpv2":
        assert "/device-group/" in commands
    test_replayable_steps.assert_replayable(run, fake)
    ids = {*fake.devices, *fake.device_groups, *fake.certificates}
    variables = run["result"]["api_variables"]
    for dialect in snippets.DIALECTS:
        steps = snippets.script(variables, calls, dialect).split(snippets.preamble(variables, dialect), 1)[1]
        assert not [i for i in ids if i in steps], dialect
        # the replayed steps draw their own identity – never the run's
        assert "SN-S1-" not in steps and "robot-s1-" not in steps, dialect
    assert "PRIVATE KEY" not in text


async def test_cmpv2_with_another_method_needs_the_bare_key_profile(store, fake, tmp_path, monkeypatch):
    """Verified live: SINGLE/EST + CMP_V2 in one policy without a bare-key profile – DTM refuses the policy."""
    monkeypatch.setattr(dtm, "PROFILE_RENEWAL_CMP", dtm.PROFILE_RENEWAL)
    run = await start(store, fake, "b1", tmp_path, field="cmpv2")
    assert run["status"] == "failed" and "allowed bare public key" in run["error"]
    assert fake.policies == {} and fake.devices == {}


@pytest.mark.parametrize("protocol,auth,field", [("rest", "apikey", "cmpv2"), ("est", "passcode", "cmpv2"),
                                                 ("cmpv2", "passcode", "cmpv2"), ("rest", "apikey", "est")])
async def test_ca_chain_step_only_where_the_factory_did_not_build_it(store, enroll_net, cmp_openssl, tmp_path,
                                                                     protocol, auth, field):
    run = await start(store, enroll_net, "b2", tmp_path, protocol=protocol, auth=auth, field=field)
    assert run["status"] == "completed", run["error"]
    purposes = [c["purpose"] for c in run["result"]["api_calls"]]
    assert purposes.count("Build ca-chain.pem from the policy") == ("cmpv2" in (protocol, field))
    assert run["result"]["cmp_id"] if "cmpv2" in (protocol, field) else not run["result"].get("cmp_id")
