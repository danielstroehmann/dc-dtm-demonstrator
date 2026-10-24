"""UC-4 – one device enrolled via EST in the factory, renewed in the field via EST simplereenroll
(mTLS with its current certificate) against the stateful fake DTM."""

import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import certs, cleanup, enrollment, snippets
from app.store import Store
from tests.fakedtm import ACCOUNT_ID, CLIENTAUTH_HOST, ECDSA_CA_ID, HOST, PROFILE_ID, FakeDTM
from tests.integration.test_uc01_flow import assert_certificate_files
from tests.integration.test_uc03_flow import all_snippets, key_body, secrets_seen  # noqa: F401 – fixture

UC = "uc04"


def params(**overrides) -> dict:
    return {"dtm_host": HOST, "account_id": ACCOUNT_ID, "variant": "api", "mode": "single", "count": 1,
            "ca_id": ECDSA_CA_ID, "ca_name": "Fake ECDSA ICA", "key_type": "P_256", "profile_id": PROFILE_ID,
            "approval": False, "protocol": "est", "auth": "passcode"} | overrides


async def start(store, fake: FakeDTM, run_id: str, tmp_path, **overrides):
    store.create_run(run_id, UC, params(**overrides))
    client = fake.client(on_call=lambda msg: store.add_event(run_id, f"API {msg}", "api"))
    try:
        await enrollment.run(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


async def renew(store, run_id: str, tmp_path):
    await enrollment.renew(store, run_id, tmp_path / "runs" / run_id)
    return store.get_run(run_id)


async def do_cleanup(store, fake: FakeDTM, run_id: str, mode: str, tmp_path):
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, run_id, mode, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


def device_file(tmp_path, run_id) -> bytes:
    return (tmp_path / "runs" / run_id / "device" / "device.pem").read_bytes()


def device_key(tmp_path, run_id) -> bytes:
    text = device_file(tmp_path, run_id).decode()
    return text[text.index("-----BEGIN PRIVATE KEY-----"):text.index("-----END PRIVATE KEY-----")].encode()  # gitleaks:allow – PEM markers, no key


def assert_device_consistent(tmp_path, run_id, newest: dict):
    """One file, 0600, in a 0700 dir, nothing else there (no temp file): exactly one key and exactly
    the newest certificate, and they belong together."""
    device = tmp_path / "runs" / run_id / "device"
    assert [p.name for p in device.iterdir()] == ["device.pem"]
    assert device.stat().st_mode & 0o777 == 0o700 and (device / "device.pem").stat().st_mode & 0o777 == 0o600
    data = device_file(tmp_path, run_id)
    assert data.count(b"-----BEGIN PRIVATE KEY-----") == 1 and data.count(b"-----BEGIN") == 2
    key = serialization.load_pem_private_key(data, None)
    (cert,) = x509.load_pem_x509_certificates(data)
    assert format(cert.serial_number, "X") == newest["serial"]
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()


def db_text(store, run_id) -> str:
    return json.dumps(store.get_run(run_id)) + json.dumps(store.events(run_id))


def renewal_requests(fake: FakeDTM):
    return [r for r in fake.enroll_requests if r.url.path.endswith("/simplereenroll")]


@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_enroll_and_renew_twice(store, enroll_net, secrets_seen, tmp_path, auth):  # noqa: F811
    fake = enroll_net
    run = await start(store, fake, "u4", tmp_path, auth=auth)
    assert run["status"] == "completed", run["error"]
    r = run["result"]
    assert r["renewals"] == [] and "estimate_min" not in r and "estimate_devices" not in r
    assert r["certificate_total"] == 1 and r["protocol"] == "est"
    cn = r["certificates"][0]["common_name"]
    assert cn == "robot-u4-uc04-est-0001"
    assert_device_consistent(tmp_path, "u4", r["certificates"][0])
    keys = [device_key(tmp_path, "u4")]
    # the renewal block is there before the first renewal: every step, not yet run
    seeded = [c for c in r["api_calls"] if c["phase"] == "renewal"]
    assert [c["purpose"] for c in seeded] == [s["purpose"] for s in enrollment.renew_steps(cn, "P_256")]
    assert [(c["count"], c["seconds"]) for c in seeded] == [(0, None)] * 3

    for n in (1, 2):
        run = await renew(store, "u4", tmp_path)
        assert run["status"] == "completed", store.events("u4")[-3:]
        r = run["result"]
        assert r["certificate_total"] == len(r["certificates"]) == n + 1
        assert len(r["renewals"]) == n
        newest = r["certificates"][-1]
        assert r["renewals"][-1]["serial"] == newest["serial"]
        assert set(r["renewals"][-1]) == {"serial", "seconds", "keygen_s", "attempts", "at"}
        assert r["renewals"][-1]["attempts"] == 1
        assert newest["common_name"] == cn  # same identity, new serial
        assert_device_consistent(tmp_path, "u4", newest)
        keys.append(device_key(tmp_path, "u4"))
        assert keys[-1] != keys[-2]  # a fresh key pair per renewal

    serials = [c["serial"] for c in r["certificates"]]
    assert len(set(serials)) == 3
    # the device authenticated with its then-current certificate each time
    assert fake.reenroll_presented == serials[:2]
    for request in renewal_requests(fake):
        assert request.url.host == CLIENTAUTH_HOST
        assert {"x-api-key", "authorization", "x-passcode"}.isdisjoint(request.headers)
        assert "account_id" not in request.url.params
    # renewal does not revoke: all three certificates are issued in DTM
    assert {c["common_name"] for c in fake.issued()} == {cn} and len(fake.issued()) == 3
    assert_certificate_files(tmp_path / "runs" / "u4", r["certificates"])

    # reproducible steps: setup + recurring (factory enrollment) + renewal block, counts add up
    calls = r["api_calls"]
    assert {c["phase"] for c in calls} == {"setup", "recurring", "renewal"}
    renewal = [c for c in calls if c["phase"] == "renewal"]
    steps = enrollment.renew_steps(cn, "P_256")
    assert [(c["purpose"], c["method"], c["path"], c["spec"]) for c in renewal] == [
        (s["purpose"], s["method"], s["path"], {"command": s["command"]}) for s in steps]
    assert [c["count"] for c in renewal] == [2, 2, 2]
    call = next(c for c in renewal if c["method"] == "POST")
    assert abs(call["seconds"] - sum(x["seconds"] for x in r["renewals"])) <= 0.02
    recurring = [c for c in calls if c["phase"] == "recurring"]
    assert [c["count"] for c in recurring if c["method"] == "POST"] == [1]

    # no key material or secret anywhere but the device directory
    stored = db_text(store, "u4") + all_snippets(run)
    assert "PRIVATE KEY" not in stored and "BEGIN CERTIFICATE" not in db_text(store, "u4")
    assert len(secrets_seen) == 3 + (auth == "certificate")
    for key in secrets_seen:
        assert key_body(key) not in stored
    if auth == "passcode":
        (passcode_record,) = fake.auth_objects["passcode"].values()
        passcode = passcode_record["body"]["passcode"]
        assert passcode not in stored
    assert any(e["message"].startswith("Renewed in ") and "the previous certificate stays valid" in e["message"]
               for e in store.events("u4"))
    others = [p for p in (tmp_path / "runs" / "u4").rglob("*") if p.is_file() and p.parent.name != "device"]
    assert all("PRIVATE KEY" not in p.read_text() for p in others)
    assert fake.violations == []


async def test_renewal_retries_while_dtm_does_not_accept_the_new_certificate(store, enroll_net, tmp_path,
                                                                            fast_timing):
    fake = enroll_net
    await start(store, fake, "rt1", tmp_path)
    fake.reenroll_unauthorized = 2
    fast_timing.clear()
    run = await renew(store, "rt1", tmp_path)
    assert run["status"] == "completed" and len(run["result"]["renewals"]) == 1
    assert len(renewal_requests(fake)) == 3
    assert fast_timing.count(enrollment.RENEW_RETRY_S) == 2
    assert run["result"]["renewals"][0]["attempts"] == 3
    assert any("attempt 3)" in e["message"] for e in store.events("rt1") if e["message"].startswith("Renewed in"))
    messages = [e["message"] for e in store.events("rt1")]
    assert sum("retrying in 3s" in m for m in messages) == 2


async def test_renewal_gives_up_after_three_401_without_changes(store, enroll_net, tmp_path, fast_timing):
    fake = enroll_net
    await start(store, fake, "rf1", tmp_path)
    before_run, before_files = store.get_run("rf1"), device_file(tmp_path, "rf1")
    pems_before = sorted((tmp_path / "runs" / "rf1" / "certificates").iterdir())
    fake.reenroll_unauthorized = 3
    fast_timing.clear()
    run = await renew(store, "rf1", tmp_path)
    assert run["status"] == "completed"
    assert run["result"] == before_run["result"]
    assert device_file(tmp_path, "rf1") == before_files
    assert sorted((tmp_path / "runs" / "rf1" / "certificates").iterdir()) == pems_before
    assert len(renewal_requests(fake)) == enrollment.RENEW_ATTEMPTS == 3
    assert fast_timing.count(enrollment.RENEW_RETRY_S) == 2  # no wait after the last attempt
    assert len(fake.issued()) == 1
    errors = [e["message"] for e in store.events("rf1") if e["level"] == "error"]
    assert errors == ['Renewal failed: EST simplereenroll returned 401: {"errors": [{"code": "error", '
                      '"message": "est_unauthorized"}]}']


async def test_revoked_certificate_cannot_renew(store, enroll_net, tmp_path):
    """Not injected: DTM refuses a client certificate that is no longer issued."""
    fake = enroll_net
    await start(store, fake, "rv1", tmp_path)
    for c in fake.certificates.values():
        c["status"] = "REVOKED"
    run = await renew(store, "rv1", tmp_path)
    assert run["status"] == "completed" and run["result"]["renewals"] == []
    assert any(e["message"].startswith("Renewal failed: EST simplereenroll returned 401")
               for e in store.events("rv1"))


async def test_renewal_network_error(store, enroll_net, tmp_path):
    import httpx
    await start(store, enroll_net, "ne1", tmp_path)
    enroll_net.enroll_fail = httpx.ConnectError("boom")
    run = await renew(store, "ne1", tmp_path)
    assert run["status"] == "completed" and run["result"]["renewals"] == []
    assert any(e["message"] == "Renewal failed: EST simplereenroll failed: ConnectError" for e in store.events("ne1"))


async def test_unexpected_renewal_error_does_not_leave_the_run_renewing(store, enroll_net, tmp_path, monkeypatch):
    """A bug in the renewal must not block the run (ACTIVE blocks cleanup and further renewals)."""
    await start(store, enroll_net, "ux1", tmp_path)
    before = device_file(tmp_path, "ux1")
    store.claim_status("ux1", "completed", "renewing")  # as the route does

    def broken(cn, key_type):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(certs, "device_request", broken)
    with pytest.raises(RuntimeError):  # re-raised for the task runner's log
        await renew(store, "ux1", tmp_path)
    run = store.get_run("ux1")
    assert run["status"] == "completed" and run["progress"] is None and run["result"]["renewals"] == []
    assert store.events("ux1")[-1]["message"] == "Renewal failed unexpectedly: RuntimeError"
    assert device_file(tmp_path, "ux1") == before


async def test_failed_renewal_after_claim_returns_to_completed(store, enroll_net, tmp_path):
    await start(store, enroll_net, "fc1", tmp_path)
    store.claim_status("fc1", "completed", "renewing")
    enroll_net.reenroll_unauthorized = 3
    run = await renew(store, "fc1", tmp_path)
    assert run["status"] == "completed" and run["progress"] is None


async def test_crash_before_replace_keeps_the_old_device_file(store, enroll_net, tmp_path, monkeypatch):
    """os.replace is the switch: if writing the new file fails, the old pair stays intact. The
    issued certificate is recorded before the switch, so it is never lost for the cleanup."""
    await start(store, enroll_net, "at1", tmp_path)
    before = device_file(tmp_path, "at1")
    monkeypatch.setattr(enrollment.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    await renew(store, "at1", tmp_path)
    assert device_file(tmp_path, "at1") == before
    assert any(e["message"].startswith("Renewal failed") for e in store.events("at1"))
    run = store.get_run("at1")
    assert run["status"] == "completed" and len(run["result"]["certificates"]) == 2


async def test_full_rollback_revokes_original_and_renewed_and_removes_the_device(store, enroll_net, tmp_path):
    fake = enroll_net
    await start(store, fake, "fr1", tmp_path, auth="certificate")
    await renew(store, "fr1", tmp_path)
    await renew(store, "fr1", tmp_path)
    assert len(fake.issued()) == 3
    fake.calls.clear()
    run = await do_cleanup(store, fake, "fr1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("fr1")
    assert fake.issued() == [] and fake.names("revoke") and len(fake.names("revoke")) == 3
    assert fake.policies == {} and fake.divisions == {}
    assert all(o["status"] == "DELETED" for objs in fake.auth_objects.values() for o in objs.values())
    assert not (tmp_path / "runs" / "fr1").exists()


async def test_certificates_cleanup_removes_the_device(store, enroll_net, tmp_path):
    fake = enroll_net
    await start(store, fake, "cc1", tmp_path)
    await renew(store, "cc1", tmp_path)
    run = await do_cleanup(store, fake, "cc1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done" and fake.issued() == []
    run_dir = tmp_path / "runs" / "cc1"
    assert not (run_dir / "device").exists()  # the key of a revoked certificate is not kept
    assert_certificate_files(run_dir, run["result"]["certificates"])  # public downloads stay
    assert len(fake.policies) == 1  # configuration kept
    run = await renew(store, "cc1", tmp_path)  # engine level: no device any more
    assert run["status"] == "completed" and len(run["result"]["renewals"]) == 1
    assert store.events("cc1")[-1]["message"].startswith("Renewal failed")


async def test_uc04_discovery_finds_unrecorded_auth_objects(store, enroll_net, tmp_path):
    fake = enroll_net
    store.create_run("d4", UC, params())
    client = fake.client()
    try:
        await client.create_auth_policy("robot-d4-uc04-auth")
    finally:
        await client.aclose()
    run = await do_cleanup(store, fake, "d4", "full", tmp_path)
    assert run["cleanup_status"] == "done"
    assert [o["status"] for o in fake.auth_objects["auth_policy"].values()] == ["DELETED"]


def test_interrupted_renewal_becomes_completed(tmp_path):
    store = Store(tmp_path / "db")
    for run_id, status in (("a", "renewing"), ("b", "running"), ("c", "completed")):
        store.create_run(run_id, UC, params())
        store.update_run(run_id, status=status)
    store.mark_interrupted()
    assert [store.get_run(i)["status"] for i in "abc"] == ["completed", "interrupted", "completed"]


def test_claim_status_is_exclusive(tmp_path):
    store = Store(tmp_path / "db")
    store.create_run("a", UC, params())
    store.update_run("a", status="completed")
    assert store.claim_status("a", "completed", "renewing") is True
    assert store.claim_status("a", "completed", "renewing") is False
    assert store.get_run("a")["status"] == "renewing"


def test_renew_steps_carry_no_secret_and_use_the_device_certificate():
    for key_type in ("P_256", "RSA_2048"):
        steps = enrollment.renew_steps("robot-x1-uc04-est-0001", key_type)
        assert [s["kind"] for s in steps] == ["keygen", "call", "convert"]
        assert {s["phase"] for s in steps} == {"renewal"}
        for s in steps:
            for text in s["command"].values():
                assert "x-api-key" not in text.lower() and "PASSCODE" not in text and "PRIVATE KEY" not in text
        call = steps[1]["command"]
        assert "clientauth.${DTM_HOST}" in call["bash"] and "--cert device.crt --key device.key" in call["bash"]
        assert "--cert-type P12 --cert device.p12" in call["powershell"]
        # DTM refuses a just-issued certificate for a few seconds – the copyable call waits first
        assert "\nsleep 10\n" in "\n" + call["bash"] and "Start-Sleep 10" in call["powershell"]
        assert "mv device-new.key device.key" in steps[2]["command"]["bash"]
        assert steps[2]["command"]["powershell"].splitlines()[-1].startswith("Remove-Item device.p12")
        assert ("rsa:2048" in steps[0]["command"]["bash"]) == (key_type == "RSA_2048")


def test_renewal_block_renders_in_every_dialect(store):
    from tests.integration.test_api_call_elements import requests_in
    for s in enrollment.renew_steps("cn", "P_256"):
        for dialect in snippets.DIALECTS:
            assert requests_in(snippets.render({"command": s["command"]}, dialect)) == (s["method"] != "LOCAL")
