"""UC-7 – Retrofit managed devices against the fake DTM: the manufacturer's ICA (outside DTM) becomes the trust
anchor of the run's authentication policy, each device leaves the factory with a device-ID certificate
(CN = serial number) and enrolls in the field via EST with it for a managed certificate (CN = device name),
filed under the device through the group's device_name mapping; renewal per device; full rollback."""

import json
import stat

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from app import certs, cleanup, devices, retrofit
from tests.fakedtm import ACCOUNT_ID, ECDSA_CA_ID, FakeDTM

UC = "uc07"


def params(fake: FakeDTM, **overrides) -> dict:
    return {"dtm_host": fake.host, "account_id": ACCOUNT_ID, "variant": "webui", "mode": "single", "count": 1,
            "ca_id": ECDSA_CA_ID, "ca_name": "Fake ECDSA ICA", "key_type": "P_256", "approval": False,
            "protocol": "est", "auth": "certificate", "field": "est", "pause": False} | overrides


def events(store, run_id) -> str:
    return "\n".join(e["message"] for e in store.events(run_id))


async def start(store, fake: FakeDTM, run_id: str, tmp_path, **overrides) -> dict:
    store.create_run(run_id, UC, params(fake, **overrides))
    client = fake.client()
    try:
        await retrofit.run(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


async def act(store, fake: FakeDTM, run_id: str, name: str, task, tmp_path) -> dict:
    """What POST /runs/{id}/devices/{name}/{enroll|renew} does: mark the device busy, then run its task."""
    devices.commit(store, run_id, lambda r: r.update(busy=[*(r.get("busy") or []), name]))
    client = fake.client()
    try:
        await task(store, client, run_id, tmp_path / "runs" / run_id, name)
    finally:
        await client.aclose()
    run = store.get_run(run_id)
    assert name not in run["result"]["busy"]
    return run


async def do_cleanup(store, fake: FakeDTM, run_id: str, tmp_path) -> dict:
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, run_id, "full", tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


async def test_devices_enroll_with_their_device_id_certificate(store, enroll_net, tmp_path):
    fake = enroll_net
    run = await start(store, fake, "u1", tmp_path, mode="batch", count=2)
    assert run["status"] == "completed", (run["error"], events(store, "u1"))
    assert fake.violations == []
    r = run["result"]
    # the manufacturer's ICA is the trust anchor of the run's authentication policy
    (anchor,) = fake.active_auth_cas()
    (auth_policy,) = fake.active_auth("auth_policy")
    assert anchor["name"] == "robot-u1-uc07-device-id-ica" and anchor["authentication_policy_id"] == auth_policy["id"]
    assert [o["name"] for o in store.objects("u1", "auth_ca")] == [anchor["name"]]
    (group,) = fake.device_groups.values()
    assert group["attributes"] == ["device_name", "serial_number"]
    assert group["policies"][0]["device_field_mappings"] == [{"key": "device_name", "field": "subject.common_name"}]
    run_dir = tmp_path / "runs" / "u1"
    ica = x509.load_pem_x509_certificate((run_dir / "manufacturer" / "ica.pem").read_bytes())
    for number, d in enumerate(r["devices"], 1):
        assert d["name"] == f"robot-u1-uc07-device-{number:04d}" and d["serial"] == f"SN-U1-{number:04d}"
        (device,) = [x for x in fake.devices.values() if x["id"] == d["id"]]
        assert device["attributes"] == [{"key": "serial_number", "value": d["serial"]}]
        # the device-ID certificate: CN = serial number, from the manufacturer's ICA, never from DTM
        folder = devices.device_dir(run_dir, d["name"])
        device_id = x509.load_pem_x509_certificates((folder / "device-id.crt").read_bytes())[0]
        assert device_id.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == d["serial"]
        device_id.verify_directly_issued_by(ica)
        assert stat.S_IMODE((folder / "device-id.key").stat().st_mode) == 0o600
        # the managed certificate: CN = device name, filed under the device
        (cert,) = [c for c in fake.certificates.values() if c.get("device_id") == d["id"]]
        assert cert["common_name"] == d["name"] and d["issued"] == 1 and d["certificates"][0]["common_name"] == d["name"]
    assert r["certificate_total"] == 2 and len(fake.devices) == 2  # no Device-<uuid> from an unmatched CN
    # authenticated by mTLS with the device-ID certificate on the device-group endpoint
    assert {c for c in fake.enroll_calls} == {("est_group", fake.clientauth_host)}
    assert stat.S_IMODE((run_dir / "manufacturer" / "ica.key").stat().st_mode) == 0o600
    assert "PRIVATE KEY" not in json.dumps(run) + events(store, "u1")


async def test_enroll_and_renew_per_click(store, enroll_net, tmp_path):
    fake = enroll_net
    run = await start(store, fake, "u2", tmp_path, pause=True)
    assert run["status"] == "completed", run["error"]
    (d,) = run["result"]["devices"]
    assert d["issued"] == 0 and fake.issued() == [] and fake.enroll_calls == []  # the field waits for the click
    run = await act(store, fake, "u2", d["name"], retrofit.enroll, tmp_path)
    assert devices.device_of(run["result"], d["name"])["issued"] == 1, events(store, "u2")
    run = await act(store, fake, "u2", d["name"], devices.renew, tmp_path)
    after = devices.device_of(run["result"], d["name"])
    assert after["issued"] == 2 and after["last"]["action"] == "Renewed", events(store, "u2")
    records = [c for c in fake.certificates.values() if c.get("device_id") == d["id"]]
    assert [c["common_name"] for c in records] == [d["name"]] * 2  # the renewal lands under the same device
    assert [x["device"] for x in run["result"]["renewals"]] == [d["name"]]


async def test_a_device_id_from_another_ca_is_refused(store, enroll_net, tmp_path):
    fake = enroll_net
    run = await start(store, fake, "u3", tmp_path, pause=True)
    (d,) = run["result"]["devices"]
    stranger = certs.manufacturer_ca("robot-zz-uc07")  # a CA DTM does not trust
    cert_pem, key_pem = certs.device_id_certificate(d["serial"], stranger["ica"], stranger["ica_key"])
    folder = devices.device_dir(tmp_path / "runs" / "u3", d["name"])
    (folder / "device-id.crt").write_text(cert_pem)
    (folder / "device-id.key").write_bytes(key_pem)
    run = await act(store, fake, "u3", d["name"], retrofit.enroll, tmp_path)
    assert devices.device_of(run["result"], d["name"])["issued"] == 0 and fake.issued() == []
    assert f"Field enrollment of {d['name']} failed" in events(store, "u3") and "401" in events(store, "u3")


async def test_enroll_after_the_group_is_gone_is_reported(store, enroll_net, tmp_path):
    fake = enroll_net
    run = await start(store, fake, "u4", tmp_path, pause=True)
    (d,) = run["result"]["devices"]
    (group,) = store.objects("u4", "device_group")
    store.mark_removed("u4", "device_group", group["dtm_id"])
    await act(store, fake, "u4", d["name"], retrofit.enroll, tmp_path)
    assert "no certificate policy or device group" in events(store, "u4") and fake.enroll_calls == []


async def test_full_rollback_deletes_the_trust_anchor_before_its_policy(store, enroll_net, tmp_path):
    fake = enroll_net
    await start(store, fake, "u5", tmp_path, mode="batch", count=2)
    # the ledger lost the trust anchor (crash between create and record) – the rollback finds it by name
    (anchor,) = store.objects("u5", "auth_ca")
    store._exec("DELETE FROM run_objects WHERE run_id = ? AND kind = 'auth_ca'", ("u5",))
    foreign = {"id": "foreign-ca", "name": "robot-zz-uc07-device-id-ica", "status": "ACTIVE",
               "authentication_policy_id": "other", "pem": ""}
    fake.auth_cas["foreign-ca"] = foreign
    run = await do_cleanup(store, fake, "u5", tmp_path)
    assert run["cleanup_status"] == "done", events(store, "u5")
    assert "Found unrecorded auth_ca robot-u5-uc07-device-id-ica" in events(store, "u5")
    assert fake.auth_cas[anchor["dtm_id"]]["status"] == "DELETED" and foreign["status"] == "ACTIVE"
    assert fake.issued() == [] and fake.active_devices() == [] and fake.policies == {}
    assert fake.active_auth("auth_policy") == [] and fake.violations == []
    order = fake.route_order()
    assert order.index("auth_ca_delete") < order.index("auth_policy_delete")
    assert not (tmp_path / "runs" / "u5").exists()  # the manufacturer's keys are gone with the run
