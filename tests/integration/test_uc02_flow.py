"""UC-2 – factory-generated keys (CSRs) against the stateful fake DTM."""

import io
import json
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import certs, cleanup, dtm, evergreen
from tests.fakedtm import ACCOUNT_ID, ECDSA_CA_ID, HOST, PROFILE_ID, RSA_CA_ID, FakeDTM
from tests.integration.test_uc01_flow import assert_certificate_files

UC = "uc02"


def params(**overrides) -> dict:
    return {"dtm_host": HOST, "account_id": ACCOUNT_ID, "variant": "api", "mode": "single", "count": 1,
            "ca_id": ECDSA_CA_ID, "ca_name": "Fake ECDSA ICA", "key_type": "P_256",
            "approval": False} | overrides  # key_generation comes from the use case, not the params


class _Capturing:
    """Stands in for cryptography's ec / rsa modules inside app.certs and records every key generated."""

    def __init__(self, module, keys):
        self._module, self._keys = module, keys

    def __getattr__(self, name):
        return getattr(self._module, name)

    def generate_private_key(self, *args, **kwargs):
        key = self._module.generate_private_key(*args, **kwargs)
        self._keys.append(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        return key


@pytest.fixture
def captured_keys(monkeypatch):
    """Every private key the 'factory' (certs.factory_csr) generates – none may leave the function."""
    keys = []
    monkeypatch.setattr(certs, "ec", _Capturing(certs.ec, keys))
    monkeypatch.setattr(certs, "rsa", _Capturing(certs.rsa, keys))
    return keys


async def start(store, fake: FakeDTM, run_id: str, tmp_path, **overrides):
    store.create_run(run_id, UC, params(**overrides))
    client = fake.client(on_call=lambda msg: store.add_event(run_id, f"API {msg}", "api"))
    try:
        await evergreen.run(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


def assert_no_private_key_anywhere(store, fake, tmp_path, keys):
    """Neither in the DB file, nor on disk, nor in any request to DTM."""
    assert keys, "no keys were generated – the capture is broken"
    blobs = [p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()]
    blobs += [r.content for r in fake.requests]
    for key in keys:
        body = b"".join(key.splitlines()[1:-1])  # base64 body without the PEM armour
        for blob in blobs:
            assert body[:40] not in blob.replace(b"\n", b"").replace(b"\\n", b"")
    for blob in blobs:
        assert b"PRIVATE KEY" not in blob


def csr_public_numbers(pem: str):
    return x509.load_pem_x509_csr(pem.encode()).public_key().public_numbers()


async def test_uc02_single(store, fake, tmp_path, captured_keys):
    run = await start(store, fake, "k1", tmp_path, count=2)
    assert run["status"] == "completed", store.events("k1")
    policy = next(iter(fake.policies.values()))
    assert policy["key_generation_option"] == "client_side"
    assert policy["batch_request_parameters"]["input_type"] == "csr"
    assert policy["single_cert_request_parameters"]["key_generation_option"] == "client_side"
    names = evergreen.common_names("k1", "single", 2, UC)
    assert names[0] == "robot-k1-uc02-single-0001"
    sent = [json.loads(r.content) for r in fake.requests if r.method == "POST" and r.url.path == evergreen.SINGLE_PATH]
    assert [b["certificate_profile_attributes"][0]["value"] for b in sent] == names
    assert all(b.get("csr", "").startswith("-----BEGIN CERTIFICATE REQUEST-----") for b in sent)
    assert not any(b.get("server_side_key_gen") for b in sent)
    assert sent[0] == dtm.single_body(next(iter(fake.policies)), names[0], sent[0]["csr"])
    r = run["result"]
    assert r["private_keys_returned"] == 0 and r["certificate_total"] == 2
    assert [c["common_name"] for c in r["certificates"]] == names
    assert r["keygen_s"] is not None and r["keygen_s"] >= 0
    assert len(captured_keys) == 2
    calls = r["api_calls"]
    assert [c["method"] for c in calls] == ["GET", "POST", "GET", "GET", "POST", "GET", "LOCAL", "POST", "LOCAL"]
    keygen, single, extract = calls[6], calls[7], calls[8]
    assert calls[4]["spec"]["json"]["certificate_policy"]["certificate_profile_id"] == "{PROFILE_ID}"  # a token
    assert run["result"]["api_variables"]["PROFILE_ID"] == policy["certificate_profile_id"]
    assert keygen["spec"]["command"]["bash"].startswith("openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256")
    # the device name follows RUN_NAME (a replay creates new names), not the literal run name
    assert keygen["spec"]["command"] == evergreen.keygen_command("{RUN_NAME}-single-0001", "P_256")
    assert "robot-k1-" not in json.dumps(keygen["spec"])
    # the snippet body carries a {CSR} token (filled from the locally generated device.csr), not our CSR
    assert single["count"] == 2 and single["spec"]["json"]["csr"] == "{CSR}"
    assert single["spec"]["json"] == dtm.single_body("{POLICY_ID}", "{RUN_NAME}-single-0001", "{CSR}")
    # client-side keys: the answer holds only the certificate – no key to extract
    assert extract["spec"]["command"]["bash"] == "jq -r .pem certificate.json.out > device.crt"
    assert "private_key" not in json.dumps(extract["spec"])
    assert "CSR" in single["purpose"]
    assert_no_private_key_anywhere(store, fake, tmp_path, captured_keys)
    assert fake.violations == []


async def test_uc02_single_certificate_matches_csr_key(store, fake, tmp_path, monkeypatch):
    answers = []
    original = fake._issue

    async def keep(request):
        response = await original(request)
        answers.append((json.loads(request.content)["csr"], json.loads(response.text, strict=False)))
        return response

    fake.router.routes["issue"].side_effect = fake._wrap("issue", keep)
    run = await start(store, fake, "k2", tmp_path)
    assert run["status"] == "completed"
    (csr, answer), = answers
    cert = x509.load_pem_x509_certificate(answer["pem"].encode())
    assert cert.public_key().public_numbers() == csr_public_numbers(csr)
    assert "private_key" not in answer


async def test_uc02_batch(store, fake, tmp_path, captured_keys, monkeypatch):
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    fake.csr_job_steps = ["pending", "pending", "completed"]
    run = await start(store, fake, "k3", tmp_path, mode="batch", count=3)
    assert run["status"] == "completed", store.events("k3")
    names = evergreen.common_names("k3", "batch", 3, UC)
    job = next(iter(fake.jobs.values()))
    assert job["client_side"] and job["names"] == names
    expected_fields = dtm.csr_batch_fields("robot-k3-uc02-batch", next(iter(fake.policies)))
    assert {k: job["fields"][k] for k in expected_fields} == expected_fields
    assert "encryption_certificate" not in job["fields"] and fake.violations == []
    # csrs.zip on disk = exactly what was uploaded, CSRs only
    archive = zipfile.ZipFile(io.BytesIO((tmp_path / "runs" / "k3" / "csrs.zip").read_bytes()))
    assert archive.namelist() == [f"{n}.csr" for n in names]
    assert [archive.read(f"{n}.csr").decode() for n in names] == fake.received_csrs
    assert sorted(p.name for p in (tmp_path / "runs" / "k3").iterdir()) == ["certificates", "csrs.zip"]
    r = run["result"]
    assert_certificate_files(tmp_path / "runs" / "k3", r["certificates"])
    assert "BEGIN CERTIFICATE" not in json.dumps(store.get_run("k3"))
    assert r["artifact"] == "csrs.zip" and r["certificate_total"] == 3 and r["private_keys_returned"] == 0
    assert [c["common_name"] for c in r["certificates"]] == names
    assert r["keygen_s"] is not None and r["per_certificate_s"] > 0
    calls = r["api_calls"]
    assert [c["method"] for c in calls] == ["GET", "POST", "GET", "GET", "POST", "GET", "LOCAL", "POST", "GET", "GET",
                                            "LOCAL"]
    # key + CSR for every device (named after RUN_NAME), packed like the run's csrs.zip
    assert calls[6]["spec"]["command"] == evergreen.csr_batch_command(3, "P_256")
    assert "seq 1 3" in calls[6]["spec"]["command"]["bash"] and "1..3" in calls[6]["spec"]["command"]["powershell"]
    assert calls[7]["spec"]["form"] == dtm.csr_batch_fields("{RUN_NAME}-batch", "{POLICY_ID}")
    assert calls[7]["spec"]["files"] == {"data": "@csrs.zip;type=application/zip"}
    assert calls[7]["spec"]["capture"]["var"] == "JOB_ID"
    assert calls[8]["spec"]["until"] == {"status": "completed"}
    assert calls[9]["spec"]["output"] == "result.zip"
    assert calls[10]["spec"]["command"]["bash"] == "rm -rf result && unzip -q result.zip -d result && ls result"
    assert not any("decrypt" in (c["spec"] or {}).get("command", "") for c in calls)
    assert not any("enc.crt" in json.dumps(c["spec"]) for c in calls)
    waits = [e["message"] for e in store.events("k3") if e["level"] == "wait"]
    assert waits and waits[0].startswith("DTM checks each CSR's signature")
    assert_no_private_key_anywhere(store, fake, tmp_path, captured_keys)


async def test_uc02_rsa_keys(store, fake, tmp_path):
    run = await start(store, fake, "k4", tmp_path, mode="batch", count=2, ca_id=RSA_CA_ID, ca_name="Fake RSA ICA",
                      key_type="RSA_2048")
    assert run["status"] == "completed"
    assert all(csr_public_numbers(c).n.bit_length() == 2048 for c in fake.received_csrs)
    assert {c["key_type"] for c in run["result"]["certificates"]} == {"RSA 2048"}
    command = run["result"]["api_calls"][6]["spec"]["command"]
    assert "-newkey rsa:2048" in command["bash"] and "-newkey rsa:2048" in command["powershell"]


async def test_uc02_batch_with_approval(store, fake, tmp_path):
    run = await start(store, fake, "k5", tmp_path, mode="batch", count=2, approval=True)
    assert run["status"] == "completed" and run["result"]["approval_s"] is not None
    assert len(fake.names("approve")) == 1


@pytest.mark.parametrize("mode,count,portal", [
    ("single", 1, {"Common name": "robot-w1-uc02-single-0001"}),
    ("single", 3, {"Common names": "robot-w1-uc02-single-0001 … robot-w1-uc02-single-0003"}),
    ("batch", 3, None),
])
async def test_uc02_webui_prepares_csrs(store, fake, tmp_path, captured_keys, mode, count, portal):
    run = await start(store, fake, "w1", tmp_path, variant="webui", mode=mode, count=count)
    assert run["status"] == "waiting"
    r = run["result"]
    assert r["artifact"] == "csrs.zip" and r.get("portal_values") == portal
    archive = zipfile.ZipFile(io.BytesIO((tmp_path / "runs" / "w1" / "csrs.zip").read_bytes()))
    assert archive.namelist() == [f"{n}.csr" for n in evergreen.common_names("w1", mode, count, UC)]
    for name in archive.namelist():
        csr = x509.load_pem_x509_csr(archive.read(name))
        assert csr.is_signature_valid
    assert fake.names("issue") == [] and fake.names("batch_create") == []
    assert len(captured_keys) == count
    assert_no_private_key_anywhere(store, fake, tmp_path, captured_keys)


async def test_uc02_full_cleanup(store, fake, tmp_path):
    await start(store, fake, "c1", tmp_path, mode="batch", count=3)
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, "c1", "full", tmp_path / "runs" / "c1")
    finally:
        await client.aclose()
    assert store.get_run("c1")["cleanup_status"] == "done"
    assert fake.issued() == [] and fake.policies == {} and fake.divisions == {}
    assert not (tmp_path / "runs" / "c1").exists()


async def test_uc02_discover_uses_its_own_prefix(store, fake, tmp_path):
    fake.division_list_lag = 10  # the create succeeds, the lookup never sees it → unrecorded division
    run = await start(store, fake, "c2", tmp_path)
    assert run["status"] == "failed" and store.objects("c2") == []
    for d in fake.divisions.values():
        d["hidden"] = 0
    # a UC-1 object with the same run id must not be touched by the UC-2 cleanup
    fake.divisions["uc01-twin"] = {"id": "uc01-twin", "name": "robot-c2-uc01-division", "hidden": 0}
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, "c2", "full", tmp_path / "runs" / "c2")
    finally:
        await client.aclose()
    assert store.get_run("c2")["cleanup_status"] == "done"
    assert set(fake.divisions) == {"uc01-twin"}
    assert any("Found unrecorded division robot-c2-uc02-division" in e["message"] for e in store.events("c2"))


async def test_key_generation_follows_the_use_case_not_the_params(store, fake, tmp_path):
    # a stale/foreign key_generation in stored params must not switch a UC-1 run to CSRs
    store.create_run("o1", "uc01", params(key_generation="client_side"))
    client = fake.client()
    try:
        await evergreen.run(store, client, "o1", tmp_path / "runs" / "o1")
    finally:
        await client.aclose()
    run = store.get_run("o1")
    assert run["status"] == "completed" and run["result"]["private_keys_returned"] == 1
    assert next(iter(fake.policies.values()))["key_generation_option"] == "server_side"
    assert fake.received_csrs == []


def test_factory_csr_returns_only_the_csr(captured_keys):
    csr_pem = certs.factory_csr("robot-x-uc02-single-0001", "P_256")
    assert isinstance(csr_pem, str) and "PRIVATE" not in csr_pem
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    assert csr.is_signature_valid and csr.subject.rfc4514_string() == "CN=robot-x-uc02-single-0001"
    (key_pem,) = captured_keys
    key = serialization.load_pem_private_key(key_pem, None)
    assert key.public_key().public_numbers() == csr.public_key().public_numbers()
    rsa_csr = certs.factory_csr("x", "RSA_2048")
    assert x509.load_pem_x509_csr(rsa_csr.encode()).public_key().key_size == 2048


def test_csr_zip_and_keygen_command():
    data = evergreen.csr_zip({"a": "CSR-A", "b": "CSR-B"})
    archive = zipfile.ZipFile(io.BytesIO(data))
    assert archive.namelist() == ["a.csr", "b.csr"] and archive.read("b.csr") == b"CSR-B"
    command = evergreen.keygen_command("cn1", "RSA_2048")
    assert set(command) == {"bash", "powershell"}
    openssl = 'openssl req -new -newkey rsa:2048 -nodes -keyout device.key -out device.csr -subj "/CN=cn1"'
    assert command["bash"].startswith(openssl + "\nexport CSR=")
    assert command["powershell"].startswith(openssl + "\n$env:CSR = (Get-Content device.csr -Raw)")
    assert "ec_paramgen_curve:P-256" in evergreen.keygen_command("cn1", "P_256")["bash"]


def test_policy_body_key_generation():
    server = dtm.policy_body(name="n", division_id="d", profile_id="p", ica_id="c", key_type="P_256",
                             require_approval=False)["certificate_policy"]
    client = dtm.policy_body(name="n", division_id="d", profile_id="p", ica_id="c", key_type="P_256",
                             require_approval=False, key_generation="client_side")["certificate_policy"]
    assert server["key_generation_option"] == "server_side" and server["batch_request_parameters"]["input_type"] == "csv"
    assert client["key_generation_option"] == "client_side" and client["batch_request_parameters"]["input_type"] == "csr"
    body = dtm.single_body("IOT_1", "cn", "CSR-PEM")
    assert body["csr"] == "CSR-PEM" and not body.get("server_side_key_gen")
    assert dtm.single_body("IOT_1", "cn")["server_side_key_gen"] is True and "csr" not in dtm.single_body("IOT_1", "cn")
    fields = dtm.csr_batch_fields("n", "IOT_1")
    assert fields["input_format"] == "csr" and "encryption_certificate" not in fields and "key_type" not in fields


async def test_client_side_policy_rejects_server_side_request(store, fake, tmp_path):
    """The fake mirrors DTM's mode check; it proves the UC-2 flow sends CSRs, not key-gen requests."""
    store.create_run("x1", UC, params())
    client = fake.client()
    try:
        division = await client.create_division("robot-x1-uc02-division", "d", "rz-a")
        policy = await client.create_policy(name="robot-x1-uc02-policy", division_id=division, profile_id=PROFILE_ID,
                                            ica_id=ECDSA_CA_ID, key_type="P_256", require_approval=False,
                                            key_generation="client_side")
        with pytest.raises(dtm.DTMError, match="requires a CSR"):
            await client.issue_single(policy, "robot-x1-uc02-single-0001")
    finally:
        await client.aclose()


# --- key generation runs in a thread --------------------------------------------------------------

async def test_factory_keygen_does_not_block_the_event_loop(monkeypatch):
    import asyncio
    import threading
    import time

    from tests.fakedtm import _real_sleep

    threads = set()
    original = certs.factory_csr

    def recording(cn, key_type):
        threads.add(threading.get_ident())
        return original(cn, key_type)

    monkeypatch.setattr(certs, "factory_csr", recording)
    ticks = []

    async def ticker(stop):
        while not stop.is_set():
            ticks.append(time.monotonic())
            await _real_sleep(0.01)

    stop = asyncio.Event()
    ticking = asyncio.create_task(ticker(stop))
    names = [f"robot-t1-uc02-batch-{i:04d}" for i in range(1, 16)]
    started = time.monotonic()
    csrs, seconds = await evergreen.factory_csrs(names, "RSA_2048", lambda *_: None)
    elapsed = time.monotonic() - started
    stop.set()
    await ticking
    assert list(csrs) == names and seconds > 0.2, "keygen too fast to prove anything – raise the count"
    assert threading.get_ident() not in threads  # ran off the event-loop thread
    during = [t for t in ticks if started <= t <= started + elapsed]
    gaps = [b - a for a, b in zip(during, during[1:])]
    assert len(during) >= elapsed / 0.05 and max(gaps) < 0.2, (len(during), max(gaps), elapsed)


async def test_factory_csrs_logs_start_and_end(store):
    events = []
    await evergreen.factory_csrs(["a", "b"], "P_256", lambda msg, level="step": events.append((level, msg)))
    assert events[0] == ("step", "Factory generates 2 key pair(s) and CSR(s)")
    assert events[1][0] == "success" and "2 CSR(s) ready in" in events[1][1]
    assert events[1][1].startswith("2 CSR(s) ready in ") and events[1][1].endswith("s")  # no explanatory tail
