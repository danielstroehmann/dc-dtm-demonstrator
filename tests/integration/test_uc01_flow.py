"""UC-1 run flows against the stateful fake DTM."""

import io
import json
import re
import zipfile

import httpx
import pytest

from app import cleanup, dtm, evergreen
from tests.fakedtm import ACCOUNT_ID, ECDSA_CA_ID, HOST, FakeDTM


def params(**overrides) -> dict:
    return {"dtm_host": HOST, "account_id": ACCOUNT_ID, "variant": "api", "mode": "single", "count": 1,
            "ca_id": ECDSA_CA_ID, "ca_name": "Fake ECDSA ICA", "key_type": "P_256",
            "approval": False} | overrides


async def start(store, fake: FakeDTM, run_id: str, tmp_path, **overrides):
    store.create_run(run_id, "uc01", params(**overrides))
    client = fake.client(on_call=lambda msg: store.add_event(run_id, f"API {msg}", "api"))
    try:
        await evergreen.run(store, client, run_id, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


def assert_clean_protocol(fake: FakeDTM):
    assert fake.violations == []
    assert not any("blueprint" in str(r.url) for r in fake.requests)


def assert_certificate_files(run_dir, certificates: list[dict]) -> None:
    """<run_dir>/certificates holds exactly one <serial>.pem per issued certificate, each the
    public certificate with that serial and common name – no key, no extra file."""
    from cryptography import x509
    files = sorted(p.name for p in (run_dir / "certificates").iterdir())
    assert files == sorted(f"{c['serial']}.pem" for c in certificates)
    for c in certificates:
        assert "pem" not in c
        text = (run_dir / "certificates" / f"{c['serial']}.pem").read_text()
        assert "PRIVATE KEY" not in text and text.count("BEGIN CERTIFICATE") == 1
        cert = x509.load_pem_x509_certificate(text.encode())
        assert format(cert.serial_number, "X") == c["serial"]
        assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == c["common_name"]


def db_text(store, run_id) -> str:
    run = store.get_run(run_id)
    return json.dumps(run) + json.dumps(store.events(run_id))


async def test_single_api(store, fake, tmp_path):
    run = await start(store, fake, "s1", tmp_path)
    assert run["status"] == "completed", store.events("s1")
    r = run["result"]
    assert r["division"] == "robot-s1-uc01-division" and r["policy"] == "robot-s1-uc01-policy"
    assert r["certificate_total"] == 1
    cert = r["certificates"][0]
    assert cert["common_name"] == "robot-s1-uc01-single-0001"
    assert cert["issuer"] == "Fake ECDSA Issuing CA" and cert["key_type"] == "ECDSA secp256r1"
    assert r["private_keys_returned"] == 1 and "private_key_returned" not in r
    assert set(r["response"]) <= {"certificate_id", "status", "serial_number", "valid_from", "valid_to"}
    assert "private_key" not in r["response"] and "pem" not in r["response"]
    assert "PRIVATE KEY" not in db_text(store, "s1") and "BEGIN CERTIFICATE" not in db_text(store, "s1")
    assert_certificate_files(tmp_path / "runs" / "s1", r["certificates"])
    # ledger: division and policy for the cleanup, both inside the run prefix
    ledger = {(o["kind"], o["name"]) for o in store.objects("s1")}
    assert ledger == {("division", "robot-s1-uc01-division"), ("policy", "robot-s1-uc01-policy")}
    assert len(fake.issued()) == 1
    policy = next(iter(fake.policies.values()))
    assert policy["require_approval_for_enroll"] is False and policy["ica_id"] == ECDSA_CA_ID
    assert fake.names("batch_create") == []
    assert_clean_protocol(fake)
    assert any(e["level"] == "api" and "POST" in e["message"] for e in store.events("s1"))


async def test_batch_api_without_approval(store, fake, tmp_path):
    run = await start(store, fake, "b1", tmp_path, mode="batch", count=3)
    assert run["status"] == "completed", store.events("b1")
    r = run["result"]
    assert r["certificate_total"] == 3 and r["private_keys_returned"] == 3
    assert [c["common_name"] for c in r["certificates"]] == evergreen.common_names("b1", "batch", 3, "uc01")
    assert r["approval_s"] is None and r["server_processing_ms"] == 1234
    assert r["success_items"] == 3 and r["failed_items"] == 0
    assert isinstance(r["duration_s"], float)
    job = next(iter(fake.jobs.values()))
    assert job["csv"] == ["subject.common_name", *evergreen.common_names("b1", "batch", 3, "uc01")]
    assert job["fields"]["name"] == "robot-b1-uc01-batch"
    assert fake.names("approve") == []
    assert [o["kind"] for o in store.objects("b1", "batch_job")] == ["batch_job"]
    assert "PRIVATE KEY" not in db_text(store, "b1")
    assert "BEGIN CERTIFICATE" not in db_text(store, "b1")  # PEMs live in files only
    # the upload ZIP (CSV of CNs) for replaying the call and the public certificates for
    # download – never key material
    run_dir = tmp_path / "runs" / "b1"
    assert sorted(f.name for f in run_dir.iterdir()) == ["batch.zip", "certificates"]
    assert_certificate_files(run_dir, r["certificates"])
    assert job["csv"] == zipfile.ZipFile(io.BytesIO((run_dir / "batch.zip").read_bytes())).read(
        "batch.csv").decode().splitlines()
    assert run["result"]["artifact"] == "batch.zip"
    assert_clean_protocol(fake)


async def test_batch_api_with_approval(store, fake, tmp_path):
    run = await start(store, fake, "b2", tmp_path, mode="batch", count=2, approval=True)
    assert run["status"] == "completed", store.events("b2")
    assert next(iter(fake.policies.values()))["require_approval_for_enroll"] is True
    assert len(fake.names("approve")) == 1
    assert next(iter(fake.jobs.values()))["approved"] is True
    assert run["result"]["approval_s"] is not None
    assert run["result"]["certificate_total"] == 2


async def test_failed_job_fails_the_run(store, fake, tmp_path):
    fake.job_steps = ["in_progress", "failed"]
    run = await start(store, fake, "b3", tmp_path, mode="batch", count=2)
    assert run["status"] == "failed"
    assert run["error"] == "batch job ended with status failed"
    assert run["finished_at"]
    assert fake.names("result") == []
    # setup objects and the job are recorded, so the cleanup can find them
    assert {o["kind"] for o in store.objects("b3")} == {"division", "policy", "batch_job"}


async def test_batch_deadline(store, fake, tmp_path, monkeypatch):
    fake.job_steps = ["in_progress"] * 50
    clock = iter(range(0, 10_000, 100))
    monkeypatch.setattr(evergreen.time, "monotonic", lambda: next(clock))
    run = await start(store, fake, "b4", tmp_path, mode="batch", count=1)
    assert run["status"] == "failed" and "did not complete within 600s" in run["error"]


async def test_policy_create_error_fails_run_and_keeps_division_in_ledger(store, fake, tmp_path):
    fake.fail["policy_create"] = httpx.Response(400, json={"errors": [{"message": "ica not usable"}]})
    run = await start(store, fake, "e1", tmp_path)
    assert run["status"] == "failed" and "ica not usable" in run["error"]
    assert [o["kind"] for o in store.objects("e1")] == ["division"]
    assert any(e["level"] == "error" for e in store.events("e1"))


async def test_single_response_without_certificate(store, fake, tmp_path):
    fake.single_overrides = {"pem": None}
    run = await start(store, fake, "e2", tmp_path)
    assert run["status"] == "failed"
    assert run["error"] == "DTM response for robot-e2-uc01-single-0001 contains no certificate"


async def test_unexpected_exception_marks_run_failed_and_propagates(store, fake, tmp_path):
    fake.fail["batch_create"] = httpx.Response(201, json={"no_id": True})
    with pytest.raises(KeyError):
        await start(store, fake, "e3", tmp_path, mode="batch", count=1)
    run = store.get_run("e3")
    assert run["status"] == "failed" and run["error"] == "KeyError" and run["progress"] is None
    # the unexpected-exception path keeps the calls made so far, too
    assert run["result"]["api_calls"][-1]["path"].endswith("/certificate-enroll")
    assert run["result"]["api_calls"][-1]["outcome"] == "ok"


async def test_webui_batch_prepares_artifact_only(store, fake, tmp_path):
    run = await start(store, fake, "w1", tmp_path, variant="webui", mode="batch", count=4)
    assert run["status"] == "waiting"
    assert run["result"]["artifact"] == "batch.zip"
    with zipfile.ZipFile(io.BytesIO((tmp_path / "runs" / "w1" / "batch.zip").read_bytes())) as archive:
        assert archive.namelist() == ["batch.csv"]
        lines = archive.read("batch.csv").decode().splitlines()
    assert lines == ["subject.common_name", *evergreen.common_names("w1", "batch", 4, "uc01")]
    assert fake.names("issue") == [] and fake.names("batch_create") == []
    assert {o["kind"] for o in store.objects("w1")} == {"division", "policy"}


async def test_webui_single_shows_portal_values(store, fake, tmp_path):
    run = await start(store, fake, "w2", tmp_path, variant="webui")
    assert run["status"] == "waiting"
    assert run["result"]["portal_values"] == {"Common name": "robot-w2-uc01-single-0001"}
    assert fake.names("issue") == []


async def test_rsa_key_type_reaches_policy(store, fake, tmp_path):
    await start(store, fake, "r1", tmp_path, ca_id="ca-rsa-ica", key_type="RSA_2048")
    policy = next(iter(fake.policies.values()))
    assert policy["key_generation_type"] == "RSA_2048" and policy["ica_id"] == "ca-rsa-ica"


# --- demo UX: API call record, progress, story, rates ----------------------------------------

def spy_progress(store, monkeypatch) -> list:
    seen = []
    original = store.update_run

    def update_run(run_id, **fields):
        if "progress" in fields:
            seen.append(fields["progress"])
        return original(run_id, **fields)

    monkeypatch.setattr(store, "update_run", update_run)
    return seen


def sent_json(fake: FakeDTM, route: str) -> dict:
    index = [n for n, _ in fake.calls].index(route)
    return json.loads(fake.requests[index].content)


def substitute(value, variables: dict):
    text = json.dumps(value)
    for name, real in variables.items():
        text = text.replace("{" + name + "}", real)
    return json.loads(text)


SETUP = [("GET", "/devicetrustmanager/api/v4/rendezvous-zone"),
         ("POST", "/devicetrustmanager/api/v4/division"),
         ("GET", "/devicetrustmanager/api/v4/division"),
         ("GET", dtm.PROFILES),  # the shared profile (found or created once)
         ("POST", "/devicetrustmanager/certificate-configuration-service/api/v2/certificate-policy"),
         ("GET", "/devicetrustmanager/certificate-configuration-service/api/v2/certificate-policy")]


async def test_single_records_api_calls(store, fake, tmp_path):
    fake.issue_delay = 0.05
    run = await start(store, fake, "a1", tmp_path)
    r = run["result"]
    calls = r["api_calls"]
    assert [(c["method"], c["path"]) for c in calls] == SETUP + [
        ("POST", "/devicetrustmanager/certificate-issuance-service/api/v2/certificate")]
    assert all(c["outcome"] == "ok" and c["count"] == 1 for c in calls)
    assert [c["seconds"] is None for c in calls] == [False, False, True, False, False, True, False]  # lookups untimed
    assert calls[6]["seconds"] >= 0.05
    variables = r["api_variables"]
    division_id, policy_id = next(iter(fake.divisions)), next(iter(fake.policies))
    profile_id = fake.profile(dtm.PROFILE_EVERGREEN.name)["id"]
    assert variables == {"DTM_HOST": HOST, "DTM_ACCOUNT_ID": ACCOUNT_ID, "DIVISION_ID": division_id,
                         "POLICY_ID": policy_id, "PROFILE_ID": profile_id}
    assert calls[3]["spec"] == {"method": "GET", "path": dtm.PROFILES} and calls[3]["phase"] == "setup"
    # The copyable JSON bodies are exactly what the client sent, once the variables are filled in.
    assert substitute(calls[1]["spec"]["json"], variables) == sent_json(fake, "division_create")
    assert substitute(calls[4]["spec"]["json"], variables) == sent_json(fake, "policy_create")
    assert calls[4]["spec"]["json"]["certificate_policy"]["certificate_profile_id"] == "{PROFILE_ID}"  # a token
    assert substitute(calls[6]["spec"]["json"], variables) == sent_json(fake, "issue")
    assert calls[6]["spec"]["json"]["certificate_policy_id"] == "{POLICY_ID}"  # a token, not a literal ID
    assert calls[1]["spec"]["json"]["account_id"] == "{DTM_ACCOUNT_ID}"
    assert r["duration_s"] >= 0.05 and calls[6]["count"] == 1
    assert run["progress"] is None


async def test_batch_records_api_calls_without_secrets(store, fake, tmp_path):
    fake.job_steps = ["in_progress"] * 4 + ["completed"]
    run = await start(store, fake, "a2", tmp_path, mode="batch", count=3, approval=True)
    assert run["status"] == "completed"
    calls = run["result"]["api_calls"]
    assert [c["method"] for c in calls] == ["GET", "POST", "GET", "GET", "POST", "GET", "LOCAL", "POST", "PUT", "GET",
                                            "GET", "LOCAL"]
    enc, upload, approve, poll, download, decrypt = calls[6:]
    assert enc["spec"]["command"].startswith("openssl req -x509 -newkey rsa:3072") and enc["seconds"] is None
    assert upload["path"].endswith("/jobs/certificate-enroll")
    assert upload["spec"]["form"] == dtm.batch_fields("robot-a2-uc01-batch", "{POLICY_ID}", "P_256")
    assert upload["spec"]["files"] == {"encryption_certificate": "<enc.crt", "data": "@batch.zip;type=application/zip"}
    sent = next(iter(fake.jobs.values()))["fields"]
    variables = run["result"]["api_variables"]
    expected = substitute(upload["spec"]["form"], variables)
    assert {k: sent[k] for k in expected} == expected  # same multipart fields as the real upload
    assert approve["path"] == "/devicetrustmanager/certificate-batch-service/api/v1/jobs/{JOB_ID}/approve"
    assert poll["count"] >= 6 and poll["path"].endswith("/jobs/{JOB_ID}") and poll["outcome"] == "ok"
    assert download["spec"]["output"] == "result.p7m"
    assert decrypt["spec"]["command"].startswith("openssl cms -decrypt") and decrypt["method"] == "LOCAL"
    assert variables["JOB_ID"] == next(iter(fake.jobs))
    everything = json.dumps(run) + json.dumps(store.events("a2"))
    for secret in ("BEGIN CERTIFICATE", "PRIVATE KEY", "BEGIN", fake.api_key):
        assert secret not in everything, secret


def assert_rates(r: dict, count: int, seconds: float, slack: float) -> None:
    """per_certificate_s and per_minute must both describe the same raw issuing time t. Only rounded
    values are visible, so t is bracketed instead of compared with a fixed tolerance (with a fake DTM t is
    ~0.1 s, where rounding duration_s alone moves the rate by more than 5 %):
    t = seconds ± slack, and t = count * (per_certificate_s ± 0.0005) (3 decimals). per_minute is
    round(count / t * 60), so it must lie within that range of t, ±0.5."""
    lo = max(seconds - slack, count * (r["per_certificate_s"] - 0.0005))
    hi = min(seconds + slack, count * (r["per_certificate_s"] + 0.0005))
    assert 0 < lo <= hi, ("per_certificate_s does not match the measured time", r["per_certificate_s"], seconds)
    assert count / hi * 60 - 0.5 <= r["per_minute"] <= count / lo * 60 + 0.5, (r["per_minute"], lo, hi)


def test_assert_rates_brackets_rounding_but_catches_wrong_rates():
    import random
    rng = random.Random(7)
    for _ in range(2000):  # the regime of the tests: a few certificates, >= 0.08 s (fake DTM) up to live times
        t, n = rng.uniform(0.08, 30), rng.randint(1, 10)
        good = evergreen.rates(t, n)
        assert_rates(good, n, round(t, 2), slack=0.005)  # the app's own rounding always passes
        for wrong in ({"per_minute": round(n / t)}, {"per_minute": round(n / t * 60 * 1.1) + 1},
                      {"per_certificate_s": round(t / n * 1.1, 3) + 0.002}):
            with pytest.raises(AssertionError):
                assert_rates(good | wrong, n, round(t, 2), slack=0.005)


async def test_batch_rates_exclude_approval(store, fake, tmp_path):
    fake.approve_delay = 0.3
    fake.job_delay = 0.03
    fake.job_steps = ["in_progress"] * 5 + ["completed"]
    run = await start(store, fake, "a9", tmp_path, mode="batch", count=4, approval=True)
    r = run["result"]
    assert r["approval_s"] >= 0.3
    issuing = r["duration_s"] - r["approval_s"]
    assert 0 < issuing < r["duration_s"]
    # the app subtracts the (already rounded) approval_s from the raw time; only duration_s adds rounding
    assert_rates(r, 4, issuing, slack=0.005)


async def test_progress_written_only_on_change_with_fixed_start(store, fake, tmp_path, monkeypatch):
    fake.job_steps = ["in_progress"] * 6 + ["completed"]
    fake.job_success_items = [0, 0, 0, 2, 2, 2]
    seen = spy_progress(store, monkeypatch)
    run = await start(store, fake, "p1", tmp_path, mode="batch", count=3)
    assert run["status"] == "completed"
    polling = [p for p in seen if p and p.get("total")]
    assert [(p["status"], p["done"]) for p in polling] == [("in_progress", 0), ("in_progress", 2), ("completed", 3)]
    assert len({p["started"] for p in polling}) == 1


async def test_batch_progress_and_wait_story(store, fake, tmp_path, monkeypatch):
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    fake.job_steps = ["in_progress", "in_progress", "in_progress", "completed"]
    fake.job_success_items = [0, 1, 2]
    seen = spy_progress(store, monkeypatch)
    run = await start(store, fake, "a3", tmp_path, mode="batch", count=3)
    assert run["status"] == "completed" and run["progress"] is None
    polling = [p for p in seen if p and p.get("total")]
    assert polling and all(p["total"] == 3 and "started" in p and p["label"] for p in polling)
    assert [p["done"] for p in polling if p["status"] == "in_progress"] == [0, 1, 2]
    assert polling[-1]["status"] == "completed"
    assert seen[-1] is None  # cleared at the end
    waits = [e["message"] for e in store.events("a3") if e["level"] == "wait"]
    assert waits and any("2 of 3 issued so far" in w for w in waits)
    assert any("Fake ECDSA ICA" in w or "P_256" in w for w in waits)  # story uses the run's parameters
    levels = {e["level"] for e in store.events("a3")}
    assert {"step", "success", "wait", "api"} <= levels and "info" not in levels


async def test_no_wait_story_while_waiting_for_approval(store, fake, tmp_path, monkeypatch):
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    fake.fail["approve"] = httpx.Response(500, json={"error": "down"})
    run = await start(store, fake, "a4", tmp_path, mode="batch", count=2, approval=True)
    assert run["status"] == "failed"
    assert not [e for e in store.events("a4") if e["level"] == "wait"]


async def test_failed_run_keeps_api_calls_and_clears_progress(store, fake, tmp_path):
    fake.fail["approve"] = httpx.Response(500, json={"error": "approval down"})
    run = await start(store, fake, "a5", tmp_path, mode="batch", count=2, approval=True)
    assert run["status"] == "failed" and run["progress"] is None
    calls = run["result"]["api_calls"]
    approve, poll = calls[-2], calls[-1]
    assert approve["method"] == "PUT" and approve["outcome"] == "error"
    assert poll["method"] == "GET" and poll["count"] >= 1  # polls are listed even though the run failed
    assert all(c["outcome"] == "ok" for c in calls[:-2])
    assert run["result"]["api_variables"]["JOB_ID"] == next(iter(fake.jobs))


async def test_setup_failure_keeps_api_calls(store, fake, tmp_path):
    fake.fail["division_create"] = httpx.Response(400, json={"errors": [{"message": "nope"}]})
    run = await start(store, fake, "a6", tmp_path)
    assert run["status"] == "failed"
    assert [(c["method"], c["outcome"]) for c in run["result"]["api_calls"]] == [("GET", "ok"), ("POST", "error")]
    assert run["result"]["api_variables"] == {"DTM_HOST": HOST, "DTM_ACCOUNT_ID": ACCOUNT_ID}


async def test_deadline_failure_still_lists_poll_calls(store, fake, tmp_path, monkeypatch):
    fake.job_steps = ["in_progress"] * 50
    clock = iter(range(0, 100_000, 100))
    monkeypatch.setattr(evergreen.time, "monotonic", lambda: next(clock))
    run = await start(store, fake, "a7", tmp_path, mode="batch", count=1)
    assert run["status"] == "failed"
    assert any(c["method"] == "GET" and c["count"] >= 1 for c in run["result"]["api_calls"])


async def test_all_certificates_are_kept(store, fake, tmp_path):
    run = await start(store, fake, "a8", tmp_path, mode="batch", count=60)
    r = run["result"]
    assert r["certificate_total"] == 60 and len(r["certificates"]) == 60
    assert [c["common_name"] for c in r["certificates"]] == evergreen.common_names("a8", "batch", 60, "uc01")


def test_rates():
    assert evergreen.rates(10.0, 100) == {"per_certificate_s": 0.1, "per_minute": 600}
    assert evergreen.rates(2.0, 1) == {"per_certificate_s": 2.0, "per_minute": 30}
    assert evergreen.rates(0, 5) == {} and evergreen.rates(5, 0) == {}



# --- single mode with a count ------------------------------------------------------------------

async def test_single_issues_count_certificates_sequentially(store, fake, tmp_path, monkeypatch):
    in_flight, peak = 0, 0
    original = fake._issue

    async def tracking(request):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            return await original(request)
        finally:
            in_flight -= 1

    fake.router.routes["issue"].side_effect = fake._wrap("issue", tracking)
    fake.issue_delay = 0.02
    seen = spy_progress(store, monkeypatch)
    run = await start(store, fake, "m1", tmp_path, count=4)
    assert run["status"] == "completed"
    sent = [json.loads(r.content)["certificate_profile_attributes"][0]["value"]
            for r in fake.requests if r.url.path.endswith("/api/v2/certificate") and r.method == "POST"]
    assert sent == evergreen.common_names("m1", "single", 4, "uc01") and peak == 1
    r = run["result"]
    assert r["certificate_total"] == 4 and r["private_keys_returned"] == 4
    assert [c["common_name"] for c in r["certificates"]] == sent
    assert r["response"]["certificate_id"] == next(iter(fake.certificates))  # DTM's answer to the FIRST request
    assert "private_key" not in r["response"] and "pem" not in r["response"]
    single = r["api_calls"][-1]
    assert (single["count"], single["outcome"]) == (4, "ok") and single["seconds"] >= 0.08
    assert single["spec"]["json"]["certificate_profile_attributes"][0]["value"] == sent[0]
    assert_rates(r, 4, r["duration_s"], slack=0.005)  # duration_s is rounded to 2 decimals
    progress = [p for p in seen if p and p.get("total")]
    assert [p["done"] for p in progress] == [1, 2, 3, 4] and {p["total"] for p in progress} == {4}
    assert progress[0]["label"] == "Requesting 4 certificates one by one" and len({p["started"] for p in progress}) == 1
    assert seen[-1] is None and run["progress"] is None
    assert "PRIVATE KEY" not in json.dumps(run)


async def test_single_wait_notes(store, fake, tmp_path, monkeypatch):
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    fake.issue_delay = 0.01
    await start(store, fake, "m2", tmp_path, count=3)
    notes = [e["message"] for e in store.events("m2") if e["level"] == "wait"]
    assert [n.split(" – ")[0] for n in notes] == ["1 of 3 issued", "2 of 3 issued"]  # none after the last one
    assert all(re.fullmatch(r"\d of 3 issued – \d+ per minute so far", n) for n in notes), notes


async def test_single_failure_midway_keeps_partial_calls_and_cleans_up(store, fake, tmp_path):
    calls = {"n": 0}

    def third_fails(request):
        calls["n"] += 1
        return httpx.Response(500, json={"error": "issuance broke"}) if calls["n"] == 3 else None

    fake.fail["issue"] = third_fails
    run = await start(store, fake, "m3", tmp_path, count=5)
    assert run["status"] == "failed" and "issuance broke" in run["error"] and run["progress"] is None
    single = run["result"]["api_calls"][-1]
    assert (single["count"], single["outcome"]) == (3, "error")  # 2 issued + the failing request
    assert calls["n"] == 3 and len(fake.issued()) == 2  # stopped after the failure
    # the two certificates that were issued are revoked by the cleanup
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, "m3", "full", tmp_path / "runs" / "m3")
    finally:
        await client.aclose()
    assert store.get_run("m3")["cleanup_status"] == "done" and fake.issued() == [] and fake.policies == {}


async def test_cleanup_expects_all_single_certificates(store, fake, tmp_path, monkeypatch):
    await start(store, fake, "m4", tmp_path, count=3)
    expected = []
    original = cleanup.revoke_all

    async def spy(client, policy_id, log, expected_count=0, beat=None):
        expected.append(expected_count)
        return await original(client, policy_id, log, expected_count, beat)

    monkeypatch.setattr(cleanup, "revoke_all", lambda client, policy_id, log, expected=0, beat=None:
                        spy(client, policy_id, log, expected, beat))
    for cert in fake.certificates.values():
        cert["status"] = "REVOKED"
    fake.revoked_count_lag = 2  # revoked listing reports 0 twice → must wait for all 3
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, "m4", "full", tmp_path / "runs" / "m4")
    finally:
        await client.aclose()
    assert expected == [3]
    assert any("not all known certificates are listed as revoked" in e["message"] for e in store.events("m4"))
    assert store.get_run("m4")["cleanup_status"] == "done"


async def test_webui_single_with_count_shows_range(store, fake, tmp_path):
    run = await start(store, fake, "m5", tmp_path, variant="webui", count=3)
    assert run["result"]["portal_values"] == {
        "Common names": "robot-m5-uc01-single-0001 … robot-m5-uc01-single-0003"}
    assert fake.names("issue") == []
