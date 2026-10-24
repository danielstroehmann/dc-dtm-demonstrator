"""UC-3 – enrollment protocols (EST, CMPv2, REST) × factory authentication (passcode, factory
certificate) against the stateful fake DTM. CMPv2 runs through a fake `openssl` on PATH that
records its argv/env and issues with the fake CA (tests/fake_openssl.py)."""

import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app import certs, cleanup, dtm, enrollment, evergreen, snippets
from tests.fakedtm import (ACCOUNT_ID, CLIENTAUTH_HOST, ECDSA_CA_ID, HOST, PROFILE_ID, RSA_CA_ID, FakeDTM,
                           _error, cert_pem)
from tests.integration.test_uc01_flow import assert_certificate_files

UC = "uc03"
COMBOS = [(protocol, auth) for protocol in enrollment.PROTOCOLS for auth in enrollment.AUTHS]


def params(**overrides) -> dict:
    return {"dtm_host": HOST, "account_id": ACCOUNT_ID, "variant": "api", "mode": "single", "count": 2,
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


async def do_cleanup(store, fake: FakeDTM, run_id: str, mode: str, tmp_path):
    client = fake.client()
    try:
        await cleanup.cleanup(store, client, run_id, mode, tmp_path / "runs" / run_id)
    finally:
        await client.aclose()
    return store.get_run(run_id)


def db_text(store, run_id) -> str:
    return json.dumps(store.get_run(run_id)) + json.dumps(store.events(run_id)) + json.dumps(store.objects(
        run_id, include_removed=True))


def all_snippets(run: dict) -> str:
    result = run["result"]
    out = []
    for dialect in snippets.DIALECTS:
        out.append(snippets.preamble(result["api_variables"], dialect))
        out += [snippets.render(c["spec"], dialect) for c in result["api_calls"] if c.get("spec")]
    return "\n".join(out)


def files_text(directory: Path) -> str:
    return "".join(p.read_text(errors="replace") for p in directory.rglob("*") if p.is_file())


@pytest.fixture
def secrets_seen(monkeypatch):
    """Records every private key the station generates (factory and device keys)."""
    keys: list[str] = []
    real_device, real_factory = certs.device_request, certs.factory_certificate

    def device_request(cn, key_type):
        key_pem, csr = real_device(cn, key_type)
        keys.append(key_pem.decode())
        return key_pem, csr

    def factory_certificate(cn):
        pem, key_pem = real_factory(cn)
        keys.append(key_pem.decode())
        return pem, key_pem

    monkeypatch.setattr(certs, "device_request", device_request)
    monkeypatch.setattr(certs, "factory_certificate", factory_certificate)
    return keys


def key_body(pem: str) -> str:
    """The base64 body of a PEM key – a key must not appear even re-wrapped."""
    return "".join(line for line in pem.splitlines() if not line.startswith("-----"))[:40]


# --- happy paths: 3 protocols × 2 authentication methods ---------------------------------------

@pytest.mark.parametrize("protocol,auth", COMBOS)
async def test_enrollment_happy_path(store, enroll_net, cmp_openssl, secrets_seen, tmp_path, monkeypatch,
                                     protocol, auth):
    fake = enroll_net
    monkeypatch.setenv("CANARY_PARENT_ENV", "must-not-reach-openssl-in-passcode-mode")
    run_id = f"{protocol[:3]}{auth[:4]}"
    run = await start(store, fake, run_id, tmp_path, protocol=protocol, auth=auth)
    assert run["status"] == "completed", run["error"]
    r = run["result"]
    names = evergreen.common_names(run_id, protocol, 2, UC)
    assert [c["common_name"] for c in r["certificates"]] == names
    assert r["certificate_total"] == 2 and r["private_keys_returned"] == 0
    assert {c["issuer"] for c in r["certificates"]} == {"Fake ECDSA Issuing CA"}
    assert r["protocol"] == protocol and r["auth"] == auth
    assert r["response"]["serial"] == r["certificates"][0]["serial"]
    base = f"robot-{run_id}-uc03"
    credential = ("passcode", f"{base}-passcode") if auth == "passcode" else ("auth_certificate", f"{base}-factory")
    assert {(o["kind"], o["name"]) for o in store.objects(run_id)} == {
        ("division", f"{base}-division"), ("auth_policy", f"{base}-auth"), credential, ("policy", f"{base}-policy")}

    # DTM side: one policy with exactly this protocol, client-side keys, the run's authentication policy
    (policy,) = fake.policies.values()
    (auth_policy,) = fake.active_auth("auth_policy")
    assert policy["certificate_management_methods"] == [dtm.ENROLLMENT_METHODS[protocol]]
    assert policy["authentication_policy_id"] == auth_policy["id"] == store.objects(run_id, "auth_policy")[0]["dtm_id"]
    assert policy["key_generation_option"] == "client_side" and policy["require_device_group_for_enroll"] is False
    assert policy["certificate_profile_id"] == (PROFILE_ID if protocol != "cmpv2" else
                                                 next(p["id"] for p in fake.profiles
                                                      if p["name"] == enrollment.CMP_PROFILE))
    passcode = fake.active_auth("passcode")[0]["body"]["passcode"] if auth == "passcode" else None
    factory = fake.active_auth("auth_certificate")[0]["body"]["pem"] if auth == "certificate" else None
    assert (passcode is None) == (auth != "passcode") and (factory is None) == (auth != "certificate")

    # Protocol side
    if protocol == "cmpv2":
        assert fake.enroll_calls == [] and fake.tls_client_cert is None  # no HTTP from the app, no mTLS
        calls = cmp_openssl.calls()
        assert len(calls) == 2
        for call, cn in zip(calls, names):
            argv = call["argv"]

            def opt(flag):
                return argv[argv.index(flag) + 1]
            assert argv[:3] == ["cmp", "-cmd", "ir"]
            assert opt("-server") == f"https://{HOST}{enrollment.CMP_PATH.format(alternative_id=policy['alternative_id'])}"
            assert opt("-subject") == f"/CN={cn}" and "-implicit_confirm" in argv and "-tls_used" in argv
            device_key = serialization.load_pem_private_key(call["files"]["-newkey"].encode(), None)
            issued = x509.load_pem_x509_certificate(call["issued"].encode())
            assert issued.public_key().public_numbers() == device_key.public_key().public_numbers()
            assert not Path(opt("-newkey")).exists()  # the device key file is gone after the run
            # minimal environment in both modes – never the app's own (DTM API key, JWT secret, …)
            assert "CANARY_PARENT_ENV" not in call["env_keys"]
            assert set(call["env_keys"]) - {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"} == (
                {"PATH", "CMP_SECRET"} if auth == "passcode" else {"PATH"})
            if auth == "passcode":
                created = next(iter(fake.auth_objects["passcode"].values()))
                assert opt("-ref") == created["alternate_id"] and opt("-secret") == "env:CMP_SECRET"
                assert call["cmp_secret"] == passcode and passcode not in " ".join(argv)
                assert not {"-cert", "-key", "-extracerts", "-trusted"} & set(argv)
            else:
                assert Path(opt("-cert")).name == "factory.crt" and Path(opt("-key")).name == "factory.key"
                assert opt("-extracerts") == opt("-cert") and Path(opt("-trusted")).name == "ca-chain.pem"
                assert call["files"]["-cert"] == factory
                assert call["files"]["-trusted"] == cert_pem(fake.ica_cert) + cert_pem(fake.root_cert)
                assert call["cmp_secret"] is None and "-ref" not in argv and "-secret" not in argv
    else:
        assert cmp_openssl.calls() == []
        host = CLIENTAUTH_HOST if auth == "certificate" else HOST
        assert fake.enroll_calls == [(protocol, host)] * 2
        for request in fake.enroll_requests:
            assert "x-api-key" not in request.headers and "account_id" not in request.url.params
            if protocol == "est":
                assert request.url.path == enrollment.EST_PATH.format(policy_id=policy["id"])
            if auth == "passcode":
                if protocol == "est":
                    assert request.headers["authorization"] == "Basic " + base64.b64encode(passcode.encode()).decode()
                else:
                    assert request.headers["x-passcode"] == passcode
            else:
                assert "authorization" not in request.headers and "x-passcode" not in request.headers
        assert fake.tls_client_cert == factory if auth == "certificate" else fake.tls_client_cert is None
        assert {c["common_name"] for c in fake.issued()} == set(names)

    # Secrets never leave the station: not in the DB, the result, events, snippets or run files
    stored = db_text(store, run_id) + all_snippets(run)
    run_files = files_text(tmp_path / "runs" / run_id)
    assert "PRIVATE KEY" not in stored and "PRIVATE KEY" not in run_files
    assert "BEGIN CERTIFICATE" not in db_text(store, run_id)  # PEMs live in files only
    assert len(secrets_seen) == 2 + (auth == "certificate")
    for key in secrets_seen:
        assert key_body(key) not in stored and key_body(key) not in run_files
    if passcode:
        assert passcode not in stored and passcode not in run_files
    assert_certificate_files(tmp_path / "runs" / run_id, r["certificates"])
    assert sorted(p.name for p in (tmp_path / "runs" / run_id).iterdir()) == ["certificates"]
    assert fake.violations == []
    assert not any("blueprint" in str(req.url) for req in fake.requests)


@pytest.mark.parametrize("protocol", ["est", "rest"])
async def test_rsa_ca_enrolls_rsa_device_keys(store, enroll_net, tmp_path, protocol):
    run = await start(store, enroll_net, "rsa1", tmp_path, protocol=protocol, ca_id=RSA_CA_ID,
                      ca_name="Fake RSA ICA", key_type="RSA_2048", count=1)
    assert run["status"] == "completed", store.events("rsa1")
    assert run["result"]["certificates"][0]["key_type"].startswith("RSA")
    assert next(iter(enroll_net.policies.values()))["key_generation_type"] == "RSA_2048"


async def test_api_calls_and_variables(store, enroll_net, cmp_openssl, tmp_path):
    run = await start(store, enroll_net, "ap1", tmp_path, protocol="cmpv2", auth="passcode", count=1)
    assert run["status"] == "completed", store.events("ap1")
    calls = run["result"]["api_calls"]
    paths = [c["path"] for c in calls]
    assert enrollment.AUTH_POLICY_PATH in paths and enrollment.PASSCODE_PATH in paths
    assert dtm.PROFILES in paths and enrollment.POLICY_PATH in paths
    variables = run["result"]["api_variables"]
    assert variables["PASSCODE"] == "<choose a passcode, 6–64 characters>"
    # the real reference belongs to the user's own passcode – the snippet reads it from the create output
    assert variables["PASSCODE_REF"] == "<alternate_id from passcode.json.out>"
    assert next(iter(enroll_net.auth_objects["passcode"].values()))["alternate_id"] not in json.dumps(variables)
    assert variables["CMP_ID"] == next(iter(enroll_net.policies.values()))["alternative_id"]
    passcode_call = next(c for c in calls if c["path"] == enrollment.PASSCODE_PATH)
    assert passcode_call["spec"]["json"]["passcode"] == "{PASSCODE}"
    assert passcode_call["spec"]["output"] == "passcode.json.out"


# --- metrics -----------------------------------------------------------------------------------

async def test_metrics_and_extrapolation(store, enroll_net, tmp_path, monkeypatch):
    """A controlled clock: keygen 0.25 s per device, round trips 0.5 / 1.0 / 3.0 s."""
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(enrollment, "time", SimpleNamespace(monotonic=lambda: clock.now, time=lambda: 1e9))
    real_device, real_enroll = certs.device_request, enrollment.Station.enroll

    def device_request(cn, key_type):
        clock.now += 0.25
        return real_device(cn, key_type)

    durations = iter([0.5, 1.0, 3.0])

    async def enroll(self, cn, key_pem, csr):
        info = await real_enroll(self, cn, key_pem, csr)
        clock.now += next(durations)
        return info

    monkeypatch.setattr(certs, "device_request", device_request)
    monkeypatch.setattr(enrollment.Station, "enroll", enroll)
    run = await start(store, enroll_net, "m1", tmp_path, count=3)
    assert run["status"] == "completed", store.events("m1")
    r = run["result"]
    assert r["duration_s"] == 4.5 and r["keygen_s"] == 0.75  # round trips only / key generation only
    assert r["per_certificate_s"] == 1.5 and r["per_minute"] == 40
    # per device (keygen + round trip): 0.75 / 1.25 / 3.25 → median 1.25 s, robust against the slow one
    assert r["median_device_s"] == 1.25 and "median_s" not in r
    assert r["estimate_devices"] == 1000 and r["estimate_min"] == 20.8  # 1000 × 1.25 s / 60
    enroll_call = next(c for c in r["api_calls"] if c["method"] == "LOCAL" and c["path"] == "EST")
    assert enroll_call["count"] == 3 and enroll_call["outcome"] == "ok"


# --- shared CMPv2 profile ----------------------------------------------------------------------

async def test_shared_cmp_profile_created_once_reused_and_never_deleted(store, enroll_net, cmp_openssl, tmp_path):
    fake = enroll_net
    first = await start(store, fake, "p1", tmp_path, protocol="cmpv2", auth="passcode", count=1)
    assert first["status"] == "completed", store.events("p1")
    (body,) = fake.created_profiles
    assert body["name"] == enrollment.CMP_PROFILE and body["account_id"] == ACCOUNT_ID
    assert body["certificate_template_id"] == "tpl-client"
    csr_entries = [e for e in body["body"] if e["key"] == "csr"]
    assert csr_entries == [{"key": "csr", "optional": False, "enabled": True,
                            "sources": ["user_supplied", "allow_bare_public_key"], "value": None}]
    assert any(e["key"] == "subject.common_name" for e in body["body"])  # rest of the base profile kept
    shared_id = next(p["id"] for p in fake.profiles if p["name"] == enrollment.CMP_PROFILE)
    assert any("Created the shared CMPv2 profile" in e["message"] for e in store.events("p1"))

    second = await start(store, fake, "p2", tmp_path, protocol="cmpv2", auth="certificate", count=1,
                         profile_id="profile-server")
    assert second["status"] == "completed", store.events("p2")
    assert len(fake.created_profiles) == 1 and fake.names("profile_get") == [PROFILE_ID]
    assert {p["certificate_profile_id"] for p in fake.policies.values()} == {shared_id}
    assert any("Using the shared CMPv2 profile" in e["message"] for e in store.events("p2"))

    cmp_openssl.sync_to_dtm()
    for run_id in ("p1", "p2"):
        assert (await do_cleanup(store, fake, run_id, "full", tmp_path))["cleanup_status"] == "done"
    assert fake.issued() == [] and fake.policies == {} and fake.divisions == {}
    shared = next(p for p in fake.profiles if p["id"] == shared_id)
    assert shared["status"] == "ACTIVE"
    assert fake.violations == []  # any profile delete/disable would hit an unmodelled endpoint


@pytest.mark.parametrize("protocol", ["est", "rest"])
async def test_non_cmp_protocols_do_not_touch_profiles(store, enroll_net, tmp_path, protocol):
    await start(store, enroll_net, "np1", tmp_path, protocol=protocol, count=1)
    assert enroll_net.created_profiles == [] and enroll_net.names("profile_get") == []


async def test_profile_without_bare_key_fails_the_run(store, enroll_net, cmp_openssl, tmp_path):
    enroll_net.fail["profile_create"] = lambda request: httpx.Response(
        201, json={"id": "profile-x", "allow_bare_public_key": False})
    run = await start(store, enroll_net, "pb1", tmp_path, protocol="cmpv2", count=1)
    assert run["status"] == "failed" and "bare public keys" in run["error"]
    assert enroll_net.policies == {} and cmp_openssl.calls() == []


# --- error cases -------------------------------------------------------------------------------

@pytest.mark.parametrize("protocol,label", [("est", "EST"), ("rest", "REST API")])
@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_dtm_rejects_enrollment(store, enroll_net, tmp_path, protocol, label, auth):
    enroll_net.enroll_fail = _error(401, "authentication failed")
    run = await start(store, enroll_net, "rj1", tmp_path, protocol=protocol, auth=auth)
    assert run["status"] == "failed"
    assert run["error"].startswith(f"{label} returned 401:") and "authentication failed" in run["error"]
    assert any(e["level"] == "error" and run["error"] in e["message"] for e in store.events("rj1"))
    if auth == "passcode":
        passcode = enroll_net.active_auth("passcode")[0]["body"]["passcode"]
        assert passcode not in db_text(store, "rj1")
    # the ledger is complete, so the rollback still finds everything
    kinds = {o["kind"] for o in store.objects("rj1")}
    assert {"division", "auth_policy", "policy"} <= kinds
    enroll = next(c for c in run["result"]["api_calls"] if c["method"] == "LOCAL" and c["path"] == label)
    assert enroll["outcome"] == "error" and enroll["count"] == 1
    assert (await do_cleanup(store, enroll_net, "rj1", "full", tmp_path))["cleanup_status"] == "done"
    assert all(o["status"] == "DELETED" for objs in enroll_net.auth_objects.values() for o in objs.values())
    assert enroll_net.policies == {} and enroll_net.divisions == {}


async def test_genuinely_wrong_passcode_is_rejected_by_the_fake(store, enroll_net, tmp_path, monkeypatch):
    """Not an injected failure: the station sends a passcode DTM does not know."""
    original = dtm.DTMClient.create_passcode

    async def create_passcode(self, name, auth_policy_id, passcode):
        return await original(self, name, auth_policy_id, passcode + "-other")
    monkeypatch.setattr(dtm.DTMClient, "create_passcode", create_passcode)
    run = await start(store, enroll_net, "wp1", tmp_path, protocol="rest")
    assert run["status"] == "failed" and run["error"].startswith("REST API returned 401")


@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_rest_enrollment_tolerates_raw_line_breaks(store, enroll_net, tmp_path, auth):
    """DTM's v2 certificate endpoint puts raw line breaks into JSON strings (the management client
    parses it leniently, app/dtm.py _json). The REST enrollment answer comes from the same endpoint."""
    enroll_net.rest_raw_control_chars = True
    run = await start(store, enroll_net, "rl1", tmp_path, protocol="rest", auth=auth, count=1)
    assert run["status"] == "completed", run["error"]


async def test_html_error_page_is_not_copied_into_the_error(store, enroll_net, tmp_path):
    enroll_net.enroll_fail = httpx.Response(502, text="<html><body>Bad gateway " + "x" * 500 + "</body></html>")
    run = await start(store, enroll_net, "he1", tmp_path)
    assert run["status"] == "failed" and run["error"] == "EST returned 502: (HTML error page)"


async def test_network_error_fails_the_run_clearly(store, enroll_net, tmp_path):
    enroll_net.enroll_fail = httpx.ConnectError("boom")
    run = await start(store, enroll_net, "ne1", tmp_path, protocol="rest")
    assert run["status"] == "failed" and run["error"] == "REST API request failed: ConnectError"


@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_cmp_rejection_reports_the_cmp_error(store, enroll_net, cmp_openssl, tmp_path, auth):
    cmp_openssl.fail_with("Invalid enrollment profile id")
    run = await start(store, enroll_net, "cr1", tmp_path, protocol="cmpv2", auth=auth)
    assert run["status"] == "failed"
    assert run["error"] == "CMPv2 request rejected: CMP error: Invalid enrollment profile id"
    if auth == "passcode":
        assert enroll_net.active_auth("passcode")[0]["body"]["passcode"] not in db_text(store, "cr1")
    assert len(cmp_openssl.calls()) == 1  # stops at the first failure
    assert not (tmp_path / "runs" / "cr1" / "certificates").exists()


async def test_openssl_missing(store, enroll_net, tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    run = await start(store, enroll_net, "om1", tmp_path, protocol="cmpv2")
    assert run["status"] == "failed" and run["error"] == "openssl is not installed – CMPv2 needs it"


@pytest.mark.parametrize("bad", ["../../x", "a b", "x" * 65, "id;rm"])
async def test_unsafe_cmp_id_from_dtm_is_refused(store, enroll_net, cmp_openssl, tmp_path, bad):
    enroll_net.fail["policy_get"] = lambda request: httpx.Response(200, json={"alternative_id": bad, "ca_chain": []})
    run = await start(store, enroll_net, "ui1", tmp_path, protocol="cmpv2")
    assert run["status"] == "failed" and run["error"].startswith("unexpected ID from DTM")
    assert cmp_openssl.calls() == []


async def test_cmp_passcode_without_reference_is_refused(store, enroll_net, cmp_openssl, tmp_path):
    def no_reference(request):
        response = enroll_net._auth_create("passcode")(request)
        data = json.loads(response.content)
        data.pop("alternate_id")
        return httpx.Response(201, json=data)
    enroll_net.fail["passcode_create"] = no_reference
    run = await start(store, enroll_net, "nr1", tmp_path, protocol="cmpv2")
    assert run["status"] == "failed" and "passcode reference" in run["error"] and cmp_openssl.calls() == []


@pytest.mark.parametrize("record", [{"account_id": "0a1b2c3d-0000-4000-8000-00000000b002", "allow_bare_public_key": True},
                                    {"account_id": ACCOUNT_ID, "allow_bare_public_key": False}])
async def test_unusable_existing_cmp_profile_is_not_used_or_changed(store, enroll_net, cmp_openssl, tmp_path, record):
    enroll_net.profiles.append({"id": "profile-taken", "name": enrollment.CMP_PROFILE, "status": "ACTIVE"} | record)
    run = await start(store, enroll_net, "up1", tmp_path, protocol="cmpv2")
    assert run["status"] == "failed" and "fix or rename it in the DTM portal" in run["error"]
    assert enroll_net.created_profiles == [] and enroll_net.policies == {} and cmp_openssl.calls() == []


async def test_concurrent_cmp_runs_create_the_shared_profile_once(store, enroll_net, cmp_openssl, tmp_path):
    import asyncio
    first, second = await asyncio.gather(
        start(store, enroll_net, "cp1", tmp_path, protocol="cmpv2", count=1),
        start(store, enroll_net, "cp2", tmp_path, protocol="cmpv2", auth="certificate", count=1))
    assert first["status"] == second["status"] == "completed"
    assert len(enroll_net.created_profiles) == 1
    assert len({p["certificate_profile_id"] for p in enroll_net.policies.values()}) == 1


async def test_policy_without_short_id_fails_cmp(store, enroll_net, cmp_openssl, tmp_path):
    enroll_net.fail["policy_get"] = lambda request: httpx.Response(200, json={"id": "x", "ca_chain": []})
    run = await start(store, enroll_net, "ns1", tmp_path, protocol="cmpv2")
    assert run["status"] == "failed" and "no short ID" in run["error"] and cmp_openssl.calls() == []


async def test_failed_credential_create_is_rolled_back(store, enroll_net, tmp_path):
    enroll_net.fail["passcode_create"] = _error(400, "passcode policy violated")
    run = await start(store, enroll_net, "fc1", tmp_path)
    assert run["status"] == "failed" and "400" in run["error"]
    assert {o["kind"] for o in store.objects("fc1")} == {"division", "auth_policy"}
    assert (await do_cleanup(store, enroll_net, "fc1", "full", tmp_path))["cleanup_status"] == "done"
    assert enroll_net.active_auth("auth_policy") == [] and enroll_net.divisions == {}


# --- cleanup -----------------------------------------------------------------------------------

@pytest.mark.parametrize("auth,credential", [("passcode", "passcode_delete"),
                                             ("certificate", "auth_certificate_delete")])
async def test_full_cleanup_order(store, enroll_net, tmp_path, auth, credential):
    fake = enroll_net
    await start(store, fake, "co1", tmp_path, protocol="rest", auth=auth)
    assert (tmp_path / "runs" / "co1" / "certificates").is_dir()
    fake.calls.clear()
    run = await do_cleanup(store, fake, "co1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("co1")
    order = [n for n in fake.route_order() if n.endswith("_delete") or n == "revoke"]
    # certificates → policy → credential → authentication policy → division
    assert order == ["revoke", "revoke", "policy_delete", credential, "auth_policy_delete", "division_delete"]
    # every soft delete is verified with a GET
    assert fake.names(credential.replace("_delete", "_get")) and fake.names("auth_policy_get")
    assert all(o["status"] == "DELETED" for objs in fake.auth_objects.values() for o in objs.values())
    assert fake.issued() == [] and fake.policies == {} and fake.divisions == {}
    assert store.objects("co1") == []
    assert not (tmp_path / "runs" / "co1").exists()  # the PEM downloads go with the full rollback
    assert fake.violations == []


async def test_certificates_cleanup_keeps_configuration_and_pems(store, enroll_net, tmp_path):
    fake = enroll_net
    run = await start(store, fake, "cc1", tmp_path)
    run = await do_cleanup(store, fake, "cc1", "certificates", tmp_path)
    assert run["cleanup_status"] == "done" and fake.issued() == []
    assert len(fake.active_auth("auth_policy")) == 1 and len(fake.active_auth("passcode")) == 1
    assert not any(n.endswith("_delete") for n in fake.route_order())
    assert_certificate_files(tmp_path / "runs" / "cc1", run["result"]["certificates"])


async def test_cmp_certificates_are_revoked_on_cleanup(store, enroll_net, cmp_openssl, tmp_path):
    await start(store, enroll_net, "cm1", tmp_path, protocol="cmpv2", auth="certificate")
    cmp_openssl.sync_to_dtm()
    assert len(enroll_net.issued()) == 2
    run = await do_cleanup(store, enroll_net, "cm1", "full", tmp_path)
    assert run["cleanup_status"] == "done" and enroll_net.issued() == []


@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_discovery_finds_unrecorded_auth_objects_of_this_run_only(store, enroll_net, tmp_path, auth):
    fake = enroll_net
    store.create_run("dc1", UC, params(auth=auth))
    client = fake.client()
    try:  # a crashed run: created in DTM, never recorded
        ap = await client.create_auth_policy("robot-dc1-uc03-auth")
        if auth == "passcode":
            await client.create_passcode("robot-dc1-uc03-passcode", ap, "pass-123456")
        else:
            await client.create_auth_certificate("robot-dc1-uc03-factory", ap, certs.factory_certificate("x")[0])
        # look-alikes that are not this run's
        other = await client.create_auth_policy("robot-dc10-uc03-auth")
        await client.create_auth_policy("customer-auth")
        await client.create_passcode("robot-dc1-uc03-passcode-x", other, "pass-654321")
        # a soft-deleted object of an earlier run with the same ID keeps its name
        old = await client.create_auth_policy("robot-dc1-uc03-auth")
        await client.delete_auth_object("auth_policy", old)
    finally:
        await client.aclose()
    fake.calls.clear()
    run = await do_cleanup(store, fake, "dc1", "full", tmp_path)
    assert run["cleanup_status"] == "done", store.events("dc1")
    statuses = sorted((o["name"], o["status"]) for objs in fake.auth_objects.values() for o in objs.values())
    credential = "robot-dc1-uc03-passcode" if auth == "passcode" else "robot-dc1-uc03-factory"
    assert statuses == sorted([("robot-dc1-uc03-auth", "DELETED"), ("robot-dc1-uc03-auth", "DELETED"),
                               (credential, "DELETED"), ("robot-dc10-uc03-auth", "ACTIVE"),
                               ("customer-auth", "ACTIVE"), ("robot-dc1-uc03-passcode-x", "ACTIVE")])
    order = [n for n in fake.route_order() if n.endswith("_delete")]
    credential_kind = "passcode" if auth == "passcode" else "auth_certificate"
    assert order == [f"{credential_kind}_delete", "auth_policy_delete"]  # the old DELETED one is not touched
    assert fake.names("auth_policy_delete") == [ap]
    messages = " | ".join(e["message"] for e in store.events("dc1"))
    assert messages.count("Found unrecorded auth_policy robot-dc1-uc03-auth") == 1
    # only the credential kind of this run is looked up
    other_kind = "auth_certificate" if auth == "passcode" else "passcode"
    assert fake.names(f"{other_kind}_list") == []


async def test_uc01_cleanup_does_not_look_for_auth_objects(store, fake, tmp_path):
    from tests.integration.test_uc01_flow import start as start_uc01
    await start_uc01(store, fake, "u1", tmp_path)
    fake.calls.clear()
    await do_cleanup(store, fake, "u1", "full", tmp_path)
    assert not any(n.startswith(("auth_", "passcode")) for n in fake.route_order())


async def test_unverified_auth_delete_fails_cleanup_and_keeps_division(store, enroll_net, tmp_path):
    fake = enroll_net
    await start(store, fake, "ud1", tmp_path)
    fake.fail["passcode_delete"] = httpx.Response(200)  # DTM acknowledges but nothing changes
    run = await do_cleanup(store, fake, "ud1", "full", tmp_path)
    assert run["cleanup_status"] == "failed"
    assert any("still ACTIVE after delete" in e["message"] for e in store.events("ud1"))
    assert len(fake.divisions) == 1 and len(fake.active_auth("auth_policy")) == 1
    assert {o["kind"] for o in store.objects("ud1")} == {"division", "auth_policy", "passcode"}
    # retry after DTM recovered
    del fake.fail["passcode_delete"]
    assert (await do_cleanup(store, fake, "ud1", "full", tmp_path))["cleanup_status"] == "done"
    assert fake.divisions == {} and store.objects("ud1") == []


async def test_auth_delete_accepts_already_deleted_object(store, enroll_net, tmp_path):
    fake = enroll_net
    await start(store, fake, "ad1", tmp_path)
    next(iter(fake.auth_objects["passcode"].values()))["status"] = "DELETED"  # deleted in the portal
    run = await do_cleanup(store, fake, "ad1", "full", tmp_path)  # the PUT gets 400, the GET says DELETED
    assert run["cleanup_status"] == "done", store.events("ad1")
    assert fake.divisions == {}


async def test_auth_delete_fails_on_404_without_entity_not_found(store, enroll_net, tmp_path):
    """A vanished route (plain 404) must not count as 'object gone'."""
    fake = enroll_net
    await start(store, fake, "vr1", tmp_path)
    fake.fail["passcode_get"] = httpx.Response(404, text="Not Found")
    run = await do_cleanup(store, fake, "vr1", "full", tmp_path)
    assert run["cleanup_status"] == "failed" and len(fake.divisions) == 1
    assert any("unexpected 404" in e["message"] for e in store.events("vr1"))


async def test_auth_delete_tolerates_already_gone_objects(store, enroll_net, tmp_path):
    fake = enroll_net
    await start(store, fake, "ag1", tmp_path)
    fake.auth_objects["passcode"].clear()  # removed in the portal meanwhile
    run = await do_cleanup(store, fake, "ag1", "full", tmp_path)
    assert run["cleanup_status"] == "done" and fake.divisions == {}


# --- copyable commands -------------------------------------------------------------------------

@pytest.mark.parametrize("protocol,auth", COMBOS)
async def test_snippets_contain_no_secret_and_the_right_auth(store, enroll_net, cmp_openssl, secrets_seen,
                                                             tmp_path, protocol, auth):
    run = await start(store, enroll_net, "sn1", tmp_path, protocol=protocol, auth=auth, count=1)
    assert run["status"] == "completed", store.events("sn1")
    text = all_snippets(run)
    for key in secrets_seen:
        assert key_body(key) not in text
    assert "PRIVATE KEY" not in text and "BEGIN CERTIFICATE" not in text
    if auth == "passcode":
        assert enroll_net.active_auth("passcode")[0]["body"]["passcode"] not in text
    enroll = next(c for c in run["result"]["api_calls"] if c["method"] == "LOCAL"
                  and c["path"] == enrollment.PROTOCOLS[protocol])
    for dialect in snippets.DIALECTS:
        command = snippets.render(enroll["spec"], dialect)
        ps = dialect == "powershell"
        assert command == enroll["spec"]["command"]["powershell" if ps else "bash"]
        assert "x-api-key" not in command.lower() and "account_id" not in command
        assert "/CN=robot-sn1-uc03-" in command
        if protocol == "cmpv2":
            assert "clientauth." not in command and "DIOT_" in command
            assert ("-secret env:PASSCODE" in command) == (auth == "passcode")
            assert ("-extracerts factory.crt -trusted ca-chain.pem" in command) == (auth == "certificate")
            builds_chain = ("ConvertFrom-Json" if ps else "jq -r '.ca_chain[].blob' policy.json") in command
            assert builds_chain == (auth == "certificate")
        else:
            assert ("clientauth." in command) == (auth == "certificate")
            client_cert = "--cert-type P12 --cert factory.p12" if ps else "--cert factory.crt --key factory.key"
            assert (client_cert in command) == (auth == "certificate")
            assert ("openssl pkcs12 -export" in command) == (ps and auth == "certificate")
            marker = "Authorization: Basic" if protocol == "est" else "x-passcode:"
            assert (marker in command) == (auth == "passcode")
            if not ps:  # an HTTP error must not produce a "certificate" file silently
                assert ("--fail-with-body" if protocol == "rest" else "curl -sS --fail ") in command
    if auth == "certificate":
        factory = next(c for c in run["result"]["api_calls"] if c["path"] == "openssl")
        command = snippets.render(factory["spec"], "curl")
        assert "openssl req -x509" in command and "extendedKeyUsage=clientAuth" in command
        assert "basicConstraints=critical,CA:FALSE" in command and "keyUsage=critical,digitalSignature" in command
        assert "FACTORY_CERT" in snippets.render(factory["spec"], "powershell")
    # management calls keep the API key header (as a variable), never its value
    management = [c for c in run["result"]["api_calls"] if c["method"] in ("POST", "GET")]
    assert management and all("x-api-key: ${DTM_API_KEY}" in snippets.render(c["spec"], "curl")
                              for c in management)


@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_station_cmp_argv_is_accepted_by_real_openssl(store, enroll_net, cmp_openssl, tmp_path, auth):
    """Replays the exact argv/env the station gave (fake) openssl against the real OpenSSL 3 cmp app
    and an unreachable server: it must fail on the connection, not on option parsing."""
    import shutil
    import subprocess
    real = next((p for p in (shutil.which("openssl", path=d) for d in os.environ["PATH"].split(os.pathsep)
                             if d != str(cmp_openssl.bin_dir)) if p), None)
    if not real or not subprocess.run([real, "version"], capture_output=True, text=True).stdout.startswith("OpenSSL 3"):
        pytest.skip("needs a real OpenSSL 3")
    run = await start(store, enroll_net, "ro1", tmp_path, protocol="cmpv2", auth=auth, count=1)
    assert run["status"] == "completed", run["error"]
    (call,) = cmp_openssl.calls()
    argv = list(call["argv"])
    replay = tmp_path / "replay"
    replay.mkdir()
    for flag, content in call["files"].items():  # the station's temp dir is gone – recreate its files
        target = replay / Path(argv[argv.index(flag) + 1]).name
        target.write_text(content)
        argv = [str(target) if a == argv[argv.index(flag) + 1] else a for a in argv]
    argv[argv.index("-server") + 1] = "https://127.0.0.1:9/cmp/DIOT_abc"
    for flag in ("-msg_timeout", "-total_timeout"):
        argv[argv.index(flag) + 1] = "5"
    env = {"PATH": "/usr/bin:/bin"} | ({"CMP_SECRET": call["cmp_secret"]} if call["cmp_secret"] else {})
    result = subprocess.run([real, *argv], env=env, capture_output=True, text=True, timeout=30)
    output = (result.stdout + result.stderr).lower()
    assert result.returncode != 0
    assert "unknown option" not in output and "invalid" not in output and "usage" not in output, output
    assert "connect" in output or "transfer" in output, output
