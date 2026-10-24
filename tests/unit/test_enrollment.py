"""UC-3 building blocks: key material, policy/profile bodies, the station's input checks and the
copyable enrollment commands. The bash commands are executed for real (openssl, jq) against a stub
`curl` that plays DTM, so what a user copies is known to work."""

import base64
import json
import os
import shutil
import subprocess
import sys
import textwrap
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import certs, dtm, enrollment, snippets
from tests.fakedtm import cert_pem, key_pem, make_cert


# --- key material ------------------------------------------------------------------------------

@pytest.mark.parametrize("key_type,kind", [("P_256", ec.EllipticCurvePrivateKey), ("RSA_2048", rsa.RSAPrivateKey)])
def test_device_request(key_type, kind):
    key_bytes, csr = certs.device_request("robot-x1-uc03-est-0001", key_type)
    key = serialization.load_pem_private_key(key_bytes, None)
    assert isinstance(key, kind)
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "robot-x1-uc03-est-0001"
    assert csr.public_key().public_numbers() == key.public_key().public_numbers()
    if key_type == "RSA_2048":
        assert key.key_size == 2048


def test_factory_certificate_is_a_self_signed_client_certificate():
    pem, key_bytes = certs.factory_certificate("robot-x1-uc03-factory")
    cert = x509.load_pem_x509_certificate(pem.encode())
    key = serialization.load_pem_private_key(key_bytes, None)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert cert.subject == cert.issuer
    cert.verify_directly_issued_by(cert)
    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.CLIENT_AUTH])
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical and usage.value.digital_signature and not usage.value.key_cert_sign
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert cert.not_valid_after_utc - cert.not_valid_before_utc <= timedelta(days=7, minutes=5)
    assert "PRIVATE KEY" not in pem and b"PRIVATE KEY" in key_bytes
    assert certs.factory_certificate("robot-x1-uc03-factory")[0] != pem  # a fresh key per run


def test_der_b64_to_pem_roundtrip():
    cert, _ = make_cert("Some CA", ca=True)
    blob = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    assert certs.der_b64_to_pem(blob) == cert_pem(cert)
    with pytest.raises(ValueError):
        certs.der_b64_to_pem(base64.b64encode(b"not a certificate").decode())


def test_parse_pkcs7_certificates_and_rejects_garbage():
    leaf, _ = make_cert("robot-x1-uc03-est-0001")
    ca, _ = make_cert("Fake ICA", ca=True)
    # verified live: DTM's EST answer carries the end-entity certificate only
    (info,) = certs.parse_pkcs7_certificates(pkcs7.serialize_certificates([leaf], serialization.Encoding.DER))
    assert info["common_name"] == "robot-x1-uc03-est-0001" and info["pem"] == cert_pem(leaf)
    assert info["serial"] == format(leaf.serial_number, "X")
    # a degenerate PKCS#7 is a DER SET – it does not keep the sender's order
    infos = certs.parse_pkcs7_certificates(pkcs7.serialize_certificates([leaf, ca], serialization.Encoding.DER))
    assert {i["common_name"] for i in infos} == {"robot-x1-uc03-est-0001", "Fake ICA"}
    with pytest.raises(ValueError):
        certs.parse_pkcs7_certificates(b"\x30\x03garbage")


def test_save_certificates_moves_pems_into_files(tmp_path):
    a, _ = make_cert("robot-x1-uc03-rest-0001")
    b, _ = make_cert("robot-x1-uc03-rest-0002")
    issued = [certs.certificate_info(a), certs.certificate_info(b), {"serial": "ABC", "common_name": "no pem"}]
    certs.save_certificates(tmp_path / "run", issued)
    certs.save_certificates(tmp_path / "run", [])  # an existing directory is fine
    files = sorted(p.name for p in (tmp_path / "run" / "certificates").iterdir())
    assert files == sorted([f"{format(a.serial_number, 'X')}.pem", f"{format(b.serial_number, 'X')}.pem"])
    assert all("pem" not in i for i in issued)
    assert (tmp_path / "run" / "certificates" / f"{format(a.serial_number, 'X')}.pem").read_text() == cert_pem(a)


# --- DTM bodies --------------------------------------------------------------------------------

@pytest.mark.parametrize("protocol,method", [("est", "EST"), ("cmpv2", "CMP_V2"), ("rest", "SINGLE")])
def test_enrollment_policy_body(protocol, method):
    body = dtm.enrollment_policy_body(name="robot-x1-uc03-policy", division_id="div", profile_id="prof",
                                      ica_id="ica", key_type="P_256", auth_policy_id="ap", protocol=protocol)
    policy = body["certificate_policy"]
    assert policy["certificate_management_methods"] == [method]
    assert policy["authentication_policy_id"] == "ap" and policy["key_generation_option"] == "client_side"
    assert policy["require_device_group_for_enroll"] is False and policy["require_approval_for_enroll"] is False
    assert ("cmp_request_parameters" in policy) == (protocol == "cmpv2")
    assert ("single_cert_request_parameters" in policy) == (protocol == "rest")
    assert "batch_request_parameters" not in policy


def test_bare_key_profile_body_replaces_only_the_csr_entry():
    base = {"certificate_template": {"id": "tpl"}, "name": "Base", "id": "p1",
            "body": [{"key": "subject.common_name", "sources": ["user_supplied"]},
                     {"key": "csr", "sources": ["user_supplied"], "optional": True}]}
    body = dtm.bare_key_profile_body(base, "robot-uc03-cmp-profile", "acc")
    assert body["name"] == "robot-uc03-cmp-profile" and body["account_id"] == "acc"
    assert body["certificate_template_id"] == "tpl" and body["divisions"] == []
    assert body["body"] == [{"key": "subject.common_name", "sources": ["user_supplied"]},
                            {"key": "csr", "optional": False, "enabled": True,
                             "sources": ["user_supplied", "allow_bare_public_key"], "value": None}]
    assert base["body"][1] == {"key": "csr", "sources": ["user_supplied"], "optional": True}  # base untouched


# --- station input checks ----------------------------------------------------------------------

def station(tmp_path, **overrides):
    args = {"host": "dtm.test", "protocol": "est", "auth": "passcode", "policy_id": "IOT_abc-1", "cmp_id": None,
            "passcode": "p" * 32, "passcode_ref": None, "factory": None, "workdir": tmp_path,
            "ca_chain_pem": ""} | overrides
    return enrollment.Station(**args)


@pytest.mark.parametrize("field,value", [("policy_id", "IOT_../../x"), ("policy_id", "a b"),
                                         ("policy_id", "x" * 65), ("cmp_id", "a;b"), ("passcode_ref", "$(id)")])
def test_station_refuses_unsafe_ids(tmp_path, field, value):
    with pytest.raises(enrollment.EnrollmentError, match="unexpected ID from DTM"):
        station(tmp_path, **({"protocol": "cmpv2", "cmp_id": "abc", "passcode_ref": "ref-1"} | {field: value}))


@pytest.mark.parametrize("overrides", [{"cmp_id": None, "passcode_ref": "ref"}, {"cmp_id": "abc", "passcode_ref": None}])
def test_station_cmp_needs_endpoint_id_and_reference(tmp_path, overrides):
    with pytest.raises(enrollment.EnrollmentError, match="CMPv2 endpoint ID or passcode reference"):
        station(tmp_path, protocol="cmpv2", **overrides)


async def test_station_hosts_and_files(tmp_path):
    factory = certs.factory_certificate("robot-x1-uc03-factory")
    for protocol, expected in (("est", "clientauth.dtm.test"), ("rest", "clientauth.dtm.test"), ("cmpv2", "dtm.test")):
        workdir = tmp_path / protocol
        workdir.mkdir()
        s = station(workdir, protocol=protocol, auth="certificate", passcode=None, factory=factory, cmp_id="abc",
                    ca_chain_pem="CHAIN")
        try:
            assert s.host == expected
            assert (workdir / "factory.crt").read_text() == factory[0]
            assert (workdir / "factory.key").stat().st_mode & 0o777 == 0o600
            assert (workdir / "ca-chain.pem").read_text() == "CHAIN"
        finally:
            await s.aclose()
    (tmp_path / "pc").mkdir()
    s = station(tmp_path / "pc")  # passcode: plain host, no factory files
    try:
        assert s.host == "dtm.test" and not (tmp_path / "pc" / "factory.key").exists()
    finally:
        await s.aclose()


# --- copyable commands: string level -----------------------------------------------------------

COMBOS = [(p, a) for p in enrollment.PROTOCOLS for a in enrollment.AUTHS]


def steps_of(protocol, auth, cn="robot-x1-uc03-dev-0001", key_type="P_256"):
    return enrollment.enroll_steps(protocol, auth, cn, key_type)


@pytest.mark.parametrize("protocol,auth", COMBOS)
def test_enroll_steps_structure(protocol, auth):
    steps = steps_of(protocol, auth)
    setup = {("est", "certificate"): 1, ("rest", "certificate"): 1, ("cmpv2", "certificate"): 1}.get((protocol, auth), 0)
    assert [s["kind"] for s in steps] == ["setup"] * setup + ["keygen", "call", "convert"]
    assert [s["phase"] for s in steps] == ["setup"] * setup + ["recurring"] * 3
    for s in steps:
        assert set(s) == {"kind", "purpose", "method", "path", "command", "phase"}
        assert set(s["command"]) == {"bash", "powershell"} and all(s["command"].values())
        assert s["method"] == ("POST" if s["kind"] == "call" else "LOCAL")
    assert len({s["purpose"] for s in steps}) == len(steps)  # each step is its own entry
    call = steps[setup + 1]
    assert call["path"] == {"rest": enrollment.REST_PATH,
                            "est": "/.well-known/est/devicetrustmanager/{POLICY_ID}/simpleenroll",
                            "cmpv2": enrollment.CMP_PATH.format(alternative_id="{CMP_ID}")}[protocol]
    if setup:
        setup_bash = steps[0]["command"]["bash"]
        if protocol == "cmpv2":
            assert "ca-chain.pem" in setup_bash and "ConvertFrom-Json" in steps[0]["command"]["powershell"]
        else:  # PKCS#12 only for Windows curl.exe; bash needs nothing
            assert setup_bash.startswith("#") and "\n" not in setup_bash
            assert "openssl pkcs12 -export" in steps[0]["command"]["powershell"]


@pytest.mark.parametrize("protocol,auth", COMBOS)
def test_enroll_steps_carry_no_secret_and_the_right_auth(protocol, auth):
    steps = steps_of(protocol, auth)
    for s in steps:
        for shell, text in s["command"].items():
            assert "x-api-key" not in text.lower() and "DTM_API_KEY" not in text and "account_id" not in text
            assert "PRIVATE KEY" not in text and "BEGIN CERTIFICATE" not in text
    call = next(s for s in steps if s["kind"] == "call")
    for shell, text in call["command"].items():
        ps = shell == "powershell"
        if auth == "passcode":  # always a variable the user sets
            assert ("$env:PASSCODE" if ps else "${PASSCODE") in text
        if protocol == "cmpv2":
            assert "clientauth." not in text and "DIOT_" in text and "-certout device.crt" in text
            assert ("-ref " in text and "-secret env:PASSCODE" in text) == (auth == "passcode")
            assert ("-extracerts factory.crt -trusted ca-chain.pem" in text) == (auth == "certificate")
        else:
            assert ("clientauth." in text) == (auth == "certificate")
            client_cert = "--cert-type P12 --cert factory.p12" if ps else "--cert factory.crt --key factory.key"
            assert (client_cert in text) == (auth == "certificate")
            marker = "Authorization: Basic" if protocol == "est" else "x-passcode:"
            assert (marker in text) == (auth == "passcode")
            assert ("--fail-with-body" if protocol == "rest" else "--fail ") in text
            assert "|" not in text.replace("printf %s \"${PASSCODE}\" | openssl base64 -A", "")  # no pipes
    for s in steps:  # .NET file IO resolves against the process dir – always "$PWD/…"
        ps = s["command"]["powershell"]
        assert ps.count("[IO.File]::") == ps.count('"$PWD/')


@pytest.mark.parametrize("key_type,expected,other", [("P_256", "P-256", "rsa"), ("RSA_2048", "rsa", "P-256")])
def test_enroll_steps_key_type(key_type, expected, other):
    for protocol in enrollment.PROTOCOLS:
        keygen = next(s for s in steps_of(protocol, "passcode", key_type=key_type) if s["kind"] == "keygen")
        bash = keygen["command"]["bash"]
        assert expected in bash and other not in bash


# --- copyable commands: executed in bash -------------------------------------------------------

CURL_STUB = textwrap.dedent("""\
    import base64, json, os, sys
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    args, i, opts, headers = sys.argv[1:], 0, {}, []
    while i < len(args):
        a = args[i]
        if a in ("-X", "--data", "--data-binary", "-o", "--cert", "--key", "--cert-type"):
            opts[a] = args[i + 1]; i += 2
        elif a == "-H":
            headers.append(args[i + 1]); i += 2
        elif a.startswith("-"):
            opts[a] = True; i += 1
        else:
            opts["url"] = a; i += 1
    body = open((opts.get("--data-binary") or opts.get("--data"))[1:]).read()
    with open(os.environ["STUB_LOG"], "a") as log:
        log.write(json.dumps({"opts": opts, "headers": headers, "body": body}) + "\\n")
    ca = x509.load_pem_x509_certificate(open(os.environ["STUB_CA"], "rb").read())
    ca_key = serialization.load_pem_private_key(open(os.environ["STUB_CA_KEY"], "rb").read(), None)
    if "/simpleenroll" in opts["url"]:
        csr = x509.load_der_x509_csr(base64.b64decode(body, validate=True))  # one line, no wrapping
    else:
        request = json.loads(body)
        csr = x509.load_pem_x509_csr(request["csr"].encode())
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca.subject)
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .sign(ca_key, hashes.SHA256()))
    if "/simpleenroll" in opts["url"]:
        answer = base64.b64encode(pkcs7.serialize_certificates([cert], serialization.Encoding.DER)).decode()
        if os.environ.get("STUB_EST_WRAP", "64") == "64":  # MIME-style lines; "none": one line
            answer = "".join(answer[i:i + 64] + "\\n" for i in range(0, len(answer), 64))
        if "-o" in opts:
            open(opts["-o"], "w").write(answer)
        else:
            sys.stdout.write(answer)
    else:
        open(opts["-o"], "w").write(json.dumps({"pem": cert.public_bytes(serialization.Encoding.PEM).decode()}))
    """)


@pytest.fixture
def bash_env(tmp_path):
    openssl = shutil.which("openssl")
    if not shutil.which("bash") or not openssl:
        pytest.skip("bash/openssl not available")
    if not subprocess.run([openssl, "version"], capture_output=True, text=True).stdout.startswith("OpenSSL 3"):
        pytest.skip("needs OpenSSL 3")
    bin_dir, work = tmp_path / "bin", tmp_path / "work"
    bin_dir.mkdir()
    work.mkdir()
    (bin_dir / "curl").write_text(f"#!{sys.executable}\n" + CURL_STUB)
    (bin_dir / "curl").chmod(0o755)
    ca, ca_key = make_cert("Stub ICA", ca=True)
    (tmp_path / "ca.pem").write_text(cert_pem(ca))
    (tmp_path / "ca.key").write_text(key_pem(ca_key))
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "STUB_LOG": str(tmp_path / "log.jsonl"),
           "STUB_CA": str(tmp_path / "ca.pem"), "STUB_CA_KEY": str(tmp_path / "ca.key"),
           "DTM_HOST": "dtm.example.com", "POLICY_ID": "IOT_abc", "PASSCODE": "s3cr3t passcode with $pecial",
           "HOME": str(tmp_path)}

    def run(script: str):
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=work, env=env,
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        log = tmp_path / "log.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return run, work, env


def bash_session(protocol, auth, cn):
    """All steps one after another in one shell – how a user pastes them."""
    return "\n".join(s["command"]["bash"] for s in steps_of(protocol, auth, cn))


@pytest.mark.parametrize("protocol", ["est", "rest"])
@pytest.mark.parametrize("auth", ["passcode", "certificate"])
def test_bash_enroll_steps_run(bash_env, protocol, auth):
    if protocol == "rest" and not shutil.which("jq"):
        pytest.skip("jq not available")
    run, work, env = bash_env
    cn = "robot-x1-uc03-dev-0001"
    (call,) = run(bash_session(protocol, auth, cn))
    host = "clientauth.dtm.example.com" if auth == "certificate" else "dtm.example.com"
    path = (enrollment.EST_PATH.format(policy_id="IOT_abc") if protocol == "est" else enrollment.REST_PATH)
    assert call["opts"]["url"] == f"https://{host}{path}" and call["opts"]["-X"] == "POST"
    if auth == "passcode":
        expected = ("Authorization: Basic " + base64.b64encode(env["PASSCODE"].encode()).decode()
                    if protocol == "est" else f"x-passcode: {env['PASSCODE']}")
        assert expected in call["headers"]
        assert "--cert" not in call["opts"]
    else:
        assert call["opts"]["--cert"] == "factory.crt" and call["opts"]["--key"] == "factory.key"
        assert not any(h.lower().startswith(("authorization", "x-passcode")) for h in call["headers"])
    assert ("--fail" if protocol == "est" else "--fail-with-body") in call["opts"]
    if protocol == "rest":
        request = json.loads(call["body"])
        assert request["certificate_policy_id"] == "IOT_abc"
        assert request["certificate_profile_attributes"] == [{"id": "subject.common_name", "value": cn}]
    # the convert step leaves a PEM device certificate for the device key
    cert = x509.load_pem_x509_certificate((work / "device.crt").read_bytes())
    key = serialization.load_pem_private_key((work / "device.key").read_bytes(), None)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == cn


@pytest.mark.parametrize("auth", ["passcode", "certificate"])
def test_bash_cmp_steps_run(bash_env, cmp_openssl, auth):
    """keygen and convert run with the real openssl, the cmp call with the recording fake."""
    if auth == "certificate" and not shutil.which("jq"):
        pytest.skip("jq not available")
    run, work, env = bash_env
    real = next(p for p in (shutil.which("openssl", path=d) for d in env["PATH"].split(os.pathsep)
                            if d != str(cmp_openssl.bin_dir)) if p)
    cmp_openssl.pass_through(real)
    env["PATH"] = f"{cmp_openssl.bin_dir}{os.pathsep}{env['PATH']}"
    env |= {"CMP_ID": "abc123", "PASSCODE_REF": "ref-42"}
    cn = "robot-x1-uc03-cmpv2-0001"
    prepare = ""
    if auth == "certificate":
        ica, _ = make_cert("Fake ICA", ca=True)
        blob = base64.b64encode(ica.public_bytes(serialization.Encoding.DER)).decode()
        (work / "policy.json").write_text(json.dumps({"ca_chain": [{"blob": blob}]}))
        prepare = enrollment.factory_command("robot-x1-uc03-factory")["bash"] + "\n"
    run(prepare + bash_session("cmpv2", auth, cn))
    (call,) = cmp_openssl.calls()
    argv = call["argv"]

    def opt(flag):
        return argv[argv.index(flag) + 1]
    assert opt("-server") == "https://dtm.example.com" + enrollment.CMP_PATH.format(alternative_id="abc123")
    assert opt("-newkey") == "device.key" and opt("-subject") == f"/CN={cn}" and opt("-certout") == "device.crt"
    if auth == "passcode":
        assert opt("-ref") == "ref-42" and opt("-secret") == "env:PASSCODE"
        assert env["PASSCODE"] not in " ".join(argv)
    else:
        assert opt("-cert") == opt("-extracerts") == "factory.crt" and opt("-trusted") == "ca-chain.pem"
        assert call["files"]["-trusted"] == cert_pem(x509.load_der_x509_certificate(base64.b64decode(blob)))
    cert = x509.load_pem_x509_certificate((work / "device.crt").read_bytes())
    key = serialization.load_pem_private_key((work / "device.key").read_bytes(), None)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()


def test_bash_est_convert_accepts_single_line_base64(bash_env):
    """DTM's line wrapping of the base64 PKCS#7 answer is not verified. `openssl base64 -d` without
    -A silently decodes a single long line to nothing; with -A it handles both forms."""
    run, work, env = bash_env
    env["STUB_EST_WRAP"] = "none"
    run(bash_session("est", "passcode", "robot-x1-uc03-dev-0001"))
    x509.load_pem_x509_certificate((work / "device.crt").read_bytes())


def test_bash_factory_command_runs(bash_env):
    run, work, _env = bash_env
    script = enrollment.factory_command("robot-x1-uc03-factory")["bash"] + '\nprintf %s "$FACTORY_CERT" > exported.txt'
    run(script)
    cert = x509.load_pem_x509_certificate((work / "factory.crt").read_bytes())
    assert cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.CLIENT_AUTH])
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical and usage.value.digital_signature
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert constraints.critical and constraints.value.ca is False
    # FACTORY_CERT is the PEM with literal \n – what the auth-certificate JSON body needs
    exported = (work / "exported.txt").read_text()
    assert "\n" not in exported and json.loads('"' + exported + '"') == (work / "factory.crt").read_text()


def test_bash_ca_chain_step_builds_the_chain_from_policy_json(bash_env):
    if not shutil.which("jq"):
        pytest.skip("jq not available")
    run, work, _env = bash_env
    ica, _ = make_cert("Fake ICA", ca=True)
    root, _ = make_cert("Fake Root", ca=True)
    blobs = [{"blob": base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()} for c in (ica, root)]
    (work / "policy.json").write_text(json.dumps({"alternative_id": "abc", "ca_chain": blobs}))
    run(enrollment.CA_CHAIN_BASH)
    chain = x509.load_pem_x509_certificates((work / "ca-chain.pem").read_bytes())
    assert chain == [ica, root]


# --- snippets: new variables -------------------------------------------------------------------

def test_new_tokens_become_shell_variables():
    spec = {"method": "POST", "path": enrollment.PASSCODE_PATH, "body_file": "passcode.json",
            "json": {"authentication_policy_id": "{AUTH_POLICY_ID}", "passcode": "{PASSCODE}",
                     "certificate_profile_id": "{PROFILE_ID}", "pem": "{FACTORY_CERT}"}}
    curl = snippets.render(spec, "curl")
    for name in ("AUTH_POLICY_ID", "PASSCODE", "PROFILE_ID", "FACTORY_CERT"):
        assert "${" + name + "}" in curl and "{" + name + "}" not in curl.replace("${" + name + "}", "")
        assert f"$($env:{name})" in snippets.render(spec, "powershell")
    assert 'x-api-key: ${DTM_API_KEY}' in curl and "account_id=${DTM_ACCOUNT_ID}" in curl


def test_render_has_no_alternative_auth_any_more():
    """Enrollment commands come from enrollment.enroll_steps only; render() always speaks to the
    management API with the API key."""
    spec = {"method": "POST", "path": enrollment.REST_PATH, "json": {}, "auth": "passcode"}
    curl = snippets.render(spec, "curl")
    assert "x-api-key: ${DTM_API_KEY}" in curl and "x-passcode" not in curl
