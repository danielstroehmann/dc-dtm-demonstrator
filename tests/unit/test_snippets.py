"""Copyable curl / wget / PowerShell snippets. The bash variants are executed for real against stub
`curl`, `wget` and `openssl` binaries (no network) to prove that what a user copies sends the same
requests the demonstrator sent."""

import json
import os
import shutil
import stat
import subprocess
import textwrap

import pytest

from app import certs, dtm, evergreen, snippets

HOST = "dtm.example.com"
ACCOUNT = "0a1b2c3d-0000-4000-8000-00000000a001"
REAL_KEY = "real-api-key-must-never-appear"
VARIABLES = {"DTM_HOST": HOST, "DTM_ACCOUNT_ID": ACCOUNT, "DIVISION_ID": "div-123", "POLICY_ID": "IOT_abc",
             "JOB_ID": "job-9"}
DIV_PATH = "/devicetrustmanager/api/v4/division"
JOBS = "/devicetrustmanager/certificate-batch-service/api/v1/jobs"

DIVISION = {"method": "POST", "path": DIV_PATH, "body_file": "division.json",
            "json": dtm.division_body("robot-x1-uc01-division", evergreen.DIVISION_DESCRIPTION, "{DTM_ACCOUNT_ID}", "rz-a")}
POLICY = {"method": "POST", "path": evergreen.POLICY_PATH, "body_file": "policy.json",
          "json": dtm.policy_body(name="robot-x1-uc01-policy", division_id="{DIVISION_ID}", profile_id="prof-1",
                                  ica_id="ca-1", key_type="P_256", require_approval=True)}
SINGLE = {"method": "POST", "path": evergreen.SINGLE_PATH, "body_file": "certificate.json",
          "json": dtm.single_body("{POLICY_ID}", "robot-x1-uc01-single-0001"), "output": "certificate.json.out"}
UPLOAD = {"method": "POST", "path": f"{JOBS}/certificate-enroll",
          "form": dtm.batch_fields("robot-x1-uc01-batch", "{POLICY_ID}", "P_256"),
          "files": {"encryption_certificate": "<enc.crt", "data": "@batch.zip;type=application/zip"}}
APPROVE = {"method": "PUT", "path": f"{JOBS}/{{JOB_ID}}/approve", "json": {}, "body_file": "empty.json"}
POLL = {"method": "GET", "path": f"{JOBS}/{{JOB_ID}}"}
DOWNLOAD = {"method": "GET", "path": f"{JOBS}/{{JOB_ID}}/download/result", "output": "result.p7m"}
ENC = {"command": evergreen.ENC_CERT_COMMAND}
DECRYPT = {"command": evergreen.DECRYPT_COMMAND}
ALL = [ENC, DIVISION, POLICY, SINGLE, UPLOAD, APPROVE, POLL, DOWNLOAD, DECRYPT]
CALLS = [{"purpose": f"step {i}", "spec": spec} for i, spec in enumerate(ALL)] + [{"purpose": "no spec", "spec": None}]


def fill(value):
    text = json.dumps(value)
    for name, real in VARIABLES.items():
        text = text.replace("{" + name + "}", real)
    return json.loads(text)


# --- string level --------------------------------------------------------------------------

@pytest.mark.parametrize("dialect", list(snippets.DIALECTS))
def test_api_key_is_always_a_placeholder(dialect):
    text = snippets.script(VARIABLES, CALLS, dialect)
    assert snippets.API_KEY_PLACEHOLDER in text and REAL_KEY not in text
    assert "<your API key>" in snippets.preamble({}, dialect)


def test_placeholder_wins_even_if_variables_carry_a_key():
    for dialect in snippets.DIALECTS:
        text = snippets.preamble(VARIABLES | {"DTM_API_KEY": REAL_KEY}, dialect)
        assert REAL_KEY not in text and snippets.API_KEY_PLACEHOLDER in text


def test_preamble_dialects():
    curl = snippets.preamble(VARIABLES, "curl")
    assert f"export DTM_HOST={HOST}" in curl and "export JOB_ID=job-9" in curl
    assert "export DTM_API_KEY='<your API key>'" in curl
    assert snippets.preamble(VARIABLES, "wget") == curl
    ps = snippets.preamble(VARIABLES, "powershell")
    assert f"$env:DTM_HOST = '{HOST}'" in ps and "$env:DTM_API_KEY = '<your API key>'" in ps
    assert '$headers = @{ "x-api-key" = $env:DTM_API_KEY }' in ps


@pytest.mark.parametrize("dialect,expected", [
    ("curl", "${POLICY_ID}"), ("wget", "${POLICY_ID}"), ("powershell", "$($env:POLICY_ID)")])
def test_token_substitution(dialect, expected):
    text = snippets.render(SINGLE, dialect)
    assert expected in text and "{POLICY_ID}" not in text.replace(expected, "")
    url_host = "${DTM_HOST}" if dialect != "powershell" else "$($env:DTM_HOST)"
    assert f"https://{url_host}{evergreen.SINGLE_PATH}?account_id=" in text


def test_local_commands_are_rendered_verbatim():
    for dialect in snippets.DIALECTS:
        assert snippets.render(ENC, dialect) == evergreen.ENC_CERT_COMMAND
        assert snippets.render(DECRYPT, dialect) == evergreen.DECRYPT_COMMAND


def test_curl_multipart():
    text = snippets.render(UPLOAD, "curl")
    assert '-F "input_format=csv"' in text and '-F "certificate_policy_id=${POLICY_ID}"' in text
    assert '-F "encryption_certificate=<enc.crt"' in text
    assert '-F "data=@batch.zip;type=application/zip"' in text
    assert "Content-Type: application/json" not in text


def test_wget_refuses_multipart():
    text = snippets.render(UPLOAD, "wget")
    assert text.startswith("# wget cannot send multipart/form-data")
    assert all(line.startswith("#") for line in text.splitlines())


def test_powershell_variants():
    upload = snippets.render(UPLOAD, "powershell")
    assert upload.startswith("Invoke-RestMethod -Method Post")
    assert "encryption_certificate = (Get-Content enc.crt -Raw)" in upload
    assert "data = Get-Item batch.zip" in upload
    assert 'certificate_policy_id = "$($env:POLICY_ID)"' in upload
    assert "-Headers $headers" in upload
    single = snippets.render(SINGLE, "powershell")
    assert single.startswith('$body = @"\n') and '\n"@\n' in single
    assert '-ContentType "application/json"' in single and "-Body $body" in single
    assert "-OutFile certificate.json.out" in single
    assert snippets.render(APPROVE, "powershell").split("\n")[3].startswith("Invoke-RestMethod -Method Put")
    assert "-OutFile result.p7m" in snippets.render(DOWNLOAD, "powershell")


def test_script_contains_every_call_with_spec_once():
    text = snippets.script(VARIABLES, CALLS, "curl")
    for i in range(len(ALL)):
        assert text.count(f"# step {i}\n") == 1
    assert "no spec" not in text and text.endswith("\n")


# --- executed in bash against stubs ------------------------------------------------------

STUB = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, sys
    with open(os.environ["STUB_LOG"], "a") as log:
        log.write(json.dumps({"tool": os.path.basename(sys.argv[0]), "argv": sys.argv[1:]}) + "\\n")
    """)


@pytest.fixture
def shell(tmp_path):
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("curl", "wget", "openssl"):
        path = bin_dir / tool
        path.write_text(STUB.replace("#!/usr/bin/env python3", f"#!{shutil.which('python3') or '/usr/bin/python3'}"))
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    work = tmp_path / "work"
    work.mkdir()
    log = tmp_path / "calls.jsonl"

    def run(script_text: str) -> list[dict]:
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "STUB_LOG": str(log), "HOME": str(tmp_path)}
        subprocess.run(["bash", "-c", script_text], cwd=work, env=env, check=True, capture_output=True, timeout=30)
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    run.work = work
    return run


def test_curl_script_sends_what_the_client_sends(shell):
    calls = shell(snippets.script(VARIABLES, CALLS, "curl"))
    tools = [c["tool"] for c in calls]
    assert tools == ["openssl", "curl", "curl", "curl", "curl", "curl", "curl", "curl", "openssl"]
    curl = [c["argv"] for c in calls if c["tool"] == "curl"]
    for argv in curl:
        assert argv[argv.index("-H") + 1] == "x-api-key: <your API key>"
        url = next(a for a in argv if a.startswith("https://"))
        assert url.startswith(f"https://{HOST}/") and url.endswith(f"?account_id={ACCOUNT}")
    division, policy, single, upload, approve, poll, download = curl
    assert division[division.index("-X") + 1] == "POST"
    # JSON bodies written by the heredocs equal the builder output with the variables filled in
    work = shell.work
    assert json.loads((work / "division.json").read_text()) == fill(DIVISION["json"])
    assert json.loads((work / "policy.json").read_text()) == fill(POLICY["json"])
    assert json.loads((work / "certificate.json").read_text()) == fill(SINGLE["json"])
    assert json.loads((work / "empty.json").read_text()) == {}
    assert "--data" in division and division[division.index("--data") + 1] == "@division.json"
    assert single[single.index("-o") + 1] == "certificate.json.out"
    fields = dict(upload[i + 1].split("=", 1) for i, a in enumerate(upload) if a == "-F")
    assert fields == fill(UPLOAD["form"]) | {"encryption_certificate": "<enc.crt",
                                            "data": "@batch.zip;type=application/zip"}
    assert approve[approve.index("-X") + 1] == "PUT" and f"/jobs/job-9/approve?" in " ".join(approve)
    assert f"/jobs/job-9?account_id={ACCOUNT}" in " ".join(poll)
    assert download[download.index("-o") + 1] == "result.p7m"
    assert calls[0]["argv"][:2] == ["req", "-x509"] and calls[-1]["argv"][:2] == ["cms", "-decrypt"]


def test_wget_script_sends_json_calls(shell):
    calls = shell(snippets.script(VARIABLES, CALLS, "wget"))
    wget = [c["argv"] for c in calls if c["tool"] == "wget"]
    assert len(wget) == 6  # every call except the multipart upload
    for argv in wget:
        assert '--header=x-api-key: <your API key>' in argv
        assert argv[-1].startswith(f"https://{HOST}/") and argv[-1].endswith(f"account_id={ACCOUNT}")
    division = wget[0]
    assert "--method=POST" in division and "--body-file=division.json" in division
    assert json.loads((shell.work / "division.json").read_text()) == fill(DIVISION["json"])
    assert "-O" in wget[-1] and wget[-1][wget[-1].index("-O") + 1] == "result.p7m"


def test_dtm_values_cannot_inject_shell_commands(shell):
    hostile = VARIABLES | {"JOB_ID": "job-$(touch PWNED_VAR)"}
    spec = {"method": "POST", "path": DIV_PATH, "body_file": "division.json",
            "json": dtm.division_body("robot-x1-uc01-division", "d", "{DTM_ACCOUNT_ID}", "rz-`touch PWNED_BODY`")}
    shell(snippets.script(hostile, [{"purpose": "x", "spec": spec}], "curl"))
    assert not (shell.work / "PWNED_VAR").exists()
    assert not (shell.work / "PWNED_BODY").exists()


HOSTILE = 'x"$(touch PWNED_A)`touch PWNED_B`\\\'$HOME;'


def test_hostile_values_survive_bash_literally(shell):
    """Escaping must keep the value byte for byte – not just stop the injection."""
    variables = VARIABLES | {"JOB_ID": HOSTILE}
    spec = {"method": "POST", "path": DIV_PATH, "body_file": "division.json",
            "json": dtm.division_body("robot-x1-uc01-division", HOSTILE, "{DTM_ACCOUNT_ID}", HOSTILE)}
    form_spec = {"method": "POST", "path": DIV_PATH, "form": {"name": HOSTILE, "certificate_policy_id": "{POLICY_ID}"}}
    text = snippets.script(variables, [{"purpose": "a", "spec": spec}, {"purpose": "b", "spec": form_spec}], "curl")
    calls = shell(text + 'printf %s "$JOB_ID" > job_id.txt\n')
    work = shell.work
    assert not list(work.glob("PWNED*"))
    assert (work / "job_id.txt").read_text() == HOSTILE
    body = json.loads((work / "division.json").read_text())
    assert body["description"] == HOSTILE and body["primary_rzone_id"] == HOSTILE
    assert body["account_id"] == ACCOUNT  # tokens still expand
    upload = calls[-1]["argv"]
    fields = dict(upload[i + 1].split("=", 1) for i, a in enumerate(upload) if a == "-F")
    assert fields == {"name": HOSTILE, "certificate_policy_id": "IOT_abc"}


def test_powershell_escaping_of_hostile_values():
    ps = snippets.preamble(VARIABLES | {"JOB_ID": "a'b$(x)"}, "powershell")
    assert "$env:JOB_ID = 'a''b$(x)'" in ps  # single-quoted: no expansion, quote doubled
    body = snippets.render({"method": "POST", "path": "/p", "json": {"v": "a$(x)`b\"q"}}, "powershell")
    assert '"v": "a`$(x)``b\\`"q"' not in body  # inside a here-string the quote is not escaped
    assert "a`$(x)``b" in body
    form = snippets.render({"method": "POST", "path": "/p", "form": {"v": 'a"$(x)'}}, "powershell")
    assert 'v = "a`"`$(x)"' in form


def test_brace_text_in_values_is_not_a_token(shell):
    spec = {"method": "POST", "path": DIV_PATH, "body_file": "division.json",
            "json": dtm.division_body("robot-x1-uc01-division", "see {NOTE}", "{DTM_ACCOUNT_ID}", "rz-a")}
    shell(snippets.script(VARIABLES, [{"purpose": "a", "spec": spec}], "curl"))
    assert json.loads((shell.work / "division.json").read_text())["description"] == "see {NOTE}"


def test_script_filters_by_phase():
    calls = [{"purpose": "zone", "phase": "setup", "spec": {"method": "GET", "path": "/zone"}},
             {"purpose": "policy", "phase": "setup", "spec": POLICY},
             {"purpose": "issue", "phase": "recurring", "spec": SINGLE},
             {"purpose": "legacy", "spec": POLL},                       # no phase → recurring
             {"purpose": "untimed", "phase": "setup", "spec": None}]
    setup = snippets.script(VARIABLES, calls, "curl", "setup")
    recurring = snippets.script(VARIABLES, calls, "curl", "recurring")
    everything = snippets.script(VARIABLES, calls, "curl")
    assert [line for line in setup.splitlines() if line.startswith("# ")] == ["# zone", "# policy"]
    assert [line for line in recurring.splitlines() if line.startswith("# ")] == ["# issue", "# legacy"]
    assert [line for line in everything.splitlines() if line.startswith("# ")] == [
        "# zone", "# policy", "# issue", "# legacy"]
    for text in (setup, recurring, everything):
        assert text.startswith(snippets.preamble(VARIABLES, "curl"))  # every script is self-contained
    assert snippets.script(VARIABLES, calls, "curl", "nonexistent") == snippets.preamble(VARIABLES, "curl") + "\n"


def test_phase_scripts_run_independently(shell):
    calls = [{"purpose": "division", "phase": "setup", "spec": DIVISION},
             {"purpose": "issue", "phase": "recurring", "spec": SINGLE}]
    ran = shell(snippets.script(VARIABLES, calls, "curl", "recurring"))
    assert [c["tool"] for c in ran] == ["curl"]
    assert json.loads((shell.work / "certificate.json").read_text()) == fill(SINGLE["json"])
    assert not (shell.work / "division.json").exists()


# --- UC-2: CSR token and per-dialect local commands ----------------------------------------------

KEYGEN = evergreen.keygen_command("robot-x1-uc02-single-0001", "P_256")
CSR_SINGLE = {"method": "POST", "path": evergreen.SINGLE_PATH, "body_file": "certificate.json",
              "json": dtm.single_body("{POLICY_ID}", "robot-x1-uc02-single-0001", "{CSR}"),
              "output": "certificate.json.out"}


def test_local_command_dict_is_rendered_per_dialect():
    assert snippets.render({"command": KEYGEN}, "curl") == KEYGEN["bash"]
    assert snippets.render({"command": KEYGEN}, "wget") == KEYGEN["bash"]
    assert snippets.render({"command": KEYGEN}, "powershell") == KEYGEN["powershell"]


@pytest.mark.parametrize("dialect,expected", [("curl", '"csr": "${CSR}"'), ("wget", '"csr": "${CSR}"'),
                                              ("powershell", '"csr": "$($env:CSR)"')])
def test_csr_token(dialect, expected):
    assert expected in snippets.render(CSR_SINGLE, dialect)


def test_csr_from_file_becomes_valid_json_in_bash(shell, tmp_path):
    """The bash keygen step turns device.csr into $CSR with literal \\n – the heredoc body must then be
    valid JSON whose csr equals the file content byte for byte."""
    csr_pem = certs.factory_csr("robot-x1-uc02-single-0001", "P_256")
    source = tmp_path / "device.csr.src"
    source.write_text(csr_pem)
    openssl = tmp_path / "bin" / "openssl"  # stub: "generate" a known CSR
    openssl.write_text(f"#!/bin/sh\ncp {source} device.csr\necho device.key > device.key\n")
    calls = [{"purpose": "keygen", "phase": "recurring", "spec": {"command": KEYGEN}},
             {"purpose": "single", "phase": "recurring", "spec": CSR_SINGLE}]
    shell(snippets.script(VARIABLES, calls, "curl", "recurring") + 'printf %s "$CSR" > csr_var.txt\n')
    work = shell.work
    body = json.loads((work / "certificate.json").read_text())
    assert body == dtm.single_body("IOT_abc", "robot-x1-uc02-single-0001", (work / "device.csr").read_text())
    assert body["csr"] == csr_pem
    assert "\n" not in (work / "csr_var.txt").read_text().rstrip("\n")  # newlines encoded as \n


def test_real_openssl_keygen_command_works(shell):
    """With the real openssl, the copied step yields a valid CSR for the device CN."""
    import shutil as _shutil
    real = _shutil.which("openssl", path="/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
    if not real:
        pytest.skip("openssl not installed")
    (shell.work.parent / "bin" / "openssl").unlink()
    (shell.work.parent / "bin" / "openssl").symlink_to(real)
    try:
        shell(KEYGEN["bash"] + '\nprintf %s "$CSR" > csr_var.txt\n')
    except subprocess.CalledProcessError as exc:
        pytest.skip(f"local openssl does not support the command: {exc.stderr[:200]!r}")
    from cryptography import x509 as _x509
    csr = _x509.load_pem_x509_csr((shell.work / "device.csr").read_bytes())
    assert csr.is_signature_valid and csr.subject.rfc4514_string() == "CN=robot-x1-uc02-single-0001"
    assert json.loads('"' + (shell.work / "csr_var.txt").read_text() + '"') == (shell.work / "device.csr").read_text()
