"""Copyable curl / wget / PowerShell snippets. The bash variants are executed for real against stub
`curl`, `wget` and `openssl` binaries (no network) to prove that what a user copies sends the same
requests the demonstrator sent."""

import json
import os
import re
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


def test_wget_falls_back_to_curl_for_multipart():
    text = snippets.render(UPLOAD, "wget")
    hint, _, rest = text.partition("\n")
    assert hint == "# wget cannot send multipart/form-data – this step uses curl"
    assert rest == snippets.render(UPLOAD, "curl") and "wget" not in rest
    # with a capture the curl fallback still sets the variable – the next wget step needs it
    captured = UPLOAD | {"capture": {"var": "JOB_ID", "jq": ".id", "ps": "$r.id"}}
    text = snippets.render(captured, "wget")
    assert text == "# wget cannot send multipart/form-data – this step uses curl\n" + snippets.render(captured, "curl")
    assert 'export JOB_ID="$(curl ' in text and ': "${JOB_ID:?' in text


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
    # every script is self-contained; a later phase keeps the IDs a replayed setup captured in this shell.
    # Only the whole script is a file to run – with a bash shebang ($RANDOM is bash)
    assert everything.startswith("#!/usr/bin/env bash\n\n" + snippets.preamble(VARIABLES, "curl") + "\n\n")
    assert setup.startswith(snippets.preamble(VARIABLES, "curl") + "\n\n")
    assert recurring.startswith(snippets.preamble(VARIABLES, "curl", keep=True) + "\n\n")
    assert snippets.preamble(VARIABLES, "curl", keep=True) != snippets.preamble(VARIABLES, "curl")
    assert snippets.script(VARIABLES, calls, "curl", "nonexistent") == snippets.preamble(VARIABLES, "curl", keep=True) + "\n"


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


# --- replay in a fresh shell: run-name token, captures, polling ---------------------------------

from app.apicalls import ApiCalls  # noqa: E402

RUN = "robot-x1-uc01"


def test_tokenize_replaces_the_run_name_deeply_and_nothing_else():
    value = {"name": f"{RUN}-division", "count": 3, "flag": True, "none": None, "token": "{POLICY_ID}",
             "list": [f"{RUN}-single-0001", {"subj": f'-subj "/CN={RUN}-batch-0002"'}, 7],
             "other_run": "robot-x10-uc01-division", "other_uc": "robot-x1-uc02-division"}
    before = json.dumps(value)
    assert snippets.tokenize(value, RUN) == {
        "name": "{RUN_NAME}-division", "count": 3, "flag": True, "none": None, "token": "{POLICY_ID}",
        "list": ["{RUN_NAME}-single-0001", {"subj": '-subj "/CN={RUN_NAME}-batch-0002"'}, 7],
        "other_run": "robot-x10-uc01-division", "other_uc": "robot-x1-uc02-division"}
    assert json.dumps(value) == before  # a new structure – the input stays as it was


async def test_api_calls_tokenize_specs_once_the_run_name_is_known():
    api = ApiCalls()
    api.add("before", "GET", "/x", None, spec={"json": {"name": f"{RUN}-division"}})
    api.run_name = RUN
    api.add("after", "POST", "/x", None, spec={"json": {"name": f"{RUN}-division", "list": [f"{RUN}-a"]}})

    async def answer():
        return "ok"

    assert await api.timed("timed", "GET", "/x", answer(), spec={"command": f'-subj "/CN={RUN}-single-0001"'}) == "ok"
    api.add("no spec", "GET", "/x", 0.1)
    specs = [c["spec"] for c in api.calls]
    assert specs[0] == {"json": {"name": f"{RUN}-division"}}  # recorded before the name was known
    assert specs[1] == {"json": {"name": "{RUN_NAME}-division", "list": ["{RUN_NAME}-a"]}}
    assert specs[2] == {"command": '-subj "/CN={RUN_NAME}-single-0001"'}
    assert specs[3] is None


@pytest.mark.parametrize("dialect,url", [
    ("curl", '"https://${DTM_HOST}/d?account_id=${DTM_ACCOUNT_ID}&limit=100"'),
    ("wget", '"https://${DTM_HOST}/d?account_id=${DTM_ACCOUNT_ID}&limit=100"'),
    ("powershell", '"https://$($env:DTM_HOST)/d?account_id=$($env:DTM_ACCOUNT_ID)&limit=100"')])
def test_query_is_appended_after_the_account(dialect, url):
    assert url in snippets.render({"method": "GET", "path": "/d", "query": evergreen.LIST}, dialect)
    assert "&" not in snippets.render({"method": "GET", "path": "/d"}, dialect)


CREATE = {"method": "POST", "path": "/a", "body_file": "a.json", "json": {"name": "{RUN_NAME}-auth"},
          "capture": {"var": "AUTH_POLICY_ID", "jq": ".id", "ps": "$r.id"}}
LOOKUP = {"method": "GET", "path": DIV_PATH, "query": evergreen.LIST,
          "capture": evergreen.by_name("DIVISION_ID", "{RUN_NAME}-division")}


def test_capture_of_a_create_in_bash():
    assert snippets.render(CREATE, "curl") == (
        'cat > a.json <<EOF\n{\n  "name": "${RUN_NAME}-auth"\n}\nEOF\n'
        'export AUTH_POLICY_ID="$(curl -sS --fail-with-body -X POST "https://${DTM_HOST}/a?account_id=${DTM_ACCOUNT_ID}" \\\n'
        '  -H "x-api-key: ${DTM_API_KEY}" \\\n  -H "Content-Type: application/json" \\\n  --data @a.json \\\n'
        "  | jq -r '(.id) // empty')\"\n"
        ': "${AUTH_POLICY_ID:?not found in the answer}"')
    hinted = CREATE | {"capture": CREATE["capture"] | {"missing": "no policy – check the key"}}
    assert snippets.render(hinted, "curl").endswith('\n: "${AUTH_POLICY_ID:?no policy – check the key}"')
    assert snippets.render(hinted, "wget").endswith('\n  | jq -r \'(.id) // empty\')"\n'
                                                    ': "${AUTH_POLICY_ID:?no policy – check the key}"')
    assert "for i in" not in snippets.render(CREATE, "curl")  # a create is never repeated


def test_capture_of_a_create_in_powershell():
    text = snippets.render(CREATE, "powershell")
    assert text.startswith('$body = @"\n{\n  "name": "$($env:RUN_NAME)-auth"\n}\n"@\n$r = Invoke-RestMethod -Method Post `')
    assert text.endswith('-Body $body\n$env:AUTH_POLICY_ID = $r.id\n'
                         'if (-not $env:AUTH_POLICY_ID) { throw "AUTH_POLICY_ID not found in the answer" }')
    assert "foreach" not in text


def test_lookup_capture_retries_then_guards():
    bash = snippets.render(LOOKUP, "curl")
    assert bash.startswith("for i in 1 2 3 4 5; do")
    assert '--arg a "${RUN_NAME}-division"' in bash and "if length == 1 then .[0].id else empty end" in bash
    assert '[ -n "$DIVISION_ID" ] && break; sleep 2\ndone\n: "${DIVISION_ID:?not found in the answer}"' in bash
    ps = snippets.render(LOOKUP, "powershell")
    assert ps.startswith("foreach ($i in 1..5) {") and "$_.name -ceq \"$($env:RUN_NAME)-division\"" in ps
    assert ".Count -eq 1" in ps and '$_.status -ne "DELETED"' in ps
    assert ps.endswith('if (-not $env:DIVISION_ID) { throw "DIVISION_ID not found in the answer" }')


@pytest.mark.parametrize("missing", ['x"; touch PWNED; "', "x $(id)", "a}b", "x`id`"])
def test_capture_hint_must_be_plain_text(missing):
    spec = CREATE | {"capture": CREATE["capture"] | {"missing": missing}}
    for dialect in snippets.DIALECTS:
        with pytest.raises(ValueError):
            snippets.render(spec, dialect)


@pytest.mark.parametrize("name", ['x"; touch PWNED; "', "a b", "x$(id)", "a'b"])
def test_record_names_must_be_plain(name):
    with pytest.raises(ValueError):
        evergreen.by_name("POLICY_ID", name)
    assert evergreen.by_name("POLICY_ID", "{RUN_NAME}-policy")["arg"] == "{RUN_NAME}-policy"


def test_until_is_bounded_and_stops_on_failure_states():
    poll = {"method": "GET", "path": f"{JOBS}/{{JOB_ID}}", "until": {"status": "completed"}}
    bash = snippets.render(poll, "curl")
    assert bash.startswith("F=0\nfor i in $(seq 1 300); do\n")
    # "failed" ends the loop only once it persists (DTM once reported failed mid-processing); the others at once
    assert ('case "$STATUS" in completed) break ;; failed) F=$((F+1)); [ "$F" -ge 8 ] && '
            '{ echo "job failed" >&2; break; } ;; rejected|""|null) ') in bash
    assert "*) F=0 ;; esac" in bash  # any other status resets the counter
    assert '/jobs/${JOB_ID}?account_id=' in bash and bash.endswith("  sleep 2\ndone")
    wait = snippets.render(poll | {"until": {"status": "pending_approval", "stop": ["completed", "failed"]}}, "wget")
    assert 'case "$STATUS" in pending_approval) break ;; failed) F=$((F+1));' in wait and "wget --method=GET" in wait
    assert ' completed|""|null) ' in wait
    ps = snippets.render(poll, "powershell")
    assert ps.startswith("$f = 0\nforeach ($i in 1..300) {\n  try { $r = Invoke-RestMethod -Method Get `")
    assert "catch { Write-Host" in ps and "if ($r.status -in 'completed', 'rejected') { break }" in ps
    assert "if ($r.status -eq 'failed') { $f++; if ($f -ge 8) { break } } else { $f = 0 }" in ps
    # without "failed" among the stop states there is no counter at all
    plain = poll | {"until": {"status": "completed", "stop": ["rejected"]}}
    assert "F=" not in snippets.render(plain, "curl") and "$f" not in snippets.render(plain, "powershell")
    assert 'case "$STATUS" in completed) break ;; rejected|""|null) ' in snippets.render(plain, "curl")


def test_command_tokens_become_shell_variables_but_written_ones_stay():
    command = 'echo "${RUN_NAME}" {RUN_NAME} x{RUN_NAME} -subj "/CN={RUN_NAME}-0001" {NOTE} $RUN_NAME awk \'{printf $0}\''
    assert snippets.render({"command": command}, "curl") == (
        'echo "${RUN_NAME}" ${RUN_NAME} x{RUN_NAME} -subj "/CN=${RUN_NAME}-0001" {NOTE} $RUN_NAME awk \'{printf $0}\'')
    per_shell = {"bash": "a {POLICY_ID}", "powershell": "b {POLICY_ID} ${env:POLICY_ID}"}
    assert snippets.render({"command": per_shell}, "wget") == "a ${POLICY_ID}"
    assert snippets.render({"command": per_shell}, "powershell") == "b ${env:POLICY_ID} ${env:POLICY_ID}"


def test_preamble_draws_a_fresh_run_name_instead_of_the_runs():
    variables = VARIABLES | {"RUN_NAME": "robot-x1-uc03"}
    for dialect in snippets.DIALECTS:
        text = snippets.preamble(variables, dialect)
        assert "robot-x1-" not in text
        assert text.count("RUN_NAME") == 1  # set once, at the end of the variables
    assert 'export RUN_NAME="robot-r${RANDOM}${RANDOM}-uc03"' in snippets.preamble(variables, "curl")
    assert '$env:RUN_NAME = "robot-r$(Get-Random -Maximum 1000000000)-uc03"' in snippets.preamble(variables, "powershell")
    assert "RUN_NAME" not in snippets.preamble(VARIABLES | {"RUN_NAME": "robot-x1-$(id)"}, "curl")  # no use case
    assert "RUN_NAME" not in snippets.preamble(VARIABLES, "curl")


# executed in bash with jq: the captures must pick exactly the right record or stop the script

@pytest.fixture
def jq_shell(tmp_path):
    if not (shutil.which("bash") and shutil.which("jq")):
        pytest.skip("needs bash and jq")
    work = tmp_path / "jq-work"
    work.mkdir()
    # curl answers the next line of answers.jsonl per call (in a file – each call runs in a subshell)
    stubs = textwrap.dedent("""\
        curl() { n=$(( $(cat n 2>/dev/null || echo 0) + 1 )); echo $n > n; sed -n "${n}p" answers.jsonl; }
        sleep() { :; }
        """)

    def run(snippet: str, answers: list, env: dict | None = None) -> subprocess.CompletedProcess:
        (work / "answers.jsonl").write_text("".join(json.dumps(a) + "\n" for a in answers))
        (work / "n").unlink(missing_ok=True)
        (work / "out.txt").unlink(missing_ok=True)
        full = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "RUN_NAME": "robot-r7-uc01",
                "DTM_ACCOUNT_ID": ACCOUNT} | (env or {})
        return subprocess.run(["bash", "-c", stubs + snippet + '\nprintf %s "$OUT" > out.txt\n'], cwd=work, env=full,
                              capture_output=True, text=True, timeout=60)

    run.work = work
    run.calls = lambda: int((work / "n").read_text())
    return run


def captured(jq_shell, spec, answers, var):
    result = jq_shell(snippets.render(spec, "curl") + f'\nOUT="${var}"', answers)
    out = jq_shell.work / "out.txt"
    return result, out.read_text() if out.exists() else None


def records(*rows):
    return {"records": [dict(r) for r in rows]}


def test_lookup_picks_the_one_live_record_of_the_replay(jq_shell):
    answer = records({"id": "d-other", "name": "robot-r8-uc01-division"},
                     {"id": "d-deleted", "name": "robot-r7-uc01-division", "status": "DELETED"},
                     {"id": "d-new", "name": "robot-r7-uc01-division", "status": "ACTIVE"})
    result, value = captured(jq_shell, LOOKUP, [answer], "DIVISION_ID")
    assert result.returncode == 0, result.stderr
    assert value == "d-new" and jq_shell.calls() == 1


@pytest.mark.parametrize("rows", [
    [],                                                                     # not there (yet)
    [{"id": "a", "name": "robot-r7-uc01-division"}, {"id": "b", "name": "robot-r7-uc01-division"}],  # ambiguous
    [{"id": "a", "name": "robot-r7-uc01-division", "status": "deleted"}],  # only a soft-deleted one
])
def test_lookup_stops_the_script_unless_exactly_one_matches(jq_shell, rows):
    result, value = captured(jq_shell, LOOKUP, [records(*rows)] * 5, "DIVISION_ID")
    assert result.returncode != 0 and value is None  # the guard ended the script before the next line
    assert "DIVISION_ID: not found in the answer" in result.stderr
    assert jq_shell.calls() == 5  # asked again – DTM lists lag behind a create


def test_lookup_waits_for_a_lagging_list(jq_shell):
    late = records({"id": "d-new", "name": "robot-r7-uc01-division"})
    result, value = captured(jq_shell, LOOKUP, [records(), records(), late], "DIVISION_ID")
    assert result.returncode == 0 and value == "d-new" and jq_shell.calls() == 3


def profile_lookup():
    """The spec as the real recorder writes it."""
    api, variables = ApiCalls(), {}

    class Client:
        async def shared_profile(self, spec):
            return "p", "used"

    import asyncio
    asyncio.run(evergreen.use_shared_profile(Client(), api, dtm.PROFILE_EVERGREEN, variables, lambda *a: None))
    return api.calls[0]["spec"]


def test_profile_lookup_is_scoped_to_the_account_and_active(jq_shell):
    name = dtm.PROFILE_EVERGREEN.name
    answer = records({"id": "foreign", "name": name, "status": "ACTIVE", "account_id": "another-account"},
                     {"id": "retired", "name": name, "status": "DISABLED", "account_id": ACCOUNT},
                     {"id": "mine", "name": name, "status": "ACTIVE", "account_id": ACCOUNT})
    result, value = captured(jq_shell, profile_lookup(), [answer], "PROFILE_ID")
    assert result.returncode == 0, result.stderr
    assert value == "mine"
    # only the other account has it active – never take theirs
    only_foreign = records(answer["records"][0], answer["records"][1])
    result, value = captured(jq_shell, profile_lookup(), [only_foreign] * 5, "PROFILE_ID")
    assert result.returncode != 0 and value is None
    assert "PROFILE_ID: not found or retired" in result.stderr
    assert jq_shell.calls() == 1  # an existing object – asked once, not retried


def test_create_capture_sets_the_id_or_stops(jq_shell):
    result, value = captured(jq_shell, CREATE, [{"id": "ap-1"}], "AUTH_POLICY_ID")
    assert result.returncode == 0 and value == "ap-1" and (jq_shell.work / "a.json").exists()
    result, value = captured(jq_shell, CREATE, [{"errors": [{"message": "name already exists"}]}], "AUTH_POLICY_ID")
    assert result.returncode != 0 and value is None and jq_shell.calls() == 1  # a create is not repeated


@pytest.mark.parametrize("statuses,polls,stderr", [
    (["in_progress", "in_progress", "completed", "completed"], 3, ""),
    (["in_progress"] + ["failed"] * 20, 9, "job failed"),  # failed persists 8 polls → ends, bounded
    (["in_progress", "failed", "failed", "in_progress", "completed"], 5, ""),  # transient failed
    (["failed"] * 7 + ["in_progress"] + ["failed"] * 7 + ["completed"], 16, ""),  # the counter resets
    (["failed", "failed", "rejected"], 3, "job rejected"),  # rejected still ends at once
    (["in_progress", None], 2, "job null"),   # an answer without status (e.g. an error) ends the loop
])
def test_until_polls_until_a_final_state(jq_shell, statuses, polls, stderr):
    poll = {"method": "GET", "path": f"{JOBS}/{{JOB_ID}}", "until": {"status": "completed"}}
    answers = [{"status": s} if s else {"errors": []} for s in statuses]
    result = jq_shell(snippets.render(poll, "curl"), answers)
    assert result.returncode == 0 and jq_shell.calls() == polls
    if stderr:
        assert stderr in result.stderr
    else:  # completed: no stop message, and the last answer read was the completed one
        assert "job " not in result.stderr and result.stdout.splitlines()[-1] == "status: completed"
    assert result.stdout.splitlines()[-1].startswith("status: ")


def test_until_gives_up_after_300_polls(jq_shell):
    poll = {"method": "GET", "path": f"{JOBS}/{{JOB_ID}}", "until": {"status": "completed"}}
    result = jq_shell(snippets.render(poll, "curl"), [{"status": "in_progress"}] * 400)
    assert result.returncode == 0 and jq_shell.calls() == 300


def test_csv_batch_command_writes_the_runs_csv(tmp_path):
    if not (shutil.which("bash") and shutil.which("zip") and shutil.which("unzip")):
        pytest.skip("needs bash, zip and unzip")
    import io
    import zipfile
    work = tmp_path / "csv"
    work.mkdir()
    # a second replay in the same directory (other name, fewer devices) leaves only its own CSV
    for run_name, count in (("robot-r4-uc01", 5), ("robot-r5-uc01", 3)):
        subprocess.run(["bash", "-c", snippets.render({"command": evergreen.csv_batch_command(count)}, "curl")],
                       cwd=work, env={"PATH": os.environ["PATH"], "RUN_NAME": run_name}, check=True,
                       capture_output=True, timeout=30)
    expected = zipfile.ZipFile(io.BytesIO(evergreen.batch_zip(evergreen.common_names("r5", "batch", 3, "uc01"))))
    replayed = zipfile.ZipFile(work / "batch.zip")
    assert replayed.namelist() == ["batch.csv"]
    assert replayed.read("batch.csv") == expected.read("batch.csv")


def test_csr_batch_command_packs_one_csr_per_device(tmp_path):
    real = shutil.which("openssl")
    if not (real and shutil.which("bash") and shutil.which("zip")):
        pytest.skip("needs bash, openssl and zip")
    from cryptography import x509 as _x509
    import zipfile
    work = tmp_path / "csr"
    (work / "csrs").mkdir(parents=True)
    (work / "csrs" / "stale.csr").write_text("from an earlier replay")
    env = {"PATH": os.environ["PATH"], "RUN_NAME": "robot-r6-uc02", "HOME": str(tmp_path)}
    result = subprocess.run(["bash", "-c", snippets.render({"command": evergreen.csr_batch_command(2, "P_256")}, "curl")],
                            cwd=work, env=env, capture_output=True, text=True, timeout=60)
    if result.returncode and "ec_paramgen_curve" in result.stderr:
        pytest.skip(f"local openssl does not support the command: {result.stderr[:200]!r}")
    assert result.returncode == 0, result.stderr
    names = evergreen.common_names("r6", "batch", 2, "uc02")
    archive = zipfile.ZipFile(work / "csrs.zip")
    assert archive.namelist() == [f"{n}.csr" for n in names]  # like the run's csrs.zip, no stale file
    for n in names:
        csr = _x509.load_pem_x509_csr(archive.read(f"{n}.csr"))
        assert csr.is_signature_valid and csr.subject.rfc4514_string() == f"CN={n}"
    assert "PRIVATE KEY" not in "".join(archive.read(f"{n}.csr").decode() for n in names)


# --- a later phase pasted on its own keeps what the replayed setup captured -------------------------

KEEP_VARIABLES = VARIABLES | {"PASSCODE": "<choose a passcode>", "ICA_ID": "ca-1", "RUN_NAME": "robot-x1-uc04"}


ZSH_LINE = '[ -n "${ZSH_VERSION:-}" ] && setopt interactivecomments'  # pasted into zsh: "#" lines are comments


def test_keep_preamble_in_bash():
    text = snippets.preamble(KEEP_VARIABLES, "curl", keep=True)
    lines = text.splitlines()
    assert lines[0] == ZSH_LINE and lines.count(ZSH_LINE) == 1
    # every variable is only a fallback – also the key, host and passcode the user filled in for the replay
    for name, value in (("DTM_API_KEY", "'<your API key>'"), ("DTM_HOST", HOST), ("DTM_ACCOUNT_ID", ACCOUNT),
                        ("ICA_ID", "ca-1"), ("PASSCODE", "'<choose a passcode>'"), ("DIVISION_ID", "div-123"),
                        ("POLICY_ID", "IOT_abc"), ("JOB_ID", "job-9")):
        assert f'[ -n "${{{name}:-}}" ] || export {name}={value}' in lines, name
    assert lines[-1] == '[ -n "${RUN_NAME:-}" ] || export RUN_NAME="robot-r${RANDOM}${RANDOM}-uc04"'
    assert all(line.startswith('[ -n "${') and line.count(" || export ") == 1 for line in lines[1:])
    assert "robot-x1-" not in text and "#" not in text  # no inline comments (zsh without interactivecomments)
    plain = snippets.preamble(KEEP_VARIABLES, "curl").splitlines()
    assert plain[0] == ZSH_LINE and snippets.preamble(KEEP_VARIABLES, "wget").splitlines()[0] == ZSH_LINE
    assert "export POLICY_ID=IOT_abc" in plain and "export DTM_API_KEY='<your API key>'" in plain
    assert not any(line.startswith("[ -n") for line in plain[1:]) and "#" not in "".join(plain)
    assert "ZSH_VERSION" not in snippets.preamble(KEEP_VARIABLES, "powershell", keep=True)


def test_keep_preamble_in_powershell():
    text = snippets.preamble(KEEP_VARIABLES | {"POLICY_ID": "IOT_a'b"}, "powershell", keep=True)
    lines = text.splitlines()
    assert "if (-not $env:DTM_API_KEY) { $env:DTM_API_KEY = '<your API key>' }" in lines
    assert f"if (-not $env:DTM_HOST) {{ $env:DTM_HOST = '{HOST}' }}" in lines
    assert "if (-not $env:ICA_ID) { $env:ICA_ID = 'ca-1' }" in lines
    assert "if (-not $env:PASSCODE) { $env:PASSCODE = '<choose a passcode>' }" in lines
    assert "if (-not $env:POLICY_ID) { $env:POLICY_ID = 'IOT_a''b' }" in lines  # quoting kept inside the guard
    assert "if (-not $env:DIVISION_ID) { $env:DIVISION_ID = 'div-123' }" in lines
    assert 'if (-not $env:RUN_NAME) { $env:RUN_NAME = "robot-r$(Get-Random -Maximum 1000000000)-uc04" }' in lines
    assert lines[-1] == '$headers = @{ "x-api-key" = $env:DTM_API_KEY }'
    assert all(line.startswith("if (-not $env:") for line in lines[:-1]) and "#" not in text


def _source(preamble: str, before: str, tmp_path) -> dict:
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    names = ("DTM_API_KEY", "DTM_HOST", "ICA_ID", "PASSCODE", "POLICY_ID", "DIVISION_ID", "RUN_NAME")
    dump = "".join(f'printf "%s=%s\\n" {n} "${{{n}:-}}"\n' for n in names)
    out = subprocess.run(["bash", "-c", before + "\n" + preamble + "\n" + dump], env={"PATH": "/usr/bin:/bin"},
                         cwd=tmp_path, capture_output=True, text=True, check=True, timeout=30).stdout
    return dict(line.split("=", 1) for line in out.splitlines())


def test_keep_preamble_keeps_captured_ids_in_bash(tmp_path):
    keep = snippets.preamble(KEEP_VARIABLES, "curl", keep=True)
    replayed = ("export POLICY_ID=IOT_replay RUN_NAME=robot-r42-uc04 DTM_HOST=other.example "
                "ICA_ID=ca-other PASSCODE=chosen DTM_API_KEY=real-key")
    env = _source(keep, replayed, tmp_path)
    assert env["POLICY_ID"] == "IOT_replay" and env["RUN_NAME"] == "robot-r42-uc04"  # captured by the setup
    # what the user filled in stays – a later phase must not reset the key to its placeholder
    assert (env["DTM_API_KEY"], env["DTM_HOST"], env["ICA_ID"], env["PASSCODE"]) == (
        "real-key", "other.example", "ca-other", "chosen")
    assert env["DIVISION_ID"] == "div-123"  # not set in this shell – the run's value is the fallback
    fresh = _source(keep, "", tmp_path)
    assert (fresh["POLICY_ID"], fresh["DIVISION_ID"], fresh["DTM_HOST"]) == ("IOT_abc", "div-123", HOST)
    assert fresh["DTM_API_KEY"] == "<your API key>" and fresh["PASSCODE"] == "<choose a passcode>"
    assert re.fullmatch(r"robot-r\d+-uc04", fresh["RUN_NAME"])
    # an exported but empty variable counts as unset
    assert _source(keep, "export POLICY_ID= DTM_API_KEY=", tmp_path)["POLICY_ID"] == "IOT_abc"
    # the plain preamble (setup / whole script) overwrites everything
    plain = _source(snippets.preamble(KEEP_VARIABLES, "curl"), replayed, tmp_path)
    assert plain["POLICY_ID"] == "IOT_abc" and plain["RUN_NAME"] != "robot-r42-uc04"
    assert plain["DTM_API_KEY"] == "<your API key>" and plain["DTM_HOST"] == HOST


def test_csr_batch_command_rerun_keeps_only_the_latest_devices(tmp_path):
    """Replaying twice in one directory (new RUN_NAME, fewer devices): csrs.zip holds only the
    second replay's CSRs – no stale CSR of the first one is uploaded again."""
    if not (shutil.which("openssl") and shutil.which("bash") and shutil.which("zip")):
        pytest.skip("needs bash, openssl and zip")
    import zipfile
    work = tmp_path / "csr-rerun"
    work.mkdir()
    for run_name, count in (("robot-r1-uc02", 3), ("robot-r2-uc02", 2)):
        result = subprocess.run(["bash", "-c", snippets.render({"command": evergreen.csr_batch_command(count, "P_256")},
                                                               "curl")],
                                cwd=work, env={"PATH": os.environ["PATH"], "RUN_NAME": run_name, "HOME": str(tmp_path)},
                                capture_output=True, text=True, timeout=60)
        if result.returncode and "ec_paramgen_curve" in result.stderr:
            pytest.skip(f"local openssl does not support the command: {result.stderr[:200]!r}")
        assert result.returncode == 0, result.stderr
    assert zipfile.ZipFile(work / "csrs.zip").namelist() == [
        f"{n}.csr" for n in evergreen.common_names("r2", "batch", 2, "uc02")]
    assert sorted(p.name for p in (work / "csrs").iterdir() if p.suffix == ".csr") == [
        f"{n}.csr" for n in evergreen.common_names("r2", "batch", 2, "uc02")]


def test_batch_steps_start_from_a_clean_directory():
    csv, csr = evergreen.csv_batch_command(2)["bash"], evergreen.csr_batch_command(2, "P_256")["bash"]
    assert csv.endswith("\nrm -f batch.zip && zip -q -j batch.zip batch.csv")
    assert csr.split("\n")[1] == "rm -rf csrs csrs.zip && mkdir csrs"  # after the zip note


@pytest.mark.parametrize("dialect", ["curl", "wget"])
def test_only_the_whole_bash_script_has_a_shebang(dialect):
    calls = [{"purpose": "a", "phase": "setup", "spec": DIVISION}, {"purpose": "b", "phase": "recurring", "spec": SINGLE}]
    whole = snippets.script(VARIABLES, calls, dialect)
    assert whole.startswith(f"#!/usr/bin/env bash\n\n{ZSH_LINE}\nexport DTM_API_KEY=") and whole.count("#!") == 1
    for phase in ("setup", "recurring", "renewal"):
        assert not snippets.script(VARIABLES, calls, dialect, phase).startswith("#!")
    assert "#!" not in snippets.script(VARIABLES, calls, "powershell")


def test_retry_only_for_lookups_right_after_a_create():
    single = {"method": "GET", "path": DIV_PATH, "capture": {"var": "RZONE_ID", "jq": ".records[0].id",
                                                             "ps": "$r.records[0].id"}}
    for dialect in snippets.DIALECTS:
        text = snippets.render(single, dialect)
        assert "for i in" not in text and "foreach" not in text and "sleep" not in text.lower(), dialect
        retried = snippets.render(single | {"capture": single["capture"] | {"retry": True}}, dialect)
        first = retried.splitlines()[0]
        assert first == ("foreach ($i in 1..5) {" if dialect == "powershell" else "for i in 1 2 3 4 5; do")
        assert "#" not in retried  # no inline comments (zsh without interactivecomments)
    assert evergreen.by_name("POLICY_ID", "{RUN_NAME}-policy")["retry"] is True
    assert "retry" not in profile_lookup()["capture"]  # the shared profile exists before – asked once


# pasted into an interactive zsh (macOS default; interactivecomments is off there) ----------------------

PASTE_CALLS = [{"purpose": "Create the division", "phase": "setup", "spec": DIVISION},
               {"purpose": "Generate the CSR (local)", "phase": "recurring",
                "spec": {"command": "# needs openssl\necho step-ran > step.txt"}},
               {"purpose": "Request the certificate", "phase": "recurring", "spec": SINGLE}]


def _stub_tools(tmp_path):
    """curl/wget that only log – the paste must run every line without reaching a network."""
    bin_dir = tmp_path / "paste-bin"
    bin_dir.mkdir()
    for tool in ("curl", "wget"):
        (bin_dir / tool).write_text(f"#!/bin/sh\necho {tool} >> \"$PWD/tools.log\"\n")
        (bin_dir / tool).chmod(0o755)
    return f"{bin_dir}:/usr/bin:/bin"


@pytest.mark.parametrize("dialect,phase", [("curl", "recurring"), ("curl", "setup"), ("wget", "recurring")])
def test_phase_script_pasted_into_interactive_zsh_has_no_comment_errors(tmp_path, dialect, phase):
    zsh = shutil.which("zsh")
    if not zsh:
        pytest.skip("zsh not installed")
    text = snippets.script(VARIABLES | {"RUN_NAME": "robot-x1-uc01"}, PASTE_CALLS, dialect, phase)
    assert "\n# " in text  # the step headings are "#" lines
    work = tmp_path / "zsh"
    work.mkdir()
    result = subprocess.run([zsh, "-f", "-i"], input=text + 'print -r -- "RUN=$RUN_NAME" > done.txt\nexit\n',
                            cwd=work, env={"PATH": _stub_tools(tmp_path), "HOME": str(tmp_path), "TERM": "dumb"},
                            capture_output=True, text=True, timeout=60)
    out = result.stdout + result.stderr
    assert "command not found" not in out and "not found: #" not in out, out[-1500:]
    assert re.fullmatch(r"RUN=robot-r\d+-uc01\n", (work / "done.txt").read_text())  # every line ran
    assert (work / "tools.log").read_text().splitlines() == [dialect]  # one request per phase here
    assert (work / "step.txt").exists() == (phase == "recurring")


def test_the_same_paste_without_the_zsh_line_would_fail(tmp_path):
    """The check above can fail: without the setopt line zsh runs "#" as a command."""
    zsh = shutil.which("zsh")
    if not zsh:
        pytest.skip("zsh not installed")
    text = snippets.script(VARIABLES, PASTE_CALLS, "curl", "recurring").replace(ZSH_LINE + "\n", "")
    result = subprocess.run([zsh, "-f", "-i"], input=text + "exit\n", cwd=tmp_path,
                            env={"PATH": _stub_tools(tmp_path), "HOME": str(tmp_path), "TERM": "dumb"},
                            capture_output=True, text=True, timeout=60)
    assert "command not found: #" in result.stdout + result.stderr


@pytest.mark.parametrize("phase", [None, "setup", "recurring"])
def test_zsh_line_is_a_no_op_in_strict_bash(tmp_path, phase):
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    path = tmp_path / "replay.sh"
    path.write_text(snippets.script(VARIABLES | {"RUN_NAME": "robot-x1-uc01"}, PASTE_CALLS, "curl", phase)
                    + 'echo "done $RUN_NAME" > done.txt\n')
    result = subprocess.run(["bash", "-eu", str(path)], cwd=tmp_path,
                            env={"PATH": _stub_tools(tmp_path), "HOME": str(tmp_path)},
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "setopt" not in result.stderr and "unbound" not in result.stderr
    assert re.fullmatch(r"done robot-r\d+-uc01\n", (tmp_path / "done.txt").read_text())
