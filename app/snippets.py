"""Copyable command-line versions of the DTM calls a run made: curl, wget (Linux/macOS) and
PowerShell 7 (Windows). Bodies come from the same builders the client sends (app/dtm.py), with
`{VAR}` tokens that each dialect turns into its own variable syntax. The API key is never
rendered – only a variable the user fills in."""

import json
import re
import shlex

DIALECTS = {"curl": "curl", "wget": "wget", "powershell": "PowerShell 7"}
# Only the variables the snippets define are tokens – other "{TEXT}" in DTM values stays as is.
VARIABLES = ("DTM_HOST", "DTM_ACCOUNT_ID", "DIVISION_ID", "POLICY_ID", "JOB_ID", "CSR",
             "AUTH_POLICY_ID", "PROFILE_ID", "PASSCODE", "FACTORY_CERT", "RUN_NAME", "ICA_ID", "RZONE_ID",
             "GROUP_ID", "DEVICE_ID", "CERT_ID", "DEVICE_NAME", "IDENTITY", "FIRMWARE_DIVISION_ID", "PAYLOAD_ID",
             "ARTIFACT_ID", "RELEASE_ID")
TOKEN = re.compile(r"\{(" + "|".join(VARIABLES) + r")\}")
# In local commands the shell variables are written out already – only bare {VAR} tokens are replaced.
COMMAND_TOKEN = re.compile(r"(?<![$\w])\{(" + "|".join(VARIABLES) + r")\}")
API_KEY_PLACEHOLDER = "<your API key>"
WGET_NO_MULTIPART = "# wget cannot send multipart/form-data"


def tokenize(value, run_name: str):
    """The run's literal name (in bodies, common names, local commands) becomes {RUN_NAME}, so a
    replay under another RUN_NAME creates its own objects instead of reusing the original names."""
    if isinstance(value, str):
        return value.replace(run_name, "{RUN_NAME}")
    if isinstance(value, dict):
        return {k: tokenize(v, run_name) for k, v in value.items()}
    if isinstance(value, list):
        return [tokenize(v, run_name) for v in value]
    return value


# Values come from DTM, so they are escaped for the target shell before the {VAR} tokens are
# turned into variable references – pasting a snippet must never execute anything else.
def _bash(text: str, heredoc: bool = False) -> str:
    # In an unquoted heredoc only \ $ ` are special; inside "…" the quote is, too.
    escaped = re.sub(r"([\\$`])" if heredoc else r'([\\$`"])', r"\\\1", text)
    return TOKEN.sub(r"${\1}", escaped)


def _ps(text: str, herestring: bool = False) -> str:
    # In an expandable here-string only ` and $ are special; inside "…" the quote is, too.
    escaped = re.sub(r"([`$])" if herestring else r'([`$"])', r"`\1", text)
    return TOKEN.sub(r"$($env:\1)", escaped)


def preamble(variables: dict, dialect: str, keep: bool = False) -> str:
    """keep: for a later phase pasted on its own – what this shell already has (the key and passcode
    the user filled in, the IDs and RUN_NAME a replayed setup captured) stays; the run's values are
    only the fallback."""
    values = {"DTM_API_KEY": API_KEY_PLACEHOLDER}
    values |= {k: v for k, v in variables.items() if k != "DTM_API_KEY"}  # the key is never rendered
    # A fresh RUN_NAME per replay: DTM keeps the names of deleted policies reserved, and a lookup by
    # name must find the replay's objects, not the run's.
    use_case = str(values.pop("RUN_NAME", "")).rpartition("-")[2]
    use_case = use_case if re.fullmatch(r"uc\d\d", use_case) else ""
    ps = dialect == "powershell"
    # macOS' interactive zsh treats pasted "# …" lines as commands unless comments are switched on.
    lines = [] if ps else ['[ -n "${ZSH_VERSION:-}" ] && setopt interactivecomments']
    for k, v in values.items():
        value = "'" + str(v).replace("'", "''") + "'" if ps else shlex.quote(str(v))
        line = f"$env:{k} = {value}" if ps else f"export {k}={value}"
        if keep:
            line = f"if (-not $env:{k}) {{ {line} }}" if ps else f'[ -n "${{{k}:-}}" ] || {line}'
        lines.append(line)
    if use_case:
        line = (f'$env:RUN_NAME = "robot-r$(Get-Random -Maximum 1000000000)-{use_case}"' if ps
                else f'export RUN_NAME="robot-r${{RANDOM}}${{RANDOM}}-{use_case}"')
        if keep:
            line = f"if (-not $env:RUN_NAME) {{ {line} }}" if ps else f'[ -n "${{RUN_NAME:-}}" ] || {line}'
        lines.append(line)
    if ps:
        lines.append('$headers = @{ "x-api-key" = $env:DTM_API_KEY }')
    return "\n".join(lines)


def render(call: dict, dialect: str) -> str:
    """call: {method, path, json?, form?, files?, output?, body_file?, command?, capture?, until?}
    capture: {var, jq, arg?, ps} – set a variable from the answer (bash: jq with $a = arg; PowerShell:
             an expression on $r), so the next steps use what DTM just created.
             missing: what to tell the user when the answer has no match (plain text).
    until:   {status, stop?} – repeat the request until .status reaches it (polling)."""
    command = call.get("command")
    if command:  # local step, e.g. openssl – a string, or per shell {"bash": …, "powershell": …}
        if isinstance(command, dict):
            command = command["powershell" if dialect == "powershell" else "bash"]
        return COMMAND_TOKEN.sub(r"${env:\1}" if dialect == "powershell" else r"${\1}", command)
    if dialect == "wget" and (call.get("form") or call.get("files")):
        return f"{WGET_NO_MULTIPART} – this step uses curl\n" + render(call, "curl")
    request = _request(call, dialect)
    if call.get("until"):
        return _until(request, call["until"], dialect)
    if call.get("capture"):
        return _capture(request, call["capture"], dialect)
    return request


def _jq(capture: dict) -> str:
    arg = f' --arg a "{_bash(capture["arg"])}"' if capture.get("arg") else ""
    return f"jq -r{arg} '({capture['jq']}) // empty'"


def _split(request: str) -> tuple[str, str]:
    """Body heredoc / here-string first, then the command itself."""
    for marker in ("\nEOF\n", '\n"@\n'):
        if marker in request:
            head, _, cmd = request.rpartition(marker)
            return head + marker, cmd
    return "", request


def _capture(request: str, capture: dict, dialect: str) -> str:
    """capture["retry"]: a lookup right after a create – asked again a few times, DTM lists lag behind."""
    var, missing = capture["var"], capture.get("missing", "not found in the answer")
    if not re.fullmatch(r"[\w\s.,–-]+", missing):  # it lands in a shell string unescaped
        raise ValueError(f"capture hint must be plain text: {missing!r}")
    head, cmd = _split(request)
    if dialect == "powershell":
        # The expression is ours (constant); only the {VAR} tokens become environment variables.
        step = f"$r = {cmd}\n$env:{var} = {TOKEN.sub(r'$($env:\1)', capture['ps'])}"
        if capture.get("retry"):
            step = ("foreach ($i in 1..5) {\n  "
                    + step.replace("\n", "\n  ") + f"\n  if ($env:{var}) {{ break }}\n  Start-Sleep 2\n}}")
        return f'{head}{step}\nif (-not $env:{var}) {{ throw "{var} {missing}" }}'
    step = f'export {var}="$({cmd} \\\n  | {_jq(capture)})"'
    if capture.get("retry"):
        step = ("for i in 1 2 3 4 5; do\n  "
                + step.replace("\n", "\n  ") + f'\n  [ -n "${var}" ] && break; sleep 2\ndone')
    return f'{head}{step}\n: "${{{var}:?{missing}}}"'


FAILED_POLLS = 8


def _until(request: str, until: dict, dialect: str) -> str:
    target, stop = until["status"], until.get("stop", ["failed", "rejected"])
    head, cmd = _split(request)
    # Bounded like the run itself (10 minutes), and an unreadable answer ends the loop, too –
    # an endless poll would keep loading DTM. DTM once reported "failed" mid-processing and then
    # completed the job, so "failed" ends the loop only once it persists (FAILED_POLLS × 2 s).
    confirm, final = "failed" in stop, [s for s in stop if s != "failed"]
    if dialect == "powershell":
        states = ", ".join(f"'{s}'" for s in [target, *final])
        cmd = cmd.replace("\n", "\n  ")
        check = (f"\n  if ($r.status -eq 'failed') {{ $f++; if ($f -ge {FAILED_POLLS}) {{ break }} }} else {{ $f = 0 }}"
                 if confirm else "")
        return (f"{head}{'$f = 0' + chr(10) if confirm else ''}foreach ($i in 1..300) {{\n  try {{ $r = {cmd} }}\n"
                '  catch { Write-Host "request failed: $($_.Exception.Message)"; break }\n'
                f'  Write-Host "status: $($r.status)"\n  if ($r.status -in {states}) {{ break }}{check}\n  Start-Sleep 2\n}}')
    failed = (f' failed) F=$((F+1)); [ "$F" -ge {FAILED_POLLS} ] && {{ echo "job failed" >&2; break; }} ;;'
              if confirm else "")
    return (f'{head}{"F=0" + chr(10) if confirm else ""}for i in $(seq 1 300); do\n  STATUS="$({cmd} \\\n    | jq -r .status)"\n'
            f'  echo "status: $STATUS"\n'
            f'  case "$STATUS" in {target}) break ;;{failed} {"|".join([*final, '""', "null"])}) '
            f'echo "job ${{STATUS:-not readable}}" >&2; break ;;{" *) F=0 ;;" if confirm else ""} esac\n'
            f"  sleep 2\ndone")


def _request(call: dict, dialect: str) -> str:
    method, path = call["method"], call["path"]
    url = f"https://{{DTM_HOST}}{path}?account_id={{DTM_ACCOUNT_ID}}" + (f"&{call['query']}" if call.get("query") else "")
    body = json.dumps(call["json"], indent=2) if call.get("json") is not None else None
    body_file = call.get("body_file", "body.json")
    if dialect == "curl":
        parts = [f'curl -sS --fail-with-body -X {method} "{_bash(url)}"', '-H "x-api-key: ${DTM_API_KEY}"']
        prefix = ""
        if body is not None:
            prefix = f"cat > {body_file} <<EOF\n{_bash(body, heredoc=True)}\nEOF\n"
            parts += ['-H "Content-Type: application/json"', f"--data @{body_file}"]
        for name, value in (call.get("form") or {}).items():
            parts.append(f'-F "{name}={_bash(value)}"')
        for name, source in (call.get("files") or {}).items():
            parts.append(f'-F "{name}={source}"')
        if call.get("output"):
            parts.append(f"-o {call['output']}")
        return prefix + " \\\n  ".join(parts)
    if dialect == "wget":
        parts = [f"wget --method={method}", '--header="x-api-key: ${DTM_API_KEY}"']
        prefix = ""
        if body is not None:
            prefix = f"cat > {body_file} <<EOF\n{_bash(body, heredoc=True)}\nEOF\n"
            parts += ['--header="Content-Type: application/json"', f"--body-file={body_file}"]
        parts.append(f"-O {call['output']}" if call.get("output") else "-qO-")
        parts.append(f'"{_bash(url)}"')
        return prefix + " \\\n  ".join(parts)
    # PowerShell 7 (Invoke-RestMethod; -Form needs PowerShell 6.1+)
    parts = [f"Invoke-RestMethod -Method {method.title()}", f'-Uri "{_ps(url)}"', "-Headers $headers"]
    prefix = ""
    if body is not None:
        prefix = f'$body = @"\n{_ps(body, herestring=True)}\n"@\n'
        parts += ['-ContentType "application/json"', "-Body $body"]
    form = [f'{n} = "{_ps(v)}"' for n, v in (call.get("form") or {}).items()]
    for name, source in (call.get("files") or {}).items():
        file = source.lstrip("@<").split(";")[0]
        form.append(f"{name} = (Get-Content {file} -Raw)" if source.startswith("<") else f"{name} = Get-Item {file}")
    if form:
        parts.append("-Form @{\n    " + "\n    ".join(form) + "\n  }")
    if call.get("output"):
        parts.append(f"-OutFile {call['output']}")
    return prefix + " `\n  ".join(parts)


def script(variables: dict, calls: list[dict], dialect: str, phase: str | None = None) -> str:
    # bash, not sh: the preamble draws RUN_NAME from $RANDOM
    blocks = ([] if dialect == "powershell" or phase else ["#!/usr/bin/env bash"])
    blocks.append(preamble(variables, dialect, keep=phase not in (None, "setup")))
    blocks += [f"# {c['purpose']}\n{render(c['spec'], dialect)}" for c in calls
               if c.get("spec") and phase in (None, c.get("phase", "recurring"))]
    return "\n\n".join(blocks) + "\n"
