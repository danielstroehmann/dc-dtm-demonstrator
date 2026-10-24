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
             "AUTH_POLICY_ID", "PROFILE_ID", "PASSCODE", "FACTORY_CERT")
TOKEN = re.compile(r"\{(" + "|".join(VARIABLES) + r")\}")
API_KEY_PLACEHOLDER = "<your API key>"


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


def preamble(variables: dict, dialect: str) -> str:
    values = {"DTM_API_KEY": API_KEY_PLACEHOLDER}
    values |= {k: v for k, v in variables.items() if k != "DTM_API_KEY"}  # the key is never rendered
    if dialect == "powershell":
        lines = [f"$env:{k} = '{str(v).replace(chr(39), chr(39) * 2)}'" for k, v in values.items()]
        lines.append('$headers = @{ "x-api-key" = $env:DTM_API_KEY }')
    else:
        lines = [f"export {k}={shlex.quote(str(v))}" for k, v in values.items()]
    return "\n".join(lines)


def render(call: dict, dialect: str) -> str:
    """call: {method, path, json?, form?, files?, output?, body_file?, command?}"""
    command = call.get("command")
    if command:  # local step, e.g. openssl – a string, or per shell {"bash": …, "powershell": …}
        if isinstance(command, dict):
            return command["powershell" if dialect == "powershell" else "bash"]
        return command
    method, path = call["method"], call["path"]
    url = f"https://{{DTM_HOST}}{path}?account_id={{DTM_ACCOUNT_ID}}"
    body = json.dumps(call["json"], indent=2) if call.get("json") is not None else None
    body_file = call.get("body_file", "body.json")
    if dialect == "curl":
        parts = [f'curl -sS -X {method} "{_bash(url)}"', '-H "x-api-key: ${DTM_API_KEY}"']
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
        if call.get("form") or call.get("files"):
            return ("# wget cannot send multipart/form-data – use the curl variant here\n"
                    "# (curl ships with Ubuntu, macOS and Windows 10+).")
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
    blocks = [preamble(variables, dialect)]
    blocks += [f"# {c['purpose']}\n{render(c['spec'], dialect)}" for c in calls
               if c.get("spec") and phase in (None, c.get("phase", "recurring"))]
    return "\n\n".join(blocks) + "\n"
