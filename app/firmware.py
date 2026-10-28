"""UC-8 firmware over the air. Every IoT minion leaves the factory with firmware 1.0.0 – a dancing figure. The operator
builds new versions per click (picks a figure, the colour is rolled) and deploys any of them to a run's devices – before
they are in the field or while they run: DTM deploys the release to the run's device group, the TrustEdge agent
downloads the zip over MQTT, unpacks it and runs its install.sh, which replaces /opt/firmware.

DTM deletes no artifact, release or deployment. Versions therefore form a catalogue shared by all runs of the account:
artifact + release robot-firmware-<n>-<figure>-<colour> in the permanent division robot-firmware-division, recycled
by every later run (re-enabled if someone disabled them). Only the deployment belongs to a run – the rollback aborts
it, and it stays in DTM as aborted."""

import html
import io
import json
import random
import re
import zipfile

from . import dtm
from .apicalls import ApiCalls
from .devices import commit, device_action
from .dtm import DTMClient
from .evergreen import prefix
from .store import Store, now

MAX_DEPLOYMENTS = 3  # per run
CHARACTERS = ("robot", "ghost", "alien")
FACTORY = {"version": 1, "character": "robot", "color": "#1976d2"}
# Saturated, friendly colours that carry the white eyes – the factory blue stays reserved for 1.0.0
PALETTE = ("#e53935", "#d81b60", "#8e24aa", "#5e35b1", "#00897b", "#43a047", "#7cb342", "#f57c00", "#fb8c00",
           "#6d4c41", "#00acc1", "#3949ab")
DIVISION = "robot-firmware-division"
DESCRIPTION = "dc-dtm-demonstrator firmware – shared by all runs, kept permanently (DTM cannot delete it)"
BUSY = "firmware"  # marks the firmware action in the run's busy list, next to the devices acting
NAME = re.compile(r"^robot-firmware-([0-9]{1,4})-(robot|ghost|alien)-([0-9a-f]{6})$")
COLOR = re.compile(r"#[0-9a-f]{6}")

FIGURES = {  # 64×64, "currentColor" becomes the version's colour
    "robot": '<line x1="32" y1="4" x2="32" y2="12" stroke="#555" stroke-width="2"/><circle cx="32" cy="4" r="3" fill="#f57c00"/>'
             '<rect x="18" y="12" width="28" height="20" rx="4" fill="currentColor"/>'
             '<circle cx="26" cy="22" r="3.5" fill="#fff"/><circle cx="38" cy="22" r="3.5" fill="#fff"/>'
             '<rect x="22" y="34" width="20" height="18" rx="3" fill="currentColor"/>'
             '<rect class="arm-l" x="12" y="36" width="8" height="4" rx="2" fill="currentColor"/>'
             '<rect class="arm-r" x="44" y="36" width="8" height="4" rx="2" fill="currentColor"/>'
             '<rect x="24" y="52" width="5" height="9" rx="2" fill="#555"/><rect x="35" y="52" width="5" height="9" rx="2" fill="#555"/>',
    "ghost": '<path d="M12 58V28a20 20 0 0 1 40 0v30l-6.7-5-6.6 5-6.7-5-6.7 5-6.6-5z" fill="currentColor"/>'
             '<ellipse cx="25" cy="28" rx="4" ry="5" fill="#fff"/><ellipse cx="39" cy="28" rx="4" ry="5" fill="#fff"/>'
             '<circle cx="26" cy="29" r="2" fill="#333"/><circle cx="40" cy="29" r="2" fill="#333"/>',
    "alien": '<ellipse cx="32" cy="22" rx="18" ry="15" fill="currentColor"/>'
             '<ellipse cx="25" cy="22" rx="5" ry="7" fill="#333" transform="rotate(-20 25 22)"/>'
             '<ellipse cx="39" cy="22" rx="5" ry="7" fill="#333" transform="rotate(20 39 22)"/>'
             '<rect x="26" y="37" width="12" height="14" rx="5" fill="currentColor"/>'
             '<path class="arm-l" d="M26 41l-9 -6" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>'
             '<path class="arm-r" d="M38 41l9 -6" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>'
             '<path d="M29 51l-3 9M35 51l3 9" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>',
}

INSTALL = """#!/bin/sh
# OTA install action: the TrustEdge agent has fetched this artifact over MQTT and unpacked it – replace the firmware.
# The newest version wins: an older one is skipped (deployments may arrive in any order).
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
DST=/opt/firmware
new=$(cat "$SRC/version.txt")
old=$(cat "$DST/version.txt" 2>/dev/null || echo 0)
if [ "$new" -le "$old" ]; then echo "firmware $old installed – $new skipped"; exit 0; fi
cp "$SRC/firmware.html" "$DST/firmware.html.new" && mv "$DST/firmware.html.new" "$DST/firmware.html"
cp "$SRC/version.txt" "$DST/version.txt.new" && mv "$DST/version.txt.new" "$DST/version.txt"
echo "firmware $new installed"
"""


def svg(look: dict, label: str | None = None) -> str:
    """The version's dancing figure – only known figures and a validated colour reach the markup. The colour goes
    into attributes: the CSP allows no inline style."""
    character = look.get("character") if look.get("character") in FIGURES else FACTORY["character"]
    color = look.get("color") if COLOR.fullmatch(str(look.get("color"))) else FACTORY["color"]
    return (f'<svg class="dancer {character}" viewBox="0 0 64 64" role="img" '
            f'aria-label="{html.escape(label or "Firmware " + semver(look))}">{FIGURES[character].replace("currentColor", color)}</svg>')


def semver(look: dict) -> str:
    """The version as DTM shows it on the artifact and release."""
    return f"{int(look.get('version') or 1)}.0.0"


def catalog(store: Store, account_id: str) -> list[dict]:
    """The account's versions as last read from DTM, newest first (refreshed on every firmware action)."""
    try:
        return json.loads(store.get_setting(f"firmware_catalog:{account_id}") or "[]")
    except ValueError:
        return []


def legacy(result: dict) -> bool:
    """A run from before the catalogue: its versions carry no catalogue name and may collide with catalogue numbers."""
    return any("name" not in r for r in result.get("firmware") or [])


def looks(result: dict) -> dict[int, dict]:
    """The versions a run's devices can have – the factory's and the deployed ones."""
    return {1: FACTORY} | {r["version"]: r for r in result.get("firmware") or []}


def payload(look: dict) -> bytes:
    page = (f'<!doctype html><meta charset="utf-8"><title>Firmware {semver(look)}</title>'
            f'<body style="font-family:sans-serif;text-align:center">{svg(look)}'
            f'<p>Firmware {semver(look)} · {look["character"]} {look["color"]}</p></body>')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        script = zipfile.ZipInfo("install.sh")
        script.external_attr = 0o100755 << 16
        script.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(script, INSTALL)
        archive.writestr("version.txt", f"{look['version']}\n")
        archive.writestr("firmware.html", page)
    return buffer.getvalue()


async def refresh(store: Store, client: DTMClient) -> list[dict]:
    """Reads the catalogue from DTM: our artifacts by name, each with its release."""
    releases = {r["name"]: r for r in await client.named_prefix(dtm.RELEASES, "robot-firmware-")}
    entries = []
    for artifact in await client.named_prefix(dtm.ARTIFACTS, "robot-firmware-"):
        match = NAME.fullmatch(str(artifact.get("name")))
        if not match:
            continue
        release_ = releases.get(artifact["name"]) or {}
        entries.append({"name": artifact["name"], "version": int(match.group(1)), "character": match.group(2), "color": "#" + match.group(3),
                        "artifact_id": artifact["id"], "artifact_enabled": artifact.get("status") == "ENABLED",
                        "release_id": release_.get("id"), "release_enabled": release_.get("status") == "ENABLED"})
    entries.sort(key=lambda e: e["version"], reverse=True)
    store.set_setting(f"firmware_catalog:{client.config.account_id}", json.dumps(entries))
    return entries


async def create(store: Store, client: DTMClient, run_id: str, character: str) -> None:
    """Per click: a new version with the chosen figure and a rolled colour joins the catalogue."""
    await device_action(store, run_id, BUSY, "New firmware version",
                        lambda log: _create(store, client, run_id, character, log))


async def deploy(store: Store, client: DTMClient, run_id: str, name: str) -> None:
    """Per click: a catalogue version (by its unique name) goes to the run's device group."""
    await device_action(store, run_id, BUSY, "Firmware deployment",
                        lambda log: _deploy(store, client, run_id, name, log))


async def _create(store: Store, client: DTMClient, run_id: str, character: str, log) -> None:
    if character not in FIGURES:
        raise ValueError("unknown figure")
    run_ = store.get_run(run_id)
    api = ApiCalls()
    api.run_name = prefix(run_id, run_["use_case"])
    entries = await refresh(store, client)
    newest = entries[0] if entries else FACTORY
    used = {e["color"] for e in entries if e["character"] == character} | {newest["color"]}
    look = {"version": newest["version"] + 1, "character": character,
            "color": random.choice([c for c in PALETTE if c not in used] or PALETTE)}
    name = f"robot-firmware-{look['version']}-{character}-{look['color'][1:]}"
    log(f"Building firmware {semver(look)}: {character} in {look['color']} – artifact and release {name}")
    division_id = await _division(client, api)
    account_id = run_["params"]["account_id"]
    payload_id = await api.timed("Upload the firmware zip (tus: create, send, finish)", "POST", dtm.UPLOADS,
                                 client.upload_payload(f"{name}.zip", payload(look)),
                                 spec={"command": _upload_command()})
    body = dtm.artifact_body(name, division_id, account_id, semver(look), DESCRIPTION, payload_id)
    artifact_id = await api.timed(
        "Create the artifact: the zip and the script the agent runs (install.sh)", "POST", dtm.ARTIFACTS,
        client.create_artifact(body),
        spec={"method": "POST", "path": dtm.ARTIFACTS, "body_file": "artifact.json", "json": body | {
            "account_id": "{DTM_ACCOUNT_ID}", "division_id": "{FIRMWARE_DIVISION_ID}", "payload_ids": ["{PAYLOAD_ID}"]},
            "capture": {"var": "ARTIFACT_ID", "jq": ".id", "ps": "$r.id"}})
    body = dtm.release_body(name, division_id, account_id, semver(look), DESCRIPTION, artifact_id)
    await api.timed("Create the release with the artifact", "POST", dtm.RELEASES, client.create_release(body),
                    spec={"method": "POST", "path": dtm.RELEASES, "body_file": "release.json", "json": body | {
                        "account_id": "{DTM_ACCOUNT_ID}", "division_id": "{FIRMWARE_DIVISION_ID}",
                        "artifact_ids": [{"id": "{ARTIFACT_ID}", "order": 0}]},
                        "capture": {"var": "RELEASE_ID", "jq": ".id", "ps": "$r.id"}})
    await refresh(store, client)
    _record(store, run_id, api, division_id)
    log(f"Firmware {semver(look)} is in the catalogue – deploy it to the devices", "success")


async def _deploy(store: Store, client: DTMClient, run_id: str, artifact: str, log) -> None:
    run_ = store.get_run(run_id)
    p, result = run_["params"], run_["result"]
    if legacy(result):
        raise ValueError("the run was started before the firmware catalogue")
    if len(result.get("firmware") or []) >= MAX_DEPLOYMENTS:
        raise ValueError(f"at most {MAX_DEPLOYMENTS} firmware deployments per run")
    groups, divisions = store.objects(run_id, "device_group"), store.objects(run_id, "division")
    if not groups or not divisions:
        raise ValueError("the run has no device group any more")
    entry = next((e for e in await refresh(store, client) if e["name"] == artifact and e["release_id"]), None)
    if entry is None:
        raise ValueError(f"firmware {artifact} is not in the catalogue")
    version = entry["version"]
    api = ApiCalls()
    api.run_name = prefix(run_id, run_["use_case"])
    log(f"Deploying firmware {semver(entry)} ({entry['character']}) to the device group")
    if not entry["artifact_enabled"]:
        await api.timed("Enable the artifact again", "PATCH", f"{dtm.ARTIFACTS}/{{id}}/enable",
                        client.enable(dtm.ARTIFACTS, entry["artifact_id"]))
    if not entry["release_enabled"]:
        await api.timed("Enable the release again", "PATCH", f"{dtm.RELEASES}/{{id}}/enable",
                        client.enable(dtm.RELEASES, entry["release_id"]))
    name = f"{api.run_name}-firmware-{version}"
    body = dtm.deployment_body(name, divisions[0]["dtm_id"], p["account_id"], groups[0]["dtm_id"], entry["release_id"])
    deployment_id = await api.timed(
        "Deploy the release to the device group now", "POST", dtm.DEPLOYMENTS, client.create_deployment(body),
        spec={"method": "POST", "path": dtm.DEPLOYMENTS, "body_file": "deployment.json", "json": dtm.deployment_body(
            "{RUN_NAME}-firmware-2", "{DIVISION_ID}", "{DTM_ACCOUNT_ID}", "{GROUP_ID}", "{RELEASE_ID}")})
    store.add_object(run_id, "deployment", deployment_id, name)
    look = {k: entry[k] for k in ("name", "version", "character", "color")}
    commit(store, run_id, lambda r: r.setdefault("firmware", []).append(look | {"at": now()}))
    _record(store, run_id, api)
    log(f"Firmware {semver(entry)} deployed – each running IoT minion installs it within about half a minute",
        "success")


def _record(store: Store, run_id: str, api: ApiCalls, division_id: str | None = None) -> None:
    """The first firmware action shows every step, later ones count up."""
    def change(r: dict) -> None:
        known = {c["purpose"]: c for c in r["api_calls"]}
        for call in api.calls:
            if call["purpose"] in known:
                known[call["purpose"]]["count"] = known[call["purpose"]].get("count", 1) + 1
            else:
                r["api_calls"].append(call | {"phase": "firmware"})
        if division_id:
            r.setdefault("api_variables", {})["FIRMWARE_DIVISION_ID"] = division_id
    commit(store, run_id, change)


async def _division(client: DTMClient, api: ApiCalls) -> str:
    """The permanent division of the shared firmware artifacts and releases."""
    found = await client.division_ids(DIVISION)
    if found:
        return found[0]
    return await api.timed("Create the permanent division for the shared firmware", "POST", dtm.DIVISIONS,
                           client.create_division(DIVISION, "dc-dtm-demonstrator – shared firmware, kept permanently"))


def _upload_command() -> dict:
    url = '"https://${DTM_HOST}' + dtm.UPLOADS
    bash = ('ZIP=firmware.zip  # install.sh + version.txt + firmware.html\n'
            'SIZE="$(wc -c < "$ZIP" | tr -d \' \')"\n'
            'META="filename $(printf %s "$ZIP" | base64)"\n'
            f'LOCATION=$(curl -sS -D - -o /dev/null -X POST {url}?account_id=${{DTM_ACCOUNT_ID}}" '
            '-H "x-api-key: ${DTM_API_KEY}" \\\n  -H "Tus-Resumable: 1.0.0" -H "Upload-Length: ${SIZE}" '
            '-H "Upload-Metadata: ${META}" | tr -d \'\\r\' | awk \'tolower($1)=="location:" {print $2}\')\n'
            'export PAYLOAD_ID="${LOCATION##*/}"\n'
            f'curl -sS -X PATCH {url}/${{PAYLOAD_ID}}?account_id=${{DTM_ACCOUNT_ID}}" -H "x-api-key: ${{DTM_API_KEY}}" '
            '-H "Tus-Resumable: 1.0.0" \\\n  -H "Upload-Offset: 0" -H "Content-Type: application/offset+octet-stream" --data-binary "@$ZIP"\n'
            f'curl -sS -X POST {url}/${{PAYLOAD_ID}}?account_id=${{DTM_ACCOUNT_ID}}" -H "x-api-key: ${{DTM_API_KEY}}" '
            '-H "Tus-Resumable: 1.0.0" -H "Content-Type: application/json" -d \'{}\'')
    ps_url = '"https://$env:DTM_HOST' + dtm.UPLOADS
    ps = ('$zip = "firmware.zip"  # install.sh + version.txt + firmware.html\n'
          '$tus = $headers + @{ "Tus-Resumable" = "1.0.0" }\n'
          '$meta = "filename " + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($zip))\n'
          f'$created = Invoke-WebRequest -Method Post -Uri {ps_url}?account_id=$env:DTM_ACCOUNT_ID" '
          '-Headers ($tus + @{ "Upload-Length" = (Get-Item $zip).Length; "Upload-Metadata" = $meta })\n'
          '$env:PAYLOAD_ID = ([string]$created.Headers.Location).Split("/")[-1]\n'
          f'Invoke-RestMethod -Method Patch -Uri {ps_url}/$env:PAYLOAD_ID`?account_id=$env:DTM_ACCOUNT_ID" '
          '-Headers ($tus + @{ "Upload-Offset" = "0" }) `\n  -ContentType "application/offset+octet-stream" -InFile $zip\n'
          f'Invoke-RestMethod -Method Post -Uri {ps_url}/$env:PAYLOAD_ID`?account_id=$env:DTM_ACCOUNT_ID" '
          '-Headers $tus -ContentType "application/json" -Body "{}"')
    return {"bash": bash, "powershell": ps}
