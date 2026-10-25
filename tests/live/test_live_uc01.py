"""UC-1 end to end against the real DTM test account (T-2), local stage 1 only.

    python -m pytest -m live

Reads DTM_HOST, DTM_API_KEY and DTM_ACCOUNT_ID from the repo's gitignored .env. Every object is
named robot-t<random>-… and removed again in a finally block; the test then asserts that no
division, policy or issued certificate of the run is left. Existing CAs are only read.
"""

import asyncio
import secrets
from pathlib import Path

import pytest
from dotenv import dotenv_values

from app import cleanup, evergreen
from app.dtm import DIVISIONS, POLICIES, DTMClient, DTMConfig, DTMError
from app.store import Store

pytestmark = pytest.mark.live

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
RUN_TIMEOUT_S = 300
# Binding author rule (CLAUDE.md): live runs keep DTM load minimal – at most 2 certificates per run,
# a batch of 2 counts as a full batch test. tests/live/conftest.py enforces the limit.
LIVE_COUNT = 2
CLEANUP_TIMEOUT_S = 600


class RedactedConfig(DTMConfig):
    """DTMConfig's dataclass repr contains the API key – pytest prints it in tracebacks."""

    def __repr__(self) -> str:
        return f"DTMConfig(host={self.host!r}, api_key=<redacted>, account_id=<redacted>)"


@pytest.fixture
def config() -> DTMConfig:
    values = dotenv_values(ENV_FILE) if ENV_FILE.is_file() else {}
    if not all(values.get(k) for k in ("DTM_HOST", "DTM_API_KEY", "DTM_ACCOUNT_ID")):
        pytest.skip("DTM_HOST, DTM_API_KEY and DTM_ACCOUNT_ID must be set in .env")
    return RedactedConfig(values["DTM_HOST"], values["DTM_API_KEY"], values["DTM_ACCOUNT_ID"])


def new_run_id() -> str:
    return "t" + secrets.token_hex(3)  # t + 6 lowercase hex characters, matches the run-id rule


async def run_params(client: DTMClient, config: DTMConfig, **overrides) -> dict:
    cas = await client.issuing_cas()
    ecdsa = [c for c in cas if c["key_type"].lower().startswith("ec")]
    assert ecdsa, f"no active ECDSA intermediate CA in the account (key types: {[c['key_type'] for c in cas]})"
    ca = ecdsa[0]
    # The web form only accepts CAs whose key type maps to a DTM policy key type.
    assert ca["key_type"] in evergreen.KEY_TYPES, f"CA key type {ca['key_type']!r} not in evergreen.KEY_TYPES"
    profiles = await client.certificate_profiles()
    profile = next((p for p in profiles if "client" in p["name"].lower()), None)
    assert profile, "no active client certificate profile"
    return {"dtm_host": config.host, "account_id": config.account_id, "variant": "api", "mode": "single",
            "count": 1, "ca_id": ca["id"], "ca_name": ca["name"], "key_type": evergreen.KEY_TYPES[ca["key_type"]],
            "profile_id": profile["id"], "approval": False} | overrides


async def leftovers(client: DTMClient, store: Store, run_id: str) -> dict:
    prefix = f"robot-{run_id}-"
    found = {
        "divisions": [d for d in await client._list(DIVISIONS) if str(d.get("name", "")).startswith(prefix)],
        "policies": [p for p in await client._list(POLICIES) if str(p.get("name", "")).startswith(prefix)],
        "issued_certificates": [],
        "unverifiable": [],
    }
    for policy in store.objects(run_id, "policy", include_removed=True):
        try:
            found["issued_certificates"] += await client.issued_certificates(policy["dtm_id"])
        except DTMError as exc:  # listing by a deleted policy may be refused
            found["unverifiable"].append(f"certificates of {policy['name']}: {exc}")
    return found


async def fallback_cleanup(client: DTMClient, found: dict) -> None:
    """Last resort if the app's cleanup left something behind – keeps the account clean."""
    for policy in found["policies"]:
        await cleanup.revoke_all(client, policy["id"], lambda _m: None)
        await client.delete_policy(policy["id"])
    for division in found["divisions"]:
        await client.delete_division(division["id"])


async def execute(config: DTMConfig, tmp_path: Path, use_case: str = "uc01",
                  **overrides) -> tuple[dict, dict, list[dict], str]:
    """Run UC-1 and always roll back. Returns (run after the run, run after cleanup, events, run id)."""
    run_id = new_run_id()
    store = Store(tmp_path / "live.db")
    run_dir = tmp_path / "runs" / run_id
    client = DTMClient(config, on_call=lambda msg: store.run_exists(run_id) and store.add_event(
        run_id, f"API {msg}", "api"))
    after_run = None
    try:
        store.create_run(run_id, use_case, await run_params(client, config, **overrides))
        try:
            await asyncio.wait_for(evergreen.run(store, client, run_id, run_dir), RUN_TIMEOUT_S)
        except TimeoutError:
            store.add_event(run_id, f"TEST: run did not finish within {RUN_TIMEOUT_S}s", "error")
        after_run = store.get_run(run_id)
    finally:
        if store.run_exists(run_id):
            await asyncio.wait_for(cleanup.cleanup(store, client, run_id, "full", run_dir), CLEANUP_TIMEOUT_S)
            found = await leftovers(client, store, run_id)
            if found["divisions"] or found["policies"] or found["issued_certificates"]:
                store.add_event(run_id, f"TEST: leftovers after app cleanup: {found}", "error")
                await fallback_cleanup(client, found)
                found_after_fallback = await leftovers(client, store, run_id)
                store.add_event(run_id, f"TEST: leftovers after fallback: {found_after_fallback}", "error")
        await client.aclose()
    events = store.events(run_id)
    after_cleanup = store.get_run(run_id)
    print(f"\n--- run {run_id} ---")
    for e in events:
        print(f"{e['ts'][11:19]} {e['level']:5} {e['message']}")
    return after_run, after_cleanup, events, run_id


def assert_clean(after_cleanup: dict, events: list[dict]):
    messages = [e["message"] for e in events]
    assert not any(m.startswith("TEST: leftovers") for m in messages), "account NOT clean – see log"
    assert after_cleanup["cleanup_status"] == "done", messages[-5:]


async def test_live_batch_with_approval(config, tmp_path):
    run, after_cleanup, events, run_id = await execute(config, tmp_path, mode="batch", count=LIVE_COUNT, approval=True)
    messages = [e["message"] for e in events]
    assert run and run["status"] == "completed", messages[-8:]
    r = run["result"]
    assert r["approval_s"] is not None, "approval step was not detected"
    assert r["certificate_total"] == LIVE_COUNT and r["private_keys_returned"] == LIVE_COUNT
    assert sorted(c["common_name"] for c in r["certificates"]) == evergreen.common_names(run_id, "batch", LIVE_COUNT,
                                                                                         "uc01")
    assert r["success_items"] == LIVE_COUNT and not r["failed_items"]
    assert "PRIVATE KEY" not in str(run) and "BEGIN" not in str(r["api_calls"])
    # rzone, division + lookup, profile, policy + lookup, CSV, key, upload, wait, approve, poll, download, decrypt
    assert [c["method"] for c in r["api_calls"]] == ["GET", "POST", "GET", "GET", "POST", "GET", "LOCAL", "LOCAL", "POST",
                                                    "GET", "PUT", "GET", "GET", "LOCAL"]
    assert set(r["api_variables"]) == {"DTM_HOST", "DTM_ACCOUNT_ID", "ICA_ID", "RZONE_ID", "DIVISION_ID", "PROFILE_ID",
                                       "POLICY_ID", "JOB_ID", "RUN_NAME"}
    assert config.api_key not in str(run)
    assert all(c["outcome"] == "ok" for c in r["api_calls"])
    assert r["per_certificate_s"] > 0 and r["per_minute"] > 0
    assert run["progress"] is None
    assert_clean(after_cleanup, events)


async def test_live_single(config, tmp_path):
    run, after_cleanup, events, run_id = await execute(config, tmp_path, mode="single", count=LIVE_COUNT)
    messages = [e["message"] for e in events]
    assert run and run["status"] == "completed", messages[-8:]
    r = run["result"]
    assert [c["common_name"] for c in r["certificates"]] == evergreen.common_names(run_id, "single", LIVE_COUNT, "uc01")
    assert all(c["key_type"].startswith("ECDSA") for c in r["certificates"])
    assert r["certificate_total"] == LIVE_COUNT and r["private_keys_returned"] == LIVE_COUNT
    assert "PRIVATE KEY" not in str(run)
    # rzone, division + lookup, shared profile, policy + lookup, the requests, then the local extract step
    assert [c["method"] for c in r["api_calls"]] == ["GET", "POST", "GET", "GET", "POST", "GET", "POST", "LOCAL"]
    assert (r["api_calls"][-2]["count"], r["api_calls"][-2]["outcome"]) == (LIVE_COUNT, "ok")
    assert r["per_certificate_s"] > 0 and r["per_minute"] > 0
    assert config.api_key not in str(run)
    assert_clean(after_cleanup, events)


async def test_live_uc02_batch(config, tmp_path):
    """UC-2: the demonstrator plays the factory – CSRs only, no private key travels."""
    run, after_cleanup, events, run_id = await execute(config, tmp_path, use_case="uc02", mode="batch", count=LIVE_COUNT)
    messages = [e["message"] for e in events]
    assert run and run["status"] == "completed", messages[-8:]
    r = run["result"]
    assert sorted(c["common_name"] for c in r["certificates"]) == evergreen.common_names(run_id, "batch", LIVE_COUNT,
                                                                                         "uc02")
    assert all(c["key_type"].startswith("ECDSA") for c in r["certificates"])
    assert r["certificate_total"] == LIVE_COUNT and r["private_keys_returned"] == 0
    assert r["keygen_s"] is not None and r["artifact"] == "csrs.zip"
    assert [c["method"] for c in r["api_calls"]] == ["GET", "POST", "GET", "GET", "POST", "GET", "LOCAL", "POST", "GET",
                                                    "GET", "LOCAL"]
    assert all(c["outcome"] == "ok" for c in r["api_calls"])
    assert "PRIVATE KEY" not in str(run) and config.api_key not in str(run)
    assert_clean(after_cleanup, events)
