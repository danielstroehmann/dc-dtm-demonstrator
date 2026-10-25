"""Reproducible steps must replay by copy & paste in a fresh shell and create NEW objects: outside
the variables preamble no step may carry the run's literal name (robot-<run_id>-…) or an ID DTM
handed out to the original run – every ID a later step uses is captured from an earlier answer."""

import re

import pytest

from app import evergreen, snippets
from tests.integration import test_uc01_flow, test_uc02_flow, test_uc03_flow, test_uc04_flow

# IDs the original run got from DTM (or configured) – none of them may be hard-wired into a step.
ID_VARIABLES = ("DIVISION_ID", "POLICY_ID", "JOB_ID", "PROFILE_ID", "AUTH_POLICY_ID", "RZONE_ID", "ICA_ID",
                "CMP_ID", "PASSCODE_REF")


def original_ids(run: dict, fake) -> set[str]:
    ids = {v for k, v in run["result"]["api_variables"].items() if k in ID_VARIABLES and v}
    ids |= set(fake.divisions) | set(fake.policies) | set(fake.jobs)
    ids |= {p["alternative_id"] for p in fake.policies.values()}
    ids |= {oid for objects in fake.auth_objects.values() for oid in objects}
    ids |= {o.get("alternate_id") for o in fake.auth_objects["passcode"].values() if o.get("alternate_id")}
    return ids


def assert_replayable(run: dict, fake) -> None:
    variables, calls = run["result"]["api_variables"], run["result"]["api_calls"]
    run_name = evergreen.prefix(run["id"], run["use_case"])
    assert variables["RUN_NAME"] == run_name  # the one place the name is set – the user can change it
    ids = original_ids(run, fake)
    assert ids >= {variables["DIVISION_ID"], variables["POLICY_ID"], variables["PROFILE_ID"]}
    for dialect in snippets.DIALECTS:
        text = snippets.script(variables, calls, dialect)
        head = ("" if dialect == "powershell" else "#!/usr/bin/env bash\n\n") + snippets.preamble(variables, dialect)
        assert text.startswith(head + "\n\n")
        steps = text[len(head):]
        assert f"robot-{run['id']}-" not in steps, dialect
        leaked = sorted(i for i in ids if i in steps)
        assert not leaked, (dialect, leaked)
        # every token became a variable reference of the dialect – none is left bare
        assert not re.findall(r"(?<!\$)\{(" + "|".join(snippets.VARIABLES) + r")\}", steps), dialect
    # the IDs are set by captures (or local jq steps) before they are used
    captured = [c["spec"]["capture"]["var"] for c in calls if (c.get("spec") or {}).get("capture")]
    for var in ("RZONE_ID", "DIVISION_ID", "PROFILE_ID", "POLICY_ID"):
        assert var in captured, var
    if "AUTH_POLICY_ID" in variables:
        assert "AUTH_POLICY_ID" in captured
    if "JOB_ID" in variables:
        assert "JOB_ID" in captured


@pytest.mark.parametrize("mode,count,approval", [("single", 2, False), ("batch", 2, True)])
async def test_uc01_steps_are_replayable(store, fake, tmp_path, mode, count, approval):
    run = await test_uc01_flow.start(store, fake, "rp1", tmp_path, mode=mode, count=count, approval=approval)
    assert run["status"] == "completed", run["error"]
    assert_replayable(run, fake)


@pytest.mark.parametrize("mode,count", [("single", 2), ("batch", 2)])
async def test_uc02_steps_are_replayable(store, fake, tmp_path, monkeypatch, mode, count):
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    run = await test_uc02_flow.start(store, fake, "rp2", tmp_path, mode=mode, count=count)
    assert run["status"] == "completed", run["error"]
    assert_replayable(run, fake)


@pytest.mark.parametrize("protocol,auth", test_uc03_flow.COMBOS)
async def test_uc03_steps_are_replayable(store, enroll_net, cmp_openssl, scep_client, tmp_path, protocol, auth):
    run = await test_uc03_flow.start(store, enroll_net, "rp3", tmp_path, protocol=protocol, auth=auth,
                                     **test_uc03_flow.protocol_params(protocol))
    assert run["status"] == "completed", run["error"]
    assert_replayable(run, enroll_net)


@pytest.mark.parametrize("protocol", ["est", "cmpv2"])
@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_uc04_steps_incl_renewal_are_replayable(store, enroll_net, cmp_openssl, tmp_path, protocol, auth):
    run = await test_uc04_flow.start(store, enroll_net, "rp4", tmp_path, protocol=protocol, auth=auth)
    assert run["status"] == "completed", run["error"]
    cmp_openssl.sync_to_dtm()
    run = await test_uc04_flow.renew(store, "rp4", tmp_path)  # the renewal block is re-recorded with counts
    assert run["status"] == "completed", store.events("rp4")[-3:]
    renewal = [c for c in run["result"]["api_calls"] if c["phase"] == "renewal"]
    assert renewal and all(c["count"] == 1 for c in renewal)
    if protocol == "est":  # the renewal CSR keeps the device's identity – named after RUN_NAME
        assert '-subj "/CN={RUN_NAME}-est-0001"' in renewal[0]["spec"]["command"]["bash"]
    assert_replayable(run, enroll_net)
