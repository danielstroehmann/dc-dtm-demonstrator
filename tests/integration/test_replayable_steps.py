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


# --- web UI variant: the local steps rebuild the run's upload file; the order itself is manual -------

def _run_local(spec: dict, work, run_name: str):
    import os
    import subprocess
    return subprocess.run(["bash", "-c", snippets.render(spec, "curl")], cwd=work, capture_output=True, text=True,
                          env={"PATH": os.environ["PATH"], "RUN_NAME": run_name, "HOME": str(work)}, timeout=60)


@pytest.mark.parametrize("use_case", ["uc01", "uc02"])
@pytest.mark.parametrize("mode,count", [("single", 1), ("single", 3), ("batch", 3)])
async def test_webui_steps_are_replayable(store, fake, tmp_path, monkeypatch, use_case, mode, count):
    import shutil
    import zipfile
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    flow = test_uc01_flow if use_case == "uc01" else test_uc02_flow
    run = await flow.start(store, fake, "wr1", tmp_path, variant="webui", mode=mode, count=count)
    assert run["status"] == "waiting", run["error"]
    assert_replayable(run, fake)
    calls = run["result"]["api_calls"]
    recurring = [c for c in calls if c["phase"] == "recurring"]
    manual = recurring[-1]
    assert (manual["method"], manual["path"], manual["seconds"]) == ("MANUAL", "DTM web UI", None)
    assert manual["spec"] == {"command": "# Certificate policy: {RUN_NAME}-policy – no API call, the portal places the order"}
    client_side = use_case == "uc02"
    artifact = "csrs.zip" if client_side else "batch.zip" if mode == "batch" else None
    task = (f"upload {artifact} as a batch request" if mode == "batch"
            else ("request the certificates one by one" if count > 1 else "request the certificate")
            + (" with the CSRs from csrs.zip" if client_side else ""))
    assert manual["purpose"] == f"Order in the DTM web UI – {task}"
    assert run["result"].get("artifact") == artifact
    names = evergreen.common_names("wr1", mode, count, use_case)
    run_name = evergreen.prefix("wr1", use_case)
    work = tmp_path / "replay"
    work.mkdir()
    if artifact is None:  # server-side single: nothing to prepare, only the manual order
        assert [c["method"] for c in recurring] == ["MANUAL"]
        return
    (local,) = recurring[:-1]
    assert local["method"] == "LOCAL"
    run_zip = zipfile.ZipFile(tmp_path / "runs" / "wr1" / artifact)
    if client_side:
        devices = "the device" if count == 1 else f"each of the {count} devices"
        assert local["purpose"] == f"Generate key + CSR for {devices} and pack the CSRs"
        assert local["spec"]["command"] == evergreen.csr_batch_command(count, "P_256", mode)
        assert local["seconds"] is not None  # the factory's key generation is measured
        assert run_zip.namelist() == [f"{n}.csr" for n in names]
        if not (shutil.which("openssl") and shutil.which("zip") and shutil.which("bash")):
            pytest.skip("needs bash, openssl and zip to replay the CSR step")
        result = _run_local(local["spec"], work, run_name)
        assert result.returncode == 0, result.stderr
        assert zipfile.ZipFile(work / "csrs.zip").namelist() == run_zip.namelist()  # same device names
    else:
        assert local["purpose"] == f"Write the CSV with the {count} device names and pack it"
        assert local["spec"]["command"] == evergreen.csv_batch_command(count)
        if not (shutil.which("zip") and shutil.which("bash")):
            pytest.skip("needs bash and zip to replay the CSV step")
        result = _run_local(local["spec"], work, run_name)
        assert result.returncode == 0, result.stderr
        replayed = zipfile.ZipFile(work / "batch.zip")
        assert replayed.namelist() == run_zip.namelist() == ["batch.csv"]
        assert replayed.read("batch.csv") == run_zip.read("batch.csv")  # byte-identical to the run's CSV


@pytest.mark.parametrize("mode", ["single", "batch"])
def test_batch_commands_name_devices_like_common_names(tmp_path, mode):
    import shutil
    import zipfile
    if not (shutil.which("zip") and shutil.which("unzip") and shutil.which("bash")):
        pytest.skip("needs bash, zip and unzip")
    result = _run_local({"command": evergreen.csv_batch_command(4, mode)}, tmp_path, "robot-n1-uc01")
    assert result.returncode == 0, result.stderr
    csv = zipfile.ZipFile(tmp_path / "batch.zip").read("batch.csv").decode()
    assert csv.splitlines() == ["subject.common_name", *evergreen.common_names("n1", mode, 4, "uc01")]
    with pytest.raises(ValueError):
        evergreen.csv_batch_command(2, "bulk")
    with pytest.raises(ValueError):
        evergreen.csr_batch_command(2, "P_256", "x; rm -rf ~")


# --- NL: the run creates its own profile – the replay creates one, too (captured, never the run's ID) ----

@pytest.mark.parametrize("use_case,mode", [("uc01", "single"), ("uc02", "batch")])
async def test_nl_steps_are_replayable(store, tmp_path, monkeypatch, use_case, mode):
    from app import dtm
    from tests.fakedtm import NL_HOST, FakeDTM
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    nl = FakeDTM(host=NL_HOST)
    flow = test_uc01_flow if use_case == "uc01" else test_uc02_flow
    run = await flow.start(store, nl, "nr1", tmp_path, dtm_host=NL_HOST, mode=mode, count=2)
    assert run["status"] == "completed", run["error"]
    assert_replayable(run, nl)
    calls = run["result"]["api_calls"]
    (profile_step,) = [c for c in calls if c["path"] == dtm.PROFILES]
    assert profile_step["method"] == "POST" and profile_step["spec"]["capture"]["var"] == "PROFILE_ID"
    assert profile_step["spec"]["json"]["name"] == "{RUN_NAME}-profile"
    for dialect in snippets.DIALECTS:
        text = snippets.script(run["result"]["api_variables"], calls, dialect)
        assert "robot-evergreen" not in text  # no shared profile lookup on NL
