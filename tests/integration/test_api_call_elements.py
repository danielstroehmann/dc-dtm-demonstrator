"""Author rule: in every use case each API call is its own element of "Reproducible steps". Every
recorded entry is rendered in all dialects; a network entry holds exactly one request, a LOCAL entry
none – so two calls merged into one element (or a request hidden in a local step) fail here."""

import re

import pytest

from app import evergreen, snippets
from tests.integration import test_uc01_flow, test_uc02_flow, test_uc03_flow, test_uc04_flow

# A request is one invocation of a network client. Comment lines are ignored (they may mention curl).
REQUEST = re.compile(r"(?<![\w.$/-])(?:curl(?:\.exe)?|wget|Invoke-RestMethod|scepclient(?:\.exe)?)(?=\s)"
                     r"|(?<![\w.-])openssl cmp(?=\s)")
WGET_MULTIPART = "# wget cannot send multipart/form-data"


def requests_in(text: str) -> int:
    return sum(len(REQUEST.findall(line)) for line in text.splitlines() if not line.lstrip().startswith("#"))


def assert_one_request_per_element(run: dict) -> int:
    calls = [c for c in run["result"]["api_calls"] if c.get("spec")]
    assert calls
    for call in calls:
        for dialect in snippets.DIALECTS:
            text = snippets.render(call["spec"], dialect)
            label = f"{call['purpose']!r} ({dialect})"
            if call["method"] == "LOCAL":
                assert requests_in(text) == 0, label
            elif dialect == "wget" and text.startswith(WGET_MULTIPART):
                assert requests_in(text) == 0, label  # documented fallback: wget has no multipart
            else:
                assert requests_in(text) == 1, label + "\n" + text
    return len(calls)


def test_counter_detects_merged_calls():
    """The checker itself must be able to fail."""
    one = 'curl -sS -X POST "https://${DTM_HOST}/x" \\\n  -H "x-api-key: ${DTM_API_KEY}"'
    assert requests_in(one) == 1 and requests_in(one + "\n" + one) == 2
    assert requests_in("# curl uses factory.crt directly") == 0
    assert requests_in("openssl cmp -cmd ir -server x") == 1 and requests_in("openssl req -new") == 0
    assert requests_in('Invoke-RestMethod -Method Get -Uri "x"\ncurl.exe -sS -X POST "x"') == 2
    assert requests_in('$(printf %s "${PASSCODE}" | openssl base64 -A)') == 0
    assert requests_in("scepclient -server-url x -challenge y") == 1
    assert requests_in("sleep 10\nStart-Sleep 10") == 0  # waiting is not a request


@pytest.mark.parametrize("mode,count", [("single", 1), ("batch", 2)])
async def test_uc01_elements(store, fake, tmp_path, mode, count):
    run = await test_uc01_flow.start(store, fake, "e1", tmp_path, mode=mode, count=count)
    assert run["status"] == "completed", run["error"]
    assert_one_request_per_element(run)


@pytest.mark.parametrize("mode,count", [("single", 1), ("batch", 2)])
async def test_uc02_elements(store, fake, tmp_path, monkeypatch, mode, count):
    monkeypatch.setattr(evergreen, "STORY_INTERVAL", 0.0)
    run = await test_uc02_flow.start(store, fake, "e2", tmp_path, mode=mode, count=count)
    assert run["status"] == "completed", run["error"]
    assert_one_request_per_element(run)


@pytest.mark.parametrize("protocol,auth", test_uc03_flow.COMBOS)
async def test_uc03_elements(store, enroll_net, cmp_openssl, scep_client, tmp_path, protocol, auth):
    run = await test_uc03_flow.start(store, enroll_net, "e3", tmp_path, protocol=protocol, auth=auth,
                                     **test_uc03_flow.protocol_params(protocol))
    assert run["status"] == "completed", run["error"]
    assert_one_request_per_element(run)
    # and exactly one of them is the enrollment request
    networked = [c for c in run["result"]["api_calls"] if c["method"] != "LOCAL"]
    assert sum(c["path"] == test_uc03_flow.protocol_call(run)["path"] for c in networked) == 1


@pytest.mark.parametrize("auth", ["passcode", "certificate"])
async def test_uc04_elements_including_the_renewal_block(store, enroll_net, tmp_path, auth):
    run = await test_uc04_flow.start(store, enroll_net, "e4", tmp_path, auth=auth)
    assert run["status"] == "completed", run["error"]
    for _ in range(2):
        run = await test_uc04_flow.renew(store, "e4", tmp_path)
    renewal = [c for c in run["result"]["api_calls"] if c["phase"] == "renewal"]
    assert len(renewal) == 3 and sum(c["method"] != "LOCAL" for c in renewal) == 1
    assert assert_one_request_per_element(run) == len(run["result"]["api_calls"])
