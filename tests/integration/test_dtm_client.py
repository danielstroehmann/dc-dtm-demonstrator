"""DTM client against respx-mocked endpoints: request shape, scoping and error handling."""

import json

import httpx
import pytest
import respx

from app import dtm
from app.dtm import DTMClient, DTMConfig, DTMError
from tests.fakedtm import ACCOUNT_ID, API_KEY, BASE, DTM, HOST, OTHER_ACCOUNT_ID

CERT = f"{DTM}/certificate-issuance-service/api/v2/certificate"
POLICY_DELETE = f"{DTM}/certificate-configuration-service/api-ui/v1/certificate-policy"


@pytest.fixture
def router():
    return respx.MockRouter(base_url=BASE, assert_all_called=False)


@pytest.fixture
async def client(router):
    calls: list[str] = []
    c = DTMClient(DTMConfig(HOST, API_KEY, ACCOUNT_ID), on_call=calls.append,
                  transport=httpx.MockTransport(router.async_handler))
    c.calls = calls
    yield c
    await c.aclose()


def page(items, key="records", total=None):
    return httpx.Response(200, json={key: items, "total": len(items) if total is None else total})


# --- scoping & headers ---------------------------------------------------------------------

async def test_every_request_carries_account_id_and_api_key(router, client):
    route = router.get(f"{DTM}/api/v4/rendezvous-zone").mock(
        return_value=page([{"id": "z", "name": "z", "status": "ENABLED"}]))
    await client.rendezvous_zone()
    request = route.calls.last.request
    assert request.url.scheme == "https" and request.url.host == HOST
    assert request.url.params["account_id"] == ACCOUNT_ID
    assert request.headers["x-api-key"] == API_KEY


async def test_account_id_cannot_be_overridden_by_caller_params(router, client):
    route = router.get("/x").mock(return_value=httpx.Response(200, json={}))
    await client._request("GET", "/x", params={"account_id": OTHER_ACCOUNT_ID, "a": "1"})
    params = route.calls.last.request.url.params
    assert params.get_list("account_id") == [ACCOUNT_ID]
    assert params["a"] == "1"


async def test_post_bodies_also_scope_division_to_account(router, client):
    router.get(f"{DTM}/api/v4/rendezvous-zone").mock(return_value=page([
        {"id": "rz-b", "name": "b", "status": "ENABLED"}, {"id": "rz-a", "name": "a", "status": "ENABLED"},
        {"id": "rz-0", "name": "0", "status": "DISABLED"}]))
    create = router.post(f"{DTM}/api/v4/division").mock(return_value=httpx.Response(200))
    router.get(f"{DTM}/api/v4/division").mock(return_value=page([{"id": "d-1", "name": "robot-x-uc01-division"},
                                                                  {"id": "d-2", "name": "other"}]))
    assert await client.create_division("robot-x-uc01-division", "desc") == "d-1"
    body = json.loads(create.calls.last.request.content)
    assert body["account_id"] == ACCOUNT_ID
    assert body["primary_rzone_id"] == "rz-a"  # first enabled zone by name


async def test_api_key_is_not_written_to_the_call_log(router, client):
    router.get("/x").mock(return_value=httpx.Response(200, json={}))
    await client._request("GET", "/x")
    assert client.calls and API_KEY not in " ".join(client.calls)


# --- JSON & errors -------------------------------------------------------------------------

async def test_lenient_json_with_raw_control_characters(router, client):
    raw = '{"pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "status": "ok\t"}'
    router.post(CERT).mock(return_value=httpx.Response(200, text=raw))
    data = await client.issue_single("IOT_1", "robot-x-uc01-single-0001")
    assert data["pem"].count("\n") == 3 and data["status"] == "ok\t"


@pytest.mark.parametrize("response,expected", [
    (httpx.Response(400, json={"errors": [{"code": "x", "message": "first"}, {"message": "second"}]}),
     "returned 400: first; second"),
    (httpx.Response(403, json={"error": "forbidden for account"}), "returned 403: forbidden for account"),
    (httpx.Response(400, text="<!DOCTYPE html><html><body>Whitelabel Error Page</body></html>"),
     "returned 400: (HTML error page)"),
    (httpx.Response(500, text="  <html>oops</html>"), "returned 500: (HTML error page)"),
    (httpx.Response(502, text="Bad gateway " + "x" * 500), "returned 502: Bad gateway "),
])
async def test_error_text_extraction(router, client, response, expected):
    router.get("/x").mock(return_value=response)
    with pytest.raises(DTMError) as info:
        await client._request("GET", "/x")
    assert expected in str(info.value)
    assert info.value.status == response.status_code
    assert len(str(info.value)) < 400  # truncated, never a full page


async def test_html_error_page_content_is_not_leaked_into_message(router, client):
    router.get("/x").mock(return_value=httpx.Response(400, text="<html><script>evil()</script></html>"))
    with pytest.raises(DTMError) as info:
        await client._request("GET", "/x")
    assert "script" not in str(info.value)


async def test_error_list_of_strings_still_gives_dtm_error(router, client):
    router.get("/x").mock(return_value=httpx.Response(400, json={"errors": ["plain string error"]}))
    with pytest.raises(DTMError, match="plain string error"):
        await client._request("GET", "/x")


async def test_transport_errors_become_dtm_error_without_status(router, client):
    router.get("/t").mock(side_effect=httpx.ReadTimeout("slow"))
    router.get("/c").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(DTMError, match="timed out") as info:
        await client._request("GET", "/t")
    assert info.value.status is None
    with pytest.raises(DTMError, match="ConnectError") as info:
        await client._request("GET", "/c")
    assert info.value.status is None


async def test_quiet_requests_are_not_logged(router, client):
    router.get("/q").mock(return_value=httpx.Response(200, json={}))
    await client._request("GET", "/q", quiet=True)
    assert client.calls == []


# --- lists & lookups -----------------------------------------------------------------------

async def test_list_follows_pages_until_total(router, client):
    items = [{"id": f"d{i}", "name": f"n{i}"} for i in range(250)]

    def paged(request):
        offset, limit = int(request.url.params["offset"]), int(request.url.params["limit"])
        return page(items[offset:offset + limit], total=len(items))

    route = router.get(f"{DTM}/api/v4/division").mock(side_effect=paged)
    assert await client.find_ids(f"{DTM}/api/v4/division", "n249") == ["d249"]
    assert [c.request.url.params["offset"] for c in route.calls] == ["0", "100", "200"]


async def test_check_account(router, client):
    route = router.get("/account/api/v1/account")
    route.mock(return_value=httpx.Response(200, json=[{"id": OTHER_ACCOUNT_ID}, {"id": ACCOUNT_ID}]))
    await client.check_account()
    route.mock(return_value=httpx.Response(200, json={"records": [{"id": ACCOUNT_ID}]}))
    await client.check_account()
    route.mock(return_value=httpx.Response(200, json=[{"id": OTHER_ACCOUNT_ID}]))
    with pytest.raises(DTMError, match="no access"):
        await client.check_account()
    route.mock(return_value=httpx.Response(401, json={"errors": [{"message": "invalid api key"}]}))
    with pytest.raises(DTMError, match="401"):
        await client.check_account()


async def test_issuing_cas_only_active_intermediates_of_this_account(router, client):
    def ca(ca_id, **kw):
        return {"id": ca_id, "name": ca_id, "key_type": "ecdsa", "cert_type": "intermediate", "status": "active",
                "account_assignments": [{"id": ACCOUNT_ID}]} | kw
    router.get("/certificate-authority/api/v1/ca").mock(return_value=page([
        ca("good"), ca("rsa", key_type="rsa"), ca("root", cert_type="root"), ca("off", status="disabled"),
        ca("foreign", account_assignments=[{"id": OTHER_ACCOUNT_ID}]), ca("unassigned", account_assignments=[]),
    ], key="items"))
    assert [c["id"] for c in await client.issuing_cas()] == ["good", "rsa"]


async def test_certificate_profiles_only_active(router, client):
    renew = {"key": "renewal_settings.renew_valid_cert", "enabled": True, "value": "anytime"}
    router.get(f"{DTM}/certificate-configuration-service/api/v1/certificate-profile").mock(return_value=page([
        {"id": "a", "name": "A", "status": "ACTIVE", "body": [renew]},
        {"id": "b", "name": "B", "status": "INACTIVE", "body": [renew]},
        {"id": "c", "name": "C", "status": "ACTIVE"}]))
    assert await client.certificate_profiles() == [{"id": "a", "name": "A", "renew_anytime": True},
                                                   {"id": "c", "name": "C", "renew_anytime": False}]


@pytest.mark.parametrize("body,expected", [
    (None, False),                                                                     # no body at all
    ([], False),                                                                       # no entry
    ([{"key": "csr", "value": "anytime"}], False),                                     # other key
    ([{"key": "renewal_settings.renew_valid_cert", "value": "anytime"}], True),        # enabled omitted
    ([{"key": "renewal_settings.renew_valid_cert", "enabled": True, "value": "anytime"}], True),
    ([{"key": "renewal_settings.renew_valid_cert", "enabled": False, "value": "anytime"}], False),
    ([{"key": "renewal_settings.renew_valid_cert", "enabled": True, "value": "dont_allow"}], False),
    ([{"key": "renewal_settings.renew_valid_cert", "enabled": True, "value": "30"}], False),  # window
    ([{"key": "renewal_settings.renew_valid_cert", "enabled": True, "value": None}], False),
    ([{"key": "renewal_settings.renew_valid_cert", "enabled": True, "value": "ANYTIME"}], False),  # exact
    ([{"key": "renewal_settings.renew_valid_cert", "enabled": None, "value": "anytime"}], True),
])
def test_renew_anytime(body, expected):
    profile = {"id": "p", "name": "P"} | ({} if body is None else {"body": body})
    assert dtm._renew_anytime(profile) is expected


async def test_no_enabled_rendezvous_zone(router, client):
    router.get(f"{DTM}/api/v4/rendezvous-zone").mock(return_value=page([{"id": "z", "name": "z",
                                                                           "status": "DISABLED"}]))
    with pytest.raises(DTMError, match="rendezvous zone"):
        await client.rendezvous_zone()


async def test_find_id_retries_while_list_lags(router, client, fast_timing):
    lists = iter([page([]), page([]), page([{"id": "d-1", "name": "n"}])])
    route = router.get(f"{DTM}/api/v4/division").mock(side_effect=lambda _r: next(lists))
    assert await client._find_id(f"{DTM}/api/v4/division", "n") == "d-1"
    assert route.call_count == 3
    assert fast_timing == [1, 2]  # backs off between lookups


async def test_find_id_gives_up_after_retries(router, client):
    route = router.get(f"{DTM}/api/v4/division").mock(return_value=page([]))
    with pytest.raises(DTMError, match="found 0"):
        await client._find_id(f"{DTM}/api/v4/division", "n")
    assert route.call_count == dtm.LOOKUP_RETRIES


async def test_find_id_refuses_ambiguous_names(router, client):
    router.get(f"{DTM}/api/v4/division").mock(return_value=page([{"id": "a", "name": "n"}, {"id": "b", "name": "n"}]))
    with pytest.raises(DTMError, match="found 2"):
        await client._find_id(f"{DTM}/api/v4/division", "n")


# --- policy -------------------------------------------------------------------------------

async def test_create_policy_payload(router, client):
    create = router.post(f"{DTM}/certificate-configuration-service/api/v2/certificate-policy").mock(
        return_value=httpx.Response(201, json={}))
    router.get(f"{DTM}/certificate-configuration-service/api/v2/certificate-policy").mock(
        return_value=page([{"id": "IOT_1", "name": "robot-x-uc01-policy"}]))
    policy_id = await client.create_policy(name="robot-x-uc01-policy", division_id="d-1", profile_id="p-1",
                                           ica_id="ca-1", key_type="P_256", require_approval=True)
    assert policy_id == "IOT_1"
    policy = json.loads(create.calls.last.request.content)["certificate_policy"]
    assert policy["division_id"] == "d-1" and policy["ica_id"] == "ca-1"
    assert policy["require_approval_for_enroll"] is True
    assert policy["key_generation_type"] == "P_256"
    assert policy["batch_request_parameters"]["key_type"] == "p_256"
    for section in ("single_cert_request_parameters", "batch_request_parameters"):
        assert policy[section]["encryption_certificate_source"] == "provided"
        assert policy[section]["key_generation_option"] == "server_side"


async def test_delete_policy_uses_api_ui_path_and_verifies(router, client):
    delete = router.delete(f"{POLICY_DELETE}/IOT_1").mock(return_value=httpx.Response(204))
    listing = router.get(f"{DTM}/certificate-configuration-service/api/v2/certificate-policy").mock(
        return_value=page([{"id": "IOT_2", "name": "other"}]))
    await client.delete_policy("IOT_1")
    assert delete.called and listing.called
    assert json.loads(delete.calls.last.request.content) == {}


async def test_delete_policy_accepts_entity_not_found(router, client):
    router.delete(f"{POLICY_DELETE}/IOT_1").mock(
        return_value=httpx.Response(404, json={"errors": [{"code": "entity_not_found", "message": "not found"}]}))
    router.get(f"{DTM}/certificate-configuration-service/api/v2/certificate-policy").mock(return_value=page([]))
    await client.delete_policy("IOT_1")


async def test_delete_policy_fails_loudly_when_api_ui_route_vanishes(router, client):
    router.delete(f"{POLICY_DELETE}/IOT_1").mock(return_value=httpx.Response(404, text="<html>Not Found</html>"))
    with pytest.raises(DTMError, match="R-1"):
        await client.delete_policy("IOT_1")


async def test_delete_policy_fails_when_policy_still_listed(router, client):
    router.delete(f"{POLICY_DELETE}/IOT_1").mock(return_value=httpx.Response(204))
    router.get(f"{DTM}/certificate-configuration-service/api/v2/certificate-policy").mock(
        return_value=page([{"id": "IOT_1", "name": "robot-x-uc01-policy"}]))
    with pytest.raises(DTMError, match="still exists"):
        await client.delete_policy("IOT_1")


async def test_delete_policy_400_html_raises(router, client):
    router.delete(f"{POLICY_DELETE}/IOT_1").mock(return_value=httpx.Response(400, text="<html>err</html>"))
    with pytest.raises(DTMError, match=r"400: \(HTML error page\)"):
        await client.delete_policy("IOT_1")


@pytest.mark.parametrize("status", [200, 204, 404])
async def test_delete_division_accepts_and_verifies(router, client, status):
    router.delete(f"{DTM}/api/v4/division/d-1").mock(return_value=httpx.Response(status))
    router.get(f"{DTM}/api/v4/division").mock(return_value=page([]))
    await client.delete_division("d-1")


async def test_delete_division_still_listed_raises(router, client):
    router.delete(f"{DTM}/api/v4/division/d-1").mock(return_value=httpx.Response(200))
    router.get(f"{DTM}/api/v4/division").mock(return_value=page([{"id": "d-1", "name": "x"}]))
    with pytest.raises(DTMError, match="still exists"):
        await client.delete_division("d-1")


# --- batch ---------------------------------------------------------------------------------

async def test_submit_batch_multipart_fields(router, client):
    route = router.post(f"{DTM}/certificate-batch-service/api/v1/jobs/certificate-enroll").mock(
        return_value=httpx.Response(201, json={"id": "job-1"}))
    job = await client.submit_batch(name="robot-x-uc01-batch", policy_id="IOT_1", key_type="P_256",
                                    payload=b"PK-zip-bytes", encryption_cert_pem="-----BEGIN CERTIFICATE-----")
    assert job == {"id": "job-1"}
    request = route.calls.last.request
    assert request.headers["content-type"].startswith("multipart/form-data")
    body = request.content
    for field, value in (("input_format", b"csv"), ("encryption_certificate", b"-----BEGIN CERTIFICATE-----"),
                         ("certificate_policy_id", b"IOT_1"), ("server_side_key_gen", b"true")):
        assert b'name="' + field.encode() + b'"\r\n\r\n' + value in body, field
    assert b'name="data"; filename="batch.zip"' in body and b"PK-zip-bytes" in body
    assert b'name="certificate"\r\n' not in body  # the spec name is ignored by DTM


async def test_submit_batch_without_encryption_cert_sends_csr_fields(router, client):
    route = router.post(f"{DTM}/certificate-batch-service/api/v1/jobs/certificate-enroll").mock(
        return_value=httpx.Response(201, json={"id": "job-2"}))
    await client.submit_batch(name="robot-x-uc02-batch", policy_id="IOT_1", key_type="P_256",
                              payload=b"PK-csrs", encryption_cert_pem=None)
    body = route.calls.last.request.content
    for field, value in dtm.csr_batch_fields("robot-x-uc02-batch", "IOT_1").items():
        assert b'name="' + field.encode() + b'"\r\n\r\n' + value.encode() in body, field
    for absent in (b'name="encryption_certificate"', b'name="server_side_key_gen"', b'name="key_type"'):
        assert absent not in body
    assert b"PK-csrs" in body


async def test_approve_and_result(router, client):
    approve = router.put(f"{DTM}/certificate-batch-service/api/v1/jobs/j1/approve").mock(
        return_value=httpx.Response(204))
    router.get(f"{DTM}/certificate-batch-service/api/v1/jobs/j1/download/result").mock(
        return_value=httpx.Response(200, content=b"\x30\x82binary"))
    await client.approve_batch("j1")
    assert approve.called
    assert await client.batch_result("j1") == b"\x30\x82binary"


# --- revoke --------------------------------------------------------------------------------

@pytest.mark.parametrize("mock,expected", [
    ({"return_value": httpx.Response(204)}, "revoked"),
    ({"return_value": httpx.Response(200)}, "revoked"),
    ({"return_value": httpx.Response(400, json={"errors": [{"message": "already revoked"}]})}, "already"),
    ({"side_effect": httpx.ReadTimeout("slow")}, "retry"),
    ({"side_effect": httpx.ConnectError("reset")}, "retry"),
    ({"return_value": httpx.Response(503, text="<html>busy</html>")}, "retry"),
    ({"return_value": httpx.Response(429, json={"error": "slow down"})}, "retry"),
    ({"return_value": httpx.Response(404, json={"error": "entity_not_found"})}, "retry"),
    ({"return_value": httpx.Response(500, text="")}, "retry"),
])
async def test_revoke_outcomes(router, client, mock, expected):
    router.put(f"{CERT}/c-1/revoke").mock(**mock)
    assert await client.revoke("c-1") == expected


async def test_revoke_request_shape_and_short_timeout(router, client):
    route = router.put(f"{CERT}/c-1/revoke").mock(return_value=httpx.Response(204))
    await client.revoke("c-1")
    request = route.calls.last.request
    assert json.loads(request.content)["reason"] == "cessation_of_operation"
    assert request.extensions["timeout"]["read"] == dtm.REVOKE_TIMEOUT == 8.0
    assert client.calls == []  # quiet: per-certificate calls stay out of the run log


async def test_issued_certificates_filter(router, client):
    route = router.get(CERT).mock(return_value=page([{"id": "c-1"}]))
    assert await client.issued_certificates("IOT_1") == [{"id": "c-1"}]
    params = route.calls.last.request.url.params
    assert params["certificate_policy_id"] == "IOT_1" and params["status"] == "issued"


@pytest.mark.parametrize("status", [401, 403])
async def test_revoke_reraises_auth_errors(router, client, status):
    router.put(f"{CERT}/c-1/revoke").mock(return_value=httpx.Response(status, json={"error": "key revoked"}))
    with pytest.raises(DTMError) as info:
        await client.revoke("c-1")
    assert info.value.status == status


@pytest.mark.parametrize("body", ["<html>login</html>", "not json", "{broken"])
async def test_non_json_success_body_raises_dtm_error(router, client, body):
    router.get("/certificate-authority/api/v1/ca").mock(return_value=httpx.Response(200, text=body))
    with pytest.raises(DTMError, match="non-JSON") as info:
        await client.issuing_cas()
    assert info.value.status == 200


async def test_count_certificates(router, client):
    route = router.get(CERT).mock(return_value=page([{"id": "c-1"}], total=42))
    assert await client.count_certificates("IOT_1", "revoked") == 42
    params = route.calls.last.request.url.params
    assert params["status"] == "revoked" and params["limit"] == "1"
    assert params["certificate_policy_id"] == "IOT_1" and params["account_id"] == ACCOUNT_ID
    assert client.calls == []  # quiet


async def test_reject_batch(router, client):
    route = router.put(f"{DTM}/certificate-batch-service/api/v1/jobs/j1/reject").mock(
        return_value=httpx.Response(204))
    await client.reject_batch("j1")
    assert route.called and route.calls.last.request.url.params["account_id"] == ACCOUNT_ID


def test_config_repr_hides_api_key():
    config = DTMConfig(HOST, "super-secret-key-value", ACCOUNT_ID)
    assert "super-secret-key-value" not in repr(config) and "super-secret-key-value" not in str(config)
    assert config.api_key == "super-secret-key-value"


@pytest.mark.parametrize("call", ["check_account", "issuing_cas", "count"])
async def test_empty_success_body_raises_dtm_error(router, client, call):
    router.get("/account/api/v1/account").mock(return_value=httpx.Response(200, text=""))
    router.get("/certificate-authority/api/v1/ca").mock(return_value=httpx.Response(200, text=""))
    router.get(CERT).mock(return_value=httpx.Response(200, text=""))
    coro = {"check_account": client.check_account, "issuing_cas": client.issuing_cas,
            "count": lambda: client.count_certificates("IOT_1", "revoked")}[call]()
    with pytest.raises(DTMError, match="empty response") as info:
        await coro
    assert info.value.status == 200


async def test_empty_error_body_still_reports_status(router, client):
    router.get("/x").mock(return_value=httpx.Response(503, text=""))
    with pytest.raises(DTMError, match="returned 503") as info:
        await client._request("GET", "/x")
    assert info.value.status == 503


async def test_empty_bodies_where_dtm_sends_none_are_fine(router, client):
    # division create (no ID in the response), revoke 204 and policy delete 204 must not parse the body
    router.get(f"{DTM}/api/v4/rendezvous-zone").mock(return_value=page([{"id": "z", "name": "z", "status": "ENABLED"}]))
    router.post(f"{DTM}/api/v4/division").mock(return_value=httpx.Response(200, text=""))
    router.get(f"{DTM}/api/v4/division").mock(return_value=page([{"id": "d-1", "name": "n"}]))
    router.put(f"{CERT}/c-1/revoke").mock(return_value=httpx.Response(204))
    router.delete(f"{POLICY_DELETE}/IOT_1").mock(return_value=httpx.Response(204))
    router.get(f"{DTM}/certificate-configuration-service/api/v2/certificate-policy").mock(return_value=page([]))
    assert await client.create_division("n", "d") == "d-1"
    assert await client.revoke("c-1") == "revoked"
    await client.delete_policy("IOT_1")
