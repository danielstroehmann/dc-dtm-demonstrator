"""DTM client: over-the-air updates (tus upload, artifact, release, deployment, abort) and UC-7's
authentication CA – against the fake DTM, plus raw MockTransport checks where the fake cannot tell."""

import base64
import json

import httpx
import pytest

from app import certs, dtm, firmware
from app.dtm import DTMClient, DTMError
from tests.fakedtm import ACCOUNT_ID, OTHER_ACCOUNT_ID, FakeDTM, _error


@pytest.fixture
async def client(fake):
    c = fake.client()
    yield c
    await c.aclose()


async def division(fake: FakeDTM, client: DTMClient, name: str = "robot-firmware-division") -> str:
    await client.create_division(name, "test")
    return next(d["id"] for d in fake.divisions.values() if d["name"] == name)


async def test_tus_upload_sends_the_zip_in_one_chunk(fake, client):
    data = firmware.payload({"version": 2, "character": "ghost", "color": "#00897b"})
    upload_id = await client.upload_payload("robot-firmware-2-ghost-00897b.zip", data)
    assert fake.uploads[upload_id]["data"] == data and fake.uploads[upload_id]["completed"]
    create, patch, finish = [r for r in fake.requests if "/resumable-upload" in r.url.path]
    assert (create.method, patch.method, finish.method) == ("POST", "PATCH", "POST")
    assert all(r.headers["tus-resumable"] == "1.0.0" for r in (create, patch))
    assert create.headers["upload-length"] == str(len(data))
    meta = dict(item.split(" ") for item in create.headers["upload-metadata"].split(","))
    assert base64.b64decode(meta["filename"]).decode() == "robot-firmware-2-ghost-00897b.zip"
    assert base64.b64decode(meta["filetype"]).decode() == "application/zip"
    assert patch.headers["upload-offset"] == "0"
    assert patch.headers["content-type"] == "application/offset+octet-stream"
    assert fake.violations == []


async def test_upload_not_completed_is_an_error(fake, client):
    fake.fail["upload_finish"] = httpx.Response(200, json={"completed": False})
    with pytest.raises(DTMError, match="was not accepted"):
        await client.upload_payload("x.zip", b"PK")


@pytest.mark.parametrize("location", ["", "https://evil/../../x?y", "https://h/upload/a b"])
async def test_upload_refuses_an_unusable_location(fake, client, location):
    fake.fail["upload_create"] = httpx.Response(201, headers={"Location": location})
    with pytest.raises(DTMError, match="unexpected ID"):
        await client.upload_payload("x.zip", b"PK")
    assert "upload_patch" not in fake.route_order()  # nothing is sent to a path built from it


async def test_artifact_release_deployment_and_abort(fake, client):
    div = await division(fake, client)
    payload_id = await client.upload_payload("a.zip", firmware.payload({"version": 2, "character": "robot",
                                                                        "color": "#e53935"}))
    body = dtm.artifact_body("robot-firmware-2-robot-e53935", div, ACCOUNT_ID, "2.0.0", "d", payload_id)
    assert body["actions"]["install"] == {"file": "install.sh", "file_type": "script", "file_sub_type": "bash"}
    artifact_id = await client.create_artifact(body)
    release_id = await client.create_release(dtm.release_body("robot-firmware-2-robot-e53935", div, ACCOUNT_ID,
                                                              "2.0.0", "d", artifact_id))
    assert [r["id"] for r in await client.named_prefix(dtm.ARTIFACTS, "robot-firmware-")] == [artifact_id]
    assert [r["id"] for r in await client.named_prefix(dtm.RELEASES, "robot-firmware-")] == [release_id]
    assert await client.named_prefix(dtm.RELEASES, "robot-other-") == []

    await client.enable(dtm.RELEASES, release_id, enabled=False)
    assert fake.releases[release_id]["status"] == "DISABLED"
    await client.enable(dtm.RELEASES, release_id)
    assert fake.releases[release_id]["status"] == "ENABLED"

    fake.device_groups["g1"] = {"id": "g1", "name": "robot-t1-uc08-group", "account_id": ACCOUNT_ID,
                                "status": "ACTIVE", "hidden": 0, "policies": []}
    deployment_id = await client.create_deployment(dtm.deployment_body("robot-t1-uc08-firmware-2", div, ACCOUNT_ID,
                                                                       "g1", release_id))
    assert fake.deployments[deployment_id]["body"]["scheduler_mode"] == "deployNow"
    assert await client.deployments_named("robot-t1-uc08-firmware-") == [(deployment_id, "robot-t1-uc08-firmware-2")]
    assert await client.deployments_named("robot-t10-uc08-firmware-") == []
    await client.abort_deployment(deployment_id)
    assert fake.deployments[deployment_id]["status"] == "ABORTED"
    # an aborted deployment is left as it is – a second rollback must not fail
    await client.abort_deployment(deployment_id)
    assert fake.violations == []


@pytest.mark.parametrize("status,tolerated", [("COMPLETED", True), ("FINISHED", True), ("IN_PROGRESS", False)])
async def test_abort_tolerates_only_a_finished_deployment(fake, client, status, tolerated):
    fake.deployments["d1"] = {"id": "d1", "name": "robot-t1-uc08-firmware-2", "status": status, "body": {}}
    fake.fail["deployment_abort"] = _error(400, "deployment cannot be aborted")
    if tolerated:
        await client.abort_deployment("d1")
    else:
        with pytest.raises(DTMError, match="returned 400"):
            await client.abort_deployment("d1")


async def test_abort_never_hides_an_authorisation_error(fake, client):
    fake.deployments["d1"] = {"id": "d1", "name": "robot-t1-uc08-firmware-2", "status": "ABORTED", "body": {}}
    fake.fail["deployment_abort"] = _error(403, "forbidden")
    with pytest.raises(DTMError, match="403"):
        await client.abort_deployment("d1")
    assert "deployment_get" not in fake.route_order()


async def test_abort_refuses_an_unsafe_id(fake, client):
    with pytest.raises(DTMError, match="unexpected ID"):
        await client.abort_deployment("../release/x")
    assert fake.requests == []


@pytest.mark.parametrize("method", ["create_artifact", "create_release", "create_deployment"])
async def test_create_refuses_an_answer_without_a_usable_id(fake, client, method):
    route = {"create_artifact": "artifact_create", "create_release": "release_create",
             "create_deployment": "deployment_create"}[method]
    fake.fail[route] = httpx.Response(200, json={"id": "../../x"})
    with pytest.raises(DTMError, match="unexpected ID"):
        await getattr(client, method)({})


async def test_named_prefix_skips_records_with_unsafe_ids(fake, client):
    fake.artifacts["ok-1"] = {"id": "ok-1", "name": "robot-firmware-2-robot-e53935", "status": "ENABLED", "body": {}}
    fake.artifacts["bad"] = {"id": "a/b", "name": "robot-firmware-3-robot-e53935", "status": "ENABLED", "body": {}}
    assert [r["id"] for r in await client.named_prefix(dtm.ARTIFACTS, "robot-firmware-")] == ["ok-1"]


# --- UC-7: the authentication CA (trust anchor) -------------------------------------------------------

async def test_auth_ca_create_list_delete(fake, client):
    pki = certs.manufacturer_ca("robot-t1-uc07")
    policy_id = await client.create_auth_policy("robot-t1-uc07-auth")
    anchor = await client.create_auth_ca(policy_id, pki["ica"])
    assert anchor["name"] == "robot-t1-uc07-device-id-ica"  # named after the CA's common name
    sent = json.loads(next(r for r in fake.requests if r.url.path == dtm.AUTH_CA and r.method == "POST").content)
    assert sent == {"authentication_policy_id": policy_id, "ca_body_pem": pki["ica"], "account_id": ACCOUNT_ID}
    assert await client.auth_cas_named("robot-t1-uc07-device-id-ica") == [(anchor["id"], anchor["name"])]
    assert await client.auth_cas_named("robot-t1-uc07-", prefix=True) == [(anchor["id"], anchor["name"])]
    assert await client.auth_cas_named("robot-t1-uc07") == []  # exact unless prefix
    await client.delete_auth_ca(anchor["id"])
    assert fake.auth_cas[anchor["id"]]["status"] == "DELETED"
    assert await client.auth_cas_named("robot-t1-uc07-device-id-ica") == []  # deleted ones are not found
    await client.delete_auth_ca(anchor["id"])  # 404: already gone – idempotent
    assert fake.violations == []
    assert f"/account/{ACCOUNT_ID}/authentication-ca/{anchor['id']}/delete" in fake.requests[-2].url.path


async def test_auth_ca_still_listed_after_delete_is_an_error(fake, client):
    fake.auth_cas["ca1"] = {"id": "ca1", "name": "robot-t1-uc07-device-id-ica", "status": "ACTIVE",
                            "authentication_policy_id": "p", "pem": ""}
    fake.fail["auth_ca_delete"] = httpx.Response(200)  # DTM says yes but keeps it
    with pytest.raises(DTMError, match="still exists after delete"):
        await client.delete_auth_ca("ca1")


async def test_auth_ca_with_unsafe_ids_is_refused(fake, client):
    fake.fail["auth_ca_create"] = httpx.Response(201, json={"id": "../x", "name": "n"})
    with pytest.raises(DTMError, match="unexpected ID"):
        await client.create_auth_ca("p", "pem")
    with pytest.raises(DTMError, match="unexpected ID"):
        await client.delete_auth_ca("a/../b")
    fake.auth_cas["x"] = {"id": "a b", "name": "robot-t1-uc07-device-id-ica", "status": "ACTIVE",
                          "authentication_policy_id": "p", "pem": ""}
    assert await client.auth_cas_named("robot-t1-uc07-device-id-ica") == []


async def test_auth_ca_delete_is_scoped_to_the_configured_account():
    """The account is part of the delete path – it must be the configured one, never another."""
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"records": [], "total": 0})
    client = DTMClient(dtm.DTMConfig("one.digicert.com", "k", OTHER_ACCOUNT_ID), transport=httpx.MockTransport(handler))
    try:
        await client.delete_auth_ca("ca-1")
    finally:
        await client.aclose()
    delete = seen[0]
    assert delete.method == "PUT" and delete.url.path == (
        f"/devicetrustmanager/authentication-service/api/v2/account/{OTHER_ACCOUNT_ID}/authentication-ca/ca-1/delete")
    assert all(r.url.params["account_id"] == OTHER_ACCOUNT_ID for r in seen)


async def test_lists_drop_records_of_another_account(fake, client):
    """The key sees several accounts – a record naming another account is never ours, whatever its name."""
    ours = {"status": "ENABLED", "body": {}}
    fake.artifacts["a1"] = ours | {"id": "a1", "name": "robot-firmware-2-robot-e53935", "account_id": ACCOUNT_ID}
    fake.artifacts["a2"] = ours | {"id": "a2", "name": "robot-firmware-3-robot-e53935", "account_id": OTHER_ACCOUNT_ID}
    fake.artifacts["a3"] = ours | {"id": "a3", "name": "robot-firmware-4-robot-e53935",
                                   "account": {"id": OTHER_ACCOUNT_ID}}
    fake.artifacts["a4"] = ours | {"id": "a4", "name": "robot-firmware-5-robot-e53935"}  # says nothing: kept
    assert [r["id"] for r in await client.named_prefix(dtm.ARTIFACTS, "robot-firmware-")] == ["a1", "a4"]
    fake.deployments["d1"] = {"id": "d1", "name": "robot-t1-uc08-firmware-2", "status": "IN_PROGRESS",
                              "account_id": OTHER_ACCOUNT_ID, "body": {}}
    fake.deployments["d2"] = {"id": "d2", "name": "robot-t1-uc08-firmware-3", "status": "IN_PROGRESS",
                              "account_id": ACCOUNT_ID, "body": {}}
    assert await client.deployments_named("robot-t1-uc08-firmware-") == [("d2", "robot-t1-uc08-firmware-3")]
    fake.auth_cas["c1"] = {"id": "c1", "name": "robot-t1-uc07-device-id-ica", "status": "ACTIVE",
                           "authentication_policy_id": "p", "pem": "", "account_id": OTHER_ACCOUNT_ID}
    assert await client.auth_cas_named("robot-t1-uc07-device-id-ica") == []
