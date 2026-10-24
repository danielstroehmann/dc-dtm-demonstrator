"""DTM REST client.

Every call is scoped to one configured account (`account_id`); the API key may see several.
Request paths and payloads follow what was verified against a live account – the public
OpenAPI spec deviates in several places (see docs/design/uc-01-evergreen.md).
"""

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

# A revoke normally returns within 1–3 s; under load single requests hang for minutes and
# often still complete server-side. Short timeouts plus re-listing beat long waits (R-4).
REVOKE_TIMEOUT = 8.0
DEFAULT_TIMEOUT = 60.0
LOOKUP_RETRIES = 3
DIVISIONS = "/devicetrustmanager/api/v4/division"
POLICIES = "/devicetrustmanager/certificate-configuration-service/api/v2/certificate-policy"
PROFILES = "/devicetrustmanager/certificate-configuration-service/api/v1/certificate-profile"
AUTH = "/devicetrustmanager/authentication-service/api/v1"
# Ledger kind → authentication-service collection (UC-3). Deleted objects stay as status DELETED.
AUTH_KINDS = {"auth_certificate": "authentication-certificate", "passcode": "passcode",
              "auth_policy": "authentication-policy"}
# Enrollment protocol (UC-3) → certificate management method of the policy.
ENROLLMENT_METHODS = {"est": "EST", "cmpv2": "CMP_V2", "rest": "SINGLE"}


class DTMError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class DTMConfig:
    host: str
    api_key: str = field(repr=False)  # never in reprs, logs or tracebacks
    account_id: str


def division_body(name: str, description: str, account_id: str, rzone_id: str) -> dict:
    return {"name": name, "description": description, "account_id": account_id, "primary_rzone_id": rzone_id}


def policy_body(*, name: str, division_id: str, profile_id: str, ica_id: str, key_type: str,
                require_approval: bool, key_generation: str = "server_side") -> dict:
    """key_generation: 'server_side' (DTM creates the key pairs) or 'client_side' (CSRs)."""
    common = {"key_generation_option": key_generation, "key_type": key_type.lower(),
              "private_key_format": "pem", "encryption_certificate_source": "provided",
              "include_chain_option": "include_ica_and_root"}
    return {"certificate_policy": {
        "name": name, "division_id": division_id, "certificate_profile_id": profile_id, "ica_id": ica_id,
        "certificate_management_methods": ["SINGLE", "BATCH"],
        "key_generation_option": key_generation, "key_generation_type": key_type,
        "require_device_group_for_enroll": False,
        "require_approval_for_enroll": require_approval, "require_approval_for_renew": False,
        "single_cert_request_parameters": {**common, "response_with_certificate_only": False,
                                           "split_certificate_response": True},
        "batch_request_parameters": {**common, "certificate_format": "pem", "ecdsa_private_key_syntax": "pkcs8",
                                     "rsa_private_key_syntax": "pkcs8",
                                     "input_type": "csv" if key_generation == "server_side" else "csr",
                                     "output_format": "zip", "report_format": "csv"},
    }}


def enrollment_policy_body(*, name: str, division_id: str, profile_id: str, ica_id: str, key_type: str,
                           auth_policy_id: str, protocol: str) -> dict:
    """UC-3: one enrollment protocol, client-side keys, authenticated by an authentication policy
    (passcode or factory certificate) – no device group, so the Essentials license is enough."""
    method = ENROLLMENT_METHODS[protocol]
    body = {"name": name, "division_id": division_id, "certificate_profile_id": profile_id, "ica_id": ica_id,
            "certificate_management_methods": [method], "authentication_policy_id": auth_policy_id,
            "key_generation_option": "client_side", "key_generation_type": key_type,
            "require_device_group_for_enroll": False, "require_approval_for_enroll": False,
            "require_approval_for_renew": False}
    if method == "CMP_V2":
        body["cmp_request_parameters"] = {}  # required; DTM fills in its defaults
    if method == "SINGLE":
        body["single_cert_request_parameters"] = {
            "key_generation_option": "client_side", "key_type": key_type.lower(), "private_key_format": "pem",
            "encryption_certificate_source": "provided", "include_chain_option": "include_ica_and_root",
            "response_with_certificate_only": False, "split_certificate_response": True}
    return {"certificate_policy": body}


def bare_key_profile_body(base: dict, name: str, account_id: str) -> dict:
    """Copy of a profile that accepts a bare public key – what CMPv2 sends instead of a CSR. The
    flag is not a field but a source of the `csr` body entry (found via the portal, not in the spec)."""
    body = [e for e in base["body"] if e["key"] != "csr"]
    body.append({"key": "csr", "optional": False, "enabled": True,
                 "sources": ["user_supplied", "allow_bare_public_key"], "value": None})
    return {"name": name, "account_id": account_id, "certificate_template_id": base["certificate_template"]["id"],
            "body": body, "divisions": [], "certificate_type": "end_entity", "ca_connector_type": "digicert_one"}


def single_body(policy_id: str, common_name: str, csr: str | None = None) -> dict:
    """Server-side key generation, or – with a CSR – the factory's own key pair."""
    body = {"certificate_policy_id": policy_id,
            "certificate_profile_attributes": [{"id": "subject.common_name", "value": common_name}],
            "split_certificate_response": True, "include_certificate_chain": True}
    if csr is None:
        return body | {"server_side_key_gen": True, "private_key_format": "pem", "private_key_syntax": "pkcs8"}
    return body | {"csr": csr}


def batch_fields(name: str, policy_id: str, key_type: str) -> dict:
    """Multipart fields of a server-side batch, without the encryption certificate and the ZIP."""
    return {"name": name, "certificate_policy_id": policy_id, "certificate_format": "pem",
            "input_format": "csv", "output_format": "zip", "server_side_key_gen": "true",
            "key_type": key_type, "private_key_format": "pem", "private_key_syntax": "pkcs8", "emails": ""}


def csr_batch_fields(name: str, policy_id: str) -> dict:
    """Multipart fields of a client-side batch (ZIP of CSR files) – no keys come back, so no encryption."""
    return {"name": name, "certificate_policy_id": policy_id, "certificate_format": "pem",
            "input_format": "csr", "output_format": "zip", "emails": ""}


def _renew_anytime(profile: dict) -> bool:
    """UC-4 renews a fresh certificate on click – the profile must allow renewing a valid
    certificate at any time (otherwise DTM answers "Renewal is disabled")."""
    body = profile.get("body")
    entries = body if isinstance(body, list) else []  # data from DTM – one odd profile must not break the forms
    entry = next((e for e in entries if isinstance(e, dict) and e.get("key") == "renewal_settings.renew_valid_cert"), {})
    return entry.get("enabled", True) is not False and entry.get("value") == "anytime"


def _json(response: httpx.Response):
    # DTM responses may contain raw control characters (e.g. PEM line breaks) inside strings.
    if not response.text:
        raise DTMError(f"unexpected empty response ({response.status_code})", response.status_code)
    try:
        return json.loads(response.text, strict=False)
    except ValueError as exc:
        raise DTMError(f"unexpected non-JSON response ({response.status_code})", response.status_code) from exc


class DTMClient:
    def __init__(self, config: DTMConfig, on_call: Callable[[str], None] | None = None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self._on_call = on_call or (lambda _msg: None)
        self._http = httpx.AsyncClient(
            base_url=f"https://{config.host}",
            headers={"x-api-key": config.api_key},
            timeout=DEFAULT_TIMEOUT,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, *, expect: tuple[int, ...] = (200,),
                       params: dict | None = None, quiet: bool = False, **kwargs) -> httpx.Response:
        # quiet: high-frequency calls (job polling, per-certificate revokes) stay out of the
        # run log; callers summarise them instead.
        on_call = (lambda _msg: None) if quiet else self._on_call
        params = {**(params or {}), "account_id": self.config.account_id}
        start = time.monotonic()
        try:
            response = await self._http.request(method, path, params=params, **kwargs)
        except httpx.TimeoutException as exc:
            on_call(f"{method} {path} → timeout")
            raise DTMError(f"{method} {path} timed out") from exc
        except httpx.HTTPError as exc:
            on_call(f"{method} {path} → {type(exc).__name__}")
            raise DTMError(f"{method} {path} failed: {type(exc).__name__}") from exc
        on_call(f"{method} {path} → {response.status_code} ({time.monotonic() - start:.1f}s)")
        if response.status_code not in expect:
            raise DTMError(f"{method} {path} returned {response.status_code}: {_error_text(response)}",
                           response.status_code)
        return response

    async def _list(self, path: str, params: dict | None = None, items_key: str = "records") -> list[dict]:
        """Fetch all pages of a list endpoint."""
        out, offset = [], 0
        while True:
            data = _json(await self._request("GET", path, params={**(params or {}), "limit": 100, "offset": offset}))
            page = data.get(items_key) or []
            out += page
            offset += len(page)
            if not page or offset >= data.get("total", 0):
                return out

    # account
    async def check_account(self) -> None:
        """Fails unless the API key can access the configured account."""
        data = _json(await self._request("GET", "/account/api/v1/account"))
        accounts = data if isinstance(data, list) else data.get("records", [])
        if not any(a.get("id") == self.config.account_id for a in accounts):
            raise DTMError("the API key has no access to the configured account ID")

    # read-only lookups
    async def issuing_cas(self) -> list[dict]:
        """Active intermediate CAs assigned to the account. They are used, never modified."""
        items = await self._list("/certificate-authority/api/v1/ca", items_key="items")
        return [
            {"id": ca["id"], "name": ca["name"], "key_type": ca.get("key_type", "")}
            for ca in items
            if ca.get("cert_type") == "intermediate" and ca.get("status") == "active"
            and any(a.get("id") == self.config.account_id for a in ca.get("account_assignments", []))
        ]

    async def certificate_profiles(self) -> list[dict]:
        items = await self._list("/devicetrustmanager/certificate-configuration-service/api/v1/certificate-profile")
        return [{"id": p["id"], "name": p["name"], "renew_anytime": _renew_anytime(p)}
                for p in items if p.get("status") == "ACTIVE"]

    async def rendezvous_zone(self) -> str:
        zones = await self._list("/devicetrustmanager/api/v4/rendezvous-zone")
        enabled = sorted((z for z in zones if z.get("status") == "ENABLED"), key=lambda z: z["name"])
        if not enabled:
            raise DTMError("no enabled rendezvous zone available for division creation")
        return enabled[0]["id"]

    async def find_ids(self, path: str, name: str) -> list[str]:
        return [r["id"] for r in await self._list(path) if r.get("name") == name]

    async def _find_id(self, path: str, name: str) -> str:
        for attempt in range(LOOKUP_RETRIES):
            matches = await self.find_ids(path, name)
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                break
            await asyncio.sleep(1 + attempt)  # list lags behind the create
        raise DTMError(f"expected exactly one object named {name!r}, found {len(matches)}")

    async def division_ids(self, name: str) -> list[str]:
        return await self.find_ids(DIVISIONS, name)

    async def policy_ids(self, name: str) -> list[str]:
        return await self.find_ids(POLICIES, name)

    # divisions – create returns no ID, so it is looked up by its unique name
    async def create_division(self, name: str, description: str, rzone_id: str | None = None) -> str:
        rzone_id = rzone_id or await self.rendezvous_zone()
        await self._request("POST", DIVISIONS,
                            json=division_body(name, description, self.config.account_id, rzone_id))
        return await self._find_id(DIVISIONS, name)

    async def delete_division(self, division_id: str) -> None:
        await self._request("DELETE", f"{DIVISIONS}/{division_id}", expect=(200, 204, 404))
        if division_id in [r["id"] for r in await self._list(DIVISIONS)]:
            raise DTMError(f"division {division_id} still exists after delete")

    # certificate policies
    async def create_policy(self, *, name: str, division_id: str, profile_id: str, ica_id: str,
                            key_type: str, require_approval: bool, key_generation: str = "server_side") -> str:
        await self._request("POST", POLICIES, expect=(200, 201), json=policy_body(
            name=name, division_id=division_id, profile_id=profile_id, ica_id=ica_id, key_type=key_type,
            require_approval=require_approval, key_generation=key_generation))
        return await self._find_id(POLICIES, name)

    async def delete_policy(self, policy_id: str) -> None:
        # Undocumented UI-internal endpoint – the only known way to delete a policy (risk R-1).
        # A 404 only counts if DTM says the policy is unknown; a vanished route must fail loudly.
        response = await self._request(
            "DELETE", f"/devicetrustmanager/certificate-configuration-service/api-ui/v1/certificate-policy/{policy_id}",
            json={}, expect=(200, 204, 404))
        if response.status_code == 404 and "entity_not_found" not in response.text:
            raise DTMError("policy delete endpoint returned 404 without entity_not_found – api-ui path changed? (R-1)")
        if policy_id in [r["id"] for r in await self._list(POLICIES)]:
            raise DTMError(f"policy {policy_id} still exists after delete")

    async def get_policy(self, policy_id: str) -> dict:
        return _json(await self._request("GET", f"{POLICIES}/{policy_id}"))

    async def create_enrollment_policy(self, **kwargs) -> str:
        await self._request("POST", POLICIES, expect=(200, 201), json=enrollment_policy_body(**kwargs))
        return await self._find_id(POLICIES, kwargs["name"])

    # UC-3: authentication policy with one credential (passcode or factory certificate)
    async def create_auth_policy(self, name: str) -> str:
        data = _json(await self._request("POST", f"{AUTH}/authentication-policy", expect=(200, 201),
                                         json={"name": name, "account_id": self.config.account_id}))
        return data["id"]

    async def create_passcode(self, name: str, auth_policy_id: str, passcode: str) -> dict:
        """Returns id and alternate_id – the reference CMPv2 sends as sender KID."""
        data = _json(await self._request("POST", f"{AUTH}/passcode", expect=(200, 201), json={
            "name": name, "account_id": self.config.account_id, "authentication_policy_id": auth_policy_id,
            "enable_username_for_passcode": False, "passcode": passcode}))
        return {"id": data["id"], "alternate_id": data.get("alternate_id")}

    async def create_auth_certificate(self, name: str, auth_policy_id: str, pem: str) -> str:
        data = _json(await self._request("POST", f"{AUTH}/authentication-certificate", expect=(200, 201), json={
            "name": name, "account_id": self.config.account_id, "authentication_policy_id": auth_policy_id,
            "pem": pem, "use_passcode": False}))
        return data["id"]

    async def auth_object_ids(self, kind: str, name: str) -> list[str]:
        """Live objects only – soft-deleted ones keep their name (e.g. of an earlier run with this ID)."""
        return [r["id"] for r in await self._list(f"{AUTH}/{AUTH_KINDS[kind]}")
                if r.get("name") == name and r.get("status") != "DELETED"]

    async def delete_auth_object(self, kind: str, object_id: str) -> None:
        """Soft delete: the object stays with status DELETED (verified live)."""
        path = f"{AUTH}/{AUTH_KINDS[kind]}/{object_id}"
        response = await self._request("PUT", f"{path}/delete", json={}, expect=(200, 204, 400, 404))
        # 400/404 are fine only if the object is gone or already deleted – a vanished route must fail.
        check = await self._request("GET", path, expect=(200, 404))
        if check.status_code == 404:
            if "entity_not_found" not in check.text:
                raise DTMError(f"{kind} {object_id}: unexpected 404 without entity_not_found")
            return
        if _json(check).get("status") != "DELETED":
            raise DTMError(f"{kind} {object_id} still {_json(check).get('status')} after delete "
                           f"({response.status_code})")

    async def bare_key_profile(self, name: str, base_profile_id: str) -> tuple[str, bool]:
        """The account's shared CMPv2 profile: found by name, else created from the base profile.
        It is never deleted – DTM refuses to delete a profile a (deleted) policy referenced.
        Returns (id, created)."""
        for record in await self._list(PROFILES):
            if record.get("name") == name and record.get("status") == "ACTIVE":
                if record.get("account_id") != self.config.account_id or not record.get("allow_bare_public_key"):
                    raise DTMError(f"profile {name} exists but does not allow bare public keys in this account – "
                                   "fix or rename it in the DTM portal")
                return record["id"], False
        base = _json(await self._request("GET", f"{PROFILES}/{base_profile_id}"))
        data = _json(await self._request("POST", PROFILES, expect=(200, 201),
                                         json=bare_key_profile_body(base, name, self.config.account_id)))
        if not data.get("allow_bare_public_key"):
            raise DTMError("DTM did not enable bare public keys on the CMPv2 profile")
        return data["id"], True

    # issuance
    async def issue_single(self, policy_id: str, common_name: str, csr: str | None = None) -> dict:
        response = await self._request(
            "POST", "/devicetrustmanager/certificate-issuance-service/api/v2/certificate",
            json=single_body(policy_id, common_name, csr))
        return _json(response)

    async def submit_batch(self, *, name: str, policy_id: str, payload: bytes, key_type: str,
                           encryption_cert_pem: str | None) -> dict:
        """With an encryption certificate: server-side keys (ZIP with a CSV). Without: a ZIP of CSRs."""
        if encryption_cert_pem:
            # The spec calls this field `certificate`; DTM only accepts `encryption_certificate`.
            fields = batch_fields(name, policy_id, key_type) | {"encryption_certificate": encryption_cert_pem}
        else:
            fields = csr_batch_fields(name, policy_id)
        response = await self._request("POST", "/devicetrustmanager/certificate-batch-service/api/v1/jobs/certificate-enroll",
                                       expect=(200, 201), data=fields,
                                       files={"data": ("batch.zip", payload, "application/zip")})
        return _json(response)

    async def batch_job(self, job_id: str, quiet: bool = False) -> dict:
        return _json(await self._request("GET", f"/devicetrustmanager/certificate-batch-service/api/v1/jobs/{job_id}",
                                         quiet=quiet))

    async def approve_batch(self, job_id: str) -> None:
        await self._request("PUT", f"/devicetrustmanager/certificate-batch-service/api/v1/jobs/{job_id}/approve",
                            json={}, expect=(200, 204))

    async def reject_batch(self, job_id: str) -> None:
        await self._request("PUT", f"/devicetrustmanager/certificate-batch-service/api/v1/jobs/{job_id}/reject",
                            json={}, expect=(200, 204))

    async def batch_result(self, job_id: str) -> bytes:
        response = await self._request(
            "GET", f"/devicetrustmanager/certificate-batch-service/api/v1/jobs/{job_id}/download/result")
        return response.content

    # certificates
    async def issued_certificates(self, policy_id: str) -> list[dict]:
        return await self._list("/devicetrustmanager/certificate-issuance-service/api/v2/certificate",
                                params={"certificate_policy_id": policy_id, "status": "issued"})

    async def count_certificates(self, policy_id: str, status: str) -> int:
        data = _json(await self._request(
            "GET", "/devicetrustmanager/certificate-issuance-service/api/v2/certificate", quiet=True,
            params={"certificate_policy_id": policy_id, "status": status, "limit": 1}))
        return int(data.get("total", 0))

    async def revoke(self, certificate_id: str) -> str:
        """Returns 'revoked', 'already' or 'retry'. Under load (R-4) timeouts, gateway errors and
        list lag are expected – the next pass re-lists and retries; nothing is raised."""
        try:
            await self._request(
                "PUT", f"/devicetrustmanager/certificate-issuance-service/api/v2/certificate/{certificate_id}/revoke",
                json={"reason": "cessation_of_operation", "comments": "dc-dtm-demonstrator cleanup"},
                expect=(200, 204), timeout=REVOKE_TIMEOUT, quiet=True)
            return "revoked"
        except DTMError as exc:
            if exc.status in (401, 403):  # a broken key will not heal by retrying
                raise
            return "already" if exc.status == 400 else "retry"


def _error_text(response: httpx.Response) -> str:
    try:
        data = _json(response)
    except DTMError:
        return response.text[:200] if not response.text.lstrip().startswith("<") else "(HTML error page)"
    if isinstance(data, dict):
        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            return "; ".join(str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in errors)[:300]
        if "error" in data:
            return str(data["error"])[:300]
    return str(data)[:300]
