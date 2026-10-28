"""DTM REST client.

Every call is scoped to one configured account (`account_id`); the API key may see several.
Request paths and payloads follow what was verified against a live account – the public
OpenAPI spec deviates in several places (verified live; the deviations are noted where they matter).
"""

import asyncio
import base64
import json
import re
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
# UC-7: a CA as trust anchor of an authentication policy – the portal's endpoint (not in the public spec)
AUTH_CA = "/devicetrustmanager/authentication-service/api/v2/authentication-ca"
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # IDs from DTM that end up in URL paths
DEVICES = "/devicetrustmanager/api/v4/device"
DEVICE_GROUPS = "/devicetrustmanager/api/v4/device-group"
CERTIFICATES = "/devicetrustmanager/certificate-issuance-service/api/v2/certificate"
UPLOADS = "/devicetrustmanager/artifacts/api/v4/resumable-upload"  # tus 1.0.0, as the portal uploads payloads
ARTIFACTS = "/devicetrustmanager/artifacts/api/v4/artifact"
RELEASES = "/devicetrustmanager/release/api/v4/release"
DEPLOYMENTS = "/devicetrustmanager/release/api/v4/deployment"
TUS = {"Tus-Resumable": "1.0.0"}
# Ledger kind → authentication-service collection (UC-3). Deleted objects stay as status DELETED.
AUTH_KINDS = {"auth_certificate": "authentication-certificate", "passcode": "passcode",
              "auth_policy": "authentication-policy"}
_profile_lock = asyncio.Lock()
# Enrollment protocol (UC-3) → certificate management method of the policy.
ENROLLMENT_METHODS = {"est": "EST", "cmpv2": "CMP_V2", "scep": "SCEP", "rest": "SINGLE"}


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


def passcode_body(name: str, account_id: str, auth_policy_id: str, passcode: str,
                  common_name: str | None = None) -> dict:
    body = {"name": name, "account_id": account_id, "authentication_policy_id": auth_policy_id,
            "enable_username_for_passcode": False, "passcode": passcode}
    if common_name is not None:  # registered values are documented for auth certificates only – accepted live
        body |= {"usage_limit": 1, "registered_values": [
            {"certificate_field": "subject.common_name", "matcher": "equals", "value": common_name}]}
    return body


def enrollment_policy_body(*, name: str, division_id: str, profile_id: str, ica_id: str, key_type: str,
                           auth_policy_id: str, protocol: str, device_group: bool = False) -> dict:
    """UC-3: one enrollment protocol, client-side keys, authenticated by an authentication policy
    (passcode or factory certificate) – no device group, so the Essentials license is enough."""
    method = ENROLLMENT_METHODS[protocol]
    body = {"name": name, "division_id": division_id, "certificate_profile_id": profile_id, "ica_id": ica_id,
            "certificate_management_methods": [method], "authentication_policy_id": auth_policy_id,
            "key_generation_option": "client_side", "key_generation_type": key_type,
            "require_device_group_for_enroll": device_group, "require_approval_for_enroll": False,
            "require_approval_for_renew": False}
    if method == "CMP_V2":
        body["cmp_request_parameters"] = {}  # required; DTM fills in its defaults
    if method == "SINGLE":
        body["single_cert_request_parameters"] = {
            "key_generation_option": "client_side", "key_type": key_type.lower(), "private_key_format": "pem",
            "encryption_certificate_source": "provided", "include_chain_option": "include_ica_and_root",
            "response_with_certificate_only": False, "split_certificate_response": True}
    return {"certificate_policy": body}


def device_policy_body(*, name: str, division_id: str, profile_id: str, ica_id: str, key_type: str,
                       protocols: tuple[str, ...], auth_policy_id: str | None = None) -> dict:
    """UC-6: the factory's and the field's protocol in one policy (e.g. REST in the factory, CMPv2 in the
    field – verified live: one policy may carry SINGLE, EST and CMP_V2; CMPv2 needs a bare-key profile),
    only for a device of a group – nothing is issued unmanaged. Without an authentication policy the API
    key authenticates the (REST) requests."""
    args = {"name": name, "division_id": division_id, "profile_id": profile_id, "ica_id": ica_id,
            "key_type": key_type, "auth_policy_id": auth_policy_id or "", "device_group": True}
    body = enrollment_policy_body(protocol=protocols[0], **args)
    policy = body["certificate_policy"]
    methods = list(dict.fromkeys(ENROLLMENT_METHODS[p] for p in protocols))
    policy["certificate_management_methods"] = methods
    for protocol in protocols[1:]:  # each method brings its own parameters
        policy |= {k: v for k, v in enrollment_policy_body(protocol=protocol, **args)["certificate_policy"].items()
                   if k.endswith("_parameters")}
    if not auth_policy_id:
        del policy["authentication_policy_id"]
    return body


def device_group_body(name: str, division_id: str, account_id: str, policy_id: str, attribute: str,
                      also: tuple[str, ...] = ()) -> dict:
    """A static group with the policy assigned. The mapping makes DTM match a certificate's common name
    to the device's inventory attribute (serial_number, mac_address) – or, UC-7, to its name (device_name).
    also: further attributes the group's devices carry. DTM refuses an assignment without status."""
    return {"name": name, "division_id": division_id, "account_id": account_id, "is_static": True,
            "attributes": [attribute, *also],
            "policies": [{"policy_id": policy_id, "assignment_name": f"{name}-policy", "type": "bootstrapCertificate",
                          "status": "ACTIVE",
                          "device_field_mappings": [{"key": attribute, "field": "subject.common_name"}]}]}


def trustedge_policy_body(*, name: str, division_id: str, profile_id: str, ica_id: str, auth_policy_id: str) -> dict:
    """UC-8: the operational policy the TrustEdge agent applies over MQTT – it creates key and CSR, DTM sets the CN
    from the device name. Shaped like a working reference (verified on US 2026-10-27): TrustEdge + EST with an
    authentication policy."""
    body = enrollment_policy_body(name=name, division_id=division_id, profile_id=profile_id, ica_id=ica_id,
                                  key_type="P_256", auth_policy_id=auth_policy_id, protocol="est")
    policy = body["certificate_policy"]
    policy.pop("require_device_group_for_enroll")
    policy["certificate_management_methods"] = ["TRUST_EDGE", "EST"]
    policy["trust_edge_parameters"] = {"request_format_type": "PKCS10", "key_algorithm": ["p_256"],
                                       "cert_attributes_source": "SW", "secure_module_primary": False}
    policy["evaluation_expression_mapping"] = {"evaluation_expressions": [
        {"certificate_field": "subject.common_name", "values": [{"expression": "##device_name##"}]}]}
    return body


def trustedge_group_body(name: str, division_id: str, account_id: str, boot_policy_id: str, op_policy_id: str,
                         auth_policy_id: str) -> dict:
    """UC-8: bootstrap certificate (EST, CN = serial number) and operational certificate (TrustEdge, CN = device
    name) in one group. Mapping field and auth_policy_id per assignment as in the working reference."""
    def assignment(policy_id: str, kind: str, key: str) -> dict:
        return {"policy_id": policy_id, "assignment_name": f"{name}-{kind[:-11]}", "type": kind, "status": "ACTIVE",
                "auth_policy_id": auth_policy_id, "device_field_mappings": [{"key": key, "field": "subject_common_name"}]}
    return {"name": name, "division_id": division_id, "account_id": account_id, "is_static": True,
            "attributes": ["device_name", "serial_number"],
            "policies": [assignment(boot_policy_id, "bootstrapCertificate", "serial_number"),
                         assignment(op_policy_id, "operationalCertificate", "device_name")]}


def artifact_body(name: str, division_id: str, account_id: str, version: str, description: str,
                  payload_id: str) -> dict:
    """An application update whose payload's install.sh the TrustEdge agent runs after unpacking it."""
    return {"name": name, "description": description, "account_id": account_id, "division_id": division_id,
            "version": version, "artifact_type": "applicationUpdate", "depends_on": [], "is_draft": False,
            "target_device_attributes": [],
            "actions": {"install": {"file": "install.sh", "file_type": "script", "file_sub_type": "bash"}},
            "payload_ids": [payload_id]}


def release_body(name: str, division_id: str, account_id: str, version: str, description: str,
                 artifact_id: str) -> dict:
    return {"name": name, "description": description, "version": version, "division_id": division_id,
            "account_id": account_id, "artifact_ids": [{"id": artifact_id, "order": 0}], "notify_user_ids": []}


def deployment_body(name: str, division_id: str, account_id: str, group_id: str, release_id: str) -> dict:
    return {"name": name, "scheduler_mode": "deployNow", "division_id": division_id, "device_group_id": group_id,
            "release_id": release_id, "account_id": account_id}


def device_body(name: str, account_id: str, group_id: str, description: str, attribute: str, value: str) -> dict:
    return {"name": name, "account_id": account_id, "device_group_id": group_id, "description": description,
            "attributes": [{"key": attribute, "value": value}]}


def device_certificate_body(policy_id: str, group_id: str, device_id: str, common_name: str, csr: str) -> dict:
    return {"certificate_policy_id": policy_id, "device_group_id": group_id, "device_id": device_id, "csr": csr,
            "certificate_profile_attributes": [{"id": "subject.common_name", "value": common_name}],
            "split_certificate_response": True, "include_certificate_chain": True}


@dataclass(frozen=True)
class ProfileSpec:
    """The settings of a certificate profile per purpose. On US (see PLATFORMS) it is shared per
    account – DTM there refuses to delete a profile a (deleted) policy referenced, so it is created
    once, found by name later and never deleted; on NL each run gets its own copy with these settings."""
    name: str
    unit: str  # validity.duration_unit, e.g. "years", "months"
    value: int
    bare_key: bool = False  # CMPv2 sends a bare public key instead of a CSR
    renew_anytime: bool = False  # UC-4 renews a fresh certificate on click


# The validity is part of the name: a release that changes it creates a new profile instead of
# altering one that other installations may rely on.
PROFILE_EVERGREEN = ProfileSpec("robot-evergreen-5y-profile", "years", 5)
PROFILE_EVERGREEN_CMP = ProfileSpec("robot-evergreen-cmp-5y-profile", "years", 5, bare_key=True)
PROFILE_RENEWAL = ProfileSpec("robot-renewal-6m-profile", "months", 6, renew_anytime=True)
PROFILE_RENEWAL_CMP = ProfileSpec("robot-renewal-cmp-6m-profile", "months", 6, bare_key=True, renew_anytime=True)
SHARED_PROFILES = (PROFILE_EVERGREEN, PROFILE_EVERGREEN_CMP, PROFILE_RENEWAL, PROFILE_RENEWAL_CMP)


def shared_profile_body(base: dict, spec: ProfileSpec, account_id: str) -> dict:
    """Copy of a base profile with the purpose's validity. The bare-key flag is not a field but a
    source of the `csr` body entry (found via the portal, not in the spec)."""
    values = {"validity.duration_unit": spec.unit, "validity.duration_value": spec.value}
    if spec.renew_anytime:
        values["renewal_settings.renew_valid_cert"] = "anytime"
    body = []
    for entry in base["body"]:
        if entry["key"] == "csr":
            continue
        entry = dict(entry)
        if entry["key"] in values:
            entry |= {"value": values.pop(entry["key"]), "enabled": True}
        body.append(entry)
    body += [{"key": key, "optional": False, "enabled": True, "sources": ["fixed_value"], "value": value}
             for key, value in values.items()]  # entries the base profile did not have
    if spec.bare_key:
        body.append({"key": "csr", "optional": False, "enabled": True,
                     "sources": ["user_supplied", "allow_bare_public_key"], "value": None})
    return {"name": spec.name, "account_id": account_id, "certificate_template_id": base["certificate_template"]["id"],
            "body": body, "divisions": [], "certificate_type": "end_entity", "ca_connector_type": "digicert_one"}


# The supported DTM platforms and how certificate profiles are handled there (author, 2026-10-25):
# NL deletes a profile once its policy is gone – one profile per run, removed by the full rollback;
# US still refuses that (DTM bug) – shared profiles per account until it is fixed. Other hosts are refused.
PLATFORMS = {"one.nl.digicert.com": "per_run", "one.digicert.com": "shared"}
PLATFORM_REGIONS = {"one.digicert.com": "US", "one.nl.digicert.com": "NL"}  # labels of the host choice


def profile_mode(host: str) -> str:
    if host not in PLATFORMS:
        raise DTMError(f"unsupported DTM platform {host} – only {' and '.join(PLATFORMS)}")
    return PLATFORMS[host]


LEGACY_PROFILES = ("robot-uc03-cmp-profile",)  # names of earlier releases – retired with the shared ones
INACTIVE = ("DISABLED", "INACTIVE")


def _profile_matches(profile: dict, spec: ProfileSpec) -> bool:
    body = {e.get("key"): e.get("value") for e in profile.get("body") or [] if isinstance(e, dict)}
    return (str(body.get("validity.duration_unit", "")).lower() == spec.unit
            and str(body.get("validity.duration_value")) == str(spec.value)
            and (not spec.bare_key or bool(profile.get("allow_bare_public_key")))
            and (not spec.renew_anytime or _renew_anytime(profile)))


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
            {"id": ca["id"], "name": ca["name"], "key_type": ca.get("key_type", ""),
             "root": (ca.get("issuer") or {}).get("name", "")}
            for ca in items
            if ca.get("cert_type") == "intermediate" and ca.get("status") == "active"
            and any(a.get("id") == self.config.account_id for a in ca.get("account_assignments", []))
        ]

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

    async def create_passcode(self, name: str, auth_policy_id: str, passcode: str,
                              common_name: str | None = None) -> dict:
        """Returns id and alternate_id – the reference CMPv2 sends as sender KID.
        common_name (UC-5): a one-time passcode bound to that CN – usage limit 1 and a registered value.
        Verified live: DTM checks the CSR's CN against it (rejects, never overrides), and a rejected
        request already uses up the passcode."""
        body = passcode_body(name, self.config.account_id, auth_policy_id, passcode, common_name)
        data = _json(await self._request("POST", f"{AUTH}/passcode", expect=(200, 201), json=body))
        return {"id": data["id"], "alternate_id": data.get("alternate_id")}

    async def passcode_usage(self, passcode_id: str) -> int:
        return int(_json(await self._request("GET", f"{AUTH}/passcode/{passcode_id}")).get("number_of_usage") or 0)

    async def create_auth_certificate(self, name: str, auth_policy_id: str, pem: str) -> str:
        data = _json(await self._request("POST", f"{AUTH}/authentication-certificate", expect=(200, 201), json={
            "name": name, "account_id": self.config.account_id, "authentication_policy_id": auth_policy_id,
            "pem": pem, "use_passcode": False}))
        return data["id"]

    async def auth_object_ids(self, kind: str, name: str) -> list[str]:
        """Live objects only – soft-deleted ones keep their name (e.g. of an earlier run with this ID)."""
        return [object_id for object_id, _name in await self.auth_objects_named(kind, name)]

    async def auth_objects_named(self, kind: str, name: str, prefix: bool = False) -> list[tuple[str, str]]:
        """(id, name) of the live objects with this name – or, with prefix, every name starting with it
        (UC-5: one passcode per device)."""
        return [(r["id"], r["name"]) for r in await self._list(f"{AUTH}/{AUTH_KINDS[kind]}")
                if (str(r.get("name", "")).startswith(name) if prefix else r.get("name") == name)
                and r.get("status") != "DELETED" and r.get("account_id") == self.config.account_id]

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

    # UC-7: the manufacturer's CA as trust anchor – every certificate it issued authenticates (verified live
    # on NL 2026-10-27). DTM names the entry after the CA's common name; records carry no account_id, the
    # list is scoped by the account parameter.
    async def create_auth_ca(self, auth_policy_id: str, pem: str) -> dict:
        data = _json(await self._request("POST", AUTH_CA, expect=(200, 201), json={
            "authentication_policy_id": auth_policy_id, "ca_body_pem": pem, "account_id": self.config.account_id}))
        _safe(data.get("id"))  # it goes into the delete path
        return {"id": data["id"], "name": str(data.get("name", ""))}

    async def auth_cas_named(self, name: str, prefix: bool = False) -> list[tuple[str, str]]:
        return [(r["id"], r["name"]) for r in await self._list(AUTH_CA)
                if (str(r.get("name", "")).startswith(name) if prefix else r.get("name") == name)
                and str(r.get("status", "")).upper() != "DELETED" and SAFE_ID.fullmatch(str(r.get("id", "")))
                and not self._foreign(r)]

    async def delete_auth_ca(self, ca_id: str) -> None:
        """No GET by ID exists – gone means: no longer listed."""
        _safe(ca_id)
        await self._request("PUT", f"{AUTH_CA.rsplit('/', 1)[0]}/account/{self.config.account_id}/authentication-ca/"
                                   f"{ca_id}/delete", json={}, expect=(200, 204, 404))
        if any(r.get("id") == ca_id and str(r.get("status", "")).upper() != "DELETED" for r in await self._list(AUTH_CA)):
            raise DTMError(f"authentication CA {ca_id} still exists after delete")

    async def _profiles(self) -> list[dict]:
        return [r for r in await self._list(PROFILES) if isinstance(r, dict)]

    def _ours(self, records: list[dict], name: str) -> dict | None:
        """Our record of that name in this account – ACTIVE before inactive, deleted ones ignored."""
        mine = [r for r in records if r.get("name") == name and r.get("account_id") == self.config.account_id
                and (r.get("status") == "ACTIVE" or r.get("status") in INACTIVE)]
        return next((r for r in mine if r.get("status") == "ACTIVE"), mine[0] if mine else None)

    async def shared_profile_status(self) -> dict[str, str]:
        """Read only: status of each shared profile in this account ("ACTIVE", "DISABLED" or "missing")."""
        records = await self._profiles()
        names = [spec.name for spec in SHARED_PROFILES]
        names += [n for n in LEGACY_PROFILES if (self._ours(records, n) or {}).get("status") == "ACTIVE"]  # shown only while active
        return {name: (lambda r: "missing" if not r else "ACTIVE" if r["status"] == "ACTIVE" else "DISABLED")(
            self._ours(records, name)) for name in names}

    async def retire_shared_profiles(self) -> dict[str, str]:
        """Disable the shared (and legacy) profiles of this account – DTM does not allow deleting used
        profiles; a later run that needs one enables it again. Returns the new status."""
        async with _profile_lock:
            records = await self._profiles()
            for name in [s.name for s in SHARED_PROFILES] + list(LEGACY_PROFILES):
                record = self._ours(records, name)
                if record and record["status"] == "ACTIVE":
                    await self._request("PUT", f"{PROFILES}/{record['id']}/disable", json={}, expect=(200, 204))
                    record["status"] = "DISABLED"
            return {spec.name: "DISABLED" if self._ours(records, spec.name) else "missing" for spec in SHARED_PROFILES}

    async def _base_profile(self, records: list[dict]) -> dict:
        """The account's profile to copy (preferably the basic client profile), with template and body."""
        bases = [r for r in records if r.get("status") == "ACTIVE" and r.get("id") and r.get("account_id")
                 in (None, self.config.account_id) and not str(r.get("name", "")).startswith("robot-")]
        if not bases:
            raise DTMError("the account has no active certificate profile to copy")
        base = next((r for r in bases if "client" in str(r.get("name", "")).lower()), bases[0])
        detail = _json(await self._request("GET", f"{PROFILES}/{base['id']}"))
        if not isinstance(detail.get("certificate_template"), dict) or not isinstance(detail.get("body"), list):
            raise DTMError(f"profile {base.get('name')} cannot be copied (no template or body)")
        return detail

    async def run_profile_body(self, spec: ProfileSpec) -> dict:
        """NL: the body of a profile for one run – a copy of the account's base profile."""
        return shared_profile_body(await self._base_profile(await self._profiles()), spec, self.config.account_id)

    async def create_run_profile(self, spec: ProfileSpec, body: dict) -> str:
        """NL: creates the run's own profile; one DTM did not take the settings of is deleted again."""
        data = _json(await self._request("POST", PROFILES, expect=(200, 201), json=body))
        if not _profile_matches(data, spec):
            message = (f"DTM did not accept the settings of {spec.name} ({spec.value} {spec.unit}) – the template "
                       "of the account's base profile may limit them")
            try:
                await self.delete_profile(data["id"])
            except DTMError as exc:  # the rollback finds it by name later – keep the useful message
                raise DTMError(f"{message}; deleting the profile failed: {exc}") from exc
            raise DTMError(f"{message}; the profile was deleted")
        return data["id"]

    async def delete_profile(self, profile_id: str) -> None:
        """Soft delete (status DELETED, the name stays reserved) – NL only, US refuses used profiles.
        Idempotent: an already deleted profile (retry after a partial cleanup, or deleted in the portal)
        answers 400/404 but is gone from the list – only a profile still listed is an error."""
        response = await self._request("PUT", f"{PROFILES}/{profile_id}/delete", json={}, expect=(200, 204, 400, 404))
        if profile_id in [r.get("id") for r in await self._profiles()]:
            reason = f": {_error_text(response)}" if response.status_code >= 400 else ""
            raise DTMError(f"profile {profile_id} still exists after delete{reason}")

    async def profile_ids(self, name: str) -> list[str]:
        return [r["id"] for r in await self._profiles() if r.get("name") == name
                and r.get("account_id") == self.config.account_id and r.get("status") != "DELETED"]

    async def shared_profile(self, spec: ProfileSpec) -> tuple[str, str]:
        """The account's profile for this purpose: found by name (restored if it was deleted, enabled again
        if it was retired), else copied once from a base profile of the account (preferably the basic
        client profile).
        Returns (id, "used" | "enabled" | "restored" | "created")."""
        async with _profile_lock:  # two runs at once must not both create it – it can never be deleted
            restored, clash = False, ""
            for attempt in (1, 2):
                records = await self._profiles()
                found = self._ours(records, spec.name)
                if found:
                    if not _profile_matches(found, spec):
                        raise DTMError(f"profile {spec.name} exists with other settings – fix or rename it in the "
                                       "DTM portal")
                    if found["status"] != "ACTIVE":
                        await self._request("PUT", f"{PROFILES}/{found['id']}/enable", json={}, expect=(200, 204))
                        return found["id"], "restored" if restored else "enabled"
                    return found["id"], "restored" if restored else "used"
                if attempt == 2:
                    if restored:  # the list may lag behind the undelete
                        raise DTMError(f"profile {spec.name} was restored but is not listed yet – start the run again")
                    break
                # Deleted in the portal: DTM keeps the name reserved (verified live), so a new profile of
                # that name is refused – restore it instead and look again.
                deleted = [r for r in await self._list(PROFILES, params={"status": "DELETED"})
                           if r.get("name") == spec.name and r.get("account_id") == self.config.account_id
                           and r.get("status") == "DELETED"]
                if deleted:
                    if not _profile_matches(deleted[0], spec):  # never bring back a profile we would not use
                        raise DTMError(f"profile {spec.name} was deleted with other settings – restore it in the DTM "
                                       "portal, then fix or rename it")
                    # 400/409: another installation restored it meanwhile – the next look finds it
                    await self._request("PUT", f"{PROFILES}/{deleted[0]['id']}/undelete", json={},
                                        expect=(200, 204, 400, 409))
                    restored = True
                    continue
                detail = await self._base_profile(records)
                response = await self._request("POST", PROFILES, expect=(200, 201, 400, 409),
                                               json=shared_profile_body(detail, spec, self.config.account_id))
                if response.status_code in (400, 409):
                    clash = _error_text(response)
                    continue  # another installation may have created it meanwhile – look once more
                data = _json(response)
                if not _profile_matches(data, spec):
                    # e.g. the base profile's template caps the validity – never leave a wrong profile active
                    await self._request("PUT", f"{PROFILES}/{data['id']}/disable", json={}, expect=(200, 204))
                    raise DTMError(f"DTM did not accept the settings of {spec.name} ({spec.value} {spec.unit}) – the "
                                   f"template of {detail.get('name')} may limit them; the profile was disabled")
                return data["id"], "created"
        raise DTMError(f"could not create profile {spec.name}: {clash}")

    # devices (UC-6, Advanced license) – verified live on NL 2026-10-26
    async def create_device_policy(self, body: dict | None = None, **kwargs) -> str:
        body = body or device_policy_body(**kwargs)
        data = _json(await self._request("POST", POLICIES, expect=(200, 201), json=body))
        policy_id = (data.get("certificate_policy") or {}).get("id")
        _safe(policy_id)  # it goes into URL paths next
        return policy_id

    async def create_device_group(self, name: str, division_id: str, policy_id: str, attribute: str,
                                  also: tuple[str, ...] = (), body: dict | None = None) -> str:
        """DTM answers without the ID – it is looked up by the name right after (lists lag a moment)."""
        await self._request("POST", DEVICE_GROUPS, expect=(200, 201), json=body or device_group_body(
            name, division_id, self.config.account_id, policy_id, attribute, also))
        for attempt in range(LOOKUP_RETRIES):
            found = await self.device_group_ids(name)
            if len(found) == 1:
                return found[0]
            await asyncio.sleep(1 + attempt)
        raise DTMError(f"device group {name} was created but not found by its name")

    async def device_group_ids(self, name: str) -> list[str]:
        records = await self._list(DEVICE_GROUPS, params={"name": name})
        return [r["id"] for r in records if r.get("name") == name and r.get("account_id") == self.config.account_id
                and str(r.get("status", "")).upper() != "DELETED"]

    async def device_ids(self, group_id: str, prefix: str) -> list[tuple[str, str]]:
        """(id, name) of this account's devices in the group that carry the run's name prefix or the name
        DTM gives a device it creates itself on an unknown EST identity. A record that names its groups
        must be a member; a device someone else put into the group is never returned."""
        records = await self._list(DEVICES, params={"device_group_id": group_id})
        found = []
        for r in records:
            member = _in_group(r, group_id)
            if (r.get("account_id") == self.config.account_id and SAFE_ID.fullmatch(str(r.get("id", "")))
                    and str(r.get("status", "")).upper() != "DELETED"
                    and member is not False and run_device(str(r.get("name", "")), prefix)):
                found.append((r["id"], r["name"]))
        return found

    async def enroll_device(self, name: str, group_id: str, description: str, attribute: str, value: str) -> str:
        """Creates the device with its inventory attribute (the identity DTM maps the certificate by)."""
        data = _json(await self._request("POST", f"{DEVICES}/enroll", expect=(200, 201), json=device_body(
            name, self.config.account_id, group_id, description, attribute, value)))
        return data["device_id"]

    async def issue_device_certificate(self, policy_id: str, group_id: str, device_id: str, common_name: str,
                                       csr: str) -> dict:
        return _json(await self._request("POST", CERTIFICATES, json=device_certificate_body(
            policy_id, group_id, device_id, common_name, csr)))

    async def renew_certificate(self, certificate_id: str, csr: str) -> dict:
        """REST renewal with the API key and a new CSR – the new certificate stays under the device."""
        _safe(certificate_id)
        return _json(await self._request("PUT", f"{CERTIFICATES}/{certificate_id}/renew", json={"csr": csr}))

    async def device_certificates(self, device_id: str, quiet: bool = False) -> list[dict]:
        data = _json(await self._request("GET", f"{DEVICES}/certificates", quiet=quiet,
                                         params={"device_id": device_id, "sort_key": "createdOn", "limit": 100}))
        return data.get("records") or []

    async def _own(self, path: str, what: str) -> dict | None:
        """The object if it is this account's and not deleted yet; None when gone. The device endpoints
        ignore account_id, so the account is checked on the object itself before anything changes."""
        _safe(path.rsplit("/", 1)[-1])
        response = await self._request("GET", path, expect=(200, 404))
        if response.status_code == 404:
            return None
        data = _json(response)
        if data.get("account_id") != self.config.account_id:
            raise DTMError(f"refusing to touch {what}: it belongs to another account")
        return None if str(data.get("status", "")).upper() == "DELETED" else data

    async def _disable_and_delete(self, path: str, what: str) -> None:
        """Devices and groups: DTM deletes only disabled ones (a soft delete, listed 14 more days)."""
        if await self._own(path, what) is None:
            return
        await self._request("PATCH", f"{path}/disable", expect=(200, 204, 400),
                            json={"reason": "dc-dtm-demonstrator cleanup"})  # 400: already disabled
        await self._request("PATCH", f"{path}/delete", expect=(200, 204), json={})
        if await self._own(path, what) is not None:
            raise DTMError(f"{what} still exists after the delete")

    async def delete_device(self, device_id: str) -> None:
        """Deleting a device does not revoke its certificates (verified live) – revoke them first."""
        await self._disable_and_delete(f"{DEVICES}/{device_id}", f"device {device_id}")

    async def delete_device_group(self, group_id: str) -> None:
        await self._disable_and_delete(f"{DEVICE_GROUPS}/{group_id}", f"device group {group_id}")

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

    async def batch_jobs_of(self, policy_ids: set[str]) -> list[dict]:
        """Batch jobs of this account under these policies – also those started in the DTM portal.
        The list ignores a policy filter (verified live), so it is filtered here."""
        records = await self._list("/devicetrustmanager/certificate-batch-service/api/v1/jobs")
        return [r for r in records if r.get("certificate_policy_id") in policy_ids
                and r.get("account_id") == self.config.account_id]

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

    async def certificates_named(self, common_name: str) -> list[dict]:
        """This account's certificates with exactly this common name, under any policy (DTM filters exactly)."""
        records = await self._list("/devicetrustmanager/certificate-issuance-service/api/v2/certificate",
                                   params={"common_name": common_name})
        return [r for r in records if r.get("common_name") == common_name
                and r.get("account_id") == self.config.account_id]

    async def certificate_pem(self, serial: str) -> str:
        """One certificate of this account as PEM text, by its serial number (the detail view of a certificate the
        app never received itself). The caller checks that the answer is that certificate."""
        if not re.fullmatch(r"[0-9A-Fa-f]{1,64}", serial):
            raise DTMError(f"unexpected serial number {serial[:40]!r}")
        response = await self._request("GET", f"{CERTIFICATES}/serial-number/{serial}/download/pem")
        if not response.text.lstrip().startswith("{"):
            return response.text
        data = _json(response)  # the PEM wrapped in JSON
        return next((v for k in ("pem", "certificate") if isinstance(v := data.get(k), str)), "")

    async def count_certificates(self, policy_id: str, status: str) -> int:
        data = _json(await self._request(
            "GET", "/devicetrustmanager/certificate-issuance-service/api/v2/certificate", quiet=True,
            params={"certificate_policy_id": policy_id, "status": status, "limit": 1}))
        return int(data.get("total", 0))

    # over-the-air updates: payload → artifact → release → deployment to a device group. DTM deletes none of
    # them – artifacts and releases can be disabled and enabled again, an aborted deployment stays as it is.

    async def upload_payload(self, filename: str, data: bytes) -> str:
        """tus upload in one chunk; the finishing POST makes DTM unpack and check the zip."""
        meta = ",".join(f"{k} {base64.b64encode(v.encode()).decode()}" for k, v in (
            ("name", filename), ("type", "application/zip"), ("filetype", "application/zip"), ("filename", filename)))
        created = await self._request("POST", UPLOADS, expect=(201,), headers=TUS | {
            "Upload-Length": str(len(data)), "Upload-Metadata": meta})
        upload_id = created.headers.get("location", "").rstrip("/").rsplit("/", 1)[-1]
        _safe(upload_id)
        await self._request("PATCH", f"{UPLOADS}/{upload_id}", expect=(204,), content=data, headers=TUS | {
            "Upload-Offset": "0", "Content-Type": "application/offset+octet-stream"})
        done = _json(await self._request("POST", f"{UPLOADS}/{upload_id}", json={}))
        if not done.get("completed"):
            raise DTMError(f"payload {filename} was not accepted")
        return upload_id

    async def named_prefix(self, path: str, prefix: str) -> list[dict]:
        """Artifacts or releases (path) whose name starts with prefix – also disabled ones."""
        return [r for r in await self._list(path, {"optional_division_filter": "true"})
                if str(r.get("name", "")).startswith(prefix) and SAFE_ID.fullmatch(str(r.get("id")))
                and not self._foreign(r)]

    async def create_artifact(self, body: dict) -> str:
        data = _json(await self._request("POST", ARTIFACTS, json=body))
        _safe(data.get("id"))
        return data["id"]

    async def create_release(self, body: dict) -> str:
        data = _json(await self._request("POST", RELEASES, json=body))
        _safe(data.get("id"))
        return data["id"]

    async def enable(self, path: str, object_id: str, enabled: bool = True) -> None:
        """Enables or disables an artifact or release (path: ARTIFACTS or RELEASES) – reversible, unlike a delete."""
        _safe(object_id)
        await self._request("PATCH", f"{path}/{object_id}/{'enable' if enabled else 'disable'}", json={})

    async def create_deployment(self, body: dict) -> str:
        data = _json(await self._request("POST", DEPLOYMENTS, json=body))
        _safe(data.get("id"))
        return data["id"]

    async def deployments_named(self, prefix: str) -> list[tuple[str, str]]:
        return [(r["id"], r["name"]) for r in await self._list(DEPLOYMENTS)
                if str(r.get("name", "")).startswith(prefix) and SAFE_ID.fullmatch(str(r.get("id")))
                and not self._foreign(r)]

    def _foreign(self, record: dict) -> bool:
        """A record of another account – some list services leave the account out, a different one is never ours."""
        nested = record.get("account")
        account = record.get("account_id") or (nested.get("id") if isinstance(nested, dict) else None)
        return bool(account) and account != self.config.account_id

    async def abort_deployment(self, deployment_id: str) -> None:
        """Ends the deployment for good – an aborted (or otherwise finished) one is left as it is."""
        _safe(deployment_id)
        try:
            await self._request("PATCH", f"{DEPLOYMENTS}/{deployment_id}/abort", json={})
        except DTMError as exc:
            if exc.status in (401, 403):
                raise
            status = _json(await self._request("GET", f"{DEPLOYMENTS}/{deployment_id}", expect=(200, 404)))
            if status.get("status") not in (None, "ABORTED", "COMPLETED", "FINISHED"):
                raise

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


def _safe(dtm_id: str) -> None:
    if not SAFE_ID.fullmatch(str(dtm_id)):
        raise DTMError(f"unexpected ID {str(dtm_id)[:40]!r}")


AUTO_DEVICE = re.compile(r"Device-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def run_device(name: str, prefix: str) -> bool:
    """A device of the run: named by it, or created by DTM in the run's group on an unknown identity."""
    return name.startswith(prefix) or bool(AUTO_DEVICE.fullmatch(name))


def _in_group(record: dict, group_id: str) -> bool | None:
    """Whether a device list record belongs to the group (checked here, in case DTM ignores the filter);
    None when the record does not say."""
    groups = record.get("device_groups")
    if isinstance(groups, list):
        return any(isinstance(g, dict) and g.get("id") == group_id for g in groups)
    if "device_group_id" in record:
        return record["device_group_id"] == group_id
    return None


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
