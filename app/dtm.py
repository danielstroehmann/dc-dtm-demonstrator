"""DTM REST client.

Every call is scoped to one configured account (`account_id`); the API key may see several.
Request paths and payloads follow what was verified against a live account – the public
OpenAPI spec deviates in several places (see docs/design/uc-01-evergreen.md).
"""

import json
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

# A revoke normally returns within 1–3 s; under load single requests hang for minutes and
# often still complete server-side. Short timeouts plus re-listing beat long waits (R-4).
REVOKE_TIMEOUT = 8.0
DEFAULT_TIMEOUT = 60.0


class DTMError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class DTMConfig:
    host: str
    api_key: str
    account_id: str


def _json(response: httpx.Response):
    # DTM responses may contain raw control characters (e.g. PEM line breaks) inside strings.
    return json.loads(response.text, strict=False) if response.text else None


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
                       params: dict | None = None, **kwargs) -> httpx.Response:
        params = {**(params or {}), "account_id": self.config.account_id}
        start = time.monotonic()
        try:
            response = await self._http.request(method, path, params=params, **kwargs)
        except httpx.TimeoutException as exc:
            self._on_call(f"{method} {path} → timeout")
            raise DTMError(f"{method} {path} timed out") from exc
        except httpx.HTTPError as exc:
            self._on_call(f"{method} {path} → {type(exc).__name__}")
            raise DTMError(f"{method} {path} failed: {type(exc).__name__}") from exc
        self._on_call(f"{method} {path} → {response.status_code} ({time.monotonic() - start:.1f}s)")
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
        return [{"id": p["id"], "name": p["name"]} for p in items if p.get("status") == "ACTIVE"]

    async def rendezvous_zone(self) -> str:
        zones = await self._list("/devicetrustmanager/api/v4/rendezvous-zone")
        enabled = sorted((z for z in zones if z.get("status") == "ENABLED"), key=lambda z: z["name"])
        if not enabled:
            raise DTMError("no enabled rendezvous zone available for division creation")
        return enabled[0]["id"]

    async def _find_id(self, path: str, name: str) -> str:
        matches = [r["id"] for r in await self._list(path) if r.get("name") == name]
        if len(matches) != 1:
            raise DTMError(f"expected exactly one object named {name!r}, found {len(matches)}")
        return matches[0]

    # divisions – create returns no ID, so it is looked up by its unique name
    async def create_division(self, name: str, description: str) -> str:
        await self._request("POST", "/devicetrustmanager/api/v4/division", json={
            "name": name, "description": description, "account_id": self.config.account_id,
            "primary_rzone_id": await self.rendezvous_zone(),
        })
        return await self._find_id("/devicetrustmanager/api/v4/division", name)

    async def delete_division(self, division_id: str) -> None:
        await self._request("DELETE", f"/devicetrustmanager/api/v4/division/{division_id}", expect=(200, 404))

    # certificate policies
    async def create_policy(self, *, name: str, division_id: str, profile_id: str, ica_id: str,
                            key_type: str, require_approval: bool) -> str:
        common = {"key_generation_option": "server_side", "key_type": key_type.lower(),
                  "private_key_format": "pem", "encryption_certificate_source": "provided",
                  "include_chain_option": "include_ica_and_root"}
        await self._request("POST", "/devicetrustmanager/certificate-configuration-service/api/v2/certificate-policy",
                            expect=(200, 201), json={"certificate_policy": {
            "name": name, "division_id": division_id, "certificate_profile_id": profile_id, "ica_id": ica_id,
            "certificate_management_methods": ["SINGLE", "BATCH"],
            "key_generation_option": "server_side", "key_generation_type": key_type,
            "require_device_group_for_enroll": False,
            "require_approval_for_enroll": require_approval, "require_approval_for_renew": False,
            "single_cert_request_parameters": {**common, "response_with_certificate_only": False,
                                               "split_certificate_response": True},
            "batch_request_parameters": {**common, "certificate_format": "pem", "ecdsa_private_key_syntax": "pkcs8",
                                         "rsa_private_key_syntax": "pkcs8", "input_type": "csv",
                                         "output_format": "zip", "report_format": "csv"},
        }})
        return await self._find_id(
            "/devicetrustmanager/certificate-configuration-service/api/v2/certificate-policy", name)

    async def delete_policy(self, policy_id: str) -> None:
        # Undocumented UI-internal endpoint – the only known way to delete a policy (risk R-1).
        await self._request("DELETE",
                            f"/devicetrustmanager/certificate-configuration-service/api-ui/v1/certificate-policy/{policy_id}",
                            json={}, expect=(200, 204, 404))

    # issuance
    async def issue_single(self, policy_id: str, common_name: str) -> dict:
        response = await self._request(
            "POST", "/devicetrustmanager/certificate-issuance-service/api/v2/certificate", json={
                "certificate_policy_id": policy_id,
                "certificate_profile_attributes": [{"id": "subject.common_name", "value": common_name}],
                "server_side_key_gen": True, "private_key_format": "pem", "private_key_syntax": "pkcs8",
                "split_certificate_response": True, "include_certificate_chain": True,
            })
        return _json(response)

    async def submit_batch(self, *, name: str, policy_id: str, key_type: str, csv_zip: bytes,
                           encryption_cert_pem: str) -> dict:
        fields = {"name": name, "certificate_policy_id": policy_id, "certificate_format": "pem",
                  "input_format": "csv", "output_format": "zip", "server_side_key_gen": "true",
                  "key_type": key_type, "private_key_format": "pem", "private_key_syntax": "pkcs8",
                  "emails": "",
                  # The spec calls this field `certificate`; DTM only accepts `encryption_certificate`.
                  "encryption_certificate": encryption_cert_pem}
        response = await self._request("POST", "/devicetrustmanager/certificate-batch-service/api/v1/jobs/certificate-enroll",
                                       expect=(200, 201), data=fields,
                                       files={"data": ("batch.zip", csv_zip, "application/zip")})
        return _json(response)

    async def batch_job(self, job_id: str) -> dict:
        return _json(await self._request("GET", f"/devicetrustmanager/certificate-batch-service/api/v1/jobs/{job_id}"))

    async def approve_batch(self, job_id: str) -> None:
        await self._request("PUT", f"/devicetrustmanager/certificate-batch-service/api/v1/jobs/{job_id}/approve",
                            json={}, expect=(200, 204))

    async def batch_result(self, job_id: str) -> bytes:
        response = await self._request(
            "GET", f"/devicetrustmanager/certificate-batch-service/api/v1/jobs/{job_id}/download/result")
        return response.content

    # certificates
    async def issued_certificates(self, policy_id: str) -> list[dict]:
        return await self._list("/devicetrustmanager/certificate-issuance-service/api/v2/certificate",
                                params={"certificate_policy_id": policy_id, "status": "issued"})

    async def revoke(self, certificate_id: str) -> str:
        """Returns 'revoked', 'already' or 'timeout'. Timeouts are expected under load (R-4)."""
        try:
            await self._request(
                "PUT", f"/devicetrustmanager/certificate-issuance-service/api/v2/certificate/{certificate_id}/revoke",
                json={"reason": "cessation_of_operation", "comments": "dc-dtm-demonstrator cleanup"},
                expect=(200, 204), timeout=REVOKE_TIMEOUT)
            return "revoked"
        except DTMError as exc:
            if exc.status == 400:  # already revoked; the issued list lags behind
                return "already"
            if exc.status is None:
                return "timeout"
            raise


def _error_text(response: httpx.Response) -> str:
    try:
        data = _json(response)
    except ValueError:
        return response.text[:200] if not response.text.lstrip().startswith("<") else "(HTML error page)"
    if isinstance(data, dict):
        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            return "; ".join(str(e.get("message", e)) for e in errors)[:300]
        if "error" in data:
            return str(data["error"])[:300]
    return str(data)[:300]
