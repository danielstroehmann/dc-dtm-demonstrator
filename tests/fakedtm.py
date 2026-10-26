"""Stateful fake of the DTM REST API, built on respx routes.

It models only what the demonstrator uses, with the behaviour verified against the live
account (see docs/design/uc-01-evergreen.md): division create without ID in the response,
policy delete only via the `api-ui` path, batch result as a CMS envelope, upper-case
certificate status, `400` on re-revoke, eventual consistency of the issued list.

Every request is checked for the `x-api-key` header and the configured `account_id`;
any violation or unknown endpoint (e.g. the forbidden blueprint service) is recorded in
`violations` so tests can assert none happened.
"""

import asyncio
import base64
import email
import io
import json
import re
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from app.dtm import DTMClient, DTMConfig

_real_sleep = asyncio.sleep  # captured before tests patch asyncio.sleep

DEVICE_ATTRIBUTES = ("serial_number", "mac_address", "device_name")  # GET /device-group/attributes (excerpt)
HOST = "one.digicert.com"  # a supported platform (dtm.PLATFORMS) – shared profiles; never contacted
BASE = f"https://{HOST}"
ACCOUNT_ID = "0a1b2c3d-0000-4000-8000-00000000a001"
OTHER_ACCOUNT_ID = "0a1b2c3d-0000-4000-8000-00000000b002"
API_KEY = "fake-api-key-for-tests-only"
DTM = "/devicetrustmanager"
CERT_PATH = f"{DTM}/certificate-issuance-service/api/v2/certificate"
POLICY_PATH = f"{DTM}/certificate-configuration-service/api/v2/certificate-policy"
POLICY_DELETE_PATH = f"{DTM}/certificate-configuration-service/api-ui/v1/certificate-policy"
DIVISION_PATH = f"{DTM}/api/v4/division"
JOBS_PATH = f"{DTM}/certificate-batch-service/api/v1/jobs"
PROFILE_PATH = f"{DTM}/certificate-configuration-service/api/v1/certificate-profile"
AUTH_PATH = f"{DTM}/authentication-service/api/v1"
DEVICE_PATH = f"{DTM}/api/v4/device"
DEVICE_GROUP_PATH = f"{DTM}/api/v4/device-group"
AUTH_COLLECTIONS = {"auth_policy": "authentication-policy", "passcode": "passcode",
                    "auth_certificate": "authentication-certificate"}
CLIENTAUTH_HOST = f"clientauth.{HOST}"
NL_HOST = "one.nl.digicert.com"  # the other supported platform – one profile per run (dtm.PLATFORMS)
EST_PATH_RE = r"/\.well-known/est/devicetrustmanager/(?P<oid>[^/]+)/simpleenroll"
REENROLL_PATH_RE = r"/\.well-known/est/devicetrustmanager/(?P<oid>[^/]+)/simplereenroll"
# UC-6: the device-group variants – only these file the certificate under the device (verified live)
EST_GROUP_RE = r"/\.well-known/est/devicetrustmanager/(?P<oid>[^/]+)/device-group/(?P<gid>[^/]+)/simpleenroll"
REENROLL_GROUP_RE = r"/\.well-known/est/devicetrustmanager/(?P<oid>[^/]+)/device-group/(?P<gid>[^/]+)/simplereenroll"
CMP_PATH_PREFIX = f"{DTM}/certificate-issuance-service/api/v1/cmp/DIOT_"

ECDSA_CA_ID = "ca-ecdsa-ica"
RSA_CA_ID = "ca-rsa-ica"
PROFILE_ID = "profile-client"


# --- PKI helpers ---------------------------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn: str, *, key=None, issuer_cert=None, issuer_key=None, ca: bool = False,
              days: int = 365):
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(_name(cn))
               .issuer_name(issuer_cert.subject if issuer_cert else _name(cn))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def cert_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def cms_envelope(data: bytes, recipient_cert_pem: bytes) -> bytes:
    recipient = x509.load_pem_x509_certificate(recipient_cert_pem)
    return (pkcs7.PKCS7EnvelopeBuilder().set_data(data).add_recipient(recipient)
            .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))


def result_zip(entries: list[tuple[str, str, str]], chain_pems: list[str]) -> bytes:
    """entries: (line file stem, certificate PEM, key PEM) – DTM's batch result layout."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        lines = []
        for stem, pem, key in entries:
            archive.writestr(f"{stem}.pem", pem + "".join(chain_pems))
            archive.writestr(f"{stem}-key.key", key)
            lines.append(f"{stem},OK")
        archive.writestr("full_results.txt", "\n".join(lines))
    return buffer.getvalue()


def _multipart(request: httpx.Request) -> tuple[dict, dict]:
    raw = b"Content-Type: " + request.headers["content-type"].encode() + b"\r\n\r\n" + request.content
    message = email.message_from_bytes(raw)
    fields, files = {}, {}
    for part in message.get_payload():
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True)
        if part.get_filename():
            files[name] = (part.get_filename(), payload)
        else:
            fields[name] = payload.decode()
    return fields, files


def _json_response(status: int, data, raw_control_chars: bool = False) -> httpx.Response:
    text = json.dumps(data)
    if raw_control_chars:
        # DTM puts raw line breaks into JSON strings (PEM); the client must parse leniently.
        text = text.replace("\\n", "\n")
    return httpx.Response(status, text=text, headers={"content-type": "application/json"})


def _error(status: int, message: str) -> httpx.Response:
    return _json_response(status, {"errors": [{"code": "error", "message": message}]})


def _profile(profile_id: str, name: str, template: str, renew_valid_cert: str | None,
             account_id: str = ACCOUNT_ID) -> dict:
    body = [{"key": "subject.common_name", "optional": False, "enabled": True, "sources": ["user_supplied"],
             "value": None},
            {"key": "csr", "optional": False, "enabled": True, "sources": ["user_supplied"], "value": None},
            {"key": "validity.duration_unit", "optional": False, "enabled": True, "sources": ["fixed_value"],
             "value": "years"},
            {"key": "validity.duration_value", "optional": False, "enabled": True, "sources": ["fixed_value"],
             "value": 1}]
    if renew_valid_cert is not None:
        body.append({"key": "renewal_settings.renew_valid_cert", "optional": False, "enabled": True,
                     "sources": ["default"], "value": renew_valid_cert})
    return {"id": profile_id, "name": name, "status": "ACTIVE", "certificate_template": {"id": template},
            "body": body, "account_id": account_id}


def renews_anytime(profile: dict) -> bool:
    """The fake's own reading of the profile (independent of app/dtm.py)."""
    for entry in profile.get("body") or []:
        if entry.get("key") == "renewal_settings.renew_valid_cert":
            return entry.get("enabled") is not False and entry.get("value") == "anytime"
    return False


# --- the fake ----------------------------------------------------------------------------

class FakeDTM:
    def __init__(self, *, account_id: str = ACCOUNT_ID, api_key: str = API_KEY,
                 ica_cn: str = "Fake ECDSA Issuing CA", ca_name: str = "Fake ECDSA ICA",
                 profile_name: str = "Basic client certificate profile", host: str = HOST):
        self.account_id = account_id
        self.api_key = api_key
        # host: US (shared profiles) or NL (per-run profiles) – they differ in deleting profiles
        self.host, self.clientauth_host = host, f"clientauth.{host}"
        self.router = respx.Router(base_url=f"https://{host}", assert_all_called=False, assert_all_mocked=True)
        # Profiles a policy ever referenced: US refuses to delete them even after the policy is gone.
        self.profiles_referenced: set[str] = set()
        # UC-5 one-time passcodes (verified live): usage limit and registered common name are enforced
        # on enrollment; a rejected request counts as a use. False = a DTM that wrongly accepts.
        self.passcode_rules = True
        self.passcode_listeners: list = []  # called on every passcode create (the fake openssl cmp)
        self.external_passcode_usage = None  # Path: uses counted by the fake openssl cmp, per alternate_id
        self.requests: list[httpx.Request] = []
        self.calls: list[tuple[str, str]] = []  # (route name, object id or "")
        self.violations: list[str] = []
        self.fail: dict[str, object] = {}  # route name -> Response | Exception | callable(request)

        self.root_cert, self.root_key = make_cert("Fake Root CA", ca=True, days=3650)
        self.ica_cert, self.ica_key = make_cert(ica_cn, issuer_cert=self.root_cert, issuer_key=self.root_key,
                                                ca=True, days=1825)
        self.cas = [
            self._ca(ECDSA_CA_ID, ca_name, "ecdsa"),
            self._ca(RSA_CA_ID, "Fake RSA ICA", "rsa"),
            self._ca("ca-root", "Fake Root", "ecdsa", cert_type="root"),
            self._ca("ca-disabled", "Disabled ICA", "ecdsa", status="disabled"),
            self._ca("ca-other-account", "Other account ICA", "ecdsa", account=OTHER_ACCOUNT_ID),
        ]
        # Profile list records carry the profile body (verified live). renewal_settings.renew_valid_cert:
        # "anytime" (live), "dont_allow" or a window before expiry (docs); the legacy one has no entry.
        # The list spans every account the API key sees – the client must filter by account_id.
        self.profiles = [
            _profile(PROFILE_ID, profile_name, "tpl-client", "anytime", account_id),
            _profile("profile-server", "Basic server certificate profile", "tpl-server", "dont_allow", account_id),
            _profile("profile-window", "Renew within 30 days profile", "tpl-client", "30", account_id),
            _profile("profile-legacy", "Legacy device profile", "tpl-client", None, account_id),
            {"id": "profile-old", "name": "Old profile", "status": "INACTIVE", "account_id": account_id},
            _profile("profile-foreign", "Other account client profile", "tpl-foreign", "anytime", OTHER_ACCOUNT_ID),
        ]
        self.template_validity_cap: dict[str, tuple[str, int]] = {}  # template id → what DTM applies instead
        self.zones = [
            {"id": "rz-b", "name": "b-zone", "status": "ENABLED"},
            {"id": "rz-a", "name": "a-zone", "status": "ENABLED"},
            {"id": "rz-0", "name": "0-zone", "status": "DISABLED"},
        ]
        self.accounts = [{"id": account_id, "name": "Test account"}, {"id": OTHER_ACCOUNT_ID, "name": "Other"}]
        self.divisions: dict[str, dict] = {}
        self.policies: dict[str, dict] = {}
        self.certificates: dict[str, dict] = {}
        self.jobs: dict[str, dict] = {}

        # behaviour knobs
        self.approval_status = "pending_approval"
        self.job_steps = ["in_progress", "completed"]  # statuses reported by successive GETs
        self.division_list_lag = 0      # division lists that do not yet show a new division
        self.issued_list_hidden: set[str] = set()  # cert ids missing from the next issued listing
        self.issued_list_stale: set[str] = set()   # revoked cert ids still listed once more
        self.revoke_plan: dict[str, list[str]] = {}  # cert id -> actions for successive revokes
        self.revoke_delay = 0.0
        self.revoke_in_flight = 0
        self.revoke_max_in_flight = 0
        self.single_overrides: dict = {}
        self.single_cn_override: str | None = None
        self.issue_delay = 0.0
        self.approve_delay = 0.0
        self.job_delay = 0.0
        self.division_delete_status = 200
        self.job_success_items: list[int] = []
        self.csr_job_steps = ["pending", "completed"]  # verified live: CSR jobs start as "pending"
        self.received_csrs: list[str] = []  # success_items reported while in_progress, per poll
        self.revoked_count_lag = 0  # revoked listings that still report nothing (eventual consistency)
        # UC-3: authentication service (soft delete → status DELETED) and enrollment endpoints
        self.auth_objects: dict[str, dict[str, dict]] = {kind: {} for kind in AUTH_COLLECTIONS}
        self.created_profiles: list[dict] = []  # profile create bodies (the shared CMPv2 profile)
        self.enroll_router = respx.Router(assert_all_called=False, assert_all_mocked=True)
        self.enroll_requests: list[httpx.Request] = []
        self.enroll_calls: list[tuple[str, str]] = []  # (protocol route, host)
        self.enroll_fail: httpx.Response | Exception | None = None
        self.tls_client_cert: str | None = None  # PEM the station loaded for mTLS (see enroll_net)
        # The management call on the same path (UC-1 single issuance) answers with raw line breaks
        # inside JSON strings. Off by default so the UC-3 suites test the rest of the flow;
        # test_rest_enrollment_tolerates_raw_line_breaks covers it explicitly.
        self.rest_raw_control_chars = False
        # UC-4: DTM answers 401 est_unauthorized for a just-issued certificate (verified live) –
        # the next N simplereenroll calls are refused that way.
        self.reenroll_unauthorized = 0
        self.reenroll_presented: list[str] = []  # serials of the client certificates presented
        self.reenroll_delay = 0.0  # real seconds per simplereenroll (to overlap requests in tests)
        # UC-6 managed devices (verified live on NL 2026-10-26, docs/design/uc-06-managed-devices.md).
        # The device endpoints ignore account_id: lists and GETs span every account the key sees,
        # the objects carry their account_id.
        self.device_groups: dict[str, dict] = {}
        self.devices: dict[str, dict] = {}
        self.device_group_list_lag = 0   # group lists that do not yet show a new group
        self.device_cert_list_lag = 0    # /device/certificates answers with total but no records yet
        self.device_answer_override: dict | None = None  # replaces "device" in a device certificate answer
        self.renew_delay = 0.0  # real seconds per PUT …/renew (to overlap requests in tests)
        self.device_list_ignores_group = False  # the device list returns devices of every group
        self.policy_create_echo = True  # verified live: the answer carries certificate_policy.id
        self.before_device_list: list = []  # called before /device/certificates (fake openssl cmp sync)
        self._register()
        self._register_enrollment()

    def _ca(self, ca_id, name, key_type, *, cert_type="intermediate", status="active", account=None):
        return {"id": ca_id, "name": name, "key_type": key_type, "cert_type": cert_type, "status": status,
                "account_assignments": [{"id": account or self.account_id}]}

    # client wiring
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.router.async_handler)

    def config(self) -> DTMConfig:
        return DTMConfig(self.host, self.api_key, self.account_id)

    def client(self, on_call=None) -> DTMClient:
        return DTMClient(self.config(), on_call, transport=self.transport())

    def factory(self):
        return lambda config, on_call: DTMClient(config, on_call, transport=self.transport())

    def names(self, route: str) -> list[str]:
        return [obj for name, obj in self.calls if name == route]

    def route_order(self) -> list[str]:
        return [name for name, _ in self.calls]

    # routing
    def _register(self) -> None:
        r = self.router
        routes = [
            ("account", "GET", r"/account/api/v1/account", self._accounts),
            ("cas", "GET", r"/certificate-authority/api/v1/ca", self._list_cas),
            ("profiles", "GET", rf"{DTM}/certificate-configuration-service/api/v1/certificate-profile",
             self._list_profiles),
            ("zones", "GET", rf"{DTM}/api/v4/rendezvous-zone", self._list_zones),
            ("division_create", "POST", rf"{DIVISION_PATH}", self._create_division),
            ("division_list", "GET", rf"{DIVISION_PATH}", self._list_divisions),
            ("division_delete", "DELETE", rf"{DIVISION_PATH}/(?P<oid>[^/]+)", self._delete_division),
            ("policy_create", "POST", rf"{POLICY_PATH}", self._create_policy),
            ("policy_get", "GET", rf"{POLICY_PATH}/(?P<oid>[^/]+)", self._get_policy),
            ("profile_get", "GET", rf"{PROFILE_PATH}/(?P<oid>[^/]+)", self._get_profile),
            ("profile_create", "POST", rf"{PROFILE_PATH}", self._create_profile),
            ("profile_enable", "PUT", rf"{PROFILE_PATH}/(?P<oid>[^/]+)/enable", self._set_profile_status("ACTIVE")),
            ("profile_disable", "PUT", rf"{PROFILE_PATH}/(?P<oid>[^/]+)/disable",
             self._set_profile_status("DISABLED")),
            ("profile_undelete", "PUT", rf"{PROFILE_PATH}/(?P<oid>[^/]+)/undelete", self._undelete_profile),
            ("profile_delete", "PUT", rf"{PROFILE_PATH}/(?P<oid>[^/]+)/delete", self._delete_profile),
            ("policy_list", "GET", rf"{POLICY_PATH}", self._list_policies),
            ("policy_delete", "DELETE", rf"{POLICY_DELETE_PATH}/(?P<oid>[^/]+)", self._delete_policy),
            ("issue", "POST", rf"{CERT_PATH}", self._issue),
            ("renew", "PUT", rf"{CERT_PATH}/(?P<oid>[^/]+)/renew", self._renew),
            ("device_group_create", "POST", rf"{DEVICE_GROUP_PATH}", self._create_device_group),
            ("device_group_list", "GET", rf"{DEVICE_GROUP_PATH}", self._list_device_groups),
            ("device_group_disable", "PATCH", rf"{DEVICE_GROUP_PATH}/(?P<oid>[^/]+)/disable",
             self._disable("device_groups")),
            ("device_group_delete", "PATCH", rf"{DEVICE_GROUP_PATH}/(?P<oid>[^/]+)/delete",
             self._soft_delete("device_groups", 24)),
            ("device_group_get", "GET", rf"{DEVICE_GROUP_PATH}/(?P<oid>[^/]+)", self._get_object("device_groups")),
            ("device_enroll", "POST", rf"{DEVICE_PATH}/enroll", self._enroll_device),
            ("device_certificates", "GET", rf"{DEVICE_PATH}/certificates", self._device_certificates),
            ("device_list", "GET", rf"{DEVICE_PATH}", self._list_devices),
            ("device_disable", "PATCH", rf"{DEVICE_PATH}/(?P<oid>[^/]+)/disable", self._disable("devices")),
            ("device_delete", "PATCH", rf"{DEVICE_PATH}/(?P<oid>[^/]+)/delete", self._soft_delete("devices", 23)),
            ("device_get", "GET", rf"{DEVICE_PATH}/(?P<oid>[^/]+)", self._get_object("devices")),
            ("cert_list", "GET", rf"{CERT_PATH}", self._list_certs),
            ("revoke", "PUT", rf"{CERT_PATH}/(?P<oid>[^/]+)/revoke", self._revoke),
            ("batch_create", "POST", rf"{JOBS_PATH}/certificate-enroll", self._create_job),
            ("approve", "PUT", rf"{JOBS_PATH}/(?P<oid>[^/]+)/approve", self._approve),
            ("reject", "PUT", rf"{JOBS_PATH}/(?P<oid>[^/]+)/reject", self._reject),
            ("result", "GET", rf"{JOBS_PATH}/(?P<oid>[^/]+)/download/result", self._result),
            ("job", "GET", rf"{JOBS_PATH}/(?P<oid>[^/]+)", self._job),
            ("jobs_list", "GET", rf"{JOBS_PATH}", self._list_jobs),
        ]
        for kind, collection in AUTH_COLLECTIONS.items():
            routes += [
                (f"{kind}_create", "POST", rf"{AUTH_PATH}/{collection}", self._auth_create(kind)),
                (f"{kind}_list", "GET", rf"{AUTH_PATH}/{collection}", self._auth_list(kind)),
                (f"{kind}_get", "GET", rf"{AUTH_PATH}/{collection}/(?P<oid>[^/]+)", self._auth_get(kind)),
                (f"{kind}_delete", "PUT", rf"{AUTH_PATH}/{collection}/(?P<oid>[^/]+)/delete", self._auth_delete(kind)),
            ]
        for name, method, path, handler in routes:
            r.route(method=method, path__regex=rf"^{path}$", name=name).mock(side_effect=self._wrap(name, handler))
        r.route(name="unknown").mock(side_effect=self._unknown)

    def _wrap(self, name, handler):
        async def side_effect(request: httpx.Request, oid: str | None = None):
            self.requests.append(request)
            self.calls.append((name, oid or ""))
            if request.headers.get("x-api-key") != self.api_key:
                self.violations.append(f"{name}: wrong or missing x-api-key")
                return _error(401, "unauthorized")
            if request.url.params.get("account_id") != self.account_id:
                self.violations.append(f"{name}: account_id {request.url.params.get('account_id')!r}")
                return _error(403, "account not accessible")
            if name in self.fail:
                injected = self.fail[name]
                if isinstance(injected, Exception):
                    raise injected
                if callable(injected):
                    result = injected(request)
                    if result is not None:
                        return result
                else:
                    return injected
            result = handler(request, oid) if oid is not None else handler(request)
            if asyncio.iscoroutine(result):
                result = await result
            return result
        return side_effect

    def _unknown(self, request: httpx.Request):
        self.requests.append(request)
        self.violations.append(f"unexpected endpoint {request.method} {request.url.path}")
        return _error(404, "not found")

    @staticmethod
    def _page(request: httpx.Request, items: list, key: str = "records") -> httpx.Response:
        limit = int(request.url.params.get("limit", 100))
        offset = int(request.url.params.get("offset", 0))
        return _json_response(200, {key: items[offset:offset + limit], "total": len(items),
                                    "limit": limit, "offset": offset})

    # account / lookups
    def _accounts(self, request):
        return _json_response(200, self.accounts)

    def _list_cas(self, request):
        return self._page(request, self.cas, "items")

    def _list_profiles(self, request):
        # Verified live: deleted profiles are hidden from the list and come back only with status=DELETED.
        status = (request.url.params.get("status") or "").upper()
        if status:
            return self._page(request, [p for p in self.profiles if str(p.get("status")).upper() == status])
        return self._page(request, [p for p in self.profiles if p.get("status") != "DELETED"])

    def _list_zones(self, request):
        return self._page(request, self.zones)

    # divisions
    def _create_division(self, request):
        body = json.loads(request.content)
        if body.get("account_id") != self.account_id:
            return _error(400, "account_id in body does not match")
        if body.get("primary_rzone_id") not in {z["id"] for z in self.zones if z["status"] == "ENABLED"}:
            return _error(400, "Primary zone ID is required if a secondary zone is present")
        if any(d["name"] == body["name"] for d in self.divisions.values()):
            return _error(409, "division name already exists")
        division_id = str(uuid.uuid4())
        self.divisions[division_id] = {"id": division_id, "name": body["name"], "hidden": self.division_list_lag}
        return httpx.Response(200)  # DTM returns no ID

    def _list_divisions(self, request):
        visible = []
        for d in self.divisions.values():
            if d["hidden"] > 0:
                d["hidden"] -= 1
            else:
                visible.append({"id": d["id"], "name": d["name"]})
        return self._page(request, visible)

    def _delete_division(self, request, oid):
        if oid not in self.divisions:
            return _error(404, "entity_not_found")
        del self.divisions[oid]
        return httpx.Response(self.division_delete_status)

    # policies
    def _create_policy(self, request):
        policy = json.loads(request.content)["certificate_policy"]
        if policy["division_id"] not in self.divisions:
            return _error(400, "division not found")
        if policy["ica_id"] not in {c["id"] for c in self.cas}:
            return _error(400, "ica not found")
        methods = policy.get("certificate_management_methods") or []
        if not methods or not set(methods) <= {"SINGLE", "BATCH", "EST", "CMP_V2", "SCEP"}:
            return _error(400, f"invalid certificate_management_methods {methods!r}")
        sections = {"SINGLE": "single_cert_request_parameters", "BATCH": "batch_request_parameters"}
        for method, section in sections.items():
            if method in methods and "encryption_certificate_source" not in policy.get(section, {}):
                return _error(400, f"{section}.encryption_certificate_source is required")
        if "CMP_V2" in methods and "cmp_request_parameters" not in policy:
            return _error(400, "cmp_request_parameters is required")
        if "SCEP" in methods and not any(c["id"] == policy["ica_id"] and c["key_type"] == "rsa" for c in self.cas):
            return _error(400, "SCEP needs an RSA issuing CA")  # SCEP encrypts to the CA with RSA
        auth_policy_id = policy.get("authentication_policy_id")
        if auth_policy_id is not None and self.auth_objects["auth_policy"].get(auth_policy_id, {}).get(
                "status") != "ACTIVE":
            return _error(400, "authentication policy not found")
        if policy.get("certificate_profile_id") not in {p["id"] for p in self.profiles if p["status"] == "ACTIVE"}:
            return _error(400, "certificate profile not found")
        profile = next(p for p in self.profiles if p["id"] == policy["certificate_profile_id"])
        if "CMP_V2" in methods and len(methods) > 1 and not profile.get("allow_bare_public_key"):
            # verified live (UC-6): EST + CMP_V2 and SINGLE + CMP_V2 in one policy need a bare-key profile
            return _error(400, "Please select certificate profile with allowed bare public key")
        policy_id = f"IOT_{uuid.uuid4()}"
        self.policies[policy_id] = {"id": policy_id, **policy, "alternative_id": uuid.uuid4().hex[:12]}
        self.profiles_referenced.add(policy["certificate_profile_id"])
        if self.policy_create_echo:
            return _json_response(201, {"certificate_policy": {"id": policy_id, "name": policy["name"]}})
        return _json_response(201, {})

    def _get_policy(self, request, oid):
        policy = self.policies.get(oid)
        if not policy:
            return _error(404, "entity_not_found")
        chain = [{"blob": base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()}
                 for c in (self.ica_cert, self.root_cert)]
        return _json_response(200, {"id": oid, "name": policy["name"], "status": "ACTIVE",
                                    "alternative_id": policy["alternative_id"], "ca_chain": chain})

    # certificate profiles (UC-3: the shared CMPv2 profile is a copy that allows bare public keys)
    def _get_profile(self, request, oid):
        profile = next((p for p in self.profiles if p["id"] == oid), None)
        if not profile:
            return _error(404, "entity_not_found")
        return _json_response(200, profile)

    def _create_profile(self, request):
        body = json.loads(request.content)
        if body.get("account_id") != self.account_id:
            return _error(400, "account_id in body does not match")
        if not body.get("certificate_template_id") or not isinstance(body.get("body"), list):
            return _error(400, "certificate_template_id and body are required")
        # unique per account – verified live: a DELETED profile keeps its name reserved
        clash = next((p for p in self.profiles if p["name"] == body.get("name")
                      and p.get("account_id") == self.account_id), None)
        if clash and clash.get("status") == "DELETED":
            return _error(400, f"Certificate profile with name {body['name']} already exists")
        if clash:
            return _error(400, "certificate profile name already exists")  # unique per account
        entries = [dict(e) for e in body["body"]]
        cap = self.template_validity_cap.get(body["certificate_template_id"])
        if cap:  # the template limits the validity – DTM applies its own values silently
            for entry in entries:
                if entry["key"] == "validity.duration_unit":
                    entry["value"] = cap[0]
                if entry["key"] == "validity.duration_value":
                    entry["value"] = cap[1]
        csr = next((e for e in entries if e.get("key") == "csr"), {})
        profile = {"id": f"profile-{uuid.uuid4().hex[:8]}", "name": body["name"], "status": "ACTIVE",
                   "account_id": body["account_id"],
                   "certificate_template": {"id": body["certificate_template_id"]}, "body": entries,
                   "allow_bare_public_key": "allow_bare_public_key" in (csr.get("sources") or [])}
        self.profiles.append(profile)
        self.created_profiles.append(body)
        return _json_response(201, profile)

    def _set_profile_status(self, status):
        def handler(request, oid):
            profile = next((p for p in self.profiles if p["id"] == oid), None)
            if not profile or profile.get("account_id") != self.account_id:
                return _error(404, "entity_not_found")
            profile["status"] = status
            return httpx.Response(204)
        return handler

    def _undelete_profile(self, request, oid):
        profile = next((p for p in self.profiles if p["id"] == oid), None)
        if not profile or profile.get("account_id") != self.account_id:
            return _error(404, "entity_not_found")
        if profile.get("status") != "DELETED":
            return _error(400, "certificate profile is not deleted")
        profile["status"] = profile.pop("status_before_delete", "ACTIVE")  # back to ACTIVE or DISABLED
        return httpx.Response(204)

    def _delete_profile(self, request, oid):
        """Soft delete. NL (verified live): allowed once no remaining policy uses the profile. US: refused
        for any profile a policy ever used, even a deleted one – hence shared profiles there."""
        profile = next((p for p in self.profiles if p["id"] == oid), None)
        if not profile or profile.get("account_id") != self.account_id or profile.get("status") == "DELETED":
            return _error(404, "entity_not_found")
        in_use = (any(pol.get("certificate_profile_id") == oid for pol in self.policies.values())
                  if self.host == NL_HOST else oid in self.profiles_referenced)
        if in_use:
            return _error(400, "Certificate profile is referenced by a certificate management policy")
        self.delete_profile(profile)
        return httpx.Response(204)

    def delete_profile(self, profile: dict) -> None:
        """Deleted in the DTM portal (the app never deletes profiles): undelete restores the status."""
        profile["status_before_delete"], profile["status"] = profile["status"], "DELETED"

    def profile(self, name: str) -> dict | None:
        return next((p for p in self.profiles if p["name"] == name and p.get("account_id") == self.account_id), None)

    # authentication service (UC-3)
    def _auth_create(self, kind):
        def create(request):
            body = json.loads(request.content)
            if body.get("account_id") != self.account_id:
                return _error(400, "account_id in body does not match")
            if not body.get("name"):
                return _error(400, "name is required")
            record = {"id": str(uuid.uuid4()), "name": body["name"], "status": "ACTIVE", "body": body}
            if kind != "auth_policy":
                parent = self.auth_objects["auth_policy"].get(body.get("authentication_policy_id"))
                if not parent or parent["status"] != "ACTIVE":
                    return _error(400, "authentication policy not found")
            if kind == "passcode":
                if not 6 <= len(body.get("passcode") or "") <= 64:
                    return _error(400, "passcode must be 6–64 characters")
                record["alternate_id"] = f"ref-{uuid.uuid4().hex[:10]}"
                registered = [v for v in body.get("registered_values") or []
                              if v.get("certificate_field") == "subject.common_name" and v.get("matcher") == "equals"]
                record |= {"usage_limit": body.get("usage_limit"), "number_of_usage": 0,
                           "registered_cn": registered[0]["value"] if registered else None,
                           "registered_values": body.get("registered_values") or []}
            if kind == "auth_certificate":
                try:
                    x509.load_pem_x509_certificate((body.get("pem") or "").encode())
                except ValueError:
                    return _error(400, "invalid certificate")
            self.auth_objects[kind][record["id"]] = record
            if kind == "passcode":
                for listener in self.passcode_listeners:
                    listener()
            return _json_response(201, {k: v for k, v in record.items() if k != "body"}
                                  | {"authentication_policy_id": body.get("authentication_policy_id")})
        return create

    def _auth_list(self, kind):
        def list_(request):  # soft-deleted objects stay listed with status DELETED
            # verified live: list records carry account_id
            return self._page(request, [{"id": o["id"], "name": o["name"], "status": o["status"],
                                         "account_id": o.get("account_id", self.account_id)}
                                        for o in self.auth_objects[kind].values()])
        return list_

    def _auth_get(self, kind):
        def get(request, oid):
            record = self.auth_objects[kind].get(oid)
            if not record:
                return _error(404, "entity_not_found")
            data = {"id": oid, "name": record["name"], "status": record["status"]}
            if kind == "passcode":
                data |= {"usage_limit": record.get("usage_limit"), "number_of_usage": self.passcode_usage(record),
                         "registered_values": record.get("registered_values") or []}
            return _json_response(200, data)
        return get

    def _auth_delete(self, kind):
        def delete(request, oid):
            record = self.auth_objects[kind].get(oid)
            if not record:
                return _error(404, "entity_not_found")
            if record["status"] == "DELETED":
                return _error(400, "already deleted")
            record["status"] = "DELETED"
            return httpx.Response(200)
        return delete

    def active_auth(self, kind: str) -> list[dict]:
        return [o for o in self.auth_objects[kind].values() if o["status"] == "ACTIVE"]

    # enrollment endpoints (UC-3) – authenticated by the policy's authentication policy, never by
    # the API key; mTLS runs on clientauth.<host>
    def enroll_transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.enroll_router.async_handler)

    def _register_enrollment(self) -> None:
        r = self.enroll_router
        for host in (self.host, self.clientauth_host):
            r.route(method="POST", host=host, path__regex=rf"^{EST_GROUP_RE}$").mock(
                side_effect=self._enroll_wrap("est_group", self._est))
            r.route(method="POST", host=host, path__regex=rf"^{EST_PATH_RE}$").mock(
                side_effect=self._enroll_wrap("est", self._est))
            r.route(method="POST", host=host, path__regex=rf"^{CERT_PATH}$").mock(
                side_effect=self._enroll_wrap("rest", self._rest))
        r.route(method="POST", host=self.clientauth_host, path__regex=rf"^{REENROLL_GROUP_RE}$").mock(
            side_effect=self._enroll_wrap("reenroll_group", self._reenroll))
        r.route(method="POST", host=self.clientauth_host, path__regex=rf"^{REENROLL_PATH_RE}$").mock(
            side_effect=self._enroll_wrap("reenroll", self._reenroll))
        r.route().mock(side_effect=self._unknown)

    def _enroll_wrap(self, name, handler):
        async def side_effect(request: httpx.Request, **groups):
            self.enroll_requests.append(request)
            self.enroll_calls.append((name, request.url.host))
            if "x-api-key" in request.headers or "account_id" in request.url.params:
                self.violations.append(f"{name}: enrollment call carries the API key or account_id")
            if self.enroll_fail is not None:
                if isinstance(self.enroll_fail, Exception):
                    raise self.enroll_fail
                return self.enroll_fail
            result = handler(request, **groups)
            return await result if asyncio.iscoroutine(result) else result
        return side_effect

    def _authenticate(self, request: httpx.Request, policy: dict, passcode: str | None):
        """None if authenticated, else the error response DTM would send."""
        auth_policy_id = policy.get("authentication_policy_id")
        if request.url.host == self.clientauth_host:
            if not self.tls_client_cert:
                return _error(401, "client certificate required")
            if not any(o["body"]["pem"].strip() == self.tls_client_cert.strip()
                       and o["body"]["authentication_policy_id"] == auth_policy_id
                       for o in self.active_auth("auth_certificate")):
                return _error(401, "client certificate not registered")
            return None
        if not passcode or not any(o["body"]["passcode"] == passcode
                                   and o["body"]["authentication_policy_id"] == auth_policy_id
                                   for o in self.active_auth("passcode")):
            return _error(401, "invalid passcode")
        return None

    def passcode_usage(self, record: dict) -> int:
        external = 0
        if self.external_passcode_usage is not None and self.external_passcode_usage.exists():
            external = json.loads(self.external_passcode_usage.read_text()).get(record.get("alternate_id"), 0)
        return record.get("number_of_usage", 0) + external

    def _use_passcode(self, policy: dict, passcode: str, cn: str):
        """UC-5 rules after authentication: usage limit first, then the use is counted (also for a
        request that is rejected next), then the registered common name. None = go on and issue."""
        record = next((o for o in self.active_auth("passcode") if o["body"]["passcode"] == passcode
                       and o["body"]["authentication_policy_id"] == policy.get("authentication_policy_id")), None)
        if record is None:
            return None
        limit = record.get("usage_limit")
        if self.passcode_rules and limit and self.passcode_usage(record) >= limit:
            return _json_response(400, {"errors": [{"code": "invalid_input",
                                                    "message": "Passcode has reached its usage limit"}]})
        record["number_of_usage"] = record.get("number_of_usage", 0) + 1
        if self.passcode_rules and record.get("registered_cn") not in (None, cn):
            return _json_response(400, {"errors": [{"code": "invalid_input", "message":
                                                    "Invalid registered value provided in attribute: subject.common_name"}]})
        return None

    def register_certificate(self, policy_id: str, cert: x509.Certificate) -> dict:
        """A certificate issued outside the fake's handlers (fake openssl cmp) – listed like any other."""
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        record = {"id": str(uuid.uuid4()), "policy_id": policy_id, "common_name": cn, "status": "ISSUED",
                  "serial_number": format(cert.serial_number, "x"),
                  "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.certificates[record["id"]] = record
        return record

    def _est(self, request, oid, gid=None):
        policy = self.policies.get(oid)
        if not policy or "EST" not in policy["certificate_management_methods"]:
            return _error(404, "EST is not enabled for this policy")
        passcode = None
        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            passcode = base64.b64decode(header[6:]).decode()
        if (denied := self._authenticate(request, policy, passcode)) is not None:
            return denied
        if request.headers.get("content-type") != "application/pkcs10":
            return _error(415, "expected application/pkcs10")
        try:
            csr = x509.load_der_x509_csr(base64.b64decode(request.content, validate=True))
        except ValueError:
            return _error(400, "invalid CSR")
        if not csr.is_signature_valid:
            return _error(400, "CSR signature invalid")
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if passcode and (refused := self._use_passcode(policy, passcode, cn)) is not None:
            return refused
        group = None
        if gid is not None and isinstance(group := self._group_for(policy, gid), httpx.Response):
            return group
        record, cert, _key = self._new_certificate(oid, cn, csr.public_key())
        record["enrollment_method"] = "EST"
        if group is not None:
            self.file_by_identity(record, group["id"], cn, cert)
        p7 = pkcs7.serialize_certificates([cert], serialization.Encoding.DER)
        return httpx.Response(200, content=base64.b64encode(p7),
                              headers={"content-type": "application/pkcs7-mime; smime-type=certs-only"})

    async def _reenroll(self, request, oid, gid=None):
        """EST simplereenroll: authenticated only by the current certificate (mTLS) – it must be a
        certificate this fake issued under that policy and still ISSUED; the CSR keeps its subject."""
        if self.reenroll_delay:
            await _real_sleep(self.reenroll_delay)
        policy = self.policies.get(oid)
        if not policy or "EST" not in policy["certificate_management_methods"]:
            return _error(404, "EST is not enabled for this policy")
        if not self.tls_client_cert:
            return _error(401, "est_unauthorized")
        current = x509.load_pem_x509_certificate(self.tls_client_cert.encode())
        self.reenroll_presented.append(format(current.serial_number, "X"))
        record = next((c for c in self.certificates.values()
                       if c["serial_number"] == format(current.serial_number, "x") and c["policy_id"] == oid), None)
        if record is None or record["status"] != "ISSUED" or current.issuer != self.ica_cert.subject:
            return _error(401, "est_unauthorized")
        current.verify_directly_issued_by(self.ica_cert)
        if self.reenroll_unauthorized > 0:
            self.reenroll_unauthorized -= 1
            return _error(401, "est_unauthorized")
        profile = next((p for p in self.profiles if p["id"] == policy.get("certificate_profile_id")), {})
        if not renews_anytime(profile):  # verified live on a profile without "anytime"
            return _json_response(400, {"errors": [{"code": "invalid_input", "message": "Renewal is disabled"}]})
        try:
            csr = x509.load_der_x509_csr(base64.b64decode(request.content, validate=True))
        except ValueError:
            return _error(400, "invalid CSR")
        if not csr.is_signature_valid or csr.subject != current.subject:
            return _error(400, "CSR subject must match the current certificate")
        if gid is not None and isinstance(refused := self._group_for(policy, gid), httpx.Response):
            return refused
        new, cert, _key = self._new_certificate(oid, record["common_name"], csr.public_key())
        new["enrollment_method"] = "EST"  # verified live: the renewal's own method, whatever issued the old one
        if gid is not None:  # verified live: the renewal lands under the same device
            new |= {"device_id": record.get("device_id"), "valid_to": cert.not_valid_after_utc.isoformat()}
        p7 = pkcs7.serialize_certificates([cert], serialization.Encoding.DER)
        return httpx.Response(200, content=base64.b64encode(p7),
                              headers={"content-type": "application/pkcs7-mime; smime-type=certs-only"})

    def _rest(self, request):
        body = json.loads(request.content)
        policy = self.policies.get(body.get("certificate_policy_id"))
        if not policy or "SINGLE" not in policy["certificate_management_methods"]:
            return _error(400, "certificate policy not found")
        if (denied := self._authenticate(request, policy, request.headers.get("x-passcode"))) is not None:
            return denied
        cn = next(a["value"] for a in body["certificate_profile_attributes"] if a["id"] == "subject.common_name")
        csr = self._check_csr(body.get("csr") or "", cn)
        if isinstance(csr, httpx.Response):
            return csr
        passcode = request.headers.get("x-passcode")
        if passcode and (refused := self._use_passcode(policy, passcode, cn)) is not None:
            return refused
        device = None
        if policy.get("require_device_group_for_enroll") or body.get("device_id"):
            if isinstance(device := self._device_for(policy, body, cn), httpx.Response):
                return device
        record, cert, _key = self._new_certificate(policy["id"], cn, csr.public_key())
        record["enrollment_method"] = "SINGLE"
        answer = None
        if device is not None:
            record |= {"device_id": device["id"], "valid_to": cert.not_valid_after_utc.isoformat()}
            answer = self.device_answer_override or {"id": device["id"], "name": device["name"], "new_device": False}
        return _json_response(200, {"certificate_id": record["id"], "serial_number": record["serial_number"],
                                    "status": "ISSUED", "pem": cert_pem(cert), "device": answer,
                                    "chain": cert_pem(self.ica_cert) + cert_pem(self.root_cert)},
                              raw_control_chars=self.rest_raw_control_chars)

    def _list_policies(self, request):
        return self._page(request, [{"id": p["id"], "name": p["name"]} for p in self.policies.values()])

    def _delete_policy(self, request, oid):
        if oid not in self.policies:
            return _error(404, "entity_not_found")
        if any(c["policy_id"] == oid and c["status"] == "ISSUED" for c in self.certificates.values()):
            return _error(400, "policy has issued certificates")
        del self.policies[oid]
        return httpx.Response(204)

    # certificates
    def _new_certificate(self, policy_id: str, cn: str, public_key=None) -> tuple[dict, x509.Certificate, object]:
        if public_key is not None:  # client-side keys: sign the CSR's public key, DTM never sees a private key
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(self.ica_cert.subject)
                    .public_key(public_key).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
                    .sign(self.ica_key, hashes.SHA256()))
            key = None
        else:
            cert, key = make_cert(cn, issuer_cert=self.ica_cert, issuer_key=self.ica_key)
        cert_id = str(uuid.uuid4())
        record = {"id": cert_id, "policy_id": policy_id, "common_name": cn, "status": "ISSUED",
                  "serial_number": format(cert.serial_number, "x"),
                  "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}  # live format
        self.certificates[cert_id] = record
        return record, cert, key

    async def _issue(self, request):
        if self.issue_delay:
            await _real_sleep(self.issue_delay)
        body = json.loads(request.content)
        policy = self.policies.get(body.get("certificate_policy_id"))
        if not policy:
            return _error(400, "certificate policy not found")
        cn = next(a["value"] for a in body["certificate_profile_attributes"] if a["id"] == "subject.common_name")
        device = None
        if policy.get("require_device_group_for_enroll") or body.get("device_id"):
            device = self._device_for(policy, body, cn)
            if isinstance(device, httpx.Response):
                return device
        client_side = policy.get("key_generation_option") == "client_side"
        public_key = None
        if client_side:
            if body.get("server_side_key_gen") or not body.get("csr"):
                return _error(400, "policy requires a CSR (client-side key generation)")
            csr = self._check_csr(body["csr"], cn)
            if isinstance(csr, httpx.Response):
                return csr
            public_key = csr.public_key()
            self.received_csrs.append(body["csr"])
        elif body.get("csr") or not body.get("server_side_key_gen"):
            return _error(400, "policy requires server-side key generation")
        record, cert, key = self._new_certificate(policy["id"], self.single_cn_override or cn, public_key)
        record["enrollment_method"] = "SINGLE"
        if device is not None:
            record |= {"device_id": device["id"], "valid_to": cert.not_valid_after_utc.isoformat()}
        data = {"certificate_id": record["id"], "serial_number": record["serial_number"],
                "status": "AUTO_APPROVED", "pem": cert_pem(cert),
                "chain": cert_pem(self.ica_cert) + cert_pem(self.root_cert),
                "valid_from": cert.not_valid_before_utc.isoformat(), "valid_to": cert.not_valid_after_utc.isoformat()}
        if key is not None:
            data["private_key"] = key_pem(key)
        if device is not None:  # verified live: the answer names the device the certificate is filed under
            data["device"] = self.device_answer_override or {"id": device["id"], "name": device["name"],
                                                             "new_device": False}
        data |= self.single_overrides
        return _json_response(200, data, raw_control_chars=True)

    @staticmethod
    def _check_csr(pem: str, cn: str | None):
        try:
            csr = x509.load_pem_x509_csr(pem.encode())
        except ValueError:
            return _error(400, "invalid CSR")
        if not csr.is_signature_valid:
            return _error(400, "CSR signature invalid")
        subject = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn is not None and (not subject or subject[0].value != cn):
            return _error(400, "CSR subject does not match the common name")
        return csr

    def _list_jobs(self, request):
        # Verified live: the list ignores a certificate_policy_id filter – every job of the account comes back.
        return self._page(request, [{"id": j["id"], "name": j.get("name"), "status": j["status"],
                                     "job_type": "certificate_enroll", "certificate_policy_id": j["policy_id"],
                                     "account_id": j.get("account_id", self.account_id)} for j in self.jobs.values()])

    def _list_certs(self, request):
        policy_id = request.url.params.get("certificate_policy_id")
        common_name = request.url.params.get("common_name")  # verified live: exact match, across policies
        status = request.url.params.get("status")
        if status and status.upper() == "REVOKED" and self.revoked_count_lag > 0:
            self.revoked_count_lag -= 1
            return self._page(request, [])
        items = []
        for c in self.certificates.values():
            if policy_id is not None and c["policy_id"] != policy_id:
                continue
            if common_name is not None and c["common_name"] != common_name:
                continue
            if c["id"] in self.issued_list_hidden:
                continue
            listed = c["status"]
            if c["id"] in self.issued_list_stale:
                listed = "ISSUED"
            if status and listed != status.upper():
                continue
            items.append({"id": c["id"], "common_name": c["common_name"], "status": listed, "created_at": c.get("created_at"),
                          "certificate_policy_id": c["policy_id"], "account_id": c.get("account_id", self.account_id)})
        self.issued_list_hidden.clear()
        self.issued_list_stale.clear()
        return self._page(request, items)

    async def _revoke(self, request, oid):
        self.revoke_in_flight += 1
        self.revoke_max_in_flight = max(self.revoke_max_in_flight, self.revoke_in_flight)
        try:
            if self.revoke_delay:
                await _real_sleep(self.revoke_delay)
            cert = self.certificates.get(oid)
            if not cert:
                return _error(404, "entity_not_found")
            plan = self.revoke_plan.get(oid)
            action = plan.pop(0) if plan else "ok"
            if action == "timeout":
                raise httpx.ReadTimeout("fake timeout", request=request)
            if action == "timeout_completed":
                # completes server-side although the client gives up, and the list lags behind
                cert["status"] = "REVOKED"
                self.issued_list_stale.add(oid)
                raise httpx.ReadTimeout("fake timeout", request=request)
            if action.startswith("status"):
                return _error(int(action[6:]), "upstream trouble")
            if cert["status"] == "REVOKED":
                return _error(400, "certificate is already revoked")
            body = json.loads(request.content)
            if not body.get("reason"):
                return _error(400, "reason is required")
            cert["status"] = "REVOKED"
            return httpx.Response(204)
        finally:
            self.revoke_in_flight -= 1

    # batch jobs
    def _create_job(self, request):
        fields, files = _multipart(request)
        policy = self.policies.get(fields.get("certificate_policy_id"))
        if policy and policy.get("key_generation_option") == "client_side":
            return self._create_csr_job(policy, fields, files)
        if fields.get("input_format") != "csv":
            return _error(400, "CSR input not supported for server side key generation")
        if not fields.get("encryption_certificate"):
            return _error(400, "Provide certificate or PGP public key")
        policy = self.policies.get(fields.get("certificate_policy_id"))
        if not policy:
            return _error(400, "certificate policy not found")
        if "data" not in files:
            return _error(400, "data is required")
        with zipfile.ZipFile(io.BytesIO(files["data"][1])) as archive:
            (csv_name,) = archive.namelist()
            lines = archive.read(csv_name).decode().splitlines()
        if lines[0] != "subject.common_name":
            return _error(400, "invalid CSV header")
        job_id = str(uuid.uuid4())
        needs_approval = policy.get("require_approval_for_enroll")
        self.jobs[job_id] = {"id": job_id, "name": fields.get("name"), "policy_id": policy["id"],
                             "fields": fields, "csv": lines, "names": lines[1:],
                             "status": self.approval_status if needs_approval else "submitted",
                             "steps": list(self.job_steps), "approved": False, "issued": []}
        return _json_response(201, {"id": job_id, "status": self.jobs[job_id]["status"]})

    def _create_csr_job(self, policy, fields, files):
        if fields.get("input_format") != "csr":
            return _error(400, "client-side policy requires input_format=csr")
        if "encryption_certificate" in fields or "encryption_certificate" in files:
            self.violations.append("encryption certificate sent for a CSR batch")
        if "data" not in files:
            return _error(400, "data is required")
        names, public_keys = [], []
        with zipfile.ZipFile(io.BytesIO(files["data"][1])) as archive:
            for entry in archive.namelist():
                if not entry.endswith(".csr"):
                    return _error(400, f"unexpected file {entry}")
                pem = archive.read(entry).decode()
                if "PRIVATE KEY" in pem:
                    self.violations.append(f"private key uploaded in {entry}")
                csr = self._check_csr(pem, entry[:-4])
                if isinstance(csr, httpx.Response):
                    return csr
                self.received_csrs.append(pem)
                names.append(entry[:-4])
                public_keys.append(csr.public_key())
        job_id = str(uuid.uuid4())
        needs_approval = policy.get("require_approval_for_enroll")
        self.jobs[job_id] = {"id": job_id, "name": fields.get("name"), "policy_id": policy["id"], "fields": fields,
                             "names": names, "public_keys": public_keys, "client_side": True,
                             "status": self.approval_status if needs_approval else "pending",
                             "steps": list(self.csr_job_steps), "approved": False, "issued": []}
        return _json_response(201, {"id": job_id, "status": self.jobs[job_id]["status"]})

    async def _job(self, request, oid):
        if self.job_delay:
            await _real_sleep(self.job_delay)
        job = self.jobs.get(oid)
        if not job:
            return _error(404, "entity_not_found")
        if job["status"] != self.approval_status and job["steps"]:
            job["status"] = job["steps"].pop(0)
            if job["status"] == "completed" and not job["issued"]:
                keys = job.get("public_keys") or [None] * len(job["names"])
                for name, public_key in zip(job["names"], keys):
                    job["issued"].append(self._new_certificate(job["policy_id"], name, public_key))
        data = {"id": oid, "status": job["status"], "data_available": True}
        if job["status"] == "in_progress" and self.job_success_items:
            data["success_items"] = self.job_success_items.pop(0)
        if job["status"] == "completed":
            data |= {"processing_time": 1234, "success_items": len(job["names"]), "failed_items": 0}
        if job["status"] == "failed":  # nothing issued yet – the fake issues on "completed" only
            data |= {"success_items": len(job["issued"]), "failed_items": len(job["names"]) - len(job["issued"]),
                     "error_report_available": False}
        return _json_response(200, data)

    async def _approve(self, request, oid):
        if self.approve_delay:
            await _real_sleep(self.approve_delay)
        job = self.jobs.get(oid)
        if not job:
            return _error(404, "entity_not_found")
        if job["status"] != self.approval_status:
            return _error(400, "job is not waiting for approval")
        job["status"], job["approved"] = "approved", True
        return httpx.Response(204)

    def _reject(self, request, oid):
        job = self.jobs.get(oid)
        if not job:
            return _error(404, "entity_not_found")
        if job["status"] != self.approval_status:
            return _error(400, "job is not waiting for approval")
        job["status"], job["steps"] = "rejected", []
        return httpx.Response(204)

    def _result(self, request, oid):
        job = self.jobs.get(oid)
        if not job or job["status"] != "completed":
            return _error(400, "result not available")
        if job.get("client_side"):  # certificates only → plain ZIP, no CMS envelope
            buffer = io.BytesIO()
            chain = cert_pem(self.ica_cert) + cert_pem(self.root_cert)
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                for i, (_record, cert, _key) in enumerate(job["issued"], start=1):
                    archive.writestr(f"Item-{i}-{_record['common_name']}.pem", cert_pem(cert) + chain)
                archive.writestr("full_results.txt", "\n".join(f"Item-{i},OK" for i in range(len(job["issued"]))))
            return httpx.Response(200, content=buffer.getvalue(), headers={"content-type": "application/zip"})
        entries = [(f"Line-{i:08d}", cert_pem(cert), key_pem(key))
                   for i, (_record, cert, key) in enumerate(job["issued"], start=1)]
        data = result_zip(entries, [cert_pem(self.ica_cert), cert_pem(self.root_cert)])
        envelope = cms_envelope(data, job["fields"]["encryption_certificate"].encode())
        return httpx.Response(200, content=envelope, headers={"content-type": "application/pkcs7-mime"})

    # UC-6 managed devices
    def _create_device_group(self, request):
        body = json.loads(request.content)
        if body.get("account_id") not in {a["id"] for a in self.accounts}:
            return _error(400, "account not accessible")
        if body.get("division_id") not in self.divisions:
            return _error(400, "division not found")
        if any(g["name"] == body.get("name") and g["account_id"] == body["account_id"]
               for g in self.device_groups.values()):  # deleted names stay reserved
            return _error(400, "device group name already exists")
        for assignment in body.get("policies") or []:
            if not assignment.get("status"):
                return _error(400, "Policy assignment status is required")  # verified live
            if assignment.get("policy_id") not in self.policies:
                return _error(400, "certificate policy not found")
        group_id = str(uuid.uuid4())
        self.device_groups[group_id] = {"id": group_id, "name": body["name"], "account_id": body["account_id"],
                                        "division_id": body["division_id"], "status": "ACTIVE",
                                        "attributes": body.get("attributes") or [],
                                        "policies": body.get("policies") or [], "body": body,
                                        "hidden": self.device_group_list_lag}
        return _json_response(200, {"code": "DEVICE_GROUP_CREATED_200"})  # verified live: no ID

    def _public(self, obj: dict) -> dict:
        return {k: v for k, v in obj.items() if k not in ("hidden", "body", "policies")}

    def _list_device_groups(self, request):
        name = request.url.params.get("name")
        visible = []
        for g in self.device_groups.values():
            if g["hidden"] > 0:
                g["hidden"] -= 1
            elif name is None or name in g["name"]:  # the filter matches parts of names, too
                visible.append(self._public(g))
        return self._page(request, visible)

    def _get_object(self, collection: str):
        def get(request, oid):
            obj = getattr(self, collection).get(oid)
            return _json_response(200, self._public(obj)) if obj else _error(404, "entity_not_found")
        return get

    def _disable(self, collection: str):
        def disable(request, oid):
            obj = getattr(self, collection).get(oid)
            if not obj or obj["status"] == "DELETED":
                return _error(404, "entity_not_found")
            if obj["status"] == "DISABLED":
                return _error(400, "already disabled")
            obj["status"] = "DISABLED"
            if collection == "devices":
                obj["operational_status"] = "DISABLED"
            return httpx.Response(204)
        return disable

    def _soft_delete(self, collection: str, code: int):
        def delete(request, oid):
            obj = getattr(self, collection).get(oid)
            if not obj or obj["status"] == "DELETED":
                return _error(404, "entity_not_found")
            if obj["status"] != "DISABLED":  # verified live: delete only when disabled
                return _json_response(400, {"errors": [{"code": code, "message": "disable before deleting"}]})
            obj["status"] = "DELETED"  # soft delete – still listed; certificates are NOT revoked
            return httpx.Response(204)
        return delete

    def _enroll_device(self, request):
        body = json.loads(request.content)
        group = self.device_groups.get(body.get("device_group_id"))
        if not group or group["status"] != "ACTIVE":
            return _error(400, "device group not found")
        if not body.get("name"):
            return _error(400, "name is required")
        attributes = body.get("attributes") or []
        if any(a.get("key") not in DEVICE_ATTRIBUTES or not a.get("value") for a in attributes):
            return _error(400, "unknown device attribute")
        if any(d["name"] == body["name"] and d["account_id"] == group["account_id"] for d in self.devices.values()):
            return _error(400, "device name already exists")
        device_id = str(uuid.uuid4())
        self.devices[device_id] = {"id": device_id, "name": body["name"], "account_id": group["account_id"],
                                   "device_group_id": group["id"], "description": body.get("description"),
                                   "status": "ACTIVE", "device_status": "ENROLLED", "operational_status": "ENABLED",
                                   "attributes": attributes}
        return _json_response(201, {"device_id": device_id, "device_status": "ENROLLED",
                                    "operational_status": "ENABLED"})

    def _list_devices(self, request):
        group_id = None if self.device_list_ignores_group else request.url.params.get("device_group_id")
        return self._page(request, [self._public(d) for d in self.devices.values()
                                    if group_id is None or d["device_group_id"] == group_id])

    def _device_for(self, policy: dict, body: dict, cn: str):
        """The device a certificate request is for – the policy issues only for a device of a group
        that has the policy assigned; the device name maps to the common name."""
        group = self.device_groups.get(body.get("device_group_id") or "")
        device = self.devices.get(body.get("device_id") or "")
        if not group or not device:
            return _error(400, "device group and device are required by the policy")
        if group["status"] != "ACTIVE" or device["status"] != "ACTIVE" or device["device_group_id"] != group["id"]:
            return _error(400, "device is not an active member of the device group")
        if not any(a.get("policy_id") == policy["id"] and a.get("status") == "ACTIVE" for a in group["policies"]):
            return _error(400, "policy is not assigned to the device group")
        return device  # verified live: device_id wins – DTM does not check the CN against the mapping

    def _device_certificates(self, request):
        for hook in self.before_device_list:
            hook()
        device_id = request.url.params.get("device_id")
        records = [{"certificate_id": c["id"], "common_name": c["common_name"],
                    "serial_number": c["serial_number"], "status": c["status"],
                    "enrollment_method": c.get("enrollment_method"),
                    "valid_to": c.get("valid_to"), "is_renewed": c.get("is_renewed", False),
                    "renew_allowed": not c.get("is_renewed", False) and c["status"] == "ISSUED",
                    "renewed_from_certificate_id": c.get("renewed_from")}
                   for c in self.certificates.values() if c.get("device_id") == device_id]
        if self.device_cert_list_lag > 0:  # verified live: total already counts, records not yet
            self.device_cert_list_lag -= 1
            return _json_response(200, {"records": [], "total": len(records)})
        return self._page(request, records)

    async def _renew(self, request, oid):
        if self.renew_delay:
            await _real_sleep(self.renew_delay)
        old = self.certificates.get(oid)
        if not old:
            return _error(404, "entity_not_found")
        if old["status"] != "ISSUED" or old.get("is_renewed"):
            return _error(400, "renewal not allowed")
        csr = self._check_csr(json.loads(request.content).get("csr") or "", old["common_name"])
        if isinstance(csr, httpx.Response):
            return csr
        record, cert, _key = self._new_certificate(old["policy_id"], old["common_name"], csr.public_key())
        record |= {"device_id": old.get("device_id"), "renewed_from": oid, "enrollment_method": "SINGLE",
                   "valid_to": cert.not_valid_after_utc.isoformat()}
        old["is_renewed"] = True  # verified live: the old one stays ISSUED, renew_allowed false
        data = {"certificate_id": record["id"], "serial_number": record["serial_number"], "status": "ISSUED",
                "pem": cert_pem(cert), "chain": cert_pem(self.ica_cert) + cert_pem(self.root_cert)}
        if (device := self.devices.get(old.get("device_id") or "")) is not None:
            data["device"] = self.device_answer_override or {"id": device["id"], "name": device["name"],
                                                             "new_device": False}
        return _json_response(200, data, raw_control_chars=True)

    def _group_for(self, policy: dict, gid: str):
        """The device-group endpoint: an active group of this fake with the policy assigned."""
        group = self.device_groups.get(gid)
        if not group or group["status"] != "ACTIVE":
            return _error(404, "device group not found")
        if not any(a.get("policy_id") == policy["id"] and a.get("status") == "ACTIVE" for a in group["policies"]):
            return _error(400, "policy is not assigned to the device group")
        return group

    def file_by_identity(self, record: dict, group_id: str, cn: str, cert=None) -> dict:
        """EST/CMPv2 on the device-group endpoint: the group's mapping (attribute → CN) finds the
        pre-created device; a value that matches none makes DTM create Device-<uuid> (verified live)."""
        group = self.device_groups[group_id]
        keys = {m["key"] for a in group["policies"] for m in a.get("device_field_mappings") or []
                if m.get("field") == "subject.common_name"}
        device = next((d for d in self.devices.values() if d["device_group_id"] == group_id
                       and d["status"] == "ACTIVE" and any(a["key"] in keys and a["value"] == cn
                                                          for a in d.get("attributes") or [])), None)
        if device is None:
            device_id = str(uuid.uuid4())
            device = self.devices[device_id] = {
                "id": device_id, "name": f"Device-{uuid.uuid4()}", "account_id": group["account_id"],
                "device_group_id": group_id, "status": "ACTIVE", "device_status": "REGISTERED",
                "operational_status": "ENABLED", "attributes": []}
        device["device_status"] = "REGISTERED"
        record["device_id"] = device["id"]
        if cert is not None:
            record["valid_to"] = cert.not_valid_after_utc.isoformat()
        return device

    def active_devices(self) -> list[dict]:
        return [d for d in self.devices.values() if d["status"] != "DELETED"]

    # convenience for tests
    def issued(self) -> list[dict]:
        return [c for c in self.certificates.values() if c["status"] == "ISSUED"]
