# UC-3 – Evergreen Device IDs via Enrollment Protocols (EST, CMPv2, REST)

> Status: implemented 2026-10-24 (`app/enrollment.py`). All protocol × authentication paths verified live through the app engine, one certificate each, cleanup without residue (apart from the shared CMPv2 profile).

## Requirements (from the author, 2026-10-24)

- A customer issues **evergreen client certificates (device IDs) in the factory**.
- The enrollment protocol is **selectable: EST, CMPv2 or REST API** (certificate issuance API,
  not the management API with API key used in UC-1/UC-2).
- **Single request**, or **up to 10 single requests in a row** ("fake batch") as a basis for
  **extrapolation** (throughput, time for N devices).
- Factory authentication is **selectable**:
  - **Passcode** handed to the factory, or
  - a **client certificate created by the factory itself**.

## How it differs from UC-1/UC-2

| | UC-1/UC-2 | UC-3 |
|---|---|---|
| Channel | Management REST API (`x-api-key`) | Enrollment protocol, authenticated by an **authentication policy** |
| Keys | server-side (UC-1) / factory CSR (UC-2) | **factory CSR** – EST/CMPv2 only work with client-side keys |
| Batch | real DTM batch job | **no DTM batch** – max. 10 single requests, measured per request |
| Factory credential | API key | passcode **or** factory client certificate (mTLS / CMP signature) |
| Extra DTM objects | division, certificate policy | + authentication policy, credential (passcode / auth certificate), device group (if required) |

## Protocol × authentication (per DigiCert docs, to verify live)

| Protocol | Passcode | Factory client certificate | Endpoint |
|---|---|---|---|
| EST `simpleenroll` | HTTP Basic (optional username + passcode) | mTLS on `clientauth.<host>` | `/.well-known/est/devicetrustmanager/IOT_<id>[/device-group/<id>]/simpleenroll` |
| REST (certificate issuance) | `x-passcode` header | mTLS on `clientauth.<host>` | `POST /certificate-issuance-service/api/v2/certificate` |
| CMPv2 `ir`/`cr` | shared secret (PBM) with the passcode reference ID as sender identifier | signature-based protection with the factory certificate | `dtr/cis/api/v1/cmp/{identifier}` (new, Oct 2026) or the older path |

Doc gaps found: the DTM authentication overview lists only "ACME credentials" for CMPv2, while
the CMPv2 concept page and the Oct 2026 release notes describe shared secret and certificates.
The EST URL is documented as "copy from the policy page" – check whether
`…/certificate-policy/{id}/enrollment-specification` returns it via API.

## Proposals

| # | Topic | Proposal |
|---|---|---|
| P1 ✔ | Who enrolls | The demonstrator plays the factory station (like UC-1/UC-2), **no device containers** – vision option B applies to the device use cases later |
| P2 ✔ | Auth choice | Applies to **all three protocols** (matrix above) – same story, three protocols side by side |
| P3 ✔ | Factory certificate | Created per run by the demonstrator: key pair + self-signed certificate `robot-<runid>-uc03-factory`, uploaded as DTM **authentication certificate** (not an auth CA). Private key only in memory/run dir, deleted on cleanup |
| P4 | Passcode | Created per run (random, 32 hex characters) via API in the authentication policy; **never shown, stored or logged** – it only lives in memory during the run; snippets use the placeholder `${PASSCODE}`. A certificates-only cleanup keeps it (harmless: nobody knows it) |
| P5 ✔ | Fake batch | **Decided:** N = 1…10 requests **sequentially**, each with its own key pair and CSR; measured per request (key generation, request → certificate) |
| P6 | Extrapolation | "1,000 devices ≈ X min" from the **median per device of key generation + request**, marked as an estimate for **one** sequential station (fixed target of 1000 – no operator input, keeps the form calm) |
| P7 | Tools | Snippets use standard tools: EST `curl` + `openssl`, CMPv2 **`openssl cmp`** (OpenSSL ≥ 3.0), REST `curl` / PowerShell. The app itself: httpx for EST/REST, CMPv2 via `openssl cmp` subprocess (no Python CMP library of good standing – NIH rule) |
| P8 | Web UI variant | **None** – protocols are machine-to-machine; reproducible steps replace it |
| P9 | Cleanup | Order: revoke certificates → delete device(s) (if DTM creates them) → device group → credential (passcode / auth certificate, `PUT …/delete`) → authentication policy → certificate policy → division. Same naming and ledger rules as UC-1 |
| P10 | Catalog | Vision rows 3 (EST + passcode) and CMPv2 from row 8 merge into this UC-3; row 4 (bootstrap → operational) stays separate |
| P11 | Live tests | Max. 2 requests per live test (CLAUDE.md load rule); one live test per protocol × auth combination only when that path changes |

## Decisions (2026-10-24)

- P1–P3 accepted (✔ above): demonstrator is the factory station; auth choice for all three
  protocols; factory certificate is a per-run self-signed DTM authentication certificate.
- P5: the fake batch runs **sequentially**.
- **Essential licence only**: no device group. The certificate policy itself carries the
  enrollment method and the authentication policy (docs: without a device group, the policy's
  authentication policy applies; device-group linking is an Advanced feature). The account has
  Advanced, but the use case must not depend on it.

## Verified live (2026-10-24, probe: 4 certificates, all revoked, all objects deleted)

| Check | Result |
|---|---|
| Policies without device group | `EST` and `SINGLE` (REST) policies with `authentication_policy_id`, `client_side`, `require_device_group_for_enroll: false` accepted |
| EST endpoint | `https://<host>/.well-known/est/devicetrustmanager/<policy id>/simpleenroll` – the `IOT_…` segment **is the policy ID**; mTLS: same path on `clientauth.<host>` |
| EST passcode | `Authorization: Basic base64(<passcode>)` (no username, `enable_username_for_passcode: false`) – first try |
| EST request/response | body base64 DER CSR, `Content-Type: application/pkcs10`; response `application/pkcs7-mime; smime-type=certs-only`, base64 PKCS#7 with the end-entity certificate only |
| REST passcode | `POST …/certificate-issuance-service/api/v2/certificate` with `x-passcode`, no API key – works |
| REST / EST with factory certificate | self-signed ECDSA certificate (KU digitalSignature, EKU clientAuth) uploaded via `POST …/authentication-certificate` with `pem` + `use_passcode: false` – mTLS on `clientauth.<host>` works for both |
| Timing (single request) | EST 0.57 s (passcode) / 0.95 s (mTLS); REST 0.66 s / 0.91 s |
| Device records | none created (`device: null` in the REST response) – cleanup needs no device step |
| Passcode object | create returns `alternate_id` (reference ID, intended as CMPv2 sender identifier) |
| Cleanup | auth certificate, passcode, authentication policy and certificate profile via `PUT …/{id}/delete` → status `DELETED` (soft delete, acceptable residue); policies via `api-ui` delete; division delete |
| CMPv2 profile | needs `allow_bare_public_key`: not a field but a **body entry** `{"key": "csr", "optional": false, "enabled": true, "sources": ["user_supplied", "allow_bare_public_key"], "value": null}` – works with the public `POST …/v1/certificate-profile` (found via HAR of the portal) |
| CMPv2 policy | `certificate_management_methods: ["CMP_V2"]` + `cmp_request_parameters: {}` (DTM fills `explicit_client_confirmation: false`) |
| CMPv2 endpoint | `https://<host>/devicetrustmanager/certificate-issuance-service/api/v1/cmp/DIOT_<alternative_id>` – the policy's `alternative_id` with the prefix `DIOT_` (copied from the portal; anything else: *"Invalid enrollment profile id"*). Signature-protected answers are signed by the issuing CA → `-trusted` = the policy's `ca_chain` |
| CMPv2 passcode | `openssl cmp -cmd ir -ref <passcode alternate_id> -secret pass:<passcode> -newkey … -subject /CN=… -implicit_confirm` – 0.86 s |
| CMPv2 factory certificate | signature protection: `-cert factory.crt -key factory.key` **plus `-extracerts factory.crt`** (without it: *"Error while reading the certificate in the extraCert field"*); plain host, no mTLS needed – 0.66 s |
| **Deleted policies are soft-deleted** | `GET …/certificate-policy/{id}` returns `status: DELETED`; the **name stays reserved** ("already exists") → a run ID cannot be reused after rollback (affects UC-1/UC-2 too) |
| **Profile of a deleted policy cannot be deleted** | *"referenced by a certificate management policy"* even after the policy is deleted → the per-run CMP profile can only be **disabled** (residue: one disabled `robot-…-cmp-profile` per CMPv2 run). The portal refuses the delete with the same error (author, 2026-10-24) – DTM behaviour, to be reported to DigiCert |

## Renewal in the field – Essentials (verified live 2026-10-24)

EST policy without device group (Essentials), authentication policy with a passcode only: enrollment with
the passcode, then `simplereenroll` on `clientauth.<host>` with the **issued device certificate as mTLS
client certificate** (no passcode, no factory certificate) → `200`, renewed certificate with the same CN,
new serial, new validity (2.6 s). Policy default `est_request_parameters.renewal_authentication_mode:
RENEWING_CERTIFICATE_ONLY`. The old certificate stays **issued** (not revoked automatically) – both count
as licenses. Candidate for a UC-4 "factory enrollment → renewal in the field".

## Open

1. CMPv2 profile residue – **implemented as recommended:** one shared `robot-uc03-cmp-profile` per account, created by the first CMPv2 run from the selected profile, found by name later, kept on full rollback (the only documented residue). Per-run profiles would leave one undeletable profile per run. The author can still decide otherwise.
2. Run-ID reuse – **decided 2026-10-24:** no check; the default run ID is 6 random `[a-z0-9]` characters.
