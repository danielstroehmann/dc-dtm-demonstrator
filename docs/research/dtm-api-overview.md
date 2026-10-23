# DigiCert Device Trust Manager (DTM) – API overview

> Status: research note, as of 2026-10-23. Sources below. Full endpoint index:
> [dtm-api-endpoints.md](dtm-api-endpoints.md).
> Lessons learned from a predecessor demo project (not public) are marked **[Practice]**.

## 1. What DTM is

DTM is the IoT product of the DigiCert ONE platform: identity and lifecycle management for
devices – from manufacturing to decommissioning.

| Phase | DTM capability |
|---|---|
| Design | Crypto agility incl. PQC (ML-KEM, ML-DSA, SLH-DSA), hardware keys (TPM2, ARM TrustZone) |
| Build / manufacturing | Single and batch certificate issuance via REST, EST, SCEP, CMPv2, ACME; client- or server-side key generation; on-prem gateway for manufacturing |
| Operate | Zero-touch provisioning into cloud platforms (AWS, Azure IoT DPS / Event Grid), OTA updates, automated certificate lifecycle, fleet monitoring |

Two device-side components belong to it:

- **TrustEdge** – ready-made agent (Linux, Zephyr RTOS), runs as `trustedge.service`
  (agent mode, connects to DTM via MQTT 3.1.1/5.0) or as a CLI
  (`trustedge certificate est|scep`, `trustedge mqtt`, `trustedge agent --reset`).
  Can report inventory attributes, install artifacts (updates/scripts), keys in TPM2.
  CLI free for non-commercial use.
- **TrustCore SDK** – library for custom agents (when TrustEdge does not fit).

## 2. Two API families

| | Management REST API | Certificate issuance APIs |
|---|---|---|
| Caller | Backend, manufacturing systems, admin tools | Device or factory station |
| Purpose | CRUD on divisions, device groups, devices, policies, artifacts, releases, deployments … | Issue/renew X.509 certificates |
| Protocols | REST/JSON | EST, SCEP, ACME, CMPv2, REST |
| Auth | Service user: `x-api-key` **or** mTLS client certificate via `clientauth.<host>` | Authentication policy: passcode (`x-passcode`), auth certificate, auth CA (mTLS), ACME credential |

**Hosts:** `one.digicert.com` (prod), `demo.one.digicert.com` (demo/PoC), regional variants
(e.g. `one.digicert.co.jp`). mTLS always via the `clientauth.` prefix.

**Path scheme:** `https://<host>/devicetrustmanager/<service>/api/v<n>/<resource>`
– the API is split into microservices internally, with **different versions per service**:

| Service path | Content |
|---|---|
| `/api/v4` | Device, device group, division, bootstrap config, rendezvous zone, labels, device logs |
| `/artifacts/api/v4` | Artifacts (upload via TUS) |
| `/release/api/v4` | Releases, deployments, API helper |
| `/certificate-issuance-service/api/v1,v2` | Request/renew/revoke certificates, ACME |
| `/certificate-configuration-service/api/v1,v2` | Certificate policies, profiles, templates, issuing CAs, trust bundles, registered values |
| `/authentication-service/api/v1,v2` | Authentication policies, passcodes, auth certificates |
| `/certificate-batch-service/api/v1` | Batch jobs (registration, enrollment, passcode import) with approve/reject |
| `/cloud-platform-policy/api/v4` | Cloud onboarding (AWS, Azure IoT DPS, Azure Event Grid), MQTT brokers |
| `/blueprint-service/api/v1` | Blueprints – **not used by this project** (see `CLAUDE.md`) |
| `/audit-log-service/api/v1` | Audit log |
| `/api/v1/secure-object` | Secure objects (managed files/secrets for devices) |

Scope per OpenAPI spec: **343 operations** in ~38 tags.

## 3. Object model

```
Account
└── Division (tenant separation/delegation; default division)
    ├── Certificate management policy ──► certificate profile/template ──► issuing CA
    │        └── Enrollment method (TrustEdge | EST | SCEP | ACME | CMPv2 | REST | batch)
    ├── Authentication policy (passcode | auth certificate | auth CA | ACME credential)
    │        └── Constraints: usage limit, validity window, registered values
    ├── Device group ──(linked)── certificate policies + authentication policies (+ cloud platform policy)
    │   └── Device ──► certificates (bootstrap → operational)
    ├── Artifact ──► release (bound to device groups) ──► deployment (rolled out to devices)
    ├── Trust bundle, secure object, registered values
    └── Rendezvous zone (onboarding zone, own certificate)
```

**Device states:** `Registered` (identity, no certificate yet) → `Provisioned` (valid
certificate) ⇄ `Disabled` (inactive, certificates stay valid) → `Deleted` (final, revokes
certificates). Additionally `ENROLLED` via `POST /device/enroll` (device without certificate
policy).

**Deletability:** certificate policies have **no delete/disable endpoint** (create, read,
update only). Divisions, authentication policies, device groups and devices can be deleted.
Device registration includes a **license check**.

## 4. Core flows (demo-relevant)

### a) Setup (one-time, admin)
Division → certificate policy (incl. enrollment method) → authentication policy (e.g.
passcode) → link device group. Helpful: `GET .../certificate-policy/{id}/enrollment-specification`
and `/example-request` return the required fields and example requests.

### b) Device identity
- **Zero touch with TrustEdge (EST)** **[Practice]**: CA certs from `/cacerts` → bootstrap
  certificate via `trustedge certificate est` (passcode) → load bootstrap config via mTLS
  (`clientauth.`) → start agent → device appears in DTM.
  EST URL pattern: `https://clientauth.<host>/.well-known/est/devicetrustmanager/IOT_<tenant>/device-group/<group>/simpleenroll` (or `simplereenroll`).
- **Registration via API**: `POST /api/v4/device/registration` (also with `x-passcode` or mTLS instead of API key).
- **Batch**: `POST /certificate-batch-service/api/v1/jobs/device-registration` or `/certificate-enroll`,
  with approval workflow. `certificate-enroll` accepts a ZIP of CSRs or a CSV (client-side
  keys via `csr` column) or uses server-side key generation (profile must allow it); max. 200 MB.

### c) Certificate lifecycle
`POST /certificate-issuance-service/api/v2/certificate` (request), `PUT .../{id}/renew`,
`PUT .../{id}/revoke`, status by ID/serial number, download in various formats.
Fleet metrics incl. **PQC-vulnerable/PQC-safe** and "expiring soon": `GET /api/v4/device/metrics`.

### d) OTA update **[Practice]**
Artifact upload via **TUS (3 steps: create → PATCH → finalize POST!)** → `POST artifact`
(`is_draft:false`, install action) → `POST release` (bound to device group, `artifact_ids`
as `[{id, order}]` – the OpenAPI type is wrong) → `POST deployment` → status via
`/deployment/{id}/summary`, abort via `/abort`. Release and deployment require an **active**
`division_id`.

### e) Cloud onboarding
Cloud platform policy (AWS / Azure IoT DPS / Azure Event Grid) + `POST /api/v4/cloud-platform-policy/cloud-provision`
→ the device is created in the cloud IoT platform with its DTM identity.

### f) Observability
Audit log, device/artifact/release/deployment logs, dashboard, scheduled reports, alert settings.

## 5. Known pitfalls [Practice]

1. Header in practice `X-API-KEY` (case-insensitive); list endpoints expect `account_id` and return `{ total, records }`.
2. TUS upload without the final finalize POST yields an artifact usable only as a draft.
3. `artifact_ids` in a release is an object array – the spec is wrong here.
4. `/division/default` returns `null` under API-key auth; deactivated divisions lead to `division.not.active`.
5. EST `simpleenroll` occasionally throws a transient `-8600 ERR_HTTP` → retry needed.
6. The TrustEdge agent crashes on empty/corrupt `desired_attributes.pb`/`metrics.pb` (`ERR_BASE64_BAD_INPUT`) → self-heal needed.
7. Update pickup is delayed by the agent's poll interval – relevant for live demos.
8. The agent needs IPv4 localhost (`::1` in `/etc/hosts` interferes).
9. Division create needs `primary_rzone_id` and returns no ID; policy create needs per-method
   parameter blocks; batch enroll needs `input_format=csv` and the field `encryption_certificate`
   (spec: `certificate`); batch `data_available` is true before completion – details in
   [UC-1](../design/uc-01-evergreen.md).
10. Certificate policies can only be deleted via the undocumented `api-ui/v1` path (R-1);
   deleting a division does not cascade (R-2); mass revocation is slow (R-4) – see
   [risks](../design/03-risks-and-tests.md).
11. → The **spec is not fully reliable**; every endpoint we use needs a real test against the demo environment.

## 6. Open research items

- What exactly is a **rendezvous zone** (onboarding concept, FDO-like?) and is it worth it for the demo?
- Can the agent receive **remote commands / desired attributes** (hint: `desired_attributes.pb`)? No docs found so far.
- Which **inventory attributes** does TrustEdge report, and how are custom ones reported (tutorial "Report custom inventory attributes")?
- **PQC demo**: MQTT with PQC (TrustEdge tutorial exists) + PQC metrics in the dashboard – strong demo topic.
- **Legacy IoT Trust API**: still relevant or ignore?
- Which roles does a service user need at minimum (least privilege instead of solution administrator)?
- Does deleting a division also remove its certificate policies? Are licenses freed immediately when a device is deleted?
- Minimum certificate validity allowed by a profile (needed for a visible renewal demo)? API rate limits?

## Sources

- API overview: <https://dev.digicert.com/device-trust-api.html>
- OpenAPI spec: <https://dev.digicert.com/api-reference/openapi/device-trust.json> (Swagger also at `https://one.digicert.com/devicetrustmanager/api-docs/index.html`)
- Management REST: <https://docs.digicert.com/en/device-trust-manager/tutorials/integrate-with-management-rest-apis.html>
- Certificate issuance: <https://docs.digicert.com/en/device-trust-manager/tutorials/integrate-with-certificate-issuance-apis.html>
- Authentication: <https://docs.digicert.com/en/device-trust-manager/references/understand-key-concepts/authentication.html>
- TrustEdge: <https://dev.digicert.com/trustedge.html>, <https://dev.digicert.com/trustedge/trustedge-as-a-service.html>
- Product overview: <https://docs.digicert.com/en/device-trust-manager.html>
- Practice: lessons learned from a predecessor demo project (not public)
