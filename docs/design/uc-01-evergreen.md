# UC-1 – Evergreen Device IDs for Factory Provisioning

> Status: requirements captured, questions open – as of 2026-10-23. No implementation yet.

## Requirements (from the author, 2026-10-23)

- Evergreen certificates are issued **individually** or as a **batch**.
- Each variant can be run **via API** (the demonstrator does it) or **via the DTM web UI**
  (the presenter does it in the portal).
- Batch: the operator sets the **number of certificates**.
- Batch via API: **measure the time from "ZIP upload complete" to "result download
  available"**. Measurement only in the API variant.
- Web UI variant: the demonstrator offers the prepared **ZIP / CSR as a download** so the
  presenter can upload it in the portal.
- Global rule applies: every call is scoped to the **configured account** (see vision, section 6).

## Variant matrix

| | API | Web UI |
|---|---|---|
| Individual | Demonstrator calls `POST /certificate-issuance-service/api/v2/certificate` | Demonstrator offers the request values (see open question 1); presenter issues in the portal |
| Batch | Demonstrator uploads ZIP to `POST /certificate-batch-service/api/v1/jobs/certificate-enroll`, polls the job, measures | Demonstrator offers ZIP download; presenter uploads in the portal |

## Decisions (2026-10-23)

| # | Topic | Decision |
|---|---|---|
| 1 | Evergreen | Example validity **1 year** is enough for the demo |
| 2 | Keys | **Server-side key generation** by DTM – simplest case, least effort for the customer |
| 3 | Measurement | Start = **end of the ZIP upload / API call** (job created). End = **job status endpoint reports "ready"** (polling) |
| 4 | Approval | Off by default. **Optional**: if selected, the demonstrator approves immediately via API – illustrates the request/approve round trip without waiting |
| 5 | Count | Operator sets the number of certificates. Each certificate consumes an **Essential license** |
| 6 | End of UC | Ends after issuance. The demonstrator **illustrates DTM's response**: parse the result (e.g. CN, serial, validity, issuer, key type per certificate). Private keys are never displayed |
| 7 | Web UI variant | **No device group needed** (Essential license). The demonstrator generates the upload artifacts (batch ZIP / single request) for manual upload in the portal |
| 8 | Results | Shown **per run only**, no history |

## Consequences

- No devices, no containers in UC-1 – it is a pure issuance use case against the DTM API.
- The result ZIP contains **private keys** → stored only under `./data/runs/<run-id>`, deleted
  on cleanup.
- Cleanup = revoke the issued certificates (and remove setup objects in *full* mode). For the
  web UI variant the demonstrator does not know the IDs → find the certificates via the
  `robot-<run-id>-…` names (CN) that the generated artifacts contain.

## Resolved questions

1. **Single request in the web UI** (server-side keys, no CSR): the demonstrator shows the
   prefilled values (CN etc.) to enter in the portal – confirmed 2026-10-23.
2. **License release on revocation:** not verified; irrelevant in the test account (license
   consumption is no concern there).
3. **Batch input format** (server-side keys): ZIP with a CSV, header `subject.common_name`,
   one CN per line – verified in end-to-end test 2.

## Findings from the test account (2026-10-23, read-only)

- Host `one.digicert.com` (production platform); `demo.one.digicert.com` rejects the key (403).
- The API key sees **two accounts** – confirms the account-scoping rule.
- Test account is empty apart from defaults: no division, no certificate policy, no
  authentication policy, no issuing CA, no devices, no batch jobs. Default certificate
  profiles/templates exist (e.g. *Basic client certificate profile*).
- **Blueprints are not used** (author decision) – DTM objects are created with the regular
  management APIs only.
- **CAs (fixed baseline, use only, never modify):** the account has a root + issuing CA pair
  for ECDSA and for RSA, visible via the CA manager API `GET /certificate-authority/api/v1/ca`
  (not in DTM's `managed-ca` list yet):
  - ECDSA root → ECDSA issuing CA
  - RSA root → RSA issuing CA
  (names and IDs are account-specific; configured locally, not in the repo)
- To verify: how a certificate policy references one of these ICAs (`assignable-ca`), without
  changing the CA itself.
- License consumption is no concern in the test account; the account still has to be left
  clean after every test.

## API test 1 (2026-10-23, run ID `apitest1`)

- `POST /api/v4/division` needs `primary_rzone_id` in practice (error otherwise:
  "Primary zone ID is required if a secondary zone is present"). The response contains **no
  ID** – look the division up by name afterwards.
- `POST /certificate-configuration-service/api/v2/certificate-policy` with SINGLE + BATCH
  needs `single_cert_request_parameters` and `batch_request_parameters`, each with
  `encryption_certificate_source` (`"provided"` works without an uploaded certificate).
  Policy IDs look like `IOT_<uuid>`. `ica_id` = CA manager ID of the ICA.
- **Deleting a policy via API failed:** `DELETE`, `PUT|PATCH …/delete|/disable` (v1/v2, also
  `enrollment-profile`) return 400 with an HTML error page; `PUT` with `status` is ignored.
- **`DELETE /api/v4/division/{id}` succeeds even with an active policy in it – no cascade.**
  The policy stays `ACTIVE` and points to the deleted division (orphan).
  → Cleanup order must be: certificates → policies → division.
- The leftover policy was deleted by the author in the portal. Captured request:
  `DELETE /devicetrustmanager/certificate-configuration-service/api-ui/v1/certificate-policy/{id}`
  (body `{}`) → `204`. This **UI-internal `api-ui` path also accepts the API key** (a fake ID
  returns a proper `entity_not_found`, not an auth error).
  → Cleanup can delete policies via `api-ui/v1`. Risk: undocumented, may change without
  notice – wrap it, test it, fail loudly.
- After the test the account again has no `robot-` objects. A personal default
  division appeared (created 14:01 UTC, presumably by the portal on first login) – not ours,
  left untouched.

## End-to-end test 2 (2026-10-23, run IDs `apitest2*`)

Spec deviations and details found (all calls with `account_id`):

- **Single issuance:** `POST /certificate-issuance-service/api/v2/certificate` with
  `certificate_profile_attributes: [{id: "subject.common_name", value: …}]`,
  `server_side_key_gen: true`, `private_key_format: pem`, `private_key_syntax: pkcs8`.
  No device group needed. Response contains `pem`, `private_key`, `chain`, `serial_number`,
  `valid_from/valid_to`; status `AUTO_APPROVED`. Validity comes from the profile (1 year).
- **Batch (server-side keys):** `POST /certificate-batch-service/api/v1/jobs/certificate-enroll`
  as `multipart/form-data`:
  - `input_format=csv` is **required** (otherwise "CSR input not supported for server side key
    generation") – not marked as required in the spec.
  - The encryption certificate goes into **`encryption_certificate`** – the spec calls it
    `certificate` (that field is ignored: "Provide certificate or PGP public key").
    A self-signed certificate works; no registration in Account Manager needed.
  - CSV: header `subject.common_name`, one CN per line, zipped.
  - `emails` empty → DTM falls back to the API key owner's email address.
- **Job status:** `GET /jobs/{id}` → `status` `in_progress` → `completed`, plus
  `processing_time` (ms), `success_items`, `failed_items`. **`data_available` is already `true`
  while `in_progress`** – not usable as a "ready" signal.
- **Result:** `GET /jobs/{id}/download/result` → CMS envelope (`.p7m`), see
  [03-risks-and-tests.md](03-risks-and-tests.md#verified-results).
- **Certificate list:** `GET /certificate-issuance-service/api/v2/certificate?certificate_policy_id=…`
  returns status in upper case (`ISSUED`, `REVOKED`); paging via `limit`/`offset`.
- **Revoke:** `PUT /certificate/{id}/revoke` with `reason` (e.g. `cessation_of_operation`).
  Returns `204` on success, `400` if already revoked. Slow, no bulk endpoint, stalls under high
  parallel load; use the failsafe pass approach (R-4).
- **Cleanup revokes every certificate under the run's policy** (not only `robot-<run>-` CNs):
  the policy belongs to the run, so portal-issued certificates with other names are included.
- **Web UI runs (2026-10-25):** the demo assumes the order was really placed in the portal. Before
  revoking, the cleanup finds portal batch jobs under the run's policy (`GET /jobs` ignores a policy
  filter – filtered client-side by `certificate_policy_id` and `account_id`), waits for them and rejects
  those pending approval. Afterwards it looks up the run's device names (`common_name` filters exactly,
  across policies) and revokes issued ones under other policies – an order placed under the wrong
  policy. Batches above 20 devices: 10 names from each end first, all names only on a hit.
  Only for a run that reached the portal step with its own policy, and only certificates created after
  the run started – an older run may have used the same run ID. Record fields verified live: certificate
  list records carry `account_id`, `certificate_policy_id`, `job_id`, `created_at` at the top level; job-list
  records carry `account_id` and `certificate_policy_id`.
  Limits (accepted): a stray only in the unsampled middle of a large batch is not found; a portal job
  under a *wrong* policy is neither waited for nor rejected (not ours to touch).
- **Policy delete via `api-ui` works with revoked certificates attached**; then division delete.
  Verified cleanup order: revoke certificates → delete policy (`api-ui`) → delete division.
- Batch jobs cannot be deleted; they expire after 30 days (`expire_at`) – accepted residue (history).
