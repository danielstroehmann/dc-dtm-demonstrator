# UC-5 – Passcode-bound device certificates

> Status: implemented 2026-10-25 (author request). Engine: `app/enrollment.py` (`uc05`).

## Story

In the factory the device only receives a **one-time passcode**. The certificate's properties are bound
to that passcode – above all the common name. In the field the device uses the passcode once to enroll
via **EST or CMPv2** (selectable).

## How DTM supports it (verified live on NL, 2026-10-25)

| Question | Finding |
|---|---|
| Bind the CN to a passcode | `registered_values: [{certificate_field: "subject.common_name", matcher: "equals", value: …}]` on `POST …/passcode` – accepted although the OpenAPI spec documents it for authentication certificates only |
| Does DTM **override** a different CN in the CSR? | **No.** It checks: EST answers 400 *"Invalid registered value provided in attribute: subject.common_name"*, CMPv2 *PKIStatus rejection / badRequest*. No profile source takes the value from the credential (`csr`, `user_supplied`, `fixed_value`, `allow_bare_public_key` only; `registered_value`, `passcode`, `credential` … are refused). Author decision: **check instead of override**. |
| One device only | `usage_limit: 1` – a second request gets *"Passcode has reached its usage limit"* (CMPv2: *Protection is not valid*). |
| A rejected request | **uses up the passcode** (`number_of_usage` 1 of 1) – a device that once sends a wrong CSR cannot enroll any more. Worth reporting to DigiCert. |

## Flow

Single device or a batch of up to 100 devices (`MAX_PASSCODE_BATCH` – every device costs a passcode, an
enrollment, a revoke and a passcode delete, one after another).

1. **One-Time Setup:** division, authentication policy, certificate profile (per platform, see
   `05-guide-and-shared-profiles.md`), policy (EST or CMPv2), for CMPv2 the policy's short ID and CA chain.
   The passcodes only follow once this succeeded – nothing is created for nothing.
2. **Factory Provisioning (per device, timed):** `robot-<run>-uc05-passcode-0001…`, each with usage limit 1
   and bound to its device's CN (`robot-<run>-uc05-<protocol>-0001…`), one request after another.
   Statistics: all passcodes, time per passcode, per minute, median, estimate for 1,000 passcodes.
   CMPv2 also reads the passcode reference (sender KID).
   **Pause (optional, on by default – author, 2026-10-26):** the run then stops with status `paused` so the
   presenter can show the passcodes in the DTM portal; *Enroll devices* (`POST /runs/{id}/enroll`) continues.
   The passcodes stay in the task's memory only (a restart interrupts the run), at most 60 minutes, and a
   rollback ends the wait.
3. **Enrollment in the Field (per device, timed):** key (+ CSR) on the device → EST `simpleenroll` / CMPv2
   `ir` with *its own* passcode → certificate; statistics as UC-3. The run fails if a certificate carries
   a name without a passcode.
4. **Checks (optional, on by default):** device 0001 enrolls again with its used passcode → rejected; a
   passcode for a device outside the batch (`…-passcode-check`) with a CSR for another CN → rejected; that
   passcode's usage afterwards (live: used up). Only DTM's answer counts as a rejection (EST 4xx, CMPv2
   `PKIStatus: rejection`) – a timeout or network error shows as "inconclusive". A failing check never
   fails the run. A certificate a check gets anyway is revoked by the rollback.

Rollback: as UC-3 – certificates, policy, profile (NL), all passcodes (unrecorded ones found by the prefix
`robot-<run>-uc05-passcode-`, own account only), authentication policy, division. Deleted passcodes are not
listed any more (verified live), so the list does not grow with every rollback.
