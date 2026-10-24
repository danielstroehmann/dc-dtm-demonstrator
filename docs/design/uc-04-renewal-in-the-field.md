# UC-4 – Evergreen Device ID with Renewal in the Field

> Status: implemented 2026-10-24 (`app/enrollment.py`, `renew`). Verified live: enrollment + renewal,
> cleanup without residue.

## Requirements (from the author, 2026-10-24)

- One device only – no batch.
- Enrollment in the factory, then **renewal in the field per click**, authenticated with the certificate
  the device already holds.
- Reproducible steps contain both, enrollment and renewal – as separate blocks, every API call on its own.

## Flow

| Phase | What happens |
|---|---|
| Setup | Division, authentication policy with the factory credential (passcode or factory certificate), EST policy – **no device group (Essentials)** |
| Factory enrollment | Key + CSR → EST `simpleenroll` → PEM. The simulated device keeps key and certificate in `<data>/runs/<id>/device/device.pem` (written atomically, 0600, never shown, removed on any cleanup) |
| Renewal in the field (per click, max. 5 per run) | New key + CSR → EST `simplereenroll` on `clientauth.<host>` with the **current device certificate as mTLS client certificate** → PEM; the device switches to the new key and certificate |

## Findings (live)

- Works on Essentials: policy default `est_request_parameters.renewal_authentication_mode:
  RENEWING_CERTIFICATE_ONLY`; same CN, new serial and validity.
- The previous certificate **stays issued** – DTM does not revoke it; every renewal consumes a license.
- Right after issuance DTM answers `401 est_unauthorized` for a few seconds; the renewal retries
  (max. 3 attempts, 3 s apart).
- A full rollback revokes all certificates of the policy (original and renewed).
- Verified live with both factory credentials (passcode, factory certificate); an immediate renewal got
  401 once and succeeded on the retry.
- The renewal block of the reproducible steps is shown right after the enrollment (untimed until the
  first renewal). A full copied script waits 10 s before `simplereenroll` because of the 401 window.
