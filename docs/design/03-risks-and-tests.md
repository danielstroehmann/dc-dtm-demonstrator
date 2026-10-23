# Risks and required test cases

> Status: living document, as of 2026-10-23. Every risk that can be detected automatically
> gets a test case. Tests marked **[live]** run against a real DTM test account.

## Risks

| ID | Risk | Impact | Mitigation |
|---|---|---|---|
| R-1 | **Undocumented UI API** `DELETE …/certificate-configuration-service/api-ui/v1/certificate-policy/{id}` is the only known way to delete a certificate policy. It may change or disappear without notice. | Full cleanup leaves orphaned policies in the account | Encapsulate in the DTM client, use only for cleanup, fail loudly, covered by T-1 |
| R-2 | Deleting a division does **not** cascade – policies survive as orphans pointing to a deleted division. | Leftovers if the cleanup order is wrong | Fixed cleanup order: certificates → policies → division; covered by T-2 |
| R-4 | **Mass revocation is unreliable and slow**: no bulk endpoint; a normal revoke returns `204` in ~1–3 s, but under load single requests hang for minutes; with 32 parallel calls DTM congested completely for several minutes. Many requests that time out on the client **still complete server-side**. The `status=issued` list lags behind (eventual consistency) – a re-revoke then returns `400`. | Cleanup of a 1000-certificate batch can take 10–60 min | Failsafe revoke: **short per-request timeout (8 s)**, moderate parallelism (≤ 16), work in passes: re-list `ISSUED` → revoke → repeat until none left; treat `400` on an already revoked certificate as done; back off when most requests time out; resumable background job with progress in the UI; covered by T-4 |
| R-5 | **Eventually consistent certificate lists**: right after issuance the `status=issued` list can be empty. For API runs cleanup compares against the known number of issued certificates (`expected`); for **web UI runs** the number is unknown, so only the 3 s confirmation re-list protects against deleting the policy too early. | A portal-issued certificate could stay `ISSUED` under a deleted policy | Residual risk accepted for v0.1; mitigation idea: let the presenter enter the number of issued certificates, or re-check after cleanup |
| R-6 | `slowapi` 0.1.10 uses `asyncio.iscoroutinefunction`, removed in Python 3.16. | Login rate limit breaks on a future Python upgrade | Revisit before moving to Python 3.16 |
| R-3 | The OpenAPI spec is incomplete or wrong in places (missing required fields, wrong types, create calls without ID in the response). | Calls fail at runtime | Every used endpoint has a [live] test; lessons recorded in the research notes |

## Test cases

| ID | Type | Description | Pass criterion |
|---|---|---|---|
| T-1 | [live] | Create a `robot-` certificate policy, delete it via `api-ui/v1` with the API key | `204`, policy no longer listed |
| T-2 | [live] | Full UC run followed by full cleanup | No `robot-<run-id>-` object remains in the account (divisions, policies, active certificates) |
| T-3 | [live] | `api-ui` delete with a non-existent ID | `404 entity_not_found` (proves auth via API key still works) |
| T-4 | [live] | Cleanup of a run with ≥ 100 certificates, interrupted and resumed | All certificates `REVOKED` after resume, no duplicate errors |
| T-5 | [ref] | Fresh install on the reference server via one-liner (`--branch` / `--version`) | UI reachable via HTTPS, login works, health endpoint OK |
| T-6 | [ref] | Upgrade: previous release → new release on the same `./data` | Comes up healthy, data intact, migrations applied once |
| T-7 | [ref] | Uninstall/purge after a test run | Package list, listening ports and filesystem match the baseline (diff against a recorded baseline inventory) |

## Test concept

### Stage 1 – local

- `docker compose` from the working tree.
- Runs the [live] tests against the DTM test account.
- Ends with a **clean-account check**: no object with the run's `robot-<run-id>-` prefix
  remains (divisions, policies, issued certificates).

### Stage 2 – reference server [ref]

Tests run as `root` via SSH (no sudo prompt). **Snapshot rollbacks are done manually by the
author and should be avoided wherever possible** – no automated access to the hypervisor.

1. Run the one-liner via SSH (`--branch <name>` or `--version vX.Y.Z`).
2. Smoke test (T-5).
3. Upgrade test (T-6): install the previous release, then the new one on the same data.
4. Return to baseline with the installer's own **uninstall/purge** (T-7) – removes containers,
   images, volumes, `./data`, and Docker itself if the installer added it.
5. Only if T-7 fails or the machine is unclear: ask the author for a manual snapshot rollback.

Option: test without pushing images – transfer locally built images with
`docker save … | ssh <reference server> docker load` and let the installer skip the pull.


## Reference machine & verified results

### Reference machine (as of 2026-10-23)

| Property | Value |
|---|---|
| OS | Ubuntu 26.04.1 LTS (resolute), **server-minimal** (`ubuntu-server-minimal`, `unminimize` available) |
| Kernel / arch | Linux 7.0.0-38-generic, x86_64 (amd64) |
| Virtualization | KVM (Proxmox), restorable via snapshot |
| CPU / RAM / disk | 16 vCPU (QEMU virtual CPU), 7.2 GiB RAM, 40 GB root (LVM), 31 GB free |
| Preinstalled | `curl` 8.18, `wget` 1.25, `ca-certificates`, `gnupg`, `openssl` 3.5 – 516 packages |
| Not installed | Docker (any variant), containerd, `git`, `jq`, `unzip`, `ufw` |
| User / sudo | Tests connect as `root` via SSH key; the regular user's sudo requires a password |
| Network | Single NIC, DHCP, private LAN; outbound HTTPS to `one.digicert.com` works |
| Firewall / ports | No firewall (no ufw, empty nftables/iptables); only SSH (22) and the local DNS stub listen |
| Time | UTC, NTP synchronized |

Consequences: the one-liner can rely on `curl`; the installer must install Docker itself.
Stage-2 tests run as `root` (no sudo). Before the first install, a **baseline inventory**
(package list, listening ports, relevant directories) is recorded for T-7.

### Verified results

| Date | Basis | What | Result |
|---|---|---|---|
| 2026-10-23 | commit `d0399d0` (design only, no code) – live calls against the DTM test account | UC-1 setup: division + certificate policy (SINGLE + BATCH, server-side P-256, ECDSA ICA) via management API | Works (see spec deviations in [uc-01-evergreen.md](uc-01-evergreen.md)) |
| 2026-10-23 | same | UC-1 single issuance via API (server-side key, PEM) | Works, **~6 s** per call, 1-year validity, issued by the ECDSA ICA |
| 2026-10-23 | same | UC-1 batch issuance, measured from end of upload to job status `completed` (0.5 s polling) | **10 → 2.1 s, 100 → 12.8 s, 1000 → 121.8 s** (≈ 0.12 s per certificate, linear); server `processing_time` matches |
| 2026-10-23 | same | Batch result | CMS envelope (`.p7m`, `application/pkcs7-mime`) encrypted to the certificate passed in `encryption_certificate`; decrypts with `openssl cms -decrypt` to a ZIP with `Line-NNNNNNNN.pem`, `Line-NNNNNNNN-key.key`, `full_results.txt`; CNs and serials verified |
| 2026-10-23 | same | Cleanup: revoke 1231 certificates | Works with the failsafe pass approach (R-4); naive long timeouts / high parallelism stall |
| 2026-10-23 | same | T-3: `api-ui` delete with fake ID | **Pass** – `404 entity_not_found` |
| 2026-10-23 | same | T-1: delete policy via `api-ui` (with 1231 revoked certificates attached) | **Pass** – `204` |
| 2026-10-23 | same | T-2: full cleanup + clean-account check | **Pass** – 0 `robot-` divisions/policies, 0 auth policies, 0 device groups, 0 devices, 0 issued certificates. Remaining by design: 1231 revoked certificates, 6 batch jobs (expire after 30 days) |
| 2026-10-23 | reference server | Read-only analysis | See reference machine above; nothing installed |
