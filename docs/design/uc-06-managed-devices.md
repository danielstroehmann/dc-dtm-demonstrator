# UC-6 – Managed devices (Advanced license)

The factory creates each device in DTM – named `robot-<run>-uc06-minion-<nnnn>` – with an inventory attribute,
a fictitious hardware identity, and gets its first certificate **for that device**. The certificate does **not**
carry the device name: its CN is the identity, and DTM files it under the right device through the group's
attribute mapping. The run page shows both side by side ("Devices in DTM": device name | identity (CN) |
certificate | status). Renewal per click renews every device; the new certificate lands under the same device.
Single device or a batch of singles (sequential, timed).

Engine: `app/devices.py` (reuses `app/enrollment.py`: Station, credentials, renewals, steps – with the
device-group endpoints); DTM client: `app/dtm.py` (`# devices`).

## Choices (form)

| Question | Options | Rule |
|---|---|---|
| Factory enrollment | REST API · EST · CMPv2 | |
| Authentication | API key (REST only) · Passcode · Factory certificate | |
| Field renewal | EST · CMPv2 (the device renews itself with its current certificate) · REST API (the backend renews) | any, independent of the factory: the policy carries both methods |
| Certificate identity | Serial number `SN-<RUN>-<nnnn>` · MAC address `02:<2 bytes of sha256(run)>:<device number>` (locally administered, never a vendor OUI) | deterministic, unique per run and device |

## Flow

| Phase | Calls |
|---|---|
| Setup | division → [authentication policy + passcode / factory certificate] → profile (`PROFILE_RENEWAL`, CMPv2: `…_CMP`) → policy with the protocol, `require_device_group_for_enroll: true` → [CMPv2: short ID + CA chain] → device group (static, `attributes: [serial_number \| mac_address]`, policy as `bootstrapCertificate`, mapping attribute → `subject.common_name`) |
| Per device | key + CSR (CN = identity) → `POST /device/enroll` with `attributes: [{key, value: identity}]` → certificate on the device-group endpoint (REST: `device_group_id` + `device_id`) → check CN = identity |
| Proof | `GET /device/certificates?device_id=` – every certificate under the device carries its identity (after registration and every renewal) |
| Renewal (click) | per device, new key: REST `PUT …/certificate/{current id}/renew` (the current ID read from DTM first) · EST `simplereenroll` (mTLS, group path) · CMPv2 `kur` (group path) |
| Rollback | revoke by policy → device: disable + delete → group: disable + delete → policy → profile → credentials → division |

## Live facts (NL, 2026-10-26)

- `GET /api/v4/device-group/attributes`: the device-name inventory key is `device_name`.
- Group create: a policy assignment **needs `status: "ACTIVE"`** ("Policy assignment status is required").
  The answer carries **no ID** (`DEVICE_GROUP_CREATED_200`) – looked up by name; the list filters by `name`.
- `POST /device/enroll` → 201 `{device_id, device_status: ENROLLED, operational_status: ENABLED}`.
- Certificate request with `device_id` → `device: {id, name, new_device: false}` in the answer.
- `/device/certificates` lags a moment behind an issuance (`total: 1`, `records: []`) – read with retries.
- Renewal with the API key by certificate ID and a new CSR: 200; the new record has
  `renewed_from_certificate_id`, the old one `is_renewed: true`, `renew_allowed: false` and stays ISSUED.
- Device and group delete **only when disabled** (error codes 23 / 24); delete is soft (listed 14 days).
- **Deleting a device does not revoke its certificates** – the rollback revokes first.
- The device endpoints ignore `account_id`: the client checks `account_id` on the object before disable/delete.
- Deleted names stay reserved (profile name clash seen live) – every name carries the run ID.

### Factory protocols and identity (NL, 2026-10-26)

- **Device-group endpoints** – only these file the certificate under the device:
  - EST `/.well-known/est/devicetrustmanager/<policy>/device-group/<group>/simpleenroll` (passcode), renewal
    `…/simplereenroll` on `clientauth.<host>` with the current certificate: both land under the device.
  - CMPv2 `…/cmp/DIOT_<short id>/device-group/<group>` – **not documented**; `ir` and `kur` land under the device.
    The plain CMPv2 path issues, but the certificate is **not** filed under the device.
  - REST: `device_group_id` + `device_id` in the body.
- **Inventory attribute at the device:** `POST /device/enroll` takes `attributes: [{key, value}]`
  (`serial_number`, `mac_address` – keys from `GET /device-group/attributes`); `GET /device/{id}` returns them.
- **Mapping by attribute, not by name:** group `attributes: ["serial_number"]` (or `mac_address`) and the mapping
  `serial_number → subject.common_name`. Device `robot-…-minion-0001`, CN `SN-…-0001`: EST and CMPv2 file the
  certificate under the pre-created device (status `ENROLLED` → `REGISTERED`).
- **REST: `device_id` wins.** A CN that matches no device's attribute is filed under the named device as well – DTM
  does not check the mapping. The app checks CN = the device's identity itself.
- **EST: a value that matches no device** is issued and DTM **creates a new device** `Device-<uuid>` in the group
  (status `REGISTERED`). Documented only – the app never sends such a value.
- **SAN:** the account's client certificate templates have no SAN field (only the TLS/SSL templates allow DNS names,
  `include: "no"/"optional"`); the profile copies the client template. The identity is in the CN only – a SAN
  would need an own template, i.e. a change of the account's configuration.
- **One policy, two protocols:** a policy may carry `SINGLE`, `EST` and `CMP_V2` together (`EST + CMP_V2` and
  `SINGLE + CMP_V2` need a bare-key profile, else "Please select certificate profile with allowed bare public key").
  Factory REST → field CMPv2 `kur`, factory EST → field CMPv2, factory REST → field EST `simplereenroll`: the
  renewed certificate is filed under the same device (`enrollment_method` of the new record: the field's).
  With the API key in the factory and EST/CMPv2 in the field the policy gets an authentication policy without
  credentials (the device authenticates with its certificate).
- **Verified through the app** (one device each, full rollback afterwards): EST + passcode + MAC, field EST;
  CMPv2 + factory certificate + MAC, field REST; REST + API key + serial, field CMPv2; EST + factory certificate + serial, field REST; REST + factory
  certificate + serial. So: the factory certificate works on all three device-group endpoints, the MAC mapping on
  EST and CMPv2, and the API-key REST renewal of EST/CMPv2 certificates (also with the bare-key CMPv2 profile and
  a CSR). The REST renewal answer carries `device: {id, name}` like the request.

## Open

- License: an Essentials-only account was not tested – the run fails with DTM's error at the group/device step.
- Rejected values: the app never sends an identity no device carries – see "Live facts" for what DTM does then.
