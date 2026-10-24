# Guided evergreen entry and shared profiles

> Decided with the author 2026-10-24, implemented the same day.

## One guided entry for UC-1 to UC-3

The home page offers **Evergreen Device IDs** (guided) and **UC-4** (renewal in the field). The guide asks:

1. Where is the key pair generated? – in DTM (server-side) / in the factory
2. How many devices at once? – batch (count) / single device (**always exactly one certificate**)
3. Single + factory keys only: protocol – REST API / EST / CMPv2, then the factory's authentication –
   API key (REST only) / passcode / factory certificate
4. Batch, server-side single, or REST + API key: via API (measured) / in the DTM web UI

The answers resolve to the existing engines (`evergreen.resolve_guide`); run data and object names keep
`uc01` / `uc02` / `uc03`. Old links `/runs/new/uc01…uc03` redirect to the guide. Questions that do not
apply are hidden and disabled (`data-when`, `app.js`); the server resolves and checks again.

## Shared certificate profiles per account

Each purpose uses its own profile with a fitting validity – but DTM refuses to delete a profile that any
(even deleted) policy referenced, verified live twice. So profiles are **shared and reused**, never per run:

| Profile | Used by | Settings |
|---|---|---|
| `robot-evergreen-5y-profile` | UC-1, UC-2, UC-3 (REST, EST) | 5 years |
| `robot-evergreen-cmp-5y-profile` | UC-3 CMPv2 | 5 years, bare public key |
| `robot-renewal-6m-profile` | UC-4 | 6 months, renew valid certificate any time |

Process for colleagues using their own account:

1. **Names carry the validity** – a release that changes a setting creates a new profile instead of
   altering one other installations rely on.
2. **Transparency first:** Settings shows per connection which shared profiles exist (read only, loaded lazily).
3. **Created only with notice:** the run form says "created once by this run, DTM keeps it" when one is
   missing; the run creates it from the account's basic client profile (else the first active profile).
4. **Template limits:** if DTM does not apply the settings (e.g. the template caps the validity) the new
   profile is disabled and the run stops with a clear message.
5. **Foreign profile with the same name** but other settings: never used or changed – "fix or rename it".
6. **Several installations, one account:** a name clash on create → look again and use the existing one.
7. **Opting out:** Settings → Shared profiles (loaded on demand) → "Retire shared profiles" disables them
   (DTM cannot delete them) – refused while the connection has runs that are not rolled back; a later run
   that needs one enables it again. The legacy `robot-uc03-cmp-profile` of earlier releases is retired too.

They are the only residue a full rollback leaves, besides revoked certificates and the audit log.
