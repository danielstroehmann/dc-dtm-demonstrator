# Guided evergreen entry and shared profiles

> Decided with the author 2026-10-24, implemented the same day.

## One guided entry for UC-1 to UC-3

The home page offers **Evergreen device certificates** (guided, UC-1..UC-3) and **Renewable device certificates** (UC-4). The guide asks:

1. Where is the key pair generated? – in DTM (server-side) / in the factory
2. How many devices at once? – batch (count) / single device (**always exactly one certificate**)
3. Single + factory keys only: protocol – REST API / EST / CMPv2, then the factory's authentication –
   API key (REST only) / passcode / factory certificate
4. Batch, server-side single, or REST + API key: via API (measured) / in the DTM web UI

The answers resolve to the existing engines (`evergreen.resolve_guide`); run data and object names keep
`uc01` / `uc02` / `uc03`. Old links `/runs/new/uc01…uc03` redirect to the guide. Questions that do not
apply are hidden and disabled (`data-when`, `app.js`); the server resolves and checks again.

## Certificate profiles per platform (author, 2026-10-25)

Only two DTM platforms are supported (`dtm.PLATFORMS`); any other host is refused when a connection is
saved and when a run starts:

| Platform | Profiles | Why |
|---|---|---|
| `one.nl.digicert.com` | **one per run** – `robot-<run>-<uc>-profile`, created by the run, deleted by the full rollback after its policy (soft delete – stays as DELETED, like the auth objects) | NL deletes a profile once no policy uses it (verified live, also with revoked certificates under the policy) |
| `one.digicert.com` | **shared per account** (below) | US still refuses to delete a profile a deleted policy used – a DTM bug; shared until it is fixed |

The per-run profile is a copy of the account's basic client profile with the purpose's settings (same
specs as the shared ones); its reproducible step is the `POST` with that body. Deleted profile names stay
reserved, which is harmless for per-run names.

## Shared certificate profiles per account (US)

Each purpose uses its own profile with a fitting validity – but DTM refuses to delete a profile that any
(even deleted) policy referenced, verified live twice. So profiles are **shared and reused**, never per run:

> **Changed DTM behaviour (verified live 2026-10-25, NL account):** a profile can now be deleted
> (`PUT …/certificate-profile/{id}/delete` → 204) after the policy that used it was deleted – tested with
> profile → division → policy → delete policy → delete profile (first without certificates, then in a full
> run with a revoked certificate under the policy).
> The author also deleted the shared profiles in the portal. **US (one.digicert.com) still refuses** the
> same sequence ("referenced by a certificate management policy", same day) – the environments run
> different DTM releases, so shared profiles stay. Deleted profile names stay reserved (a new profile of
> that name → 400 "already exists"); deleted profiles are listed with `status=DELETED` and
> `PUT …/{id}/undelete` restores them – `shared_profile` does that when the shared profile was deleted
> in the portal.

| Profile | Used by | Settings |
|---|---|---|
| `robot-evergreen-5y-profile` | UC-1, UC-2, UC-3 (REST, EST) | 5 years |
| `robot-evergreen-cmp-5y-profile` | UC-3 CMPv2 | 5 years, bare public key |
| `robot-renewal-6m-profile` | UC-4 | 6 months, renew valid certificate any time |

Process for colleagues using their own account:

1. **Names carry the validity** – a release that changes a setting creates a new profile instead of
   altering one other installations rely on.
2. **Transparency first:** Settings shows per connection which shared profiles exist (read only, loaded lazily).
3. **Created only with notice:** the run form says "created or restored by this run, DTM keeps it" when one
   is missing; the run restores a profile of that name deleted in the portal (if its settings match – else
   it stops with a clear message), otherwise creates it from the account's basic client profile (else the
   first active profile).
4. **Template limits:** if DTM does not apply the settings (e.g. the template caps the validity) the new
   profile is disabled and the run stops with a clear message.
5. **Foreign profile with the same name** but other settings: never used or changed – "fix or rename it".
6. **Several installations, one account:** a name clash on create → look again and use the existing one.
7. **Opting out:** Settings → Shared profiles (loaded on demand) → "Retire shared profiles" disables them
   (the app never deletes them; US refuses it anyway) – refused while the connection has runs that are not rolled back; a later run
   that needs one enables it again. The legacy `robot-uc03-cmp-profile` of earlier releases is retired too.

They are the only residue a full rollback leaves, besides revoked certificates and the audit log.
