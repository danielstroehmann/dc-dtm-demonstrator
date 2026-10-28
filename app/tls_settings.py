"""The demonstrator's own HTTPS certificate, set in Settings: a PEM pair or a PKCS#12 file, applied live; "Reset to
default" goes back to what .env configures. Validation is tls_setup's – this module only stores, swaps and reloads.

The files live in the directory Caddy serves from (host ./tls-live), shared with the `tls` service: cert.pem/key.pem
is what Caddy serves, settings-*.pem the uploaded pair (the admin's choice, which the `tls` service prefers at every
start) and default-*.pem what .env resolves to. A PKCS#12 upload is stored as the checked PEM pair – its password is
never stored.

Caddy does not watch certificate files. After swapping them, the app re-posts Caddy's running config to its admin API
with "Cache-Control: must-revalidate", which forces a reload that re-reads the files (what `caddy reload --force`
does). The admin API listens only on a unix socket in a volume that just the proxy and the app mount – no TCP port,
nothing reachable from the host network or the other containers. A config Caddy refuses leaves it running unchanged;
the previous files are then put back."""

import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.x509.oid import NameOID

from . import certinfo, tls_setup
from .tls_setup import ACTIVE, DEFAULT, EXPIRY_WARNING, MAX_SIZE, SETTINGS, TLSError

log = logging.getLogger("demonstrator")
LIVE = Path(os.environ.get("TLS_LIVE_DIR", "/tls-live"))
ADMIN_SOCKET = os.environ.get("CADDY_ADMIN_SOCKET", "/run/caddy-admin/admin.sock")
SELF_SIGNED = "DTM Demonstrator self-signed"  # the organisation the installer puts in its default certificate
_swapping = threading.Lock()


class ApplyError(Exception):
    """A short message for the form; the previous certificate is active again."""


def parse(mode: str, certificate: bytes, private_key: bytes, keystore: bytes, password: str):
    """The uploaded material as (chain, key) – checked like the `tls` service checks .env, and not expired."""
    if max(len(certificate), len(private_key), len(keystore)) > MAX_SIZE:
        raise TLSError("a file is larger than 1 MB – not a certificate or key")
    if mode == "pem":
        if not (certificate.strip() and private_key.strip()):
            raise TLSError("choose the certificate and the private key file")
        chain, key = tls_setup.from_pem(certificate, private_key, "the certificate file", "the private key file")
    elif mode == "pkcs12":
        if not keystore.strip():
            raise TLSError("choose the PKCS#12 file")
        chain, key = tls_setup.from_pkcs12(keystore, password, "the PKCS#12 file", "password")
    else:
        raise TLSError("choose PEM or PKCS#12")
    leaf = tls_setup.check(chain, key)
    if tls_setup.remaining(leaf).total_seconds() <= 0:
        raise TLSError("the certificate has expired")
    if leaf.not_valid_before_utc > datetime.now(timezone.utc):
        raise TLSError("the certificate is not valid yet")
    return chain, key


def admin_client() -> httpx.Client:
    # Over a unix socket Caddy accepts Host 127.0.0.1 (its check against DNS rebinding).
    return httpx.Client(transport=httpx.HTTPTransport(uds=ADMIN_SOCKET), base_url="http://127.0.0.1", timeout=20)


def reload() -> None:
    try:
        with admin_client() as client:
            config = client.get("/config/")
            config.raise_for_status()
            client.post("/load", content=config.content, headers={
                "Content-Type": "application/json", "Cache-Control": "must-revalidate"}).raise_for_status()
    except httpx.HTTPStatusError as exc:
        log.warning("TLS: Caddy refused the reload: HTTP %s %s", exc.response.status_code, exc.response.text[:500])
        raise ApplyError("The proxy refused the certificate – the previous one stays active.") from exc
    except httpx.HTTPError as exc:
        log.warning("TLS: Caddy admin API not reachable: %s", exc)
        raise ApplyError("The proxy could not be reached – the previous certificate stays active.") from exc


def _swap(files: dict[str, bytes | None]) -> None:
    """Writes (or, for None, removes) the files, reloads Caddy and on any failure puts the previous files back."""
    with _swapping:
        backups, touched = {}, []
        reloading = False
        try:
            for name, data in files.items():
                path = LIVE / name
                touched.append(name)
                if path.exists():
                    backups[name] = path.with_name(f".{name}.bak")
                    path.replace(backups[name])
                if data is not None:
                    tls_setup.write_file(path, data, private=name.endswith("key.pem"))
            reloading = True
            reload()
        except (OSError, ApplyError) as exc:
            for name in touched:
                (LIVE / name).unlink(missing_ok=True)
                if name in backups:
                    backups[name].replace(LIVE / name)
            if reloading:  # a lost answer may hide a reload that happened – serve the restored files for sure
                try:
                    reload()
                except ApplyError:
                    pass
            if isinstance(exc, ApplyError):
                raise
            log.error("TLS: the certificate files cannot be written: %s", exc)
            raise ApplyError("The certificate could not be stored – the previous one stays active.") from exc
        for backup in backups.values():
            backup.unlink(missing_ok=True)


def upload(chain, key) -> None:
    cert_pem, key_pem = tls_setup.pem_pair(chain, key)
    _swap({ACTIVE[0]: cert_pem, ACTIVE[1]: key_pem, SETTINGS[0]: cert_pem, SETTINGS[1]: key_pem})
    log.info("TLS: certificate from Settings applied: %s", chain[0].subject.rfc4514_string())


def reset() -> None:
    try:
        cert_pem, key_pem = ((LIVE / name).read_bytes() for name in DEFAULT)
    except OSError as exc:
        raise ApplyError("No default certificate – check the TLS settings in .env and restart.") from exc
    _swap({ACTIVE[0]: cert_pem, ACTIVE[1]: key_pem, SETTINGS[0]: None, SETTINGS[1]: None})
    log.info("TLS: back to the default certificate")


def status() -> dict | None:
    """The certificate Caddy serves, for the Settings page – None when there is none to show."""
    try:
        active = (LIVE / ACTIVE[0]).read_bytes()
    except OSError:
        return None
    chain = certinfo.load(active.decode(errors="replace"))
    if not chain:
        return None
    leaf, details = chain[0], certinfo.details(active.decode())
    settings = LIVE / SETTINGS[0]
    try:
        chosen = settings.read_bytes() == active
    except OSError:
        chosen = False
    organisation = [a.value for a in leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    left = tls_setup.remaining(leaf)
    return {
        "source": "Settings" if chosen else "Self-signed default" if SELF_SIGNED in organisation else ".env",
        "common_name": details["common_name"],
        "sans": details["sans"],
        "issuer": details["chain"][1] if len(details["chain"]) > 1 else details["common_name"],
        "not_after": leaf.not_valid_after_utc.strftime("%Y-%m-%d"),
        "days_left": left.days,
        "state": "expired" if left.total_seconds() <= 0 else "soon" if left < EXPIRY_WARNING else "ok",
        "sha256": details["sha256"],
        "can_reset": settings.exists(),  # also after a restart fell back from a broken Settings pair
    }
