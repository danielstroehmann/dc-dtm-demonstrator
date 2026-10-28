"""The demonstrator's own HTTPS certificate, set in Settings: a PEM pair or a PKCS#12 file, applied live, or paths
of such files on the Docker host, which the root `tls-watch` service reads (app/tls_watch.py); "Reset to
default" goes back to what .env configures. Whatever the admin chose last wins: an upload clears the host paths and
the other way round. Validation is tls_setup's – this module only stores, swaps and reloads.

The files live in the directory Caddy serves from (host ./tls-live), shared with the `tls` service: cert.pem/key.pem
is what Caddy serves, settings-*.pem the uploaded pair (the admin's choice, which the `tls` service prefers at every
start) and default-*.pem what .env resolves to. A PKCS#12 upload is stored as the checked PEM pair – its password is
never stored. Host paths are handed to the watcher as a request (REQUEST, with a fresh id) and answered in STATUS.

Caddy does not watch certificate files. After swapping them, the app re-posts Caddy's running config to its admin API
with "Cache-Control: must-revalidate", which forces a reload that re-reads the files (what `caddy reload --force`
does). The admin API listens only on a unix socket in a volume that just the proxy, the app and tls-watch mount – no
TCP port, nothing reachable from the host network or the other containers. A config Caddy refuses leaves it running unchanged;
the previous files are then put back. An admin socket that does not answer (the proxy is down or restarting) puts them
back for an upload or reset, which the admin is told failed; the watcher keeps its checked files instead – Caddy reads
them when it starts – and retries the reload."""

import json
import logging
import os
import posixpath
import secrets
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.x509.oid import NameOID

from . import certinfo, tls_setup
from .tls_setup import ACTIVE, DEFAULT, EXPIRY_WARNING, HOST_PATHS, MAX_SIZE, SETTINGS, TLSError

log = logging.getLogger("demonstrator")
LIVE = Path(os.environ.get("TLS_LIVE_DIR", "/tls-live"))
ADMIN_SOCKET = os.environ.get("CADDY_ADMIN_SOCKET", "/run/caddy-admin/admin.sock")
SELF_SIGNED = "DTM Demonstrator self-signed"  # the organisation the installer puts in its default certificate
REQUEST = "settings-paths.request.json"  # host paths to apply, written by the app (holds a PKCS#12 password: 0640)
STATUS = "settings-paths.status.json"  # the watcher's answer to a request, and its last renewal check
ANSWER_TIMEOUT = 10  # seconds; the watcher looks for a request every second (a slow reload: see request_host)
RELOAD_PENDING = "The proxy could not be reached – the certificate is stored and served once the proxy is back."
MAX_PATH = 1024
_swapping = threading.Lock()


class ApplyError(Exception):
    """A short message for the form; the previous certificate is active again."""


class Unreachable(ApplyError):
    """Caddy's admin socket did not answer – unlike a refusal, nothing says the files are wrong."""


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
    tls_setup.usable(chain, key)
    return chain, key


def host_config(mode: str, certificate: str, private_key: str, keystore: str, password: str) -> dict:
    """The host paths as entered, checked as text: absolute and inside TLS_HOST_DIR. Whether the files exist and
    where their links lead only the watcher can check – the app cannot read them."""
    root = tls_setup.HOST_DIR
    if not root:
        raise TLSError("set TLS_HOST_DIR in .env first (or run install.sh --tls-dir PATH)")

    def path(value: str, what: str) -> str:
        value = value.strip()
        if not value:
            raise TLSError(f"enter the path of {what}")
        if len(value) > MAX_PATH or not value.isprintable():
            raise TLSError(f"the path of {what} is not valid")
        if not value.startswith("/"):
            raise TLSError(f"the path of {what} must be absolute")
        value = posixpath.normpath(value)
        if not value.startswith(root.rstrip("/") + "/"):
            raise TLSError(f"the path of {what} must be inside {root}")
        return value

    if mode == "pem":
        return {"mode": "pem", "certificate": path(certificate, "the certificate file"),
                "private_key": path(private_key, "the private key file")}
    if mode == "pkcs12":
        if len(password) > MAX_PATH:
            raise TLSError("the password is too long")
        return {"mode": "pkcs12", "keystore": path(keystore, "the PKCS#12 file"), "password": password}
    raise TLSError("choose PEM or PKCS#12")


def admin_client() -> httpx.Client:
    # Over a unix socket Caddy accepts Host 127.0.0.1 (its check against DNS rebinding).
    return httpx.Client(transport=httpx.HTTPTransport(uds=ADMIN_SOCKET), base_url="http://127.0.0.1", timeout=20)


def reload(quiet: bool = False) -> None:
    """quiet: an unreachable admin socket is expected (the watcher's retries) – not logged every time."""
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
        log.log(logging.DEBUG if quiet else logging.WARNING, "TLS: Caddy admin API not reachable: %s", exc)
        raise Unreachable("The proxy could not be reached – the previous certificate stays active.") from exc


@contextmanager
def locked():
    """One change of the files at a time: across the app's threads, and – flock on the shared directory – with the
    tls-watch service. Not reentrant."""
    with _swapping:
        try:
            fd = tls_setup.lock(LIVE)
        except OSError as exc:
            log.error("TLS: the certificate directory cannot be opened: %s", exc)
            raise ApplyError("The certificate could not be stored – the previous one stays active.") from exc
        try:
            yield
        finally:
            os.close(fd)  # releases the lock


def _swap(files: dict[str, bytes | None], keep_unreachable: bool = False) -> None:
    """Writes (or, for None, removes) the files, reloads Caddy and on any failure puts the previous files back –
    with keep_unreachable not when only the admin socket did not answer (Unreachable is raised all the same).
    Call it within locked()."""
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
                tls_setup.write_file(path, data, private=not name.endswith("cert.pem"))
        reloading = True
        reload()
    except (OSError, ApplyError) as exc:
        if keep_unreachable and isinstance(exc, Unreachable):
            for backup in backups.values():
                backup.unlink(missing_ok=True)
            raise
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
    with locked():
        _swap({ACTIVE[0]: cert_pem, ACTIVE[1]: key_pem, SETTINGS[0]: cert_pem, SETTINGS[1]: key_pem,
               HOST_PATHS: None, STATUS: None})
    log.info("TLS: certificate from Settings applied: %s", chain[0].subject.rfc4514_string())


def reset() -> None:
    try:
        cert_pem, key_pem = ((LIVE / name).read_bytes() for name in DEFAULT)
    except OSError as exc:
        raise ApplyError("No default certificate – check the TLS settings in .env and restart.") from exc
    with locked():
        _swap({ACTIVE[0]: cert_pem, ACTIVE[1]: key_pem, SETTINGS[0]: None, SETTINGS[1]: None, HOST_PATHS: None,
               STATUS: None})
    log.info("TLS: back to the default certificate")


def apply_host(chain, key, config: dict) -> None:
    """The watcher's side: the pair read from the host paths becomes the Settings pair. Only a refusal by Caddy rolls
    back; an unreachable proxy keeps the checked files and raises Unreachable. Call it within locked()."""
    cert_pem, key_pem = tls_setup.pem_pair(chain, key)
    _swap({ACTIVE[0]: cert_pem, ACTIVE[1]: key_pem, SETTINGS[0]: cert_pem, SETTINGS[1]: key_pem,
           HOST_PATHS: json.dumps(config).encode()}, keep_unreachable=True)


def _json(name: str) -> dict:
    try:
        data = json.loads(tls_setup.read_private(LIVE / name))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def request_host(config: dict) -> None:
    """Hands the host paths to the watcher and waits for its answer: applied, or why not."""
    request_id = secrets.token_hex(8)
    try:
        tls_setup.write_file(LIVE / REQUEST, json.dumps({"id": request_id} | config).encode(), private=True)
    except OSError as exc:
        log.error("TLS: the host path request cannot be written: %s", exc)
        raise ApplyError("The request could not be stored – the previous certificate stays active.") from exc
    deadline = time.monotonic() + ANSWER_TIMEOUT
    while (status := _json(STATUS)).get("request") != request_id:
        if time.monotonic() >= deadline:
            # The watcher reads the request under the lock: once we hold it, it has either answered (a reload can
            # take longer than ANSWER_TIMEOUT) or not taken the request – then withdrawn, a watcher starting later
            # must not apply it unasked.
            with locked():
                status = _json(STATUS)
                if status.get("request") != request_id:
                    (LIVE / REQUEST).unlink(missing_ok=True)
                    log.warning("TLS: the tls-watch service did not answer within %s s", ANSWER_TIMEOUT)
                    raise ApplyError("The tls-watch service did not answer – the request was withdrawn. Check that "
                                     "the service runs, then try again.")
            break
        time.sleep(0.2)
    if status.get("request_error"):
        raise TLSError(str(status["request_error"]))
    log.info("TLS: certificate from the host path applied")


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
    host = _json(HOST_PATHS) if chosen else {}
    watch = _json(STATUS) if host else {}
    organisation = [a.value for a in leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    left = tls_setup.remaining(leaf)
    return {
        "source": "From host path" if host else "Settings" if chosen
        else "Self-signed default" if SELF_SIGNED in organisation else ".env",
        "common_name": details["common_name"],
        "sans": details["sans"],
        "issuer": details["chain"][1] if len(details["chain"]) > 1 else details["common_name"],
        "not_after": leaf.not_valid_after_utc.strftime("%Y-%m-%d"),
        "days_left": left.days,
        "state": "expired" if left.total_seconds() <= 0 else "soon" if left < EXPIRY_WARNING else "ok",
        "sha256": details["sha256"],
        # the password of a PKCS#12 file is never shown
        "host_paths": [host[k] for k in ("certificate", "private_key", "keystore") if isinstance(host.get(k), str)],
        "checked": _when(watch.get("checked")),
        "check_error": watch.get("error") or (RELOAD_PENDING if watch.get("reload_pending") else None),
        # also after a restart fell back from a broken Settings pair
        "can_reset": settings.exists() or (LIVE / HOST_PATHS).exists(),
    }


def _when(stamp) -> str | None:
    try:
        return datetime.fromisoformat(stamp).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return None
