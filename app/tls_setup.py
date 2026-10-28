"""TLS material for the proxy, resolved at every start (the `tls` service in docker-compose.yml).

The paths come from .env and are mounted read-only: TLS_CERT_FILE + TLS_KEY_FILE (PEM: certificate
with chain, private key – as Let's Encrypt delivers them; default: the self-signed pair the installer
created) or TLS_PKCS12_FILE + TLS_PKCS12_PASSWORD. PEM wins when both are configured. An unset path
is mounted as /dev/null, i.e. read as empty. The result is written as PEM for Caddy; anything wrong
stops here with a clear message, so the proxy never starts with a broken or mismatched pair.

A certificate uploaded in Settings (app/tls_settings.py, kept in TARGET as settings-*.pem) wins over .env, so a
restart keeps the admin's choice. The .env pair is always written as default-*.pem too: that is what "Reset to
default" in Settings goes back to – the app itself cannot read the files .env points to."""

import os
import sys
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

SOURCE = Path(os.environ.get("TLS_SOURCE_DIR", "/tls-in"))
TARGET = Path(os.environ.get("TLS_TARGET_DIR", "/tls"))
EXPIRY_WARNING = timedelta(days=30)
DEV_NULL = os.stat(os.devnull).st_rdev  # 1:3 in every Linux container
MAX_SIZE = 1 << 20  # a certificate chain or keystore is a few KB
ACTIVE = ("cert.pem", "key.pem")  # what Caddy serves
DEFAULT = ("default-cert.pem", "default-key.pem")  # from .env (or the installer's self-signed pair)
SETTINGS = ("settings-cert.pem", "settings-key.pem")  # uploaded in Settings
# The app's group (see Dockerfile): the app replaces the live files and reads the default pair, the proxy reads
# the keys through it (both have no CAP_DAC_OVERRIDE) – so keys are 0640 and the directory 0770 for this group.
GROUP = int(os.environ.get("TLS_GROUP", "10001"))


class TLSError(Exception):
    pass


def _read(name: str) -> bytes:
    """An unset path is mounted as /dev/null (empty). Anything else must be a readable regular file."""
    path = SOURCE / name
    try:
        # A bind-mounted /dev/null is the host's node, not the container's – compare the device number.
        if not path.exists() or (path.is_char_device() and path.stat().st_rdev == DEV_NULL):
            return b""
        if not path.is_file():
            raise TLSError(f"{name} is not a file – check the path in .env")
        with path.open("rb") as handle:
            data = handle.read(MAX_SIZE + 1)
    except OSError as exc:  # e.g. a 0600 key of another user – the service has no CAP_DAC_OVERRIDE
        raise TLSError(f"{name} cannot be read – it must be readable by root") from exc
    if len(data) > MAX_SIZE:
        raise TLSError(f"{name} is larger than 1 MB – not a certificate or key")
    return data


# The names in the messages are the .env keys here; Settings passes the names its form uses.
def from_pem(cert_pem: bytes, key_pem: bytes, cert_name: str = "TLS_CERT_FILE",
             key_name: str = "TLS_KEY_FILE") -> tuple[list[x509.Certificate], object]:
    try:
        chain = x509.load_pem_x509_certificates(cert_pem)
    except ValueError as exc:
        raise TLSError(f"{cert_name} is not a PEM certificate") from exc
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except TypeError as exc:  # encrypted PEM key
        raise TLSError(f"{key_name} is encrypted – use an unencrypted PEM key or a PKCS#12 file with password") from exc
    except ValueError as exc:
        raise TLSError(f"{key_name} is not a PEM private key") from exc
    return chain, key


def from_pkcs12(data: bytes, password: str, name: str = "TLS_PKCS12_FILE",
                password_name: str = "TLS_PKCS12_PASSWORD") -> tuple[list[x509.Certificate], object]:
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, password.encode() or None)
    except ValueError as exc:
        raise TLSError(f"{name} could not be opened – wrong {password_name} or not a PKCS#12 file") from exc
    if key is None or cert is None:
        raise TLSError(f"{name} holds no private key and certificate")
    return [cert, *extra], key


def check(chain: list[x509.Certificate], key) -> x509.Certificate:
    """The first certificate is the server's and must belong to the key."""
    leaf = chain[0]
    public = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    if public(leaf.public_key()) != public(key.public_key()):
        raise TLSError("the private key does not belong to the certificate (the server certificate must come first)")
    return leaf


def resolve() -> tuple[str, list[x509.Certificate], object]:
    cert_pem, key_pem, p12 = _read("cert.pem"), _read("key.pem"), _read("keystore.p12")
    if cert_pem.strip() or key_pem.strip():
        if not (cert_pem.strip() and key_pem.strip()):
            raise TLSError("set both TLS_CERT_FILE and TLS_KEY_FILE (or clear both to use TLS_PKCS12_FILE)")
        if p12.strip():
            print("TLS: PEM files are configured – TLS_PKCS12_FILE is ignored", flush=True)
        return "PEM", *from_pem(cert_pem, key_pem)
    if p12.strip():
        return "PKCS#12", *from_pkcs12(p12, os.environ.get("TLS_PKCS12_PASSWORD", ""))
    raise TLSError("no certificate configured – set TLS_CERT_FILE and TLS_KEY_FILE (or TLS_PKCS12_FILE) in .env")


def remaining(leaf: x509.Certificate) -> timedelta:
    return leaf.not_valid_after_utc - datetime.now(timezone.utc)


def pem_pair(chain: list[x509.Certificate], key) -> tuple[bytes, bytes]:
    return (b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def write_file(path: Path, data: bytes, private: bool) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    if os.geteuid() == 0:  # the tls service: hand the file to the app's group (an owner may chgrp to its own groups)
        with suppress(OSError):  # not a member (compose without group_add): the directory warning says it all
            os.chown(tmp, -1, GROUP)
    tmp.chmod(0o640 if private else 0o644)
    tmp.replace(path)  # atomic: the proxy never sees half a file


def write(chain: list[x509.Certificate], key, names: tuple[str, str] = ACTIVE) -> None:
    TARGET.mkdir(parents=True, exist_ok=True)
    if os.geteuid() == 0:
        try:  # the app replaces the live files at runtime – the directory must be writable for its group
            os.chown(TARGET, -1, GROUP)
            TARGET.chmod(0o770)
        except OSError as exc:
            print(f"TLS: WARNING – {TARGET} cannot be shared with the app ({exc.strerror}) – Settings cannot "
                  "change the certificate", file=sys.stderr, flush=True)
    for name, data, private in zip(names, pem_pair(chain, key), (False, True)):
        write_file(TARGET / name, data, private)


def from_settings() -> tuple[list[x509.Certificate], object] | None:
    """The pair uploaded in Settings – the app checked it already; a broken one falls back to .env."""
    cert, key = (TARGET / name for name in SETTINGS)
    if not cert.exists():
        return None
    try:
        chain, private = from_pem(cert.read_bytes(), key.read_bytes(), cert.name, key.name)
        check(chain, private)
    except (TLSError, OSError) as exc:
        print(f"TLS: WARNING – the certificate from Settings is not usable ({exc}) – using .env",
              file=sys.stderr, flush=True)
        return None
    return chain, private


def main() -> int:
    settings = from_settings()
    try:
        kind, chain, key = resolve()
        check(chain, key)
    except TLSError as exc:
        if not settings:
            print(f"TLS: {exc}", file=sys.stderr, flush=True)
            return 1
        # The admin's choice still serves; only "Reset to default" has nothing to go back to.
        print(f"TLS: WARNING – {exc} – serving the certificate from Settings", file=sys.stderr, flush=True)
        for name in DEFAULT:
            (TARGET / name).unlink(missing_ok=True)
    else:
        write(chain, key, DEFAULT)
    if settings:
        kind, (chain, key) = "Settings", settings
    write(chain, key)
    leaf = chain[0]
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        covers = ", ".join(str(n.value) for n in names)
    except x509.ExtensionNotFound:
        covers = leaf.subject.rfc4514_string()
    left = remaining(leaf)
    print(f"TLS: {kind} certificate for {covers}, valid until {leaf.not_valid_after_utc:%Y-%m-%d}", flush=True)
    if left < EXPIRY_WARNING:
        print(f"TLS: WARNING – the certificate {'has expired' if left.total_seconds() < 0 else 'expires soon'}",
              file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
