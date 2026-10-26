"""TLS material for the proxy, resolved at every start (the `tls` service in docker-compose.yml).

The paths come from .env and are mounted read-only: TLS_CERT_FILE + TLS_KEY_FILE (PEM: certificate
with chain, private key – as Let's Encrypt delivers them; default: the self-signed pair the installer
created) or TLS_PKCS12_FILE + TLS_PKCS12_PASSWORD. PEM wins when both are configured. An unset path
is mounted as /dev/null, i.e. read as empty. The result is written as PEM for Caddy; anything wrong
stops here with a clear message, so the proxy never starts with a broken or mismatched pair."""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

SOURCE = Path(os.environ.get("TLS_SOURCE_DIR", "/tls-in"))
TARGET = Path(os.environ.get("TLS_TARGET_DIR", "/tls"))
EXPIRY_WARNING = timedelta(days=30)
MAX_SIZE = 1 << 20  # a certificate chain or keystore is a few KB


class TLSError(Exception):
    pass


def _read(name: str) -> bytes:
    """An unset path is mounted as /dev/null (empty). Anything else must be a readable regular file."""
    path = SOURCE / name
    try:
        if not path.exists() or (path.is_char_device() and os.path.samefile(path, "/dev/null")):
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


def from_pem(cert_pem: bytes, key_pem: bytes) -> tuple[list[x509.Certificate], object]:
    try:
        chain = x509.load_pem_x509_certificates(cert_pem)
    except ValueError as exc:
        raise TLSError("TLS_CERT_FILE is not a PEM certificate") from exc
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except TypeError as exc:  # encrypted PEM key
        raise TLSError("TLS_KEY_FILE is encrypted – use an unencrypted PEM key or a PKCS#12 file with password") from exc
    except ValueError as exc:
        raise TLSError("TLS_KEY_FILE is not a PEM private key") from exc
    return chain, key


def from_pkcs12(data: bytes, password: str) -> tuple[list[x509.Certificate], object]:
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, password.encode() or None)
    except ValueError as exc:
        raise TLSError("TLS_PKCS12_FILE could not be opened – wrong TLS_PKCS12_PASSWORD or not a PKCS#12 file") from exc
    if key is None or cert is None:
        raise TLSError("TLS_PKCS12_FILE holds no private key and certificate")
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


def write(chain: list[x509.Certificate], key) -> None:
    TARGET.mkdir(parents=True, exist_ok=True)
    files = {"cert.pem": (b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain), 0o644),
             "key.pem": (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()), 0o600)}
    for name, (data, mode) in files.items():
        tmp = TARGET / f".{name}.tmp"
        tmp.write_bytes(data)
        tmp.chmod(mode)
        tmp.replace(TARGET / name)  # atomic: the proxy never sees half a file


def main() -> int:
    try:
        kind, chain, key = resolve()
        leaf = check(chain, key)
    except TLSError as exc:
        print(f"TLS: {exc}", file=sys.stderr, flush=True)
        return 1
    write(chain, key)
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        covers = ", ".join(str(n.value) for n in names)
    except x509.ExtensionNotFound:
        covers = leaf.subject.rfc4514_string()
    left = leaf.not_valid_after_utc - datetime.now(timezone.utc)
    print(f"TLS: {kind} certificate for {covers}, valid until {leaf.not_valid_after_utc:%Y-%m-%d}", flush=True)
    if left < EXPIRY_WARNING:
        print(f"TLS: WARNING – the certificate {'has expired' if left.total_seconds() < 0 else 'expires soon'}",
              file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
