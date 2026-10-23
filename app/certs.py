"""Key material and certificate parsing. Private keys are written to the run directory only
and are never returned to the UI."""

import io
import zipfile
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

MAX_RESULT_ENTRIES = 100_000
MAX_RESULT_BYTES = 500 * 1024 * 1024  # zip-bomb guard for the decrypted batch result


def encryption_keypair(common_name: str) -> tuple[bytes, bytes]:
    """Self-signed RSA certificate + key for DTM to encrypt the batch result to (CMS)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def decrypt_result(envelope: bytes, cert_pem: bytes, key_pem: bytes) -> bytes:
    """Decrypt DTM's CMS envelope (.p7m, DER) to the inner ZIP."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    return pkcs7.pkcs7_decrypt_der(envelope, cert, key, [])


def certificate_info(cert: x509.Certificate) -> dict:
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    public_key = cert.public_key()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type = f"ECDSA {public_key.curve.name}"
    elif isinstance(public_key, rsa.RSAPublicKey):
        key_type = f"RSA {public_key.key_size}"
    else:
        key_type = type(public_key).__name__
    return {
        "common_name": cn[0].value if cn else "",
        "serial": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "issuer": issuer_cn[0].value if issuer_cn else cert.issuer.rfc4514_string(),
        "key_type": key_type,
    }


def parse_pem_certificate(pem: str) -> dict:
    return certificate_info(x509.load_pem_x509_certificate(pem.encode()))


def parse_batch_zip(data: bytes) -> tuple[list[dict], int]:
    """Return info for every end-entity certificate in the result ZIP and the number of keys."""
    certs, keys = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_RESULT_ENTRIES or sum(e.file_size for e in entries) > MAX_RESULT_BYTES:
            raise ValueError("batch result exceeds size limits")
        for entry in sorted(entries, key=lambda e: e.filename):
            if entry.filename.endswith(".key"):
                keys += 1
            elif entry.filename.endswith(".pem"):
                # The first certificate in each file is the end-entity certificate; chain follows.
                first = x509.load_pem_x509_certificates(archive.read(entry))[0]
                certs.append(certificate_info(first))
    return certs, keys
