"""Key material and certificate parsing. Private keys are never written to disk or returned to
the UI."""

import base64
import io
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def factory_csr(common_name: str, key_type: str) -> str:
    """CSR for a fresh key pair as the factory creates it (P_256 → ECDSA P-256, RSA_2048 → RSA 2048).
    The private key never leaves this function – the demo has no use for it."""
    key = new_device_key(key_type)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def new_device_key(key_type: str):
    """A device key pair as the factory creates it (P_256 → ECDSA P-256, RSA_2048 → RSA 2048)."""
    if key_type.upper().startswith("RSA"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(key_type.split("_")[1]))
    return ec.generate_private_key(ec.SECP256R1())


def device_request(common_name: str, key_type: str) -> tuple[bytes, x509.CertificateSigningRequest]:
    """UC-3: key (PEM, for openssl cmp – it builds the CMP request from the key) and CSR."""
    key = new_device_key(key_type)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
           .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return key_pem, csr


def factory_certificate(common_name: str) -> tuple[str, bytes]:
    """UC-3: the factory's own client certificate (self-signed ECDSA, clientAuth), registered in DTM
    as an authentication certificate. Returns (certificate PEM, key PEM)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem


MANUFACTURER = "Fictitious Manufacturer"


def _ca(subject: str, issuer: x509.Certificate | None, issuer_key, days: int, path_length: int | None):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, MANUFACTURER),
                      x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = datetime.now(timezone.utc)
    signer = issuer_key or key
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer.subject if issuer else name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .sign(signer, hashes.SHA256()))
    return cert, key


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def manufacturer_ca(base: str) -> dict:
    """UC-7: the manufacturer's own PKI outside DTM – root → device-ID ICA, ECDSA P-256. Demo material of
    one run: PEMs (ICA key included) for the run dir, removed by the rollback."""
    root, root_key = _ca(f"{base}-manufacturer-root", None, None, 3 * 365, 1)
    ica, ica_key = _ca(f"{base}-device-id-ica", root, root_key, 2 * 365, 0)
    return {"root": _pem(root), "ica": _pem(ica), "ica_key": _key_pem(ica_key)}


def device_id_certificate(serial: str, ica_pem: str, ica_key_pem: bytes) -> tuple[str, bytes]:
    """UC-7: the unmanaged device-ID certificate the factory gives a device (CN = serial number, clientAuth),
    issued by the manufacturer's ICA. Returns (certificate + ICA chain PEM, key PEM)."""
    ica = x509.load_pem_x509_certificate(ica_pem.encode())
    ica_key = serialization.load_pem_private_key(ica_key_pem, password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, MANUFACTURER),
                                     x509.NameAttribute(NameOID.COMMON_NAME, serial)]))
            .issuer_name(ica.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ica_key.public_key()), critical=False)
            .sign(ica_key, hashes.SHA256()))
    return _pem(cert) + ica_pem, _key_pem(key)


def der_b64_to_pem(blob: str) -> str:
    """DTM returns CA certificates as base64 DER (policy ca_chain)."""
    return x509.load_der_x509_certificate(base64.b64decode(blob)).public_bytes(serialization.Encoding.PEM).decode()


def parse_pkcs7_certificates(der: bytes) -> list[dict]:
    """EST answers with a certs-only PKCS#7; the end-entity certificate comes first."""
    return [certificate_info(c) for c in pkcs7.load_der_pkcs7_certificates(der)]


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
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode(),  # moved to a file by save_certificates
    }


def save_certificates(run_dir: Path, issued: list[dict]) -> None:
    """Issued certificates (public, never keys) as <serial>.pem for download; the run's data keeps
    only the parsed fields. Removed with the run directory on a full rollback."""
    target = run_dir / "certificates"
    target.mkdir(parents=True, exist_ok=True)
    for info in issued:
        pem = info.pop("pem", None)
        if pem:
            (target / f"{info['serial']}.pem").write_text(pem)


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
