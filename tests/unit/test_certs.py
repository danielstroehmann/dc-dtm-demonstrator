import io
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app import certs
from tests.fakedtm import cert_pem, cms_envelope, key_pem, make_cert, result_zip


@pytest.fixture(scope="module")
def encryption():
    return certs.encryption_keypair("robot-x1-uc01-encryption")


@pytest.fixture(scope="module")
def pki():
    root, root_key = make_cert("Test Root", ca=True)
    ica, ica_key = make_cert("Test ICA", issuer_cert=root, issuer_key=root_key, ca=True)
    leaves = [make_cert(f"robot-x1-uc01-batch-{i:04d}", issuer_cert=ica, issuer_key=ica_key) for i in (1, 2, 3)]
    return root, ica, leaves


def test_encryption_keypair(encryption):
    cert_bytes, key_bytes = encryption
    cert = x509.load_pem_x509_certificate(cert_bytes)
    key = serialization.load_pem_private_key(key_bytes, password=None)
    assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == 3072
    assert key_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")  # PKCS#8, unencrypted
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "robot-x1-uc01-encryption"
    now = datetime.now(timezone.utc)
    assert cert.not_valid_before_utc <= now < cert.not_valid_after_utc <= now + timedelta(days=31)


def test_keypairs_are_unique():
    a, b = certs.encryption_keypair("a"), certs.encryption_keypair("a")
    assert a[1] != b[1]


def test_cms_roundtrip(encryption, pki):
    cert_bytes, key_bytes = encryption
    _root, _ica, leaves = pki
    inner = result_zip([("Line-00000001", cert_pem(leaves[0][0]), key_pem(leaves[0][1]))], [])
    envelope = cms_envelope(inner, cert_bytes)
    assert inner not in envelope
    assert certs.decrypt_result(envelope, cert_bytes, key_bytes) == inner


def test_decrypt_with_wrong_key_fails(encryption):
    cert_bytes, _ = encryption
    other_cert, other_key = certs.encryption_keypair("other")
    envelope = cms_envelope(b"PK-secret", cert_bytes)
    with pytest.raises(ValueError):
        certs.decrypt_result(envelope, other_cert, other_key)


def test_decrypt_garbage_fails(encryption):
    with pytest.raises(ValueError):
        certs.decrypt_result(b"<html>not cms</html>", *encryption)


def test_parse_batch_zip(pki):
    root, ica, leaves = pki
    entries = [(f"Line-{i:08d}", cert_pem(c), key_pem(k)) for i, (c, k) in enumerate(reversed(leaves), start=1)]
    data = result_zip(entries, [cert_pem(ica), cert_pem(root)])
    infos, keys = certs.parse_batch_zip(data)
    assert keys == 3
    # end-entity certificates only (not the chain), sorted by file name
    assert [i["common_name"] for i in infos] == [f"robot-x1-uc01-batch-{n:04d}" for n in (3, 2, 1)]
    assert {i["issuer"] for i in infos} == {"Test ICA"}
    assert {i["key_type"] for i in infos} == {"ECDSA secp256r1"}
    assert infos[0]["serial"] == format(leaves[2][0].serial_number, "X")
    # The public end-entity PEM rides along (moved to a file by save_certificates) – never a key,
    # never the chain.
    assert [i["pem"] for i in infos] == [cert_pem(c) for c, _k in reversed(leaves)]
    text = repr(infos)
    assert "PRIVATE KEY" not in text
    assert text.count("BEGIN") == len(infos) == 3


def test_parse_batch_zip_rejects_oversized_result(monkeypatch, pki):
    _root, _ica, leaves = pki
    data = result_zip([("Line-00000001", cert_pem(leaves[0][0]), key_pem(leaves[0][1]))], [])
    monkeypatch.setattr(certs, "MAX_RESULT_BYTES", 100)
    with pytest.raises(ValueError, match="size limits"):
        certs.parse_batch_zip(data)


def test_parse_batch_zip_rejects_too_many_entries(monkeypatch, pki):
    _root, _ica, leaves = pki
    data = result_zip([(f"Line-{i:08d}", cert_pem(c), key_pem(k)) for i, (c, k) in enumerate(leaves)], [])
    monkeypatch.setattr(certs, "MAX_RESULT_ENTRIES", 3)  # 3 pem + 3 key + report = 7 entries
    with pytest.raises(ValueError, match="size limits"):
        certs.parse_batch_zip(data)


def test_zip_bomb_guard_uses_declared_sizes_before_decompressing():
    """A highly compressible 600 MB entry must be refused without inflating it."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        with archive.open("Line-00000001.pem", "w", force_zip64=True) as entry:
            chunk = b"\0" * (1 << 20)
            for _ in range(600):
                entry.write(chunk)
    with pytest.raises(ValueError, match="size limits"):
        certs.parse_batch_zip(buffer.getvalue())


def test_parse_batch_zip_rejects_non_zip():
    with pytest.raises(zipfile.BadZipFile):
        certs.parse_batch_zip(b"not a zip")


def test_parse_pem_certificate_rsa():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert, _ = make_cert("robot-x1-uc01-single-0001", key=key)
    info = certs.parse_pem_certificate(cert_pem(cert))
    assert info["common_name"] == "robot-x1-uc01-single-0001"
    assert info["key_type"] == "RSA 2048"
    assert info["issuer"] == "robot-x1-uc01-single-0001"
    assert info["not_after"].endswith(" UTC")


def test_certificate_without_cn_falls_back_to_rfc4514_issuer():
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org Only")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .sign(key, __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()))
    info = certs.certificate_info(cert)
    assert info["common_name"] == "" and info["issuer"] == "O=Org Only"
    assert info["key_type"] == "ECDSA secp384r1"


def test_parse_pem_certificate_rejects_garbage():
    with pytest.raises(ValueError):
        certs.parse_pem_certificate("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
