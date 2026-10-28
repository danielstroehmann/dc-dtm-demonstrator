"""Certificate detail parsing: EC and RSA keys, SANs, key usages, chain names, missing extensions, broken input."""

import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import certinfo

NOW = datetime(2026, 10, 28, 9, 30, tzinfo=timezone.utc)


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def build(subject, key, issuer=None, issuer_key=None, extensions=(), serial=0x4F2A9A1):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(NOW).not_valid_after(NOW + timedelta(days=365)))
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


def pem(*certs) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


def pki():
    root_key, ica_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP256R1())
    root = build(name("Test Root"), root_key, serial=1)
    ica = build(name("Test ICA"), ica_key, root.subject, root_key, serial=2)
    return root, ica, ica_key


def test_ec_leaf_with_every_extension():
    root, ica, ica_key = pki()
    leaf = build(name("device-0001"), ec.generate_private_key(ec.SECP256R1()), ica.subject, ica_key, extensions=(
        x509.SubjectAlternativeName([x509.DNSName("device-0001.example"), x509.IPAddress(ipaddress.ip_address("10.0.0.7")),
                                     x509.RFC822Name("ops@example.com"), x509.UniformResourceIdentifier("urn:dev:1")]),
        x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                      key_agreement=True, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH,
                               x509.ObjectIdentifier("1.2.3.4")])))
    info = certinfo.details(pem(leaf), pem(ica, root))
    assert info["common_name"] == "device-0001" and info["serial"] == "4F2A9A1"
    assert info["sans"] == ["DNS device-0001.example", "IP 10.0.0.7", "Email ops@example.com", "URI urn:dev:1"]
    assert (info["not_before"], info["not_after"]) == ("2026-10-28 09:30", "2027-10-28 09:30")
    assert info["chain"] == ["device-0001", "Test ICA", "Test Root"]
    assert info["key_usage"] == ["Digital signature", "Key agreement"]
    assert info["extended_key_usage"] == ["Client auth", "Server auth", "1.2.3.4"]  # unknown OIDs stay dotted
    assert info["key"] == "ECDSA P-256"
    expected = leaf.fingerprint(hashes.SHA256()).hex().upper()
    assert info["sha256"].replace(":", "") == expected and info["sha256"].count(":") == 31


def test_rsa_leaf_without_extensions():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root, ica, ica_key = pki()
    leaf = build(name("rsa-device"), key, ica.subject, ica_key)
    info = certinfo.details(pem(leaf))
    assert info["key"] == "RSA 2048"
    assert info["sans"] == [] and info["key_usage"] is None and info["extended_key_usage"] is None
    # no CA certificates known: the chain ends with the issuer's name taken from the leaf
    assert info["chain"] == ["rsa-device", "Test ICA"]


def test_chain_from_the_pem_itself_and_a_root_key_curve():
    root, ica, ica_key = pki()
    leaf = build(name("d"), ec.generate_private_key(ec.SECP256R1()), ica.subject, ica_key)
    assert certinfo.details(pem(leaf, ica, root))["chain"] == ["d", "Test ICA", "Test Root"]
    assert certinfo.details(pem(root))["chain"] == ["Test Root"]  # self-signed: ends at itself
    assert certinfo.details(pem(root))["key"] == "ECDSA P-384"


def test_unrelated_ca_certificates_do_not_extend_the_chain():
    root, ica, ica_key = pki()
    other_root, _other_ica, _ = pki()
    leaf = build(name("d"), ec.generate_private_key(ec.SECP256R1()), ica.subject, ica_key)
    other = build(name("Elsewhere"), ec.generate_private_key(ec.SECP256R1()))
    assert certinfo.details(pem(leaf), pem(other))["chain"] == ["d", "Test ICA"]


def test_subject_without_common_name_is_named_by_its_dn():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = build(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Only O")]), key)
    assert certinfo.details(pem(cert))["common_name"] == "O=Only O"


def test_broken_or_missing_input_gives_none():
    root, _ica, _ = pki()
    good = pem(root)
    for broken in ("", "not a certificate", good.replace("A", "B", 40)[:200], "-----BEGIN CERTIFICATE-----\nAAAA\n"
                   "-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                   "\udcff"):
        assert certinfo.details(broken) is None, broken
    # a broken CA file does not hide the leaf
    assert certinfo.details(good, "garbage")["common_name"] == "Test Root"
