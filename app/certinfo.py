"""What the certificate detail view shows of one certificate: parsed from its PEM with `cryptography`, never
from free text. Anything that cannot be parsed yields None – the view then shows "–" instead of guessing."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MAX_CHAIN = 5  # leaf, issuing CA, root – and some room for deeper hierarchies
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
KEY_USAGES = (("digital_signature", "Digital signature"), ("content_commitment", "Non-repudiation"),
              ("key_encipherment", "Key encipherment"), ("data_encipherment", "Data encipherment"),
              ("key_agreement", "Key agreement"), ("key_cert_sign", "Certificate signing"), ("crl_sign", "CRL signing"))
EXTENDED_KEY_USAGES = {
    ExtendedKeyUsageOID.CLIENT_AUTH: "Client auth", ExtendedKeyUsageOID.SERVER_AUTH: "Server auth",
    ExtendedKeyUsageOID.CODE_SIGNING: "Code signing", ExtendedKeyUsageOID.EMAIL_PROTECTION: "Email protection",
    ExtendedKeyUsageOID.TIME_STAMPING: "Time stamping", ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP signing",
}
SAN_KINDS = {x509.DNSName: "DNS", x509.IPAddress: "IP", x509.RFC822Name: "Email",
             x509.UniformResourceIdentifier: "URI"}


def load(pem: str) -> list[x509.Certificate]:
    """Every certificate in a PEM text – empty when there is none or it is broken."""
    try:
        return x509.load_pem_x509_certificates(pem.encode())
    except (ValueError, UnicodeEncodeError):
        return []


def details(pem: str, ca_pem: str = "") -> dict | None:
    """The leaf (first certificate of `pem`) as the view shows it. `ca_pem`: CA certificates the run knows (e.g. the
    policy's chain) – used only to name the chain up to the root."""
    found = load(pem)
    if not found:
        return None
    leaf = found[0]
    sha256 = leaf.fingerprint(hashes.SHA256()).hex().upper()
    return {
        "common_name": _name(leaf.subject),
        "sans": _sans(leaf),
        "not_before": leaf.not_valid_before_utc.strftime("%Y-%m-%d %H:%M"),
        "not_after": leaf.not_valid_after_utc.strftime("%Y-%m-%d %H:%M"),
        "chain": chain(leaf, found[1:] + load(ca_pem)),
        "sha256": ":".join(sha256[i:i + 2] for i in range(0, len(sha256), 2)),
        "serial": format(leaf.serial_number, "X"),
        "key_usage": _key_usage(leaf),
        "extended_key_usage": _extended_key_usage(leaf),
        "key": key_name(leaf.public_key()),
    }


def chain(leaf: x509.Certificate, cas: list[x509.Certificate]) -> list[str]:
    """Names from the leaf up: each issuer found among `cas` continues the chain; an unknown issuer ends it with its
    name (from the certificate below), a self-signed CA ends it as the root."""
    names, current = [_name(leaf.subject)], leaf
    while current.issuer != current.subject and len(names) < MAX_CHAIN:
        issuer = next((c for c in cas if c.subject == current.issuer), None)
        names.append(_name(current.issuer))
        if issuer is None:
            break
        current = issuer
    return names


def key_name(key) -> str:
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {CURVES.get(key.curve.name, key.curve.name)}"
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(key).__name__


def _name(name: x509.Name) -> str:
    cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(cn[0].value) if cn else name.rfc4514_string()


def _extension(cert: x509.Certificate, kind):
    try:
        return cert.extensions.get_extension_for_class(kind).value
    except (x509.ExtensionNotFound, ValueError):  # ValueError: a malformed extension
        return None


def _sans(cert: x509.Certificate) -> list[str]:
    san = _extension(cert, x509.SubjectAlternativeName)
    return [f"{SAN_KINDS.get(type(g), 'Other')} {g.value}" for g in san] if san else []


def _key_usage(cert: x509.Certificate) -> list[str] | None:
    usage = _extension(cert, x509.KeyUsage)
    return [label for field, label in KEY_USAGES if getattr(usage, field)] if usage else None


def _extended_key_usage(cert: x509.Certificate) -> list[str] | None:
    usage = _extension(cert, x509.ExtendedKeyUsage)
    return [EXTENDED_KEY_USAGES.get(oid, oid.dotted_string) for oid in usage] if usage else None
