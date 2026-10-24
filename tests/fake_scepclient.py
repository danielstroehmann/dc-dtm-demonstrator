"""Stand-in for micromdm's `scepclient` in UC-3 tests (installed on PATH by the `scep_client`
fixture). Like the real client it reads the device key (PKCS#1 RSA), builds the subject from -cn,
-organization and -ou and writes the certificate to -certificate; the "CA" is the fake DTM's issuing
CA. Every call is recorded (argv, environment keys, SSL_CERT_FILE, the key file) – config.json next
to the installed script: {"ca_cert", "ca_key", "record", "fail"}. With "fail" set it fails the way
the real client does: a logfmt line `ts=… level=info op=GetCACert error="…"` followed by the bare Go
error as the last line ("{challenge}" in the cause echoes the challenge, as a careless server
message might), exit 1. Like the real client it leaves csr.pem and self.pem next to the key and
records whether such files were already there (scepclient would reuse them)."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FLAGS = {"-server-url", "-challenge", "-cn", "-organization", "-ou", "-private-key", "-certificate"}


def main() -> None:
    config = json.loads((Path(sys.argv[0]).resolve().parent / "config.json").read_text())
    argv = sys.argv[1:]
    options = {argv[i]: argv[i + 1] for i in range(0, len(argv) - 1, 2) if argv[i] in FLAGS}
    key_text = Path(options["-private-key"]).read_text() if Path(options.get("-private-key", "")).is_file() else ""
    workdir = Path(options.get("-private-key", ".")).parent
    record = {"argv": argv, "env_keys": sorted(os.environ), "ssl_cert_file": os.environ.get("SSL_CERT_FILE"),
              "key_file": key_text, "issued": None,
              "stale": sorted(n for n in ("csr.pem", "self.pem") if (workdir / n).exists())}

    def fail(cause):
        with open(config["record"], "a") as out:
            out.write(json.dumps(record) + "\n")
        quoted = cause.replace("\\", "\\\\").replace('"', '\\"')
        print(f'ts=2026-10-24T10:00:00.000Z level=info op=GetCACert error="{quoted}"', file=sys.stderr)
        print(cause, file=sys.stderr)
        sys.exit(1)

    if config.get("fail"):
        fail(config["fail"].replace("{challenge}", options.get("-challenge", "")))
    if not options.get("-challenge") or "/scep/DIOT_" not in options.get("-server-url", ""):
        fail("missing challenge or server URL")
    key = serialization.load_pem_private_key(key_text.encode(), None)
    if not isinstance(key, rsa.RSAPrivateKey) or "BEGIN RSA PRIVATE KEY" not in key_text:
        fail("expected a PKCS#1 RSA key")
    ca = x509.load_pem_x509_certificate(config["ca_cert"].encode())
    ca_key = serialization.load_pem_private_key(config["ca_key"].encode(), None)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, options["-cn"]),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, options["-organization"]),
                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, options["-ou"])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=365)).sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    (workdir / "csr.pem").write_text("-----BEGIN CERTIFICATE REQUEST-----\n(stand-in)\n")
    (workdir / "self.pem").write_text("-----BEGIN CERTIFICATE-----\n(stand-in)\n")
    Path(options["-certificate"]).write_bytes(pem)
    record["issued"] = pem.decode()
    with open(config["record"], "a") as out:
        out.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    main()
