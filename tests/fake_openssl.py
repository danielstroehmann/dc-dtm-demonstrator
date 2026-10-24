"""Stand-in for `openssl cmp` in UC-3 tests (installed as `openssl` on PATH by the `cmp_openssl`
fixture). It does what the real client does locally – read the device key, build the subject – and
issues the certificate with the fake DTM's issuing CA, so the engine parses a real certificate.

Every call is recorded (argv, the CMP_SECRET environment variable, the files the arguments point
to) so tests can assert the exact flags afterwards. Configuration lives next to the installed
script in `config.json`: {"ca_cert", "ca_key", "record", "fail", "real_openssl"} – with
"real_openssl" set, every other openssl command is passed on to the real binary.

Like the real client it rejects an incomplete protection (no -ref/-secret and no -cert/-key) and
prints a "CMP error" line plus exits non-zero when told to fail.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

VALUE_FLAGS = {"-cmd", "-server", "-tls_trusted", "-newkey", "-subject", "-msg_timeout", "-total_timeout",
               "-certout", "-ref", "-secret", "-cert", "-key", "-extracerts", "-trusted"}


RECORD: dict = {}
CONFIG: dict = {}


def save(issued: str | None = None) -> None:
    with open(CONFIG["record"], "a") as out:
        out.write(json.dumps(RECORD | {"issued": issued}) + "\n")


def fail(message: str) -> None:
    save()
    print("Warning: fake openssl warning line", file=sys.stderr)
    print(f"CMP error: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    config = CONFIG
    config.update(json.loads((Path(sys.argv[0]).resolve().parent / "config.json").read_text()))
    argv = sys.argv[1:]
    if argv[:1] != ["cmp"] and config.get("real_openssl"):  # everything but cmp: the real tool
        os.execv(config["real_openssl"], [config["real_openssl"], *argv])
    options, i = {}, 1
    while i < len(argv):
        if argv[i] in VALUE_FLAGS:
            options[argv[i]] = argv[i + 1]
            i += 2
        else:
            options[argv[i]] = True
            i += 1
    files = {}
    for flag in ("-cert", "-key", "-extracerts", "-trusted", "-newkey"):
        if flag in options and Path(options[flag]).is_file():
            files[flag] = Path(options[flag]).read_text()
    RECORD.update({"argv": argv, "cmp_secret": os.environ.get("CMP_SECRET"), "env_keys": sorted(os.environ),
                   "files": files})

    if argv[:1] != ["cmp"] or options.get("-cmd") != "ir":
        fail("only 'cmp -cmd ir' is modelled")
    if config.get("fail"):
        fail(config["fail"])
    secret = options.get("-secret", "")
    mac = "-ref" in options and secret.startswith("env:") and os.environ.get(secret[4:])
    signature = "-cert" in files and "-key" in files
    if not mac and not signature:
        fail("no valid message protection")
    if "-newkey" not in files or not str(options.get("-subject", "")).startswith("/CN="):
        fail("missing -newkey or -subject")

    device_key = serialization.load_pem_private_key(files["-newkey"].encode(), None)
    ca_cert = x509.load_pem_x509_certificate(config["ca_cert"].encode())
    ca_key = serialization.load_pem_private_key(config["ca_key"].encode(), None)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, options["-subject"][4:])]))
            .issuer_name(ca_cert.subject).public_key(device_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=365))
            .sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    Path(options["-certout"]).write_bytes(pem)
    save(pem.decode())


if __name__ == "__main__":
    main()
