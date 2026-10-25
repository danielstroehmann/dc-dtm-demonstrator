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
    print("cmp_main: error while running the CMP client", file=sys.stderr)  # a trailing generic line
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

    if argv[:1] != ["cmp"] or options.get("-cmd") not in ("ir", "kur"):
        fail("only 'cmp -cmd ir' and 'cmp -cmd kur' are modelled")
    if options.get("-cmd") == "kur":
        key_update(config, options, files)
        return
    if config.get("fail"):  # "{secret}" echoes the MAC secret, as a careless server message might
        fail(config["fail"].replace("{secret}", os.environ.get("CMP_SECRET", "")))
    secret = options.get("-secret", "")
    mac = "-ref" in options and secret.startswith("env:") and os.environ.get(secret[4:])
    signature = "-cert" in files and "-key" in files
    if not mac and not signature:
        fail("no valid message protection")
    if "-newkey" not in files or not str(options.get("-subject", "")).startswith("/CN="):
        fail("missing -newkey or -subject")

    passcode_rules(config, options)
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
    if config.get("auto_state"):  # replay tests: DTM now lists this certificate as issued
        state_file = Path(sys.argv[0]).resolve().parent / "state.json"
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        alternative_id = str(options.get("-server", "")).rsplit("DIOT_", 1)[-1]
        state.setdefault(alternative_id, []).append(format(cert.serial_number, "x"))
        state_file.write_text(json.dumps(state))


def passcode_rules(config: dict, options: dict) -> None:
    """UC-5 one-time passcodes, like DTM (verified live): the usage limit is checked first, every
    request counts as a use (also a rejected one), then the registered common name. The fake DTM
    publishes its passcodes into config.json and reads the uses back from the usage file."""
    rule = (config.get("passcodes") or {}).get(options.get("-ref"))
    if not rule:
        return
    import hashlib
    secret = os.environ.get(str(options.get("-secret", ""))[4:], "")
    if hashlib.sha256(secret.encode()).hexdigest() != rule["secret_sha256"]:  # MAC with another passcode
        fail('request rejected by server:PKIStatus: rejection; StatusString: "MAC verification failed"; '
             "PKIFailureInfo: badMessageCheck")
    if not (rule.get("limit") or rule.get("cn")):
        return
    usage_file = Path(config["usage_file"])
    usage = json.loads(usage_file.read_text()) if usage_file.exists() else {}
    ref = options["-ref"]
    if rule["enforce"] and rule.get("limit") and usage.get(ref, 0) + rule.get("used", 0) >= rule["limit"]:
        fail('request rejected by server:PKIStatus: rejection; StatusString: "Passcode has reached its usage limit"; '
             "PKIFailureInfo: badRequest")
    usage[ref] = usage.get(ref, 0) + 1
    usage_file.write_text(json.dumps(usage))
    if rule["enforce"] and rule.get("cn") and options["-subject"][4:] != rule["cn"]:
        fail('request rejected by server:PKIStatus: rejection; StatusString: "Invalid registered value provided in '
             'attribute: subject.common_name"; PKIFailureInfo: badRequest')


REJECTION = ('request rejected by server:PKIStatus: rejection; StatusString: "certificate not yet valid for '
             'key update"; PKIFailureInfo: badRequest')


def key_update(config: dict, options: dict, files: dict) -> None:
    """kur: signature protection with the current certificate. Like DTM: the signer must be a
    certificate issued under the policy behind DIOT_<id> and not revoked (state.json, published by
    the test from the fake DTM), and its key must sign; the new certificate keeps the subject."""
    if config.get("kur_reject", 0) > 0:  # DTM refuses a just-issued certificate for a few seconds
        config["kur_reject"] -= 1
        (Path(sys.argv[0]).resolve().parent / "config.json").write_text(json.dumps(config))
        fail(REJECTION)  # the live wording
    if config.get("kur_fail"):  # a failure that is not DTM's rejection (transport, local files, …)
        fail(config["kur_fail"])
    if not all(f in files for f in ("-cert", "-key", "-extracerts", "-trusted", "-newkey")):
        fail("kur needs -cert, -key, -extracerts, -trusted and -newkey")
    state = json.loads((Path(sys.argv[0]).resolve().parent / "state.json").read_text())
    alternative_id = str(options.get("-server", "")).rsplit("DIOT_", 1)[-1]
    current = x509.load_pem_x509_certificate(files["-cert"].encode())
    signer = serialization.load_pem_private_key(files["-key"].encode(), None)
    if format(current.serial_number, "x") not in state.get(alternative_id, []):
        fail("signer certificate is not an issued certificate of this policy")
    if signer.public_key().public_numbers() != current.public_key().public_numbers():
        fail("message signature invalid")
    if x509.load_pem_x509_certificate(files["-extracerts"].encode()) != current:
        fail("Error while reading the certificate in the extraCert field")
    if config["ca_cert"].strip() not in files["-trusted"]:
        fail("cannot validate the response signature (-trusted)")
    new_key = serialization.load_pem_private_key(files["-newkey"].encode(), None)
    ca_cert = x509.load_pem_x509_certificate(config["ca_cert"].encode())
    ca_key = serialization.load_pem_private_key(config["ca_key"].encode(), None)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(current.subject).issuer_name(ca_cert.subject)
            .public_key(new_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=180))
            .sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    Path(options["-certout"]).write_bytes(pem)
    save(pem.decode())


if __name__ == "__main__":
    main()
