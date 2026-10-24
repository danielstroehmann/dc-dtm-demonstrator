"""UC-3 – evergreen device IDs via an enrollment protocol (EST, CMPv2 or REST). The factory
station generates each key pair, authenticates with a passcode or its own client certificate and
enrolls up to MAX_REQUESTS devices one after another; the timings are extrapolated.

Enrollment calls never carry the API key: DTM authenticates them through the run's
authentication policy. Verified live 2026-10-24 (docs/design/uc-03-factory-protocols.md)."""

import asyncio
import base64
import re
import secrets
import shutil
import ssl
import statistics
import tempfile
import time
from pathlib import Path

import certifi
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import certs, dtm
from .apicalls import ApiCalls
from .dtm import DTMClient, DTMError
from .evergreen import common_names, create_division, prefix, rates
from .store import Store, now

PROTOCOLS = {"est": "EST", "cmpv2": "CMPv2", "rest": "REST API"}
AUTHS = {"passcode": "Passcode", "certificate": "Factory certificate"}
MAX_REQUESTS = 10
ESTIMATE_DEVICES = 1000
# One shared, reused profile per account: DTM refuses to delete a profile that a (deleted)
# policy referenced, so per-run profiles would pile up (accepted residue, see the UC-3 design).
CMP_PROFILE = "robot-uc03-cmp-profile"
REQUEST_TIMEOUT = 30.0
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # DTM IDs that end up in openssl argv / URLs
# Two CMPv2 runs at once must not both create the shared profile (it can never be deleted).
_cmp_profile_lock = asyncio.Lock()

AUTH_POLICY_PATH = f"{dtm.AUTH}/authentication-policy"
PASSCODE_PATH = f"{dtm.AUTH}/passcode"
AUTH_CERT_PATH = f"{dtm.AUTH}/authentication-certificate"
POLICY_PATH = dtm.POLICIES
REST_PATH = "/devicetrustmanager/certificate-issuance-service/api/v2/certificate"
EST_PATH = "/.well-known/est/devicetrustmanager/{policy_id}/simpleenroll"
CMP_PATH = "/devicetrustmanager/certificate-issuance-service/api/v1/cmp/DIOT_{alternative_id}"


class EnrollmentError(ValueError):
    pass


class Station:
    """The factory station's protocol side – one instance per run, files in a private temp dir."""

    def __init__(self, host: str, protocol: str, auth: str, policy_id: str, cmp_id: str | None,
                 passcode: str | None, passcode_ref: str | None, factory: tuple[str, bytes] | None, workdir: Path,
                 ca_chain_pem: str = ""):
        for value in (policy_id, cmp_id, passcode_ref):
            if value is not None and not SAFE_ID.fullmatch(value):
                raise EnrollmentError(f"unexpected ID from DTM: {value[:40]!r}")
        if protocol == "cmpv2" and (not cmp_id or (auth == "passcode" and not passcode_ref)):
            raise EnrollmentError("DTM returned no CMPv2 endpoint ID or passcode reference")
        self.protocol, self.auth, self.policy_id, self.cmp_id = protocol, auth, policy_id, cmp_id
        self.passcode, self.passcode_ref, self.workdir = passcode, passcode_ref, workdir
        # mTLS for REST/EST goes to the clientauth host; CMPv2 signs the message instead.
        self.host = f"clientauth.{host}" if auth == "certificate" and protocol != "cmpv2" else host
        context = ssl.create_default_context(cafile=certifi.where())
        if factory:
            (workdir / "factory.crt").write_text(factory[0])
            key_file = workdir / "factory.key"
            key_file.write_bytes(factory[1])
            key_file.chmod(0o600)
            if self.host.startswith("clientauth."):
                context.load_cert_chain(workdir / "factory.crt", key_file)
        # DTM signs signature-protected CMPv2 responses with the issuing CA – trust its chain.
        (workdir / "ca-chain.pem").write_text(ca_chain_pem)
        self.http = httpx.AsyncClient(verify=context, timeout=REQUEST_TIMEOUT)

    async def aclose(self) -> None:
        await self.http.aclose()

    async def enroll(self, cn: str, key_pem: bytes, csr: x509.CertificateSigningRequest) -> dict:
        """One device: returns the certificate info. Only the network round trip is in here."""
        if self.protocol == "rest":
            return await self._rest(cn, csr)
        if self.protocol == "est":
            return await self._est(csr)
        return await self._cmp(cn, key_pem)

    async def _post(self, path: str, **kwargs) -> httpx.Response:
        try:
            response = await self.http.post(f"https://{self.host}{path}", **kwargs)
        except httpx.HTTPError as exc:
            raise EnrollmentError(f"{PROTOCOLS[self.protocol]} request failed: {type(exc).__name__}") from exc
        if response.status_code >= 300:
            text = response.text[:200] if not response.text.lstrip().startswith("<") else "(HTML error page)"
            raise EnrollmentError(f"{PROTOCOLS[self.protocol]} returned {response.status_code}: {text}")
        return response

    async def _rest(self, cn: str, csr) -> dict:
        headers = {"x-passcode": self.passcode} if self.auth == "passcode" else {}
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        response = await self._post(REST_PATH, headers=headers, json=dtm.single_body(self.policy_id, cn, csr_pem))
        pem = dtm._json(response).get("pem")  # DTM may put raw line breaks into JSON strings
        if not pem:
            raise EnrollmentError("REST response contains no certificate")
        return certs.parse_pem_certificate(pem)

    async def _est(self, csr) -> dict:
        headers = {"Content-Type": "application/pkcs10", "Content-Transfer-Encoding": "base64"}
        if self.auth == "passcode":  # verified: Basic base64(<passcode>), no username
            headers["Authorization"] = "Basic " + base64.b64encode(self.passcode.encode()).decode()
        response = await self._post(EST_PATH.format(policy_id=self.policy_id), headers=headers,
                                    content=base64.b64encode(csr.public_bytes(serialization.Encoding.DER)))
        try:
            issued = certs.parse_pkcs7_certificates(base64.b64decode(response.content))
        except ValueError as exc:
            raise EnrollmentError("EST response is not a PKCS#7 certificate list") from exc
        if not issued:
            raise EnrollmentError("EST response contains no certificate")
        return issued[0]

    async def _cmp(self, cn: str, key_pem: bytes) -> dict:
        """openssl cmp (OpenSSL ≥ 3.0) – no Python CMP library of good standing exists."""
        openssl = shutil.which("openssl")
        if not openssl:
            raise EnrollmentError("openssl is not installed – CMPv2 needs it")
        key_file, cert_file = self.workdir / "device.key", self.workdir / "device.crt"
        key_file.write_bytes(key_pem)
        key_file.chmod(0o600)
        cert_file.unlink(missing_ok=True)
        args = [openssl, "cmp", "-cmd", "ir", "-server", f"https://{self.host}{CMP_PATH.format(alternative_id=self.cmp_id)}",
                "-tls_used", "-tls_trusted", certifi.where(), "-newkey", str(key_file), "-subject", f"/CN={cn}",
                "-implicit_confirm", "-unprotected_errors", "-msg_timeout", "20", "-total_timeout", "30",
                "-certout", str(cert_file)]
        env = {"PATH": "/usr/bin:/bin"}  # minimal: the app's own secrets stay out of the child
        if self.auth == "passcode":  # MAC protection; the secret goes via the environment, not argv
            args += ["-ref", self.passcode_ref, "-secret", "env:CMP_SECRET"]
            env["CMP_SECRET"] = self.passcode
        else:  # signature protection; DTM needs the signer certificate in extraCerts (verified)
            args += ["-cert", str(self.workdir / "factory.crt"), "-key", str(self.workdir / "factory.key"),
                     "-extracerts", str(self.workdir / "factory.crt"), "-trusted", str(self.workdir / "ca-chain.pem")]
        # openssl cmp reports on stdout and stderr – read both for the error reason.
        process = await asyncio.create_subprocess_exec(*args, env=env, stdin=asyncio.subprocess.DEVNULL,
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            err, _ = await asyncio.wait_for(process.communicate(), REQUEST_TIMEOUT + 5)
        except TimeoutError as exc:
            raise EnrollmentError("CMPv2 request timed out") from exc
        finally:  # also on cancellation (app shutdown): never leave openssl running
            if process.returncode is None:
                process.kill()
                await process.wait()
            key_file.unlink(missing_ok=True)
        if process.returncode != 0 or not cert_file.exists():
            lines = [line for line in err.decode(errors="replace").splitlines()
                     if line.strip() and not line.startswith("Warning:")]
            reason = [line for line in lines if "CMP error" in line] or lines
            raise EnrollmentError("CMPv2 request rejected: " + (reason[-1][:200] if reason else "openssl failed"))
        return certs.parse_pem_certificate(cert_file.read_text())


async def run(store: Store, client: DTMClient, run_id: str, run_dir: Path) -> None:
    run_ = store.get_run(run_id)
    p = run_["params"] | {"use_case": run_["use_case"]}
    protocol, auth = p["protocol"], p["auth"]
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    api = ApiCalls()
    # Snippet variables: secrets only as placeholders – the passcode never leaves this function.
    variables = {"DTM_HOST": p["dtm_host"], "DTM_ACCOUNT_ID": p["account_id"]}
    if auth == "passcode":
        variables["PASSCODE"] = "<choose a passcode, 6–64 characters>"
    result: dict = {"api_calls": api.calls, "api_variables": variables}
    store.update_run(run_id, status="running")
    base = prefix(run_id, p["use_case"])
    station = None
    try:
        with tempfile.TemporaryDirectory(prefix="dtm-uc03-") as tmp:
            division_id = await create_division(client, api, store, run_id, p["use_case"], variables, log)

            log(f"Creating authentication policy {base}-auth – the factory's credential lives here")
            auth_policy_id = await api.timed(
                "Create an authentication policy for the factory", "POST", AUTH_POLICY_PATH,
                client.create_auth_policy(f"{base}-auth"),
                spec={"method": "POST", "path": AUTH_POLICY_PATH, "body_file": "auth-policy.json",
                      "json": {"name": f"{base}-auth", "account_id": "{DTM_ACCOUNT_ID}"}}, phase="setup")
            store.add_object(run_id, "auth_policy", auth_policy_id, f"{base}-auth")
            variables["AUTH_POLICY_ID"] = auth_policy_id

            passcode = passcode_ref = factory = None
            if auth == "passcode":
                passcode = secrets.token_hex(16)
                log(f"Creating passcode {base}-passcode – what the factory receives from the CA operator")
                created = await api.timed(
                    "Create the factory's passcode", "POST", PASSCODE_PATH,
                    client.create_passcode(f"{base}-passcode", auth_policy_id, passcode),
                    spec={"method": "POST", "path": PASSCODE_PATH, "body_file": "passcode.json",
                          "output": "passcode.json.out",
                          "json": {"name": f"{base}-passcode", "account_id": "{DTM_ACCOUNT_ID}",
                                   "authentication_policy_id": "{AUTH_POLICY_ID}",
                                   "enable_username_for_passcode": False, "passcode": "{PASSCODE}"}},
                    phase="setup")
                store.add_object(run_id, "passcode", created["id"], f"{base}-passcode")
                passcode_ref = created["alternate_id"]
                if protocol == "cmpv2":  # CMPv2 sender KID of the user's own passcode
                    variables["PASSCODE_REF"] = "<alternate_id from passcode.json.out>"
            else:
                log("The factory creates its own client certificate (self-signed) and registers it in DTM")
                factory = certs.factory_certificate(f"{base}-factory")
                api.add("Create the factory's own client certificate (local, once)", "LOCAL", "openssl", None,
                        spec={"command": factory_command(f"{base}-factory")}, phase="setup")
                await api.timed(
                    "Register the factory certificate as authentication certificate", "POST", AUTH_CERT_PATH,
                    _record(store, run_id, "auth_certificate", f"{base}-factory",
                            client.create_auth_certificate(f"{base}-factory", auth_policy_id, factory[0])),
                    spec={"method": "POST", "path": AUTH_CERT_PATH, "body_file": "auth-certificate.json",
                          "json": {"name": f"{base}-factory", "account_id": "{DTM_ACCOUNT_ID}",
                                   "authentication_policy_id": "{AUTH_POLICY_ID}", "pem": "{FACTORY_CERT}",
                                   "use_passcode": False}},
                    phase="setup")

            profile_id = p["profile_id"]
            if protocol == "cmpv2":  # CMPv2 sends a bare public key – needs a profile that allows it
                async with _cmp_profile_lock:
                    profile_id, created = await api.timed(
                        f"Find the shared CMPv2 profile {CMP_PROFILE} – created once from the selected profile, "
                        "its csr entry allows a bare public key", "GET",
                        dtm.PROFILES, client.bare_key_profile(CMP_PROFILE, p["profile_id"]),
                        spec={"method": "GET", "path": dtm.PROFILES}, phase="setup")
                log(f"{'Created' if created else 'Using'} the shared CMPv2 profile {CMP_PROFILE}")
            variables["PROFILE_ID"] = profile_id

            policy_name = f"{base}-policy"
            log(f"Creating certificate policy {policy_name} ({PROTOCOLS[protocol]}, {p['key_type']}, {p['ca_name']})")
            policy_args = {"profile_id": profile_id, "ica_id": p["ca_id"], "key_type": p["key_type"],
                           "auth_policy_id": auth_policy_id, "protocol": protocol}
            policy_id = await api.timed(
                f"Create the certificate policy ({PROTOCOLS[protocol]}, client-side keys)", "POST", POLICY_PATH,
                client.create_enrollment_policy(name=policy_name, division_id=division_id, **policy_args),
                spec={"method": "POST", "path": POLICY_PATH, "body_file": "policy.json",
                      "json": dtm.enrollment_policy_body(
                          name=policy_name, division_id="{DIVISION_ID}", **policy_args
                          | {"profile_id": "{PROFILE_ID}", "auth_policy_id": "{AUTH_POLICY_ID}"})},
                phase="setup")
            store.add_object(run_id, "policy", policy_id, policy_name)
            variables["POLICY_ID"] = policy_id
            cmp_id, ca_chain_pem = None, ""
            if protocol == "cmpv2":  # the endpoint uses the policy's short ID; ca_chain signs the answers
                detail = await api.timed("Read the policy's short ID and CA chain for CMPv2", "GET",
                                         f"{POLICY_PATH}/{{POLICY_ID}}", client.get_policy(policy_id),
                                         spec={"method": "GET", "path": f"{POLICY_PATH}/{{POLICY_ID}}",
                                               "output": "policy.json"}, phase="setup")
                cmp_id = detail.get("alternative_id")
                if not cmp_id:
                    raise EnrollmentError("DTM returned no short ID for the CMPv2 endpoint")
                ca_chain_pem = "".join(certs.der_b64_to_pem(c["blob"]) for c in detail.get("ca_chain") or []
                                       if c.get("blob"))
                variables["CMP_ID"] = cmp_id
            log("DTM is configured for this run", "success")
            result |= {"division": f"{base}-division", "policy": policy_name, "protocol": protocol, "auth": auth}

            station = Station(p["dtm_host"], protocol, auth, policy_id, cmp_id, passcode, passcode_ref, factory,
                              Path(tmp), ca_chain_pem)
            result |= await _enroll(station, api, store, run_id, p, log)
        certs.save_certificates(run_dir, result.get("certificates") or [])
        store.update_run(run_id, status="completed", result=result, progress=None, finished_at=now())
        log("Run completed", "success")
    except (DTMError, ValueError) as exc:
        log(f"Run failed: {exc}", "error")
        store.update_run(run_id, status="failed", error=str(exc), progress=None, finished_at=now(), result=result)
    except Exception as exc:  # keep the run visible as failed instead of silently dying
        log(f"Run failed unexpectedly: {type(exc).__name__}", "error")
        store.update_run(run_id, status="failed", error=type(exc).__name__, progress=None, finished_at=now(),
                         result=result)
        raise
    finally:
        if station:
            await station.aclose()


async def _record(store: Store, run_id: str, kind: str, name: str, create) -> str:
    object_id = await create
    store.add_object(run_id, kind, object_id, name)
    return object_id


async def _enroll(station: Station, api: ApiCalls, store: Store, run_id: str, p: dict, log) -> dict:
    """The fake batch: one device after another, each with its own key pair. Only the protocol
    round trip is measured; key generation is reported separately."""
    names = common_names(run_id, p["protocol"], p["count"], p["use_case"])
    log(f"Enrolling {len(names)} device(s) via {PROTOCOLS[p['protocol']]} ({AUTHS[p['auth']].lower()}), one by one")
    issued, seconds, keygen, per_device = [], [], 0.0, []
    started_wall = time.time()
    outcome = "error"
    try:
        for done, cn in enumerate(names, 1):
            start = time.monotonic()
            key_pem, csr = await asyncio.to_thread(certs.device_request, cn, p["key_type"])
            generated = time.monotonic()
            keygen += generated - start
            issued.append(await station.enroll(cn, key_pem, csr))
            seconds.append(time.monotonic() - generated)
            per_device.append(time.monotonic() - start)
            log(f"{cn} enrolled in {seconds[-1]:.2f}s", "success" if done == len(names) else "step")
            store.update_run(run_id, progress={"label": f"Enrolling {len(names)} devices one by one",
                                               "started": started_wall, "total": len(names), "done": done})
        outcome = "ok"
    finally:
        api.add(f"Enroll a device via {PROTOCOLS[p['protocol']]} (once per device)", "LOCAL",
                PROTOCOLS[p["protocol"]], sum(seconds) or None, outcome, count=len(issued) + (outcome != "ok"),
                spec={"command": enroll_command(p["protocol"], p["auth"], names[0], p["key_type"])})
    total = sum(seconds)
    # A station also generates every key pair – the extrapolation uses the median per device of
    # key generation + round trip (robust against one slow request).
    median_device = statistics.median(per_device)
    log(f"{len(issued)} device(s) enrolled – {total / len(seconds):.2f}s per request", "success")
    return {"duration_s": round(total, 2), **rates(total, len(issued)), "median_device_s": round(median_device, 3),
            "keygen_s": round(keygen, 2), "estimate_devices": ESTIMATE_DEVICES,
            "estimate_min": round(ESTIMATE_DEVICES * median_device / 60, 1),
            "response": {"protocol": PROTOCOLS[p["protocol"]], "authentication": AUTHS[p["auth"]],
                         "common_name": issued[0]["common_name"], "serial": issued[0]["serial"]},
            "certificates": issued, "certificate_total": len(issued), "private_keys_returned": 0}


def factory_command(cn: str) -> dict:
    openssl = ('openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout factory.key '
               f'-out factory.crt -days 7 -subj "/CN={cn}" -addext "basicConstraints=critical,CA:FALSE" '
               '-addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=clientAuth"')
    return {"bash": openssl + "\nexport FACTORY_CERT=\"$(awk '{printf \"%s\\\\n\", $0}' factory.crt)\"",
            "powershell": openssl + '\n$env:FACTORY_CERT = (Get-Content factory.crt -Raw).Replace("`r", "").Replace("`n", "\\n")'}


CA_CHAIN_BASH = ("# ca-chain.pem from the policy (policy.json): DTM signs CMPv2 answers with the issuing CA\n"
                 "jq -r '.ca_chain[].blob' policy.json | while read -r b; do\n"
                 "  printf %s \"$b\" | openssl base64 -d -A | openssl x509 -inform DER; done > ca-chain.pem")
CA_CHAIN_PS = ("# ca-chain.pem from the policy (policy.json): DTM signs CMPv2 answers with the issuing CA\n"
               "(Get-Content policy.json -Raw | ConvertFrom-Json).ca_chain | ForEach-Object {\n"
               '  [IO.File]::WriteAllBytes("$PWD/ca.der", [Convert]::FromBase64String($_.blob))\n'
               "  openssl x509 -inform DER -in ca.der } | Set-Content ca-chain.pem")
# Windows' curl.exe (Schannel) takes the client certificate as PKCS#12, not PEM + key.
P12_PS = "openssl pkcs12 -export -inkey factory.key -in factory.crt -out factory.p12 -passout pass:"


def enroll_command(protocol: str, auth: str, cn: str, key_type: str) -> dict:
    """Copyable device enrollment, per shell. Secrets only as variables the user sets."""
    command = _enroll_command(protocol, auth, cn, key_type)
    if auth == "certificate" and protocol == "cmpv2":
        command = {"bash": CA_CHAIN_BASH + "\n" + command["bash"], "powershell": CA_CHAIN_PS + "\n" + command["powershell"]}
    elif auth == "certificate":
        command["powershell"] = P12_PS + "\n" + command["powershell"]
    return command


def _enroll_command(protocol: str, auth: str, cn: str, key_type: str) -> dict:
    new_key = "rsa:2048" if key_type.upper().startswith("RSA") else "ec -pkeyopt ec_paramgen_curve:P-256"
    keygen = f'openssl req -new -newkey {new_key} -nodes -keyout device.key -subj "/CN={cn}"'
    clientauth = auth == "certificate" and protocol != "cmpv2"
    if protocol == "rest":
        tls = "--cert factory.crt --key factory.key" if clientauth else '-H "x-passcode: ${PASSCODE}"'
        ps_tls = "--cert-type P12 --cert factory.p12" if clientauth else '-H "x-passcode: $env:PASSCODE"'
        host_b = "clientauth.${DTM_HOST}" if clientauth else "${DTM_HOST}"
        host_p = "clientauth.$env:DTM_HOST" if clientauth else "$env:DTM_HOST"
        body = '{"certificate_policy_id": "%s", "csr": "%s", "certificate_profile_attributes": [{"id": "subject.common_name", "value": "%s"}]}'
        return {
            "bash": (f"{keygen} -out device.csr\nexport CSR=\"$(awk '{{printf \"%s\\\\n\", $0}}' device.csr)\"\n"
                     f"cat > certificate.json <<EOF\n{body % ('${POLICY_ID}', '${CSR}', cn)}\nEOF\n"
                     f'curl -sS --fail-with-body -X POST "https://{host_b}{REST_PATH}" {tls} \\\n'
                     '  -H "Content-Type: application/json" --data @certificate.json -o certificate.json.out'),
            "powershell": (f"{keygen} -out device.csr\n"
                           '$env:CSR = (Get-Content device.csr -Raw).Replace("`r", "").Replace("`n", "\\n")\n'
                           f'Set-Content certificate.json "{(body % ("$env:POLICY_ID", "$env:CSR", cn)).replace(chr(34), chr(96) + chr(34))}"\n'
                           f'curl.exe -sS -X POST "https://{host_p}{REST_PATH}" {ps_tls} `\n'
                           '  -H "Content-Type: application/json" --data "@certificate.json" -o certificate.json.out'),
        }
    if protocol == "est":
        path_b = EST_PATH.format(policy_id="${POLICY_ID}")
        path_p = EST_PATH.format(policy_id="$env:POLICY_ID")
        tls = ("--cert factory.crt --key factory.key" if clientauth else
               '-H "Authorization: Basic $(printf %s "${PASSCODE}" | openssl base64 -A)"')
        ps_tls = ("--cert-type P12 --cert factory.p12" if clientauth else
                  '-H "Authorization: Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($env:PASSCODE)))"')
        host_b = "clientauth.${DTM_HOST}" if clientauth else "${DTM_HOST}"
        host_p = "clientauth.$env:DTM_HOST" if clientauth else "$env:DTM_HOST"
        return {
            "bash": (f"{keygen} -outform DER -out device.der\nopenssl base64 -A -in device.der -out device.b64\n"
                     f'curl -sS --fail -X POST "https://{host_b}{path_b}" {tls} \\\n'
                     '  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \\\n'
                     "  --data-binary @device.b64 | base64 -d > device.p7b\n"
                     "openssl pkcs7 -inform DER -in device.p7b -print_certs -out device.crt"),
            "powershell": (f"{keygen} -outform DER -out device.der\n"
                           '[Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD/device.der")) | Set-Content device.b64\n'
                           f'curl.exe -sS -X POST "https://{host_p}{path_p}" {ps_tls} `\n'
                           '  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" `\n'
                           '  --data-binary "@device.b64" -o device.b64.out\n'
                           '[IO.File]::WriteAllBytes("$PWD/device.p7b", [Convert]::FromBase64String((Get-Content device.b64.out -Raw)))\n'
                           "openssl pkcs7 -inform DER -in device.p7b -print_certs -out device.crt"),
        }
    genkey = ("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out device.key"
              if key_type.upper().startswith("RSA") else
              "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out device.key")
    creds = ("-ref ${PASSCODE_REF} -secret env:PASSCODE" if auth == "passcode"
             else "-cert factory.crt -key factory.key -extracerts factory.crt -trusted ca-chain.pem")
    ps_creds = ("-ref $env:PASSCODE_REF -secret env:PASSCODE" if auth == "passcode"
                else "-cert factory.crt -key factory.key -extracerts factory.crt -trusted ca-chain.pem")
    lines = [f"-server https://{{host}}{CMP_PATH.format(alternative_id='{cmp}')}",
             "-tls_used -tls_trusted {bundle}", f'-newkey device.key -subject "/CN={cn}"', "{creds}",
             "-implicit_confirm -certout device.crt"]
    bash = [line.format(host="${DTM_HOST}", cmp="${CMP_ID}", bundle="${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}",
                        creds=creds) for line in lines]
    ps = [line.format(host="$env:DTM_HOST", cmp="$env:CMP_ID", bundle="$env:CA_BUNDLE", creds=ps_creds) for line in lines]
    return {"bash": ("# CA_BUNDLE: public root CAs for TLS (macOS: /etc/ssl/cert.pem)\n"
                     + genkey + "\nopenssl cmp -cmd ir " + " \\\n  ".join(bash)),
            "powershell": ("# CA_BUNDLE: a PEM file with the public root CAs (Windows has none by default)\n"
                           + genkey + "\nopenssl cmp -cmd ir " + " `\n  ".join(ps))}
