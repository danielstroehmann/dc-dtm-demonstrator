"""UC-3 – evergreen device IDs via an enrollment protocol (EST, CMPv2 or REST). The factory
station generates each key pair, authenticates with a passcode or its own client certificate and
enrolls one device; the timing is extrapolated to a production run.

Enrollment calls never carry the API key: DTM authenticates them through the run's
authentication policy. Verified live 2026-10-24 (docs/design/uc-03-factory-protocols.md)."""

import asyncio
import base64
import os
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
from .evergreen import common_names, create_division, prefix, rates, use_shared_profile
from .store import Store, now

PROTOCOLS = {"est": "EST", "cmpv2": "CMPv2", "scep": "SCEP", "rest": "REST API"}
AUTHS = {"passcode": "Passcode", "certificate": "Factory certificate"}
ESTIMATE_DEVICES = 1000
REQUEST_TIMEOUT = 30.0
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")  # DTM IDs that end up in openssl argv / URLs

AUTH_POLICY_PATH = f"{dtm.AUTH}/authentication-policy"
PASSCODE_PATH = f"{dtm.AUTH}/passcode"
AUTH_CERT_PATH = f"{dtm.AUTH}/authentication-certificate"
POLICY_PATH = dtm.POLICIES
REST_PATH = "/devicetrustmanager/certificate-issuance-service/api/v2/certificate"
EST_PATH = "/.well-known/est/devicetrustmanager/{policy_id}/simpleenroll"
CMP_PATH = "/devicetrustmanager/certificate-issuance-service/api/v1/cmp/DIOT_{alternative_id}"
SCEP_PATH = "/devicetrustmanager/certificate-issuance-service/api/v1/scep/DIOT_{alternative_id}"
# Subject fields the SCEP client always sends (its own defaults would be "scep-client" / "MDM"; its
# default C=US is dropped by DTM because the shared profile has no country field).
SCEP_SUBJECT = ("dc-dtm-demonstrator", "Factory")
RENEW_PATH = "/.well-known/est/devicetrustmanager/{policy_id}/simplereenroll"
# DTM accepts a just-issued certificate for renewal only after a few seconds (401 est_unauthorized
# right after issuance, verified live) – a renewal clicked immediately retries a little.
RENEW_ATTEMPTS = 3
RENEW_RETRY_S = 3.0
MAX_RENEWALS = 5  # every renewal consumes a license and DTM requests


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
        if protocol == "scep" and (not cmp_id or auth != "passcode"):
            raise EnrollmentError("SCEP needs the endpoint ID and a passcode (challenge password)")
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
        self.last_key: bytes | None = None

    async def aclose(self) -> None:
        await self.http.aclose()

    async def enroll(self, cn: str, key_pem: bytes, csr: x509.CertificateSigningRequest) -> dict:
        """One device: returns the certificate info. Only the network round trip is in here."""
        if self.protocol == "rest":
            return await self._rest(cn, csr)
        if self.protocol == "est":
            return await self._est(csr)
        if self.protocol == "scep":
            return await self._scep(cn, key_pem)
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
        return await self._tool("CMPv2", args, env, key_file, cert_file, "CMP error")

    async def _scep(self, cn: str, key_pem: bytes) -> dict:
        """scepclient (micromdm, Debian package `scep`) – an established SCEP client; the passcode is the
        challenge password. SCEP encrypts to the CA with RSA, so the device key is RSA (PKCS#1 for the client)."""
        tool = shutil.which("scepclient")
        if not tool:
            raise EnrollmentError("scepclient is not installed – SCEP needs it")
        key = serialization.load_pem_private_key(key_pem, password=None)
        key_file, cert_file = self.workdir / "device.key", self.workdir / "device.crt"
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                               serialization.NoEncryption()))
        key_file.chmod(0o600)
        for stale in (cert_file, self.workdir / "csr.pem", self.workdir / "self.pem"):  # scepclient reuses its own files
            stale.unlink(missing_ok=True)
        # scepclient takes the challenge only as an argument – visible to the container and, via ps, to users
        # of the host for about a second; the passcode is random per run and void after the rollback.
        args = [tool, "-server-url", f"https://{self.host}{SCEP_PATH.format(alternative_id=self.cmp_id)}",
                "-challenge", self.passcode, "-cn", cn, "-organization", SCEP_SUBJECT[0], "-ou", SCEP_SUBJECT[1],
                "-private-key", str(key_file), "-certificate", str(cert_file)]
        return await self._tool("SCEP", args, {"PATH": "/usr/bin:/bin", "SSL_CERT_FILE": certifi.where()},
                                key_file, cert_file, "")

    async def _tool(self, label: str, args: list[str], env: dict, key_file: Path, cert_file: Path, marker: str) -> dict:
        """Run an enrollment CLI with a timeout; the device key file is removed whatever happens."""
        # The tools report on stdout and stderr – read both for the error reason.
        process = await asyncio.create_subprocess_exec(*args, env=env, stdin=asyncio.subprocess.DEVNULL,
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            err, _ = await asyncio.wait_for(process.communicate(), REQUEST_TIMEOUT + 5)
        except TimeoutError as exc:
            raise EnrollmentError(f"{label} request timed out") from exc
        finally:  # also on cancellation (app shutdown): never leave the tool running
            if process.returncode is None:
                process.kill()
                await process.wait()
            key_file.unlink(missing_ok=True)
        if process.returncode != 0 or not cert_file.exists():
            lines = [line for line in err.decode(errors="replace").splitlines()
                     if line.strip() and not line.startswith("Warning:")]
            # openssl cmp: the last "CMP error" line; scepclient: its last line is the bare cause.
            reason = ([line for line in lines if marker in line] if marker else []) or lines
            text = reason[-1] if reason else "the client failed"
            if self.passcode:
                text = text.replace(self.passcode, "<passcode>")
            raise EnrollmentError(f"{label} request rejected: " + (text if len(text) <= 200 else "…" + text[-200:]))
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

            # UC-4 renews: 6 months, renewable at any time; CMPv2 sends a bare public key.
            spec = (dtm.PROFILE_RENEWAL if p["use_case"] == "uc04" else
                    dtm.PROFILE_EVERGREEN_CMP if protocol == "cmpv2" else dtm.PROFILE_EVERGREEN)
            profile_id = await use_shared_profile(client, api, spec, variables, log)

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
            if protocol in ("cmpv2", "scep"):  # the endpoint uses the policy's short ID; ca_chain signs CMP answers
                detail = await api.timed(f"Read the policy's short ID for the {PROTOCOLS[protocol]} endpoint", "GET",
                                         f"{POLICY_PATH}/{{POLICY_ID}}", client.get_policy(policy_id),
                                         spec={"method": "GET", "path": f"{POLICY_PATH}/{{POLICY_ID}}",
                                               "output": "policy.json"}, phase="setup")
                cmp_id = detail.get("alternative_id")
                if not cmp_id:
                    raise EnrollmentError(f"DTM returned no short ID for the {PROTOCOLS[protocol]} endpoint")
                ca_chain_pem = "".join(certs.der_b64_to_pem(c["blob"]) for c in detail.get("ca_chain") or []
                                       if c.get("blob"))
                variables["CMP_ID"] = cmp_id
            log("DTM is configured for this run", "success")
            result |= {"division": f"{base}-division", "policy": policy_name, "protocol": protocol, "auth": auth}

            station = Station(p["dtm_host"], protocol, auth, policy_id, cmp_id, passcode, passcode_ref, factory,
                              Path(tmp), ca_chain_pem)
            result |= await _enroll(station, api, store, run_id, p, log)
            if p["use_case"] == "uc04":  # the device in the field: its key and certificate
                _save_device(run_dir, station.last_key, result["certificates"][-1]["pem"])
                result["renewals"] = []
                _record_renewal_steps(api.calls, result["certificates"][-1]["common_name"], p["key_type"], None, None)
                for key in ("estimate_min", "estimate_devices"):  # one device – nothing to extrapolate
                    result.pop(key, None)
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


def _save_device(run_dir: Path, key_pem: bytes, cert_pem: str) -> None:
    """UC-4: the simulated device's key and current certificate in one file – written atomically
    (a crash never leaves a mismatching pair) and created with 0600. Demo material: never shown or
    downloadable, removed on any cleanup."""
    device = run_dir / "device"
    device.mkdir(parents=True, exist_ok=True)
    device.chmod(0o700)
    tmp = device / "device.pem.tmp"
    tmp.unlink(missing_ok=True)
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(key_pem + cert_pem.encode())
    os.replace(tmp, device / "device.pem")


async def renew(store: Store, run_id: str, run_dir: Path) -> None:
    """UC-4, per click: the device renews in the field via EST simplereenroll. It authenticates with
    its current certificate (mTLS on the clientauth host) – no passcode, no factory certificate.
    Verified live on Essentials: same CN, new serial and validity; the old certificate stays issued.
    Whatever happens, the run leaves "renewing" again."""
    log = lambda msg, level="step": store.add_event(run_id, msg, level)  # noqa: E731
    try:
        await _renew(store, run_id, run_dir, log)
    except (DTMError, ValueError, OSError) as exc:
        log(f"Renewal failed: {exc}", "error")
    except Exception as exc:
        log(f"Renewal failed unexpectedly: {type(exc).__name__}", "error")
        raise
    finally:
        store.claim_status(run_id, "renewing", "completed")
        store.update_run(run_id, progress=None)


async def _renew(store: Store, run_id: str, run_dir: Path, log) -> None:
    run_ = store.get_run(run_id)
    p, result = run_["params"], run_["result"]
    policies = store.objects(run_id, "policy")
    if not policies or not SAFE_ID.fullmatch(policies[0]["dtm_id"]):
        raise EnrollmentError("the run has no usable certificate policy")
    policy_id, cn = policies[0]["dtm_id"], result["certificates"][0]["common_name"]
    store.update_run(run_id, progress={"label": "Renewing in the field", "started": time.time()})
    log("Renewal in the field: the device authenticates with its current certificate")
    start = time.monotonic()
    key_pem, csr = await asyncio.to_thread(certs.device_request, cn, p["key_type"])  # a fresh key pair
    keygen = time.monotonic() - start
    context = ssl.create_default_context(cafile=certifi.where())
    context.load_cert_chain(run_dir / "device" / "device.pem")
    async with httpx.AsyncClient(verify=context, timeout=REQUEST_TIMEOUT) as http:
        for attempt in range(1, RENEW_ATTEMPTS + 1):
            start = time.monotonic()
            try:
                response = await http.post(
                    f"https://clientauth.{p['dtm_host']}{RENEW_PATH.format(policy_id=policy_id)}",
                    headers={"Content-Type": "application/pkcs10", "Content-Transfer-Encoding": "base64"},
                    content=base64.b64encode(csr.public_bytes(serialization.Encoding.DER)))
            except httpx.HTTPError as exc:
                raise EnrollmentError(f"EST simplereenroll failed: {type(exc).__name__}") from exc
            seconds = time.monotonic() - start
            if response.status_code != 401 or attempt == RENEW_ATTEMPTS:
                break
            log(f"DTM does not accept the new certificate yet – retrying in {RENEW_RETRY_S:g}s", "wait")
            await asyncio.sleep(RENEW_RETRY_S)
    if response.status_code >= 300:
        text = response.text[:200] if not response.text.lstrip().startswith("<") else "(HTML error page)"
        hint = (" – the certificate profile does not allow renewing a valid certificate"
                if "Renewal is disabled" in response.text else "")
        raise EnrollmentError(f"EST simplereenroll returned {response.status_code}: {text}{hint}")
    try:
        issued = certs.parse_pkcs7_certificates(base64.b64decode(response.content))[0]
    except (ValueError, IndexError) as exc:
        raise EnrollmentError("EST simplereenroll answer contains no certificate") from exc
    pem = issued["pem"]
    certs.save_certificates(run_dir, [issued])  # the result knows the certificate before the device switches
    result["certificates"].append(issued)
    result["certificate_total"] = len(result["certificates"])
    result["renewals"] = result.get("renewals", []) + [
        {"serial": issued["serial"], "seconds": round(seconds, 2), "keygen_s": round(keygen, 2),
         "attempts": attempt, "at": now()}]
    _record_renewal_steps(result["api_calls"], cn, p["key_type"], keygen, seconds)
    store.update_run(run_id, result=result)
    _save_device(run_dir, key_pem, pem)
    log(f"Renewed in {seconds:.2f}s (round trip{f', attempt {attempt}' if attempt > 1 else ''}) – new serial "
        f"{issued['serial']}, valid until {issued['not_after']}; the previous certificate stays valid", "success")
    store.update_run(run_id, status="completed")


def _record_renewal_steps(calls: list[dict], cn: str, key_type: str, keygen: float | None,
                          seconds: float | None) -> None:
    """The renewal block of the reproducible steps: seeded untimed right after the enrollment, then
    each renewal adds its count and time per step."""
    existing = {c["purpose"]: c for c in calls if c.get("phase") == "renewal"}
    timing = {"keygen": keygen, "call": seconds}
    renewed = seconds is not None
    for step in renew_steps(cn, key_type):
        took = timing.get(step["kind"])
        if step["purpose"] in existing:
            entry = existing[step["purpose"]]
            entry["count"] += renewed
            if took is not None:
                entry["seconds"] = round((entry["seconds"] or 0) + took, 2)
            continue
        calls.append({"purpose": step["purpose"], "method": step["method"], "path": step["path"],
                      "seconds": None if took is None else round(took, 2), "outcome": "ok", "count": int(renewed),
                      "spec": {"command": step["command"]}, "phase": "renewal"})


async def _record(store: Store, run_id: str, kind: str, name: str, create) -> str:
    object_id = await create
    store.add_object(run_id, kind, object_id, name)
    return object_id


async def _enroll(station: Station, api: ApiCalls, store: Store, run_id: str, p: dict, log) -> dict:
    """The fake batch: one device after another, each with its own key pair. Only the protocol
    round trip is measured; key generation is reported separately."""
    names = common_names(run_id, p["protocol"], p["count"], p["use_case"])
    log(f"Enrolling the device via {PROTOCOLS[p['protocol']]} ({AUTHS[p['auth']].lower()})")
    issued, seconds, keygen, per_device, keys = [], [], 0.0, [], 0
    started_wall = time.time()
    outcome = "error"
    try:
        for done, cn in enumerate(names, 1):
            start = time.monotonic()
            key_pem, csr = await asyncio.to_thread(certs.device_request, cn, p["key_type"])
            station.last_key = key_pem  # UC-4: the device keeps it for the renewal in the field
            generated = time.monotonic()
            keygen += generated - start
            keys += 1
            issued.append(await station.enroll(cn, key_pem, csr))
            seconds.append(time.monotonic() - generated)
            per_device.append(time.monotonic() - start)
            log(f"{cn} enrolled in {seconds[-1]:.2f}s", "success" if done == len(names) else "step")
            store.update_run(run_id, progress={"label": "Enrolling the device",
                                               "started": started_wall, "total": len(names), "done": done})
        outcome = "ok"
    finally:
        timing = {"keygen": (keygen or None, "ok", keys),
                  "call": (sum(seconds) or None, outcome, len(issued) + (outcome != "ok"))}
        for step in enroll_steps(p["protocol"], p["auth"], names[0], p["key_type"]):
            seconds_, outcome_, count = timing.get(step["kind"], (None, "ok", 1))
            api.add(step["purpose"], step["method"], step["path"], seconds_, outcome_, count=count,
                    spec={"command": step["command"]}, phase=step["phase"])
    total = sum(seconds)
    # A station also generates every key pair – the extrapolation uses the median per device of
    # key generation + round trip (robust against one slow request).
    median_device = statistics.median(per_device)
    log(f"Device enrolled – {total / len(seconds):.2f}s for the request", "success")
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
P12_PS = "openssl pkcs12 -export -inkey factory.key -in factory.crt -out factory.p12 -passout pass:"


def enroll_steps(protocol: str, auth: str, cn: str, key_type: str) -> list[dict]:
    """Copyable device enrollment as separate steps, like the other use cases: generate key (+ CSR)
    locally → the protocol call → turn the answer into a PEM certificate. One-time preparations
    are setup steps. Secrets only as variables the user sets.
    Each step: purpose, method, path (for the label), command {bash, powershell}, phase, kind
    ("keygen" | "call" | "convert" | "setup")."""
    rsa = key_type.upper().startswith("RSA")
    new_key = "rsa:2048" if rsa else "ec -pkeyopt ec_paramgen_curve:P-256"
    req = f'openssl req -new -newkey {new_key} -nodes -keyout device.key -subj "/CN={cn}"'
    clientauth = auth == "certificate" and protocol != "cmpv2"
    host_b, host_p = ("clientauth.${DTM_HOST}", "clientauth.$env:DTM_HOST") if clientauth else ("${DTM_HOST}", "$env:DTM_HOST")
    steps = []

    def step(kind, purpose, method, path, bash, powershell, phase="recurring"):
        steps.append({"kind": kind, "purpose": purpose, "method": method, "path": path,
                      "command": {"bash": bash, "powershell": powershell}, "phase": phase})

    if clientauth:  # Windows' curl.exe (Schannel) takes the client certificate as PKCS#12
        step("setup", "Convert the factory certificate for Windows curl.exe (local, once)", "LOCAL", "openssl",
             "# Linux/macOS: curl uses factory.crt and factory.key directly – nothing to do", P12_PS, "setup")
    if protocol == "cmpv2" and auth == "certificate":
        step("setup", "Build ca-chain.pem from the policy – DTM signs CMPv2 answers with the issuing CA (local, once)",
             "LOCAL", "openssl", CA_CHAIN_BASH, CA_CHAIN_PS, "setup")

    if protocol == "rest":
        tls = "--cert factory.crt --key factory.key" if clientauth else '-H "x-passcode: ${PASSCODE}"'
        ps_tls = "--cert-type P12 --cert factory.p12" if clientauth else '-H "x-passcode: $env:PASSCODE"'
        body = '{"certificate_policy_id": "%s", "csr": "%s", "certificate_profile_attributes": [{"id": "subject.common_name", "value": "%s"}]}'
        step("keygen", "Generate the device key and CSR (local, per device)", "LOCAL", "openssl",
             f"{req} -out device.csr\nexport CSR=\"$(awk '{{printf \"%s\\\\n\", $0}}' device.csr)\"",
             f"{req} -out device.csr\n" + '$env:CSR = (Get-Content device.csr -Raw).Replace("`r", "").Replace("`n", "\\n")')
        step("call", "Send the CSR, receive the certificate (once per device)", "POST", REST_PATH,
             f"cat > certificate.json <<EOF\n{body % ('${POLICY_ID}', '${CSR}', cn)}\nEOF\n"
             f'curl -sS --fail-with-body -X POST "https://{host_b}{REST_PATH}" {tls} \\\n'
             '  -H "Content-Type: application/json" --data @certificate.json -o certificate.json.out',
             f'Set-Content certificate.json "{(body % ("$env:POLICY_ID", "$env:CSR", cn)).replace(chr(34), chr(96) + chr(34))}"\n'
             f'curl.exe -sS --fail-with-body -X POST "https://{host_p}{REST_PATH}" {ps_tls} `\n'
             '  -H "Content-Type: application/json" --data "@certificate.json" -o certificate.json.out')
        step("convert", "Extract the certificate from the JSON response (local)", "LOCAL", "jq",
             "jq -r .pem certificate.json.out > device.crt",
             "(Get-Content certificate.json.out -Raw | ConvertFrom-Json).pem | Set-Content device.crt")
    elif protocol == "est":
        path_b, path_p = EST_PATH.format(policy_id="${POLICY_ID}"), EST_PATH.format(policy_id="$env:POLICY_ID")
        tls = ("--cert factory.crt --key factory.key" if clientauth else
               '-H "Authorization: Basic $(printf %s "${PASSCODE}" | openssl base64 -A)"')
        ps_tls = ("--cert-type P12 --cert factory.p12" if clientauth else
                  '-H "Authorization: Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($env:PASSCODE)))"')
        step("keygen", "Generate the device key and CSR, base64 DER for EST (local, per device)", "LOCAL", "openssl",
             f"{req} -outform DER -out device.der\nopenssl base64 -A -in device.der -out device.b64",
             f"{req} -outform DER -out device.der\n"
             '[Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD/device.der")) | Set-Content device.b64')
        step("call", "Send the CSR via EST simpleenroll (once per device)", "POST",
             EST_PATH.format(policy_id="{POLICY_ID}"),
             f'curl -sS --fail -X POST "https://{host_b}{path_b}" {tls} \\\n'
             '  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \\\n'
             "  --data-binary @device.b64 -o device.b64.out",
             f'curl.exe -sS --fail -X POST "https://{host_p}{path_p}" {ps_tls} `\n'
             '  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" `\n'
             '  --data-binary "@device.b64" -o device.b64.out')
        step("convert", "Convert the PKCS#7 answer to a PEM certificate (local)", "LOCAL", "openssl",
             "openssl base64 -d -A -in device.b64.out -out device.p7b\n"
             "openssl pkcs7 -inform DER -in device.p7b -print_certs -out device.crt",
             '[IO.File]::WriteAllBytes("$PWD/device.p7b", [Convert]::FromBase64String((Get-Content device.b64.out -Raw)))\n'
             "openssl pkcs7 -inform DER -in device.p7b -print_certs -out device.crt")
    elif protocol == "scep":
        org, ou = SCEP_SUBJECT
        args = [f"-server-url https://{{host}}{SCEP_PATH.format(alternative_id='{cmp}')}", "-challenge {secret}",
                f'-cn {cn} -organization "{org}" -ou "{ou}"', "-private-key device.key -certificate device.crt"]
        step("keygen", "Generate the device key – RSA, SCEP encrypts to the CA with RSA (local, per device)", "LOCAL",
             "openssl", "openssl genrsa -traditional -out device.key 2048", "openssl genrsa -traditional -out device.key 2048")
        step("call", "Request the certificate via SCEP – the passcode is the challenge password (once per device)", "POST",
             SCEP_PATH.format(alternative_id="{CMP_ID}"),
             "# scepclient: Debian/Ubuntu package scep (micromdm)\nscepclient " + " \\\n  ".join(
                 a.format(host="${DTM_HOST}", cmp="${CMP_ID}", secret='"${PASSCODE}"') for a in args),
             "# scepclient.exe: release of github.com/micromdm/scep\nscepclient " + " `\n  ".join(
                 a.format(host="$env:DTM_HOST", cmp="$env:CMP_ID", secret="$env:PASSCODE") for a in args))
        step("convert", "Inspect the issued certificate – scepclient already wrote it as PEM (local)", "LOCAL", "openssl",
             "openssl x509 -in device.crt -noout -subject -serial -enddate",
             "openssl x509 -in device.crt -noout -subject -serial -enddate")
    else:
        genkey = ("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out device.key" if rsa else
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
        step("keygen", "Generate the device key – CMPv2 sends the public key, no CSR (local, per device)", "LOCAL",
             "openssl", genkey, genkey)
        step("call", "Request the certificate via CMPv2 (initialization request, once per device)", "POST",
             CMP_PATH.format(alternative_id="{CMP_ID}"),
             "# CA_BUNDLE: public root CAs for TLS (macOS: /etc/ssl/cert.pem)\nopenssl cmp -cmd ir " + " \\\n  ".join(bash),
             "# CA_BUNDLE: a PEM file with the public root CAs (Windows has none by default)\n"
             "openssl cmp -cmd ir " + " `\n  ".join(ps))
        step("convert", "Inspect the issued certificate – openssl cmp already wrote it as PEM (local)", "LOCAL", "openssl",
             "openssl x509 -in device.crt -noout -subject -serial -enddate",
             "openssl x509 -in device.crt -noout -subject -serial -enddate")
    return steps


def renew_steps(cn: str, key_type: str) -> list[dict]:
    """UC-4 renewal in the field, as separate steps: new key + CSR → EST simplereenroll with the
    current certificate as mTLS client certificate → PEM; the new key replaces the old one."""
    new_key = "rsa:2048" if key_type.upper().startswith("RSA") else "ec -pkeyopt ec_paramgen_curve:P-256"
    req = (f'openssl req -new -newkey {new_key} -nodes -keyout device-new.key -subj "/CN={cn}" '
           "-outform DER -out renew.der")
    path_b, path_p = RENEW_PATH.format(policy_id="${POLICY_ID}"), RENEW_PATH.format(policy_id="$env:POLICY_ID")
    return [
        {"kind": "keygen", "phase": "renewal", "method": "LOCAL", "path": "openssl",
         "purpose": "Generate a new device key and CSR – the identity fields are taken from the current certificate (local)",
         "command": {"bash": f"{req}\nopenssl base64 -A -in renew.der -out renew.b64",
                     "powershell": f"{req}\n"
                                   '[Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD/renew.der")) | Set-Content renew.b64\n'
                                   "# Windows curl.exe takes the current certificate as PKCS#12\n"
                                   "openssl pkcs12 -export -inkey device.key -in device.crt -out device.p12 -passout pass:"}},
        {"kind": "call", "phase": "renewal", "method": "POST", "path": RENEW_PATH.format(policy_id="{POLICY_ID}"),
         "purpose": "Renew via EST simplereenroll – authenticated by the current device certificate (in the field)",
         "command": {"bash": "# DTM accepts a just-issued certificate for renewal only after a few seconds\nsleep 10\n"
                             f'curl -sS --fail -X POST "https://clientauth.${{DTM_HOST}}{path_b}" '
                             "--cert device.crt --key device.key \\\n"
                             '  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \\\n'
                             "  --data-binary @renew.b64 -o renew.b64.out",
                     "powershell": "# DTM accepts a just-issued certificate for renewal only after a few seconds\nStart-Sleep 10\n"
                                   f'curl.exe -sS --fail -X POST "https://clientauth.$env:DTM_HOST{path_p}" '
                                   "--cert-type P12 --cert device.p12 `\n"
                                   '  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" `\n'
                                   '  --data-binary "@renew.b64" -o renew.b64.out'}},
        {"kind": "convert", "phase": "renewal", "method": "LOCAL", "path": "openssl",
         "purpose": "Convert the answer to PEM and switch the device to the new key and certificate (local)",
         "command": {"bash": "openssl base64 -d -A -in renew.b64.out -out renew.p7b\n"
                             "openssl pkcs7 -inform DER -in renew.p7b -print_certs -out device.crt\n"
                             "mv device-new.key device.key",
                     "powershell": '[IO.File]::WriteAllBytes("$PWD/renew.p7b", [Convert]::FromBase64String((Get-Content renew.b64.out -Raw)))\n'
                                   "openssl pkcs7 -inform DER -in renew.p7b -print_certs -out device.crt\n"
                                   "Move-Item -Force device-new.key device.key\n"
                                   "Remove-Item device.p12  # it holds the previous key"}},
    ]
