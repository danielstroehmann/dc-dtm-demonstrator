import asyncio
import hashlib
import logging
import re
import secrets
import shutil
import sqlite3
import string
import time
import uuid
from urllib.parse import urlencode, urlsplit
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import cleanup, enrollment, evergreen, snippets
from .auth import COOKIE, Auth
from .config import APP_VERSION, DATA_DIR
from .dtm import DTMClient, DTMConfig, DTMError
from .store import Store

log = logging.getLogger("demonstrator")
HERE = Path(__file__).parent
RUN_ID = re.compile(r"^[a-z0-9]{1,16}$")
SERIAL = re.compile(r"^[0-9A-F]{1,64}$")
RUN_ID_ALPHABET = string.ascii_lowercase + string.digits


def new_run_id() -> str:
    """Default run ID: 6 random characters. DTM keeps the names of deleted policies reserved, so a
    reused run ID would fail – random IDs make a collision practically impossible."""
    return "".join(secrets.choice(RUN_ID_ALPHABET) for _ in range(6))
NAME = re.compile(r"[A-Za-z0-9 ._-]{1,40}")
HOST = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
ACTIVE = {"pending", "running", "renewing"}
SHOWN_EVENTS = 200
CERTIFICATES_PER_PAGE = 10
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")

ClientFactory = Callable[[DTMConfig, Callable[[str], None]], DTMClient]
# Catalog of use cases offered under "New run".
USE_CASES = evergreen.USE_CASES


def create_app(store: Store, auth: Auth, client_factory: ClientFactory = DTMClient,
               data_dir: Path = DATA_DIR) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["version"] = APP_VERSION
    # Cache busting: static URLs carry a hash of the files, so a new build is never hidden by the cache.
    templates.env.globals["asset_v"] = _asset_hash(HERE / "static")
    templates.env.globals["use_cases"] = USE_CASES
    templates.env.globals["use_case_names"] = evergreen.DISPLAY_NAMES
    templates.env.globals["catalog"] = evergreen.CATALOG
    templates.env.globals["snippets"] = snippets
    templates.env.globals["protocols"] = enrollment.PROTOCOLS
    templates.env.globals["auths"] = enrollment.AUTHS
    templates.env.globals["max_renewals"] = enrollment.MAX_RENEWALS
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    tasks: set[asyncio.Task] = set()
    store.mark_interrupted()

    def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
        # Shell (nav, connection chip) only for logged-in users – error pages are also served anonymously.
        authenticated = auth.is_authenticated(request)
        default = store.connection(None) if authenticated else None
        ctx = {"nav": None, "authenticated": authenticated,
               "default_connection": _public(default) if default else None} | ctx
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def run_connection(run: dict) -> dict | None:
        """The connection a run was created with – its own, whatever is the default now. Old runs
        (no connection_id) are matched by host and account."""
        params = run["params"]
        account = (params.get("dtm_host"), params.get("account_id"))
        conn = store.connection(params["connection_id"]) if params.get("connection_id") else None
        if not conn or (conn["host"], conn["account_id"]) != account:
            # Bound connection gone or changed: any connection to the same account will do.
            conn = store.connection_for(*account) if all(account) else None
        # A run is bound to the account it was created in – never act on it via another one.
        if conn and (conn["host"], conn["account_id"]) == account:
            return conn
        return None

    def in_use(connection_id: int) -> bool:
        """Runs that still need this connection to roll back."""
        return any(not _rolled_back(r) and (run_connection(r) or {}).get("id") == connection_id
                   for r in store.list_runs())

    def client_for(run_id: str | None = None, connection_id: int | None = None) -> DTMClient:
        if run_id:
            run = store.get_run(run_id)
            conn = run_connection(run)
            if not conn:
                raise HTTPException(409, f"Run {run_id} belongs to account {run['params'].get('account_id')} on "
                                         f"{run['params'].get('dtm_host')}, which is no longer configured.")
            on_call = lambda msg: store.add_event(run_id, f"API {msg}", "api")  # noqa: E731
        else:
            conn = store.connection(connection_id)
            if not conn:
                raise HTTPException(409, "DTM connection is not configured")
            on_call = lambda _m: None  # noqa: E731
        return client_factory(DTMConfig(conn["host"], conn["api_key"], conn["account_id"]), on_call)

    def selected_connection(value: str | None) -> dict:
        """The connection picked for the next run, or the default."""
        if value:
            conn = store.connection(int(value)) if value.isascii() and value.isdecimal() and len(value) < 19 else None
            if not conn:
                raise HTTPException(404, "Connection not found")
            return conn
        conn = store.connection(None)
        if not conn:
            raise HTTPException(409, "DTM connection is not configured")
        return conn

    def spawn(coro_factory, run_id: str, with_client: bool = True) -> None:
        client = client_for(run_id) if with_client else None  # fails in the request, before anything is started

        async def runner():
            try:
                await coro_factory(client)
            except Exception:
                log.exception("background task for run %s failed", run_id)
            finally:
                if client:
                    await client.aclose()
        task = asyncio.create_task(runner())
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.method == "POST" and not _same_origin(request):
            # SameSite treats other apps on this host (any port) as same-site; Origin does not.
            return HTMLResponse("Cross-origin request refused", status_code=403)
        public = request.url.path in ("/login", "/healthz") or request.url.path.startswith("/static/")
        if not public and not auth.is_authenticated(request):
            if request.headers.get("hx-request"):
                return HTMLResponse("", status_code=401, headers={"HX-Redirect": "/login"})
            return RedirectResponse("/login", status_code=303)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        # same-origin: browsers keep sending a real Origin on our own form posts (no-referrer → "null").
        response.headers["Referrer-Policy"] = "same-origin"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/runs/{run_id}/delete")
    async def delete_run(run_id: str):
        run = get_run_or_404(run_id)
        # Only after a full rollback – the ledger is what a cleanup needs, so it must not vanish earlier.
        if not _rolled_back(run):
            raise HTTPException(409, "Only runs with a completed full rollback can be deleted")
        shutil.rmtree(data_dir / "runs" / run_id, ignore_errors=True)
        store.delete_run(run_id)
        log.info("run %s deleted after full rollback", run_id)
        return RedirectResponse("/", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return render(request, "error.html", exc.status_code, message=exc.detail)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _exc):
        return render(request, "error.html", 400, message="Invalid or missing form values.")

    @app.exception_handler(RateLimitExceeded)
    async def rate_limited(request: Request, _exc):
        return render(request, "login.html", 429, error="Too many attempts – wait a minute and try again.")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "version": APP_VERSION}

    @app.get("/login")
    async def login_page(request: Request):
        return render(request, "login.html")

    @app.post("/login")
    @limiter.limit("5/minute")
    async def login(request: Request, password: str = Form(...)):
        if not auth.check_password(password):
            log.warning("failed login from %s", get_remote_address(request))
            return render(request, "login.html", 401, error="Wrong password.")
        response = RedirectResponse("/", status_code=303)
        auth.set_cookie(response, auth.issue())
        return response

    @app.post("/logout")
    async def logout():
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE)
        return response

    @app.get("/")
    async def index(request: Request):
        runs = [run | {"rolled_back": _rolled_back(run)} for run in store.list_runs()]
        several = len(store.connections()) > 1
        runs = [run | {"connection": (run_connection(run) or {}).get("name")
                       or f"{run['params'].get('connection_name', '–')} (not configured)"} for run in runs]
        connections = store.connections()
        return render(request, "index.html", nav="runs", runs=runs, configured=bool(connections), several=several,
                      connections=[_public(c) for c in connections],
                      selected=store.connection(None)["id"] if connections else None)

    def settings_view(request: Request, status_code: int = 200, **form):
        connections = [_public(c) for c in store.connections()]
        used = {c["id"]: in_use(c["id"]) for c in connections}
        return render(request, "settings.html", status_code, nav="settings", connections=connections, in_use=used,
                      form=form or {"host": "one.digicert.com"})

    @app.get("/settings")
    async def settings_page(request: Request, edit: int | None = None):
        conn = store.connection(edit) if edit else None
        if edit and not conn:
            raise HTTPException(404, "Connection not found")
        if conn:
            return settings_view(request, id=conn["id"], name=conn["name"], host=conn["host"],
                                 account_id=conn["account_id"], has_key=True)
        return settings_view(request)

    @app.post("/settings/connections")
    async def save_connection(request: Request, name: str = Form(...), host: str = Form(...),
                              account_id: str = Form(...), api_key: str = Form(""), id: str = Form("")):
        connection_id = int(id) if id.isdigit() else None
        existing = store.connection(connection_id) if connection_id else None
        if connection_id and not existing:
            raise HTTPException(404, "Connection not found")
        name, host, account_id, api_key = name.strip(), host.strip().lower(), account_id.strip(), api_key.strip()
        error = None
        if not NAME.fullmatch(name):
            error = "Name: 1–40 letters, digits, spaces, dots, hyphens or underscores."
        elif any(c["name"].lower() == name.lower() and c["id"] != connection_id for c in store.connections()):
            error = f"A connection named {name!r} already exists."
        elif not HOST.fullmatch(host):
            error = "Invalid host name."
        elif not _is_uuid(account_id):
            error = "The account ID must be a UUID."
        elif existing and (host, account_id) != (existing["host"], existing["account_id"]) and in_use(existing["id"]):
            # Its runs must stay reachable for their rollback.
            error = "This connection has runs that are not rolled back – create a new connection for another account."
        elif not api_key and existing and host != existing["host"]:
            # Never send the stored key to a host it was not entered for.
            error = "Enter the API key again when changing the host."
        api_key = api_key or (existing or {}).get("api_key", "")
        if not error and not api_key:
            error = "An API key is required."
        if not error:
            client = client_factory(DTMConfig(host, api_key, account_id), lambda _m: None)
            try:
                await client.check_account()
            except DTMError as exc:
                error = f"Connection check failed: {exc}"
            finally:
                await client.aclose()
        if error and not store.connections():
            return render(request, "index.html", 400, nav="runs", configured=False, runs=[], connections=[],
                          form={"name": name, "host": host, "account_id": account_id, "error": error})
        if error:
            return settings_view(request, 400, id=connection_id, name=name, host=host, account_id=account_id,
                                 has_key=bool(existing), error=error)
        first = not store.connections()
        try:
            store.save_connection(connection_id, name, host, account_id, api_key)
        except sqlite3.IntegrityError:  # a concurrent save took the name meanwhile
            return settings_view(request, 400, id=connection_id, name=name, host=host, account_id=account_id,
                                 has_key=bool(existing), error=f"A connection named {name!r} already exists.")
        # The very first connection comes from the welcome page – go straight on to the use cases.
        return RedirectResponse("/" if first else "/settings", status_code=303)

    def connection_or_404(connection_id: int) -> dict:
        conn = store.connection(connection_id)
        if not conn:
            raise HTTPException(404, "Connection not found")
        return conn

    @app.post("/settings/connections/{connection_id}/default")
    async def make_default(connection_id: int):
        connection_or_404(connection_id)
        store.set_default_connection(connection_id)
        return RedirectResponse("/settings", status_code=303)

    @app.get("/settings/connections/{connection_id}/profiles")
    async def shared_profiles(request: Request, connection_id: int):
        """Loaded lazily per connection: which shared profiles exist in that account (read only)."""
        conn = connection_or_404(connection_id)
        client = client_for(connection_id=conn["id"])
        try:
            status, error = await client.shared_profile_status(), None
        except DTMError as exc:
            status, error = {}, str(exc)
        finally:
            await client.aclose()
        return render(request, "_shared_profiles.html", connection=_public(conn), status=status, error=error,
                      busy=account_in_use(conn))

    def account_in_use(conn: dict) -> bool:
        """Shared profiles belong to the account – any connection to it with open runs counts."""
        return any(in_use(c["id"]) for c in store.connections()
                   if (c["host"], c["account_id"]) == (conn["host"], conn["account_id"]))

    @app.post("/settings/connections/{connection_id}/profiles/retire")
    async def retire_profiles(request: Request, connection_id: int):
        conn = connection_or_404(connection_id)
        if account_in_use(conn):  # its runs may still issue or renew with these profiles
            raise HTTPException(409, "Roll back the runs of this connection before retiring its shared profiles")
        client = client_for(connection_id=conn["id"])
        try:
            status, error = await client.retire_shared_profiles(), None
            log.info("retired shared profiles in connection %s", conn["name"])
        except DTMError as exc:
            status, error = {}, f"Retiring failed: {exc}"
        finally:
            await client.aclose()
        return render(request, "_shared_profiles.html", connection=_public(conn), status=status, error=error, busy=False)

    @app.post("/settings/connections/{connection_id}/delete")
    async def delete_connection(connection_id: int):
        conn = connection_or_404(connection_id)
        if in_use(conn["id"]):
            raise HTTPException(409, f"Connection {conn['name']!r} still has runs that are not rolled back")
        store.delete_connection(connection_id)
        return RedirectResponse("/settings", status_code=303)

    @app.get("/runs/new")
    async def use_case_catalog(request: Request, connection: str | None = None):
        connections = store.connections()
        selected = selected_connection(connection)["id"] if connections else None
        return render(request, "run_catalog.html", connections=[_public(c) for c in connections],
                      selected=selected)

    @app.get("/runs/new/{use_case}")
    async def new_run(request: Request, use_case: str, connection: str | None = None):
        if use_case in ("uc01", "uc02", "uc03"):  # old links: these are answers of the guide now
            query = f"?{urlencode({'connection': connection})}" if connection else ""
            return RedirectResponse(f"/runs/new/evergreen{query}", status_code=303)
        if use_case not in evergreen.CATALOG:
            raise HTTPException(404, "Unknown use case")
        conn = selected_connection(connection)
        client = client_for(connection_id=conn["id"])
        try:
            cas, profile_status = await client.issuing_cas(), await client.shared_profile_status()
        except DTMError as exc:
            return render(request, "error.html", 502, message=f"Could not load data from DTM: {exc}")
        finally:
            await client.aclose()
        return render(request, "run_new.html", use_case=evergreen.CATALOG[use_case], use_case_id=use_case, cas=cas,
                      profile_status=profile_status, connection=_public(conn),
                      default_connection=_public(conn), several=len(store.connections()) > 1,
                      max_batch=evergreen.MAX_BATCH,
                      default_run_id=new_run_id())

    @app.post("/runs")
    async def create_run(request: Request, run_id: str = Form(""), variant: str = Form("api"),
                         mode: str = Form(...), count: int = Form(10), ca_id: str = Form(...),
                         approval: bool = Form(False),
                         use_case: str = Form("uc01"), connection_id: str = Form(""),
                         protocol: str = Form(""), auth_method: str = Form(""), key_location: str = Form("")):
        run_id = run_id.strip().lower() or new_run_id()
        if use_case == "evergreen":
            if key_location not in ("server", "factory") or mode not in ("single", "batch"):
                raise HTTPException(400, "Answer where the key is generated and how many devices.")
            use_case, protocol, auth_method = evergreen.resolve_guide(key_location, mode, protocol, auth_method)
        if use_case not in USE_CASES:
            raise HTTPException(400, "Unknown use case")
        if mode == "single":  # a single device is exactly one certificate
            count = 1
        enrolled = use_case in ("uc03", "uc04")  # both run on the enrollment engine
        if use_case == "uc04":  # one device; renewal later per click (EST simplereenroll or CMPv2 kur)
            protocol, count = protocol or "est", 1
            if protocol not in ("est", "cmpv2"):
                raise HTTPException(400, "Renewal in the field: EST or CMPv2.")
        if enrolled:  # enrollment protocols: API only, sequential single requests, no approval
            variant, mode, approval = "api", "single", False
            # Checked before DTM is asked for anything.
            if protocol not in enrollment.PROTOCOLS or auth_method not in enrollment.AUTHS:
                raise HTTPException(400, "An API key works only with the REST API." if auth_method == "apikey"
                                    else "Select an enrollment protocol and an authentication method.")
            if protocol == "scep" and auth_method != "passcode":
                raise HTTPException(400, "SCEP authenticates with a passcode (challenge password).")
            count = 1
        conn = selected_connection(connection_id)
        client = client_for(connection_id=conn["id"])
        try:
            cas = {c["id"]: c for c in await client.issuing_cas()}
        except DTMError as exc:
            raise HTTPException(502, f"Could not load data from DTM: {exc}") from exc
        finally:
            await client.aclose()
        error = None
        if not RUN_ID.fullmatch(run_id):
            error = "Run ID: 1–16 lowercase letters or digits, no hyphen."
        elif store.run_exists(run_id):
            error = f"A run named {run_id!r} already exists."
        elif variant not in ("api", "webui") or mode not in ("single", "batch"):
            error = "Invalid variant or mode."
        elif not 1 <= count <= evergreen.MAX_BATCH:
            error = f"Number of certificates: 1–{evergreen.MAX_BATCH}."
        elif ca_id not in cas or cas[ca_id]["key_type"] not in evergreen.KEY_TYPES:
            error = "Select an issuing CA of this account."
        elif protocol == "scep" and cas[ca_id]["key_type"] != "rsa":
            error = "SCEP needs an RSA issuing CA (with 'Allow CA to decrypt and sign SCEP packets')."
        if error:
            raise HTTPException(400, error)
        ca = cas[ca_id]
        # The connection may have changed while DTM was asked; never create a run on a stale snapshot.
        if store.connection(conn["id"]) != conn:
            raise HTTPException(409, "The connection changed meanwhile – please start the run again")
        params = {"connection_id": conn["id"], "connection_name": conn["name"],
                  "dtm_host": conn["host"], "account_id": conn["account_id"],
                  "variant": variant, "mode": mode, "count": count,
                  "ca_id": ca_id, "ca_name": ca["name"], "key_type": evergreen.KEY_TYPES[ca["key_type"]],
                  "approval": approval and mode == "batch" and variant == "api"}
        if enrolled:
            params |= {"protocol": protocol, "auth": auth_method}
        # A reused run ID must not inherit files of a deleted run (e.g. an old batch.zip).
        shutil.rmtree(data_dir / "runs" / run_id, ignore_errors=True)
        store.create_run(run_id, use_case, params)
        engine = enrollment.run if enrolled else evergreen.run
        spawn(lambda c: engine(store, c, run_id, data_dir / "runs" / run_id), run_id)
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    def get_run_or_404(run_id: str) -> dict:
        run = store.get_run(run_id) if RUN_ID.fullmatch(run_id) else None
        if not run:
            raise HTTPException(404, "Run not found")
        return run

    @app.get("/runs/{run_id}")
    async def run_page(request: Request, run_id: str):
        run = get_run_or_404(run_id)
        return render(request, "run.html", **live_context(run), **certificate_page(run, 1), dialect="curl")

    @app.get("/runs/{run_id}/live")
    async def run_live(request: Request, run_id: str):
        run = get_run_or_404(run_id)
        if not _active(run) and request.headers.get("hx-request"):
            # The page was polling and the run/cleanup just finished: reload once to show the result.
            return HTMLResponse("", headers={"HX-Refresh": "true"})
        return render(request, "_run_live.html", **live_context(run))

    @app.get("/runs/{run_id}/timeline")
    async def run_timeline(request: Request, run_id: str):
        run = get_run_or_404(run_id)
        return render(request, "_timeline_items.html", **live_context(run))

    @app.get("/runs/{run_id}/api")
    async def run_api_calls(request: Request, run_id: str, dialect: str = "curl"):
        run = get_run_or_404(run_id)
        if dialect not in snippets.DIALECTS:
            raise HTTPException(404, "Unknown dialect")
        return render(request, "_api_calls.html", run=run, dialect=dialect)

    def live_context(run: dict) -> dict:
        events = store.events(run["id"])
        start = _epoch(events[0]["ts"]) if events else 0
        timeline = [e | {"t": _clock(_epoch(e["ts"]) - start)} for e in reversed(events[-SHOWN_EVENTS:])]
        progress = run.get("progress")
        if progress and _active(run):
            progress = progress | {"elapsed": int(time.time() - progress.get("started", time.time()))}
        else:
            progress = None
        return {"run": run, "events": timeline, "events_total": len(events), "active": _active(run),
                "progress": progress,
                "rolled_back": _rolled_back(run),
                "artifact_available": _artifact_path(data_dir, run) is not None}

    def certificate_page(run: dict, page: int) -> dict:
        certificates = (run.get("result") or {}).get("certificates") or []
        pages = max(1, -(-len(certificates) // CERTIFICATES_PER_PAGE))
        page = min(max(page, 1), pages)
        first = (page - 1) * CERTIFICATES_PER_PAGE
        return {"cert_rows": certificates[first:first + CERTIFICATES_PER_PAGE], "cert_page": page,
                "cert_pages": pages, "cert_first": first + 1,
                "pem_available": (data_dir / "runs" / run["id"] / "certificates").is_dir()}

    @app.get("/runs/{run_id}/certificates")
    async def run_certificates(request: Request, run_id: str, page: int = 1):
        run = get_run_or_404(run_id)
        return render(request, "_certificates.html", run=run, **certificate_page(run, page))

    @app.post("/runs/{run_id}/renew")
    async def renew_run(run_id: str):
        run = get_run_or_404(run_id)
        if run["use_case"] == "uc04" and run["status"] == "renewing":  # double click: just show the run
            return RedirectResponse(f"/runs/{run_id}", status_code=303)
        if run["use_case"] != "uc04" or run["status"] != "completed" or run.get("cleanup_status"):
            raise HTTPException(409, "Only a completed run of renewable device certificates that is not cleaned up can be renewed")
        if len((run.get("result") or {}).get("renewals") or []) >= enrollment.MAX_RENEWALS:
            raise HTTPException(409, f"At most {enrollment.MAX_RENEWALS} renewals per run")
        # Claim the run before the task starts – a concurrent request must not start a second renewal.
        if store.claim_status(run_id, "completed", "renewing"):
            spawn(lambda _c: enrollment.renew(store, run_id, data_dir / "runs" / run_id), run_id, with_client=False)
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    @app.get("/runs/{run_id}/certificates/{serial}.pem")
    async def run_certificate_pem(run_id: str, serial: str):
        run = get_run_or_404(run_id)
        info = next((c for c in (run.get("result") or {}).get("certificates") or [] if c.get("serial") == serial), None)
        path = data_dir / "runs" / run_id / "certificates" / f"{serial}.pem"
        # The serial must be one of the run's certificates – no path built from free input.
        if not info or not SERIAL.fullmatch(serial) or not path.is_file():
            raise HTTPException(404, "Certificate not found")
        return FileResponse(path, media_type="application/x-pem-file", filename=f"{info['common_name'] or serial}.pem")

    @app.get("/runs/{run_id}/artifact")
    async def run_artifact(run_id: str):
        run = get_run_or_404(run_id)
        path = _artifact_path(data_dir, run)
        if path is None:
            raise HTTPException(404, "No artifact for this run")
        return FileResponse(path, media_type="application/zip", filename=f"robot-{run_id}-{run['use_case']}-{path.name}")

    @app.post("/runs/{run_id}/cleanup")
    async def run_cleanup(run_id: str, mode: str = Form(...)):
        run = get_run_or_404(run_id)
        if mode not in ("full", "certificates") or _active(run):
            raise HTTPException(409, "Cleanup not possible right now")
        if _rolled_back(run):
            raise HTTPException(409, "This run has already been rolled back")
        spawn(lambda c: cleanup.cleanup(store, c, run_id, mode, data_dir / "runs" / run_id), run_id)
        store.update_run(run_id, cleanup_status="running")
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    return app


def _is_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


def _same_origin(request: Request) -> bool:
    """Modern browsers state the relation in Sec-Fetch-Site; otherwise compare Origin (or Referer)
    with this app's scheme and host. Non-browser clients send none of these and are accepted –
    they carry no ambient session cookie."""
    site = request.headers.get("sec-fetch-site")
    if site:
        return site in ("same-origin", "none")
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return True
    parts = urlsplit(source)
    return (parts.scheme, parts.netloc) == (request.url.scheme, request.headers.get("host", ""))


def _asset_hash(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(directory)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()[:10]


def _public(conn: dict) -> dict:
    """Connection data for templates – never the API key."""
    return {k: v for k, v in conn.items() if k != "api_key"}


def _clock(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 3600}:{seconds // 60 % 60:02d}:{seconds % 60:02d}" if seconds >= 3600 \
        else f"{seconds // 60}:{seconds % 60:02d}"


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


ARTIFACTS = ("batch.zip", "csrs.zip")


def _artifact_path(data_dir: Path, run: dict) -> Path | None:
    name = (run.get("result") or {}).get("artifact")
    path = data_dir / "runs" / run["id"] / name if name in ARTIFACTS else None
    return path if path and path.is_file() else None


def _rolled_back(run: dict) -> bool:
    return run.get("cleanup_mode") == "full" and run.get("cleanup_status") == "done"


def _active(run: dict) -> bool:
    return run["status"] in ACTIVE or run.get("cleanup_status") == "running"


def build() -> FastAPI:
    """Entry point for uvicorn (`app.main:build`, factory mode)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per DTM call is too much
    return create_app(Store(DATA_DIR / "demonstrator.db"), Auth.from_env())
