import asyncio
import hashlib
import importlib.util
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
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import cleanup, devices, dtm, enrollment, evergreen, firmware, minions, retrofit, snippets, trustedge
from .auth import COOKIE, MAX_PASSWORD, MIN_PASSWORD, Auth
from .config import APP_VERSION, BUILD, DATA_DIR, DEV_MODE, build_label
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
DEVICE_CASES = ("uc06", "uc07", "uc08")  # Advanced: one tile per device, enrolled/renewed per click
FIELD_START = ("uc07", "uc08")  # devices that go into the field per click from their tile


def max_renewals(run: dict) -> int:
    """Renewal rounds per run – the route and the button use the same limit."""
    return devices.MAX_RENEWALS if run["use_case"] in DEVICE_CASES else enrollment.MAX_RENEWALS


def create_app(store: Store, auth: Auth, client_factory: ClientFactory = DTMClient,
               data_dir: Path = DATA_DIR, dev_mode: bool = DEV_MODE) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["build_label"] = build_label(dev_mode)
    # Cache busting: static URLs carry a hash of the files, so a new build is never hidden by the cache.
    templates.env.globals["asset_v"] = _asset_hash(HERE / "static")
    templates.env.globals["use_cases"] = USE_CASES
    templates.env.globals["use_case_names"] = evergreen.DISPLAY_NAMES
    templates.env.globals["platforms"] = dtm.PLATFORMS
    templates.env.globals["platform_regions"] = dtm.PLATFORM_REGIONS
    templates.env.filters["dtm_message"] = enrollment.dtm_message  # also tidies runs stored before it existed
    templates.env.globals["catalog"] = evergreen.CATALOG
    templates.env.globals["snippets"] = snippets
    templates.env.globals["protocols"] = enrollment.PROTOCOLS
    templates.env.globals["auths"] = enrollment.AUTHS | {"apikey": "API key"}
    templates.env.globals["max_renewals"] = max_renewals
    templates.env.globals["renewals_of"] = devices.renewals_of
    templates.env.globals["max_device_renewals"] = devices.MAX_RENEWALS
    templates.env.globals["device_cases"] = DEVICE_CASES
    templates.env.globals["firmware"] = firmware
    templates.env.globals["max_minions"] = trustedge.MAX_DEVICES
    templates.env.globals["store_catalog"] = store  # the firmware card reads the cached catalogue
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    # Feedback overlay: dev mode only, and only where its code exists – the release image does not contain it.
    dev_tools = dev_mode and importlib.util.find_spec(f"{__package__}.devtools") is not None
    if dev_tools:
        from .devtools import feedback
        feedback.install(app, data_dir / "feedback", BUILD)
    templates.env.globals["dev_tools"] = dev_tools
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    tasks: set[asyncio.Task] = set()
    store.mark_interrupted()

    def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
        # Shell (nav, connection chip) only for logged-in users – error pages are also served anonymously.
        authenticated = auth.is_authenticated(request)
        default = store.connection(None) if authenticated else None
        ctx = {"nav": None, "authenticated": authenticated, "page_template": name,
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
        public = request.url.path in ("/login", "/setup", "/healthz", "/version") or request.url.path.startswith("/static/")
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
        return render(request, "error.html", exc.status_code, message=exc.detail, status=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _exc):
        return render(request, "error.html", 400, message="Invalid or missing form values.")

    @app.exception_handler(RateLimitExceeded)
    async def rate_limited(request: Request, _exc):
        return render(request, "login.html", 429, setup=not auth.has_password(),
                      error="Too many attempts – wait a minute and try again.")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "version": APP_VERSION}

    @app.get("/version")
    async def version():
        """Build identity – public like the version in the login page's footer; nothing secret."""
        return BUILD | {"dev": dev_tools}

    @app.get("/login")
    async def login_page(request: Request):
        # No password yet: the first visitor sets it (no installer prompt, nothing in .env).
        return render(request, "login.html", setup=not auth.has_password())

    @app.post("/setup")
    @limiter.limit("5/minute")
    async def setup(request: Request, password: str = Form(...), repeat: str = Form(...)):
        if auth.has_password():
            return RedirectResponse("/login", status_code=303)
        error = (f"At least {MIN_PASSWORD} characters." if len(password) < MIN_PASSWORD
                 else f"At most {MAX_PASSWORD} characters." if len(password) > MAX_PASSWORD
                 else "The passwords do not match." if password != repeat else None)
        if error:
            return render(request, "login.html", 400, setup=True, error=error)
        if not await run_in_threadpool(auth.set_password, password):  # another request was first
            return RedirectResponse("/login", status_code=303)
        log.warning("login password set from %s", get_remote_address(request))
        response = RedirectResponse("/", status_code=303)
        auth.set_cookie(response, auth.issue())
        return response

    @app.post("/login")
    @limiter.limit("5/minute")
    async def login(request: Request, password: str = Form(...)):
        if not auth.has_password():
            return RedirectResponse("/login", status_code=303)
        if not await run_in_threadpool(auth.check_password, password):  # Argon2: ~50 ms, not on the loop
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

    def list_row(run: dict) -> dict:
        """A run as the runs list shows it (rolled back?, connection name)."""
        return run | {"rolled_back": _rolled_back(run),
                      "connection": (run_connection(run) or {}).get("name")
                      or f"{run['params'].get('connection_name', '–')} (not configured)"}

    @app.get("/runs/{run_id}/row")
    async def run_row(request: Request, run_id: str):
        """The list row on its own – it polls itself while a full rollback runs."""
        run = store.get_run(run_id) if RUN_ID.fullmatch(run_id) else None
        if not run:  # deleted meanwhile: 286 makes htmx stop polling, the empty body removes the row
            return HTMLResponse("", status_code=286)
        return render(request, "_run_row.html", run=list_row(run), several=len(store.connections()) > 1)

    @app.get("/")
    async def index(request: Request):
        runs = [list_row(run) for run in store.list_runs()]
        several = len(store.connections()) > 1
        connections = store.connections()
        return render(request, "index.html", nav="runs", runs=runs, configured=bool(connections), several=several,
                      connections=[_public(c) for c in connections], minions_ready=await minions.available(),
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
        elif host not in dtm.PLATFORMS and not (existing and host == existing["host"]):
            # An older connection on another host stays editable (e.g. a new key) – its runs must roll back.
            error = "Only one.digicert.com (US) and one.nl.digicert.com (NL) are supported."
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
        mode = dtm.PLATFORMS.get(conn["host"])
        if mode != "shared":  # NL: one profile per run; other hosts: no new runs – nothing shared to show
            return render(request, "_shared_profiles.html", connection=_public(conn), status={}, error=None,
                          busy=False, per_run=mode == "per_run", unsupported=mode is None)
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
                      selected=selected, minions_ready=await minions.available())

    @app.get("/runs/new/{use_case}")
    async def new_run(request: Request, use_case: str, connection: str | None = None):
        if use_case in ("uc01", "uc02", "uc03"):  # old links: these are answers of the guide now
            query = f"?{urlencode({'connection': connection})}" if connection else ""
            return RedirectResponse(f"/runs/new/evergreen{query}", status_code=303)
        if use_case not in evergreen.CATALOG:
            raise HTTPException(404, "Unknown use case")
        conn = selected_connection(connection)
        if (platform := evergreen.CATALOG[use_case].platform) and conn["host"] != platform:
            # e.g. UC-8: the default connection is NL – take the first one on the use case's platform
            conn = next((c for c in store.connections() if c["host"] == platform), None)
            if not conn:
                return render(request, "error.html", 400, message=f"This use case needs a connection to {platform}.")
        if use_case == "uc08" and not await minions.available():
            return render(request, "error.html", 400, message="This use case needs the IoT minion runtime (Docker).")
        profile_mode = dtm.PLATFORMS.get(conn["host"])
        if not profile_mode:
            return render(request, "error.html", 400,
                          message="Only one.digicert.com (US) and one.nl.digicert.com (NL) are supported – "
                                  "change the connection in Settings.")
        client = client_for(connection_id=conn["id"])
        try:
            cas = await client.issuing_cas()
            profile_status = await client.shared_profile_status() if profile_mode == "shared" else {}
        except DTMError as exc:
            return render(request, "error.html", 502, message=f"Could not load data from DTM: {exc}")
        finally:
            await client.aclose()
        return render(request, "run_new.html", nav="runs", use_case=evergreen.CATALOG[use_case], use_case_id=use_case, cas=cas,
                      profile_status=profile_status, profile_mode=profile_mode, connection=_public(conn),
                      default_connection=_public(conn), several=len(store.connections()) > 1,
                      max_batch=evergreen.MAX_BATCH, max_passcode_batch=enrollment.MAX_PASSCODE_BATCH,
                      max_devices=devices.MAX_DEVICES,
                      default_run_id=new_run_id())

    @app.post("/runs")
    async def create_run(request: Request, run_id: str = Form(""), variant: str = Form("api"),
                         mode: str = Form(...), count: int = Form(10), ca_id: str = Form(...),
                         approval: bool = Form(False),
                         use_case: str = Form("uc01"), connection_id: str = Form(""),
                         protocol: str = Form(""), auth_method: str = Form(""), key_location: str = Form(""),
                         checks: bool = Form(False), pause: bool = Form(False), field: str = Form("est"), identity: str = Form("serial")):
        run_id = run_id.strip().lower() or new_run_id()
        if use_case == "evergreen":
            if key_location not in ("server", "factory") or mode not in ("single", "batch"):
                raise HTTPException(400, "Answer where the key is generated and how many devices.")
            use_case, protocol, auth_method = evergreen.resolve_guide(key_location, mode, protocol, auth_method)
        if use_case not in USE_CASES:
            raise HTTPException(400, "Unknown use case")
        if mode == "single":  # a single device is exactly one certificate
            count = 1
        if use_case == "uc06":  # checked before DTM is asked for anything
            protocol, auth_method = protocol or "rest", auth_method or "apikey"
            if problem := devices.check_choice(protocol, auth_method, field, identity):
                raise HTTPException(400, problem)
        enrolled = use_case in ("uc03", "uc04", "uc05")  # all run on the enrollment engine
        if use_case in ("uc04", "uc05", "uc07"):  # field enrollment / renewal via EST or CMPv2
            protocol = protocol or "est"
            if protocol not in ("est", "cmpv2"):
                raise HTTPException(400, "Field enrollment: EST or CMPv2.")
        if use_case == "uc05":
            auth_method = "passcode"
        if enrolled:  # enrollment protocols: API only, sequential single requests, no approval
            variant, approval = "api", False
            if use_case != "uc05":  # UC-5 batch: one passcode per device, enrolled one after another
                mode = "single"
            # Checked before DTM is asked for anything.
            if protocol not in enrollment.PROTOCOLS or auth_method not in enrollment.AUTHS:
                raise HTTPException(400, "An API key works only with the REST API." if auth_method == "apikey"
                                    else "Select an enrollment protocol and an authentication method.")
            if protocol == "scep" and auth_method != "passcode":
                raise HTTPException(400, "SCEP authenticates with a passcode (challenge password).")
            if mode == "single":
                count = 1
        conn = selected_connection(connection_id)
        if conn["host"] not in dtm.PLATFORMS:  # a connection saved before the platforms were limited
            raise HTTPException(400, "Only one.digicert.com (US) and one.nl.digicert.com (NL) are supported.")
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
        elif use_case in ("uc06", "uc07") and count > devices.MAX_DEVICES:
            error = f"Number of devices: 1–{devices.MAX_DEVICES}."
        elif use_case == "uc05" and count > enrollment.MAX_PASSCODE_BATCH:
            error = f"Number of devices: 1–{enrollment.MAX_PASSCODE_BATCH} (one passcode each)."
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
        if use_case == "uc05":
            params |= {"checks": checks, "pause": pause}
        if use_case == "uc06":  # sequential requests per device – no portal, no approval
            params |= {"variant": "api", "approval": False, "protocol": protocol, "auth": auth_method,
                       "field": field, "identity": identity}
        if use_case == "uc08":  # TrustEdge: EST bootstrap, the agent fetches the operational certificate
            if (not trustedge.supported(conn["host"]) or count > trustedge.MAX_DEVICES
                    or cas[ca_id]["key_type"] != "ecdsa" or not await minions.available()):
                raise HTTPException(400, f"TrustEdge managed devices: a US connection, an ECDSA issuing CA, the IoT "
                                         f"minion runtime and 1–{trustedge.MAX_DEVICES} devices.")
            params |= {"variant": "api", "approval": False, "protocol": "trustedge", "auth": "passcode",
                       "pause": pause}
        if use_case == "uc07":  # the device-ID certificate authenticates; the field protocol also renews
            params |= {"protocol": protocol, "auth": "certificate", "field": protocol, "pause": pause}
        # A reused run ID must not inherit files of a deleted run (e.g. an old batch.zip).
        shutil.rmtree(data_dir / "runs" / run_id, ignore_errors=True)
        store.create_run(run_id, use_case, params)
        engine = (enrollment.run if enrolled else devices.run if use_case == "uc06" else retrofit.run if use_case == "uc07"
                  else trustedge.run if use_case == "uc08" else evergreen.run)
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
        return render(request, "run.html", nav="runs", **live_context(run), **certificate_page(run, 1), dialect="curl")

    @app.get("/runs/{run_id}/live")
    async def run_live(request: Request, run_id: str, busy: str = ""):
        run = get_run_or_404(run_id)
        # busy: the devices acting when the page was rendered – one finishing reloads its tile's results
        now_busy = ",".join((run.get("result") or {}).get("busy") or [])
        if request.headers.get("hx-request") and (not _active(run) or busy != now_busy):
            # The page was polling and the run/cleanup/a device just finished: reload once to show the result.
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
        """UC-4: the run's one device renews. Device-level use cases renew per device (see below)."""
        run = get_run_or_404(run_id)
        renewable = run["use_case"] == "uc04"
        if renewable and run["status"] == "renewing":  # double click: just show the run
            return RedirectResponse(f"/runs/{run_id}", status_code=303)
        if not renewable or run["status"] != "completed" or run.get("cleanup_status"):
            raise HTTPException(409, "Only a completed run of renewable device certificates that is not cleaned up can be renewed")
        limit = max_renewals(run)
        if len((run.get("result") or {}).get("renewals") or []) >= limit:
            raise HTTPException(409, f"At most {limit} renewals per run")
        # Claim the run before the task starts – a concurrent request must not start a second renewal.
        if store.claim_status(run_id, "completed", "renewing"):
            spawn(lambda _c: enrollment.renew(store, run_id, data_dir / "runs" / run_id), run_id, with_client=False)
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    @app.get("/runs/{run_id}/devices/{name}/tile")
    async def device_tile(request: Request, run_id: str, name: str, i: int = 1):
        """One device's tile – polled while the device acts, so its stage shows live."""
        run = get_run_or_404(run_id)
        device = next((d for d in (run.get("result") or {}).get("devices") or [] if d.get("name") == name), None)
        if run["use_case"] not in DEVICE_CASES or device is None:
            raise HTTPException(404, "Device not found")
        if device.get("container") and name not in (run["result"].get("busy") or []):
            # A running minion lives on its own (agent connects, installs updates) – the tile reads what it reports
            try:
                seen = await minions.state(device["container"])
            except minions.MinionError:
                seen = None
            if seen:
                change = {"agent": seen["agent"], "agent_since": seen["since"], "next_connect": seen["next_connect"]} | (
                    {"firmware": seen["firmware"]} if seen["firmware"] else {})
                if any(device.get(k) != v for k, v in change.items()):
                    run["result"] = devices.commit(store, run_id, lambda r: devices.device_of(r, name).update(change))
                    device = devices.device_of(run["result"], name)
        return render(request, "_device_tile.html", run=run, d=device, loop_index=max(1, min(i, 1000)))

    @app.post("/runs/{run_id}/devices/add")
    async def add_device(run_id: str):
        """UC-8 per click: one more IoT minion from the factory."""
        run = get_run_or_404(run_id)
        result = run.get("result") or {}
        if run["use_case"] != "uc08" or not result.get("devices"):
            raise HTTPException(404, "No IoT minions in this run")
        if trustedge.ADDING in (result.get("busy") or []):  # a double click
            return RedirectResponse(f"/runs/{run_id}", status_code=303)
        if run["status"] != "completed" or run.get("cleanup_status"):
            raise HTTPException(409, "Only a completed run that is not cleaned up can add devices")
        if len(result["devices"]) >= trustedge.MAX_DEVICES:
            raise HTTPException(409, f"At most {trustedge.MAX_DEVICES} IoT minions per run")
        devices.commit(store, run_id, lambda r: r.update(busy=[*(r.get("busy") or []), trustedge.ADDING]))
        try:
            spawn(lambda c: trustedge.add_device(store, c, run_id, data_dir / "runs" / run_id), run_id)
        except Exception:
            devices.commit(store, run_id, lambda r: r.update(busy=[n for n in r.get("busy") or [] if n != trustedge.ADDING]))
            raise
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    @app.post("/runs/{run_id}/firmware/{action}/{value}")
    async def firmware_action(run_id: str, action: str, value: str):
        """UC-8 per click: a new firmware version (new/<figure>) or a catalogue version to the devices (deploy/<name>)."""
        run = get_run_or_404(run_id)
        result = run.get("result") or {}
        if run["use_case"] != "uc08" or not result.get("devices") or action not in ("new", "deploy"):
            raise HTTPException(404, "No firmware for this run")
        if firmware.BUSY in (result.get("busy") or []):  # a double click
            return RedirectResponse(f"/runs/{run_id}", status_code=303)
        if run["status"] != "completed" or run.get("cleanup_status"):
            raise HTTPException(409, "Only a completed run that is not cleaned up can change firmware")
        if action == "new" and value not in firmware.CHARACTERS:
            raise HTTPException(404, "Unknown figure")
        if firmware.legacy(result):
            raise HTTPException(409, "This run was started before the firmware catalogue")
        if action == "deploy":
            if value not in {e["name"] for e in firmware.catalog(store, run["params"]["account_id"])}:
                raise HTTPException(404, "Unknown firmware version")
            if len(result.get("firmware") or []) >= firmware.MAX_DEPLOYMENTS:
                raise HTTPException(409, f"At most {firmware.MAX_DEPLOYMENTS} firmware deployments per run")
        devices.commit(store, run_id, lambda r: r.update(busy=[*(r.get("busy") or []), firmware.BUSY]))
        engine = (lambda c: firmware.create(store, c, run_id, value)) if action == "new" else (
            lambda c: firmware.deploy(store, c, run_id, value))
        try:
            spawn(engine, run_id)
        except Exception:
            devices.commit(store, run_id, lambda r: r.update(busy=[n for n in r.get("busy") or [] if n != firmware.BUSY]))
            raise
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    @app.post("/runs/{run_id}/devices/{name}/{action}")
    async def device_action(run_id: str, name: str, action: str):
        """Advanced use cases: one device, per click – UC-7 enrolls it in the field, UC-6/UC-7 renew it."""
        run = get_run_or_404(run_id)
        result = run.get("result") or {}
        # The name must be one of the run's devices – nothing is built from free input.
        device = next((d for d in result.get("devices") or [] if d.get("name") == name), None)
        if run["use_case"] not in DEVICE_CASES or device is None or action not in ("enroll", "renew"):
            raise HTTPException(404, "Device not found")
        if name in (result.get("busy") or []):  # a double click: just show the run
            return RedirectResponse(f"/runs/{run_id}", status_code=303)
        if run["status"] != "completed" or run.get("cleanup_status"):
            raise HTTPException(409, "Only a completed run that is not cleaned up can act on its devices")
        if action == "enroll" and (run["use_case"] not in FIELD_START or device.get("issued") or device.get("container")):
            raise HTTPException(409, "This device is enrolled already")
        if action == "renew" and run["use_case"] == "uc08":
            raise HTTPException(409, "The TrustEdge agent renews its certificate itself")
        if action == "renew":
            if not device.get("issued"):
                raise HTTPException(409, "Enroll the device first")
            if devices.renewals_of(result, name) >= devices.MAX_RENEWALS:
                raise HTTPException(409, f"At most {devices.MAX_RENEWALS} renewals per device")
        # Devices act independently – only this one is busy (marked before the task starts, so a second
        # request for it is a double click); the run stays completed.
        devices.commit(store, run_id, lambda r: r.update(busy=[*(r.get("busy") or []), name]))
        engine = ({"uc07": retrofit.enroll, "uc08": trustedge.enroll}[run["use_case"]] if action == "enroll"
                  else devices.renew)
        try:
            spawn(lambda c: engine(store, c, run_id, data_dir / "runs" / run_id, name), run_id)
        except Exception:  # no client (connection gone or changed) – the device must not stay busy
            devices.commit(store, run_id, lambda r: r.update(busy=[n for n in r.get("busy") or [] if n != name]))
            raise
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    @app.post("/runs/{run_id}/enroll")
    async def enroll_run(run_id: str):
        """UC-5: the run paused after the factory step continues with the field enrollment."""
        run = get_run_or_404(run_id)
        if run["use_case"] != "uc05":
            raise HTTPException(409, "Only a passcode-bound run waits for the field enrollment")
        if not run.get("cleanup_status"):  # a double click or a stale page just shows the run as it is
            store.claim_status(run_id, "paused", "running")
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
    async def run_cleanup(request: Request, run_id: str, mode: str = Form(...)):
        """mode "certificates" is API-only now – the UI offers the full rollback in the runs list."""
        from_list = bool(request.headers.get("hx-request"))
        run = get_run_or_404(run_id)
        try:
            if mode not in ("full", "certificates") or _active(run):
                raise HTTPException(409, "Cleanup not possible right now")
            if _rolled_back(run):
                raise HTTPException(409, "This run has already been rolled back")
            spawn(lambda c: cleanup.cleanup(store, c, run_id, mode, data_dir / "runs" / run_id), run_id)
        except HTTPException as exc:
            if not from_list:
                raise
            # htmx swaps no error responses – the row comes back with the current state and the reason
            return render(request, "_run_row.html", run=list_row(store.get_run(run_id)),
                          several=len(store.connections()) > 1, error=exc.detail)
        store.update_run(run_id, cleanup_status="running", progress=None)  # no leftover numbers of the run
        if from_list:  # the row, now showing the rollback
            return await run_row(request, run_id)
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
    return (run["status"] in ACTIVE or run.get("cleanup_status") == "running"
            or bool((run.get("result") or {}).get("busy")))  # a device of an Advanced run is enrolling/renewing


def build() -> FastAPI:
    """Entry point for uvicorn (`app.main:build`, factory mode)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per DTM call is too much
    store = Store(DATA_DIR / "demonstrator.db")
    return create_app(store, Auth.from_env(store))
