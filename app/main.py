import asyncio
import logging
import re
import uuid
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

from . import cleanup, uc01
from .auth import COOKIE, Auth
from .config import APP_VERSION, DATA_DIR
from .dtm import DTMClient, DTMConfig, DTMError
from .store import Store

log = logging.getLogger("demonstrator")
HERE = Path(__file__).parent
RUN_ID = re.compile(r"^[a-z0-9]{1,16}$")
HOST = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
ACTIVE = {"pending", "running"}
SHOWN_EVENTS = 200
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")

ClientFactory = Callable[[DTMConfig, Callable[[str], None]], DTMClient]


def create_app(store: Store, auth: Auth, client_factory: ClientFactory = DTMClient,
               data_dir: Path = DATA_DIR) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["version"] = APP_VERSION
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    tasks: set[asyncio.Task] = set()
    store.mark_interrupted()

    def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def dtm_config() -> DTMConfig | None:
        values = [store.get_setting(k) for k in ("dtm_host", "dtm_api_key", "dtm_account_id")]
        return DTMConfig(*values) if all(values) else None

    def client_for(run_id: str | None = None) -> DTMClient:
        config = dtm_config()
        if not config:
            raise HTTPException(409, "DTM connection is not configured")
        if run_id:
            # A run is bound to the account it was created in – never act on it via another one.
            params = store.get_run(run_id)["params"]
            if (params.get("dtm_host"), params.get("account_id")) != (config.host, config.account_id):
                raise HTTPException(409, f"Run {run_id} belongs to account {params.get('account_id')} on "
                                         f"{params.get('dtm_host')} – switch the settings back to clean it up.")
            on_call = lambda msg: store.add_event(run_id, f"API {msg}", "api")  # noqa: E731
        else:
            on_call = lambda _m: None  # noqa: E731
        return client_factory(config, on_call)

    def spawn(coro_factory, run_id: str) -> None:
        client = client_for(run_id)  # fails in the request, before anything is started

        async def runner():
            try:
                await coro_factory(client)
            except Exception:
                log.exception("background task for run %s failed", run_id)
            finally:
                await client.aclose()
        task = asyncio.create_task(runner())
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    @app.middleware("http")
    async def security(request: Request, call_next):
        public = request.url.path in ("/login", "/healthz") or request.url.path.startswith("/static/")
        if not public and not auth.is_authenticated(request):
            if request.headers.get("hx-request"):
                return HTMLResponse("", status_code=401, headers={"HX-Redirect": "/login"})
            return RedirectResponse("/login", status_code=303)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

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
        return render(request, "index.html", runs=store.list_runs(), configured=dtm_config() is not None)

    @app.get("/settings")
    async def settings_page(request: Request):
        return render(request, "settings.html", host=store.get_setting("dtm_host") or "one.digicert.com",
                      account_id=store.get_setting("dtm_account_id") or "",
                      has_key=bool(store.get_setting("dtm_api_key")))

    @app.post("/settings")
    async def save_settings(request: Request, host: str = Form(...), account_id: str = Form(...),
                            api_key: str = Form("")):
        host, account_id, api_key = host.strip().lower(), account_id.strip(), api_key.strip()
        error = None
        if not HOST.fullmatch(host):
            error = "Invalid host name."
        elif not _is_uuid(account_id):
            error = "The account ID must be a UUID."
        elif not api_key and store.get_setting("dtm_api_key") and host != store.get_setting("dtm_host"):
            # Never send the stored key to a host it was not entered for.
            error = "Enter the API key again when changing the host."
        api_key = api_key or store.get_setting("dtm_api_key") or ""
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
        if error:
            return render(request, "settings.html", 400, host=host, account_id=account_id,
                          has_key=bool(store.get_setting("dtm_api_key")), error=error)
        for key, value in (("dtm_host", host), ("dtm_account_id", account_id), ("dtm_api_key", api_key)):
            store.set_setting(key, value)
        return RedirectResponse("/", status_code=303)

    @app.get("/runs/new")
    async def new_run(request: Request):
        client = client_for()
        try:
            cas, profiles = await client.issuing_cas(), await client.certificate_profiles()
        except DTMError as exc:
            return render(request, "error.html", 502, message=f"Could not load data from DTM: {exc}")
        finally:
            await client.aclose()
        return render(request, "run_new.html", cas=cas, profiles=profiles, max_batch=uc01.MAX_BATCH,
                      default_run_id=datetime.now().strftime("%y%m%d%H%M%S"))

    @app.post("/runs")
    async def create_run(request: Request, run_id: str = Form(""), variant: str = Form(...),
                         mode: str = Form(...), count: int = Form(10), ca_id: str = Form(...),
                         profile_id: str = Form(...), approval: bool = Form(False)):
        run_id = run_id.strip().lower() or datetime.now().strftime("%y%m%d%H%M%S")
        client = client_for()
        try:
            cas = {c["id"]: c for c in await client.issuing_cas()}
            profiles = {p["id"] for p in await client.certificate_profiles()}
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
        elif mode == "batch" and not 1 <= count <= uc01.MAX_BATCH:
            error = f"Number of certificates: 1–{uc01.MAX_BATCH}."
        elif ca_id not in cas or cas[ca_id]["key_type"] not in uc01.KEY_TYPES:
            error = "Select an issuing CA of this account."
        elif profile_id not in profiles:
            error = "Select a certificate profile."
        if error:
            raise HTTPException(400, error)
        ca = cas[ca_id]
        config = dtm_config()
        params = {"dtm_host": config.host, "account_id": config.account_id,
                  "variant": variant, "mode": mode, "count": count if mode == "batch" else 1,
                  "ca_id": ca_id, "ca_name": ca["name"], "key_type": uc01.KEY_TYPES[ca["key_type"]],
                  "profile_id": profile_id, "approval": approval and mode == "batch" and variant == "api"}
        store.create_run(run_id, uc01.USE_CASE, params)
        spawn(lambda c: uc01.run(store, c, run_id, data_dir / "runs" / run_id), run_id)
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    def get_run_or_404(run_id: str) -> dict:
        run = store.get_run(run_id) if RUN_ID.fullmatch(run_id) else None
        if not run:
            raise HTTPException(404, "Run not found")
        return run

    @app.get("/runs/{run_id}")
    async def run_page(request: Request, run_id: str):
        run = get_run_or_404(run_id)
        return render(request, "run.html", **live_context(run))

    @app.get("/runs/{run_id}/live")
    async def run_live(request: Request, run_id: str):
        run = get_run_or_404(run_id)
        return render(request, "_run_live.html", **live_context(run))

    def live_context(run: dict) -> dict:
        events = store.events(run["id"])
        return {"run": run, "events": events[-SHOWN_EVENTS:], "events_total": len(events), "active": _active(run),
                "artifact_available": (data_dir / "runs" / run["id"] / "batch.zip").is_file()}

    @app.get("/runs/{run_id}/artifact")
    async def run_artifact(run_id: str):
        get_run_or_404(run_id)
        path = data_dir / "runs" / run_id / "batch.zip"
        if not path.is_file():
            raise HTTPException(404, "No artifact for this run")
        return FileResponse(path, media_type="application/zip", filename=f"robot-{run_id}-uc01-batch.zip")

    @app.post("/runs/{run_id}/cleanup")
    async def run_cleanup(run_id: str, mode: str = Form(...)):
        run = get_run_or_404(run_id)
        if mode not in ("full", "certificates") or _active(run):
            raise HTTPException(409, "Cleanup not possible right now")
        if run.get("cleanup_mode") == "full" and run.get("cleanup_status") == "done":
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


def _active(run: dict) -> bool:
    return run["status"] in ACTIVE or run.get("cleanup_status") == "running"


def build() -> FastAPI:
    """Entry point for uvicorn (`app.main:build`, factory mode)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per DTM call is too much
    return create_app(Store(DATA_DIR / "demonstrator.db"), Auth.from_env())
