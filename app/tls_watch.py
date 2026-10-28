"""The `tls-watch` service: applies the HTTPS certificate from paths on the Docker host chosen in Settings, and its
renewals.

A certbot-style layout (live/<name>/fullchain.pem → ../../archive/<name>/fullchain3.pem, keys 0600 root) is readable
by root only, the app is not – so this root service reads the files. Only TLS_HOST_DIR is mounted (read-only, at the
same path, so links resolve as on the host), and every path must resolve into it (tls_setup.read_host).

The app writes a request with a fresh id (tls_settings.REQUEST); within a second the watcher checks the files like an
upload, applies them live (rollback included, tls_settings) and answers in STATUS with that id. The applied paths are
kept in HOST_PATHS – with the PKCS#12 password, because every renewal has to be opened again (0640, the app's group;
never logged or shown). Every minute the files are read again: a renewed certificate is applied, an unusable one keeps
the current certificate, and the error shows in Settings until the files are fine again."""

import json
import logging
import sys
import time
from datetime import datetime, timezone

from . import tls_settings, tls_setup
from .tls_settings import STATUS, REQUEST, ApplyError
from .tls_setup import HOST_PATHS, SETTINGS, TLSError

log = logging.getLogger("demonstrator")
INTERVAL = 60  # seconds between renewal checks
POLL = 1  # seconds between looks for a request
_state: dict = {}  # what STATUS says: the last request answered, the last renewal check


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_status() -> None:
    tls_setup.write_file(tls_settings.LIVE / STATUS, json.dumps(_state).encode(), private=True)


def handle_request() -> None:
    path = tls_settings.LIVE / REQUEST
    try:
        request = json.loads(path.read_bytes())
        request_id = str(request["id"])
        fields = [str(request.get(k, "")) for k in ("certificate", "private_key", "keystore", "password")]
    except FileNotFoundError:
        return
    except (OSError, ValueError, KeyError, TypeError) as exc:
        log.warning("TLS: unreadable host path request ignored (%s)", type(exc).__name__)
        path.unlink(missing_ok=True)
        return
    with tls_settings.locked():
        try:  # the app checked the paths as text already; checked again, the request file is no authority
            config = tls_settings.host_config(str(request.get("mode")), *fields)
            chain, key = tls_setup.load_host(config)
            tls_settings.apply_host(chain, key, config)
        except (TLSError, ApplyError) as exc:
            log.warning("TLS: certificate from the host path refused: %s", exc)
            _state.update(request=request_id, request_error=str(exc))
        else:
            log.info("TLS: certificate from the host path applied: %s", chain[0].subject.rfc4514_string())
            _state.update(request=request_id, request_error=None, checked=_now(), error=None)
        path.unlink(missing_ok=True)
        _write_status()


def _current() -> tuple[bytes, ...] | None:
    try:
        return tuple((tls_settings.LIVE / name).read_bytes() for name in SETTINGS)
    except OSError:
        return None


def check() -> None:
    """A renewal (the links point to new files) is applied; unusable files keep the current certificate."""
    with tls_settings.locked():
        try:
            config = json.loads((tls_settings.LIVE / HOST_PATHS).read_bytes())
        except FileNotFoundError:
            return  # no host path chosen, or an upload / reset replaced it
        except (OSError, ValueError) as exc:
            log.warning("TLS: the host path configuration cannot be read (%s)", type(exc).__name__)
            return
        error = None
        try:
            chain, key = tls_setup.load_host(config)
            if tls_setup.pem_pair(chain, key) != _current():
                tls_settings.apply_host(chain, key, config)
                log.info("TLS: renewed certificate from the host path applied: %s, valid until %s",
                         chain[0].subject.rfc4514_string(), f"{chain[0].not_valid_after_utc:%Y-%m-%d}")
        except (TLSError, ApplyError, KeyError, AttributeError) as exc:
            error = str(exc) if isinstance(exc, (TLSError, ApplyError)) else "the configuration is not usable"
        if error and error != _state.get("error"):  # once per new problem, not every minute
            log.warning("TLS: the certificate from the host path stays as it is: %s", error)
        elif not error and _state.get("error"):
            log.info("TLS: the files of the host path are usable again")
        _state.update(checked=_now(), error=error)
        _write_status()


def run(rounds: int | None = None) -> None:
    """The service's loop; `rounds` bounds it for tests."""
    _state.update(tls_settings._json(STATUS))
    next_check = 0.0
    while rounds is None or rounds > 0:
        _safely(handle_request)
        if time.monotonic() >= next_check:
            _safely(check)
            next_check = time.monotonic() + INTERVAL
        if rounds is not None:
            rounds -= 1
        time.sleep(POLL)


def _safely(step) -> None:
    try:
        step()
    except Exception:  # e.g. a full disk: the watch goes on, the next round tries again
        log.exception("TLS: %s failed", step.__name__)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    log.info("TLS: watching %s", tls_setup.HOST_DIR or "nothing – TLS_HOST_DIR is not set")
    run()
