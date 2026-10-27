import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from argon2 import PasswordHasher
from starlette.requests import Request
from starlette.responses import Response

from app.auth import ALGORITHM, COOKIE, MAX_PASSWORD, PASSWORD_KEY, SESSION_HOURS, Auth
from app.store import Store
from tests.conftest import PASSWORD, SECRET


def request_with(token: str | None) -> Request:
    headers = [(b"cookie", f"{COOKIE}={token}".encode())] if token is not None else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


@pytest.fixture
def auth():
    return Auth(PASSWORD, SECRET)


def test_short_secret_is_rejected():
    with pytest.raises(RuntimeError):
        Auth(PASSWORD, "x" * 31)
    Auth(PASSWORD, "x" * 32)


@pytest.mark.parametrize("candidate,ok", [
    (PASSWORD, True), (PASSWORD + " ", False), (PASSWORD.upper(), False), ("", False), (PASSWORD[:-1], False),
])
def test_check_password(auth, candidate, ok):
    assert auth.check_password(candidate) is ok


def test_non_ascii_password(auth):
    a = Auth("pässwört-€", SECRET)
    assert a.check_password("pässwört-€") and not a.check_password("passwort-€")


def test_issued_token_authenticates_and_expires_after_session_hours(auth):
    token = auth.issue()
    assert auth.is_authenticated(request_with(token))
    claims = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
    assert claims["sub"] == "admin"
    assert claims["exp"] - claims["iat"] == SESSION_HOURS * 3600


def _token(**overrides) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": "admin", "iat": now, "exp": now + timedelta(hours=1)} | overrides
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, SECRET, algorithm=ALGORITHM)


@pytest.mark.parametrize("token", [
    None,
    "",
    "garbage",
    _token(exp=datetime.now(timezone.utc) - timedelta(seconds=5)),  # expired
    _token(sub="someone"),                                             # wrong subject
    _token(sub=None),                                                  # missing subject
    _token(exp=None),                                                  # no expiry
    jwt.encode({"sub": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
               "w" * 48, algorithm=ALGORITHM),                         # foreign secret
    jwt.encode({"sub": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
               None, algorithm="none"),                                # alg=none
], ids=["no-cookie", "empty", "garbage", "expired", "wrong-sub", "no-sub", "no-exp", "foreign-secret",
        "alg-none"])
def test_invalid_tokens_are_rejected(auth, token):
    assert auth.is_authenticated(request_with(token)) is False


def test_tampered_payload_is_rejected(auth):
    header, payload, signature = auth.issue().split(".")
    forged_payload = jwt.utils.base64url_encode(b'{"sub":"admin","exp":9999999999}').decode()
    assert not auth.is_authenticated(request_with(f"{header}.{forged_payload}.{signature}"))
    flipped = signature[:-2] + ("A" if signature[-2] != "A" else "B") + signature[-1]
    assert not auth.is_authenticated(request_with(f"{header}.{payload}.{flipped}"))


def test_cookie_flags(auth):
    response = Response()
    auth.set_cookie(response, "tok")
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith(f"{COOKIE}=tok")
    assert "httponly" in cookie
    # Lax (not Strict): links opened from mail/chat must arrive logged in; cross-site POSTs still carry no cookie
    assert "samesite=lax" in cookie
    assert "; secure" in cookie
    assert f"max-age={SESSION_HOURS * 3600}" in cookie


def test_cookie_without_secure_when_disabled():
    response = Response()
    Auth(PASSWORD, SECRET, secure_cookie=False).set_cookie(response, "tok")
    assert "secure" not in response.headers["set-cookie"].lower()


def test_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_PASSWORD", "pw-from-env")
    monkeypatch.setenv("JWT_SECRET", "e" * 40)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    a = Auth.from_env(Store(tmp_path / "db"))
    assert a.check_password("pw-from-env") and a.secure_cookie is True
    monkeypatch.setenv("COOKIE_SECURE", "FALSE")
    assert Auth.from_env(Store(tmp_path / "db2")).secure_cookie is False


@pytest.mark.parametrize("value", [None, ""])
def test_from_env_without_admin_password_starts_without_password(monkeypatch, tmp_path, value):
    """New installs no longer write ADMIN_PASSWORD (missing) and compose passes ${ADMIN_PASSWORD:-} (empty)."""
    if value is None:
        monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("ADMIN_PASSWORD", value)
    monkeypatch.setenv("JWT_SECRET", "e" * 40)
    store = Store(tmp_path / "db")
    a = Auth.from_env(store)
    assert not a.has_password() and store.get_setting(PASSWORD_KEY) is None
    assert not a.check_password("") and not a.check_password("anything at all")


@pytest.mark.parametrize("value", [None, "", "x" * 31])
def test_from_env_still_requires_jwt_secret(monkeypatch, tmp_path, value):
    monkeypatch.setenv("ADMIN_PASSWORD", "pw")
    if value is None:
        monkeypatch.delenv("JWT_SECRET", raising=False)
    else:
        monkeypatch.setenv("JWT_SECRET", value)
    with pytest.raises(RuntimeError):
        Auth.from_env(Store(tmp_path / "db"))


# --- password storage (Argon2id, set once) ----------------------------------------------------------


NEW = "a brand new password 123"


def test_stored_value_is_an_argon2id_hash_not_the_plaintext(tmp_path):
    store = Store(tmp_path / "db")
    a = Auth(None, SECRET, store=store)
    assert not a.has_password() and a.set_password(NEW) and a.has_password()
    stored = store.get_setting(PASSWORD_KEY)
    assert stored.startswith("$argon2id$") and NEW not in stored
    assert NEW.encode() not in (tmp_path / "db").read_bytes()  # nowhere in the database file
    assert PasswordHasher().verify(stored, NEW)


def test_hash_is_salted(tmp_path):
    first, second = Store(tmp_path / "a"), Store(tmp_path / "b")
    Auth(NEW, SECRET, store=first)
    Auth(NEW, SECRET, store=second)
    assert first.get_setting(PASSWORD_KEY) != second.get_setting(PASSWORD_KEY)


@pytest.mark.parametrize("with_store", [True, False], ids=["store", "memory"])
def test_check_password_against_the_stored_hash(tmp_path, with_store):
    a = Auth(None, SECRET, store=Store(tmp_path / "db") if with_store else None)
    assert not a.check_password(NEW)  # no hash yet
    assert a.set_password(NEW)
    assert a.check_password(NEW)
    for wrong in ("", NEW[:-1], NEW + " ", NEW.upper(), "x" * (MAX_PASSWORD + 1)):
        assert not a.check_password(wrong)


def test_password_longer_than_the_cap_never_matches(tmp_path):
    """Even when exactly that long string was stored (e.g. a long ADMIN_PASSWORD from an older .env)."""
    long_pw = "y" * MAX_PASSWORD
    assert Auth(long_pw, SECRET).check_password(long_pw)
    too_long = "z" * (MAX_PASSWORD + 1)
    assert not Auth(too_long, SECRET).check_password(too_long)


def test_corrupt_stored_hash_is_a_failed_login_not_a_crash(tmp_path):
    store = Store(tmp_path / "db")
    store.set_setting(PASSWORD_KEY, "not-a-hash")
    a = Auth(None, SECRET, store=store)
    assert a.has_password() and not a.check_password("not-a-hash") and not a.check_password(NEW)


@pytest.mark.parametrize("with_store", [True, False], ids=["store", "memory"])
def test_password_is_set_only_once(tmp_path, with_store):
    store = Store(tmp_path / "db") if with_store else None
    a = Auth(None, SECRET, store=store)
    assert a.set_password(NEW) is True
    assert a.set_password("an attacker's password") is False
    assert a.check_password(NEW) and not a.check_password("an attacker's password")


def test_second_instance_cannot_override_the_first(tmp_path):
    """Two Auth objects on one database (= two requests racing): only the first write wins."""
    store = Store(tmp_path / "db")
    first, second = Auth(None, SECRET, store=store), Auth(None, SECRET, store=store)
    assert not first.has_password() and not second.has_password()  # both saw "no password"
    assert first.set_password(NEW) is True
    assert second.set_password("the slower request 1") is False
    assert first.check_password(NEW) and second.check_password(NEW)
    assert not second.check_password("the slower request 1")


def test_concurrent_setup_has_exactly_one_winner(tmp_path):
    store = Store(tmp_path / "db")
    a = Auth(None, SECRET, store=store)
    candidates = [f"concurrent password {i:02d}" for i in range(8)]
    barrier = threading.Barrier(len(candidates))

    def attempt(pw):
        barrier.wait()
        return a.set_password(pw)

    with ThreadPoolExecutor(len(candidates)) as pool:
        results = list(pool.map(attempt, candidates))
    assert results.count(True) == 1
    winner = candidates[results.index(True)]
    assert [pw for pw in candidates if a.check_password(pw)] == [winner]


def test_migration_from_env_sets_the_password_when_none_is_stored(tmp_path, caplog):
    store = Store(tmp_path / "db")
    with caplog.at_level(logging.INFO, logger="demonstrator"):
        a = Auth("old-env-password", SECRET, store=store)
    assert a.check_password("old-env-password")
    assert store.get_setting(PASSWORD_KEY).startswith("$argon2id$")
    assert "old-env-password" not in caplog.text


def test_migration_never_overwrites_a_stored_password(tmp_path, caplog):
    store = Store(tmp_path / "db")
    Auth(None, SECRET, store=store).set_password(NEW)
    before = store.get_setting(PASSWORD_KEY)
    with caplog.at_level(logging.INFO, logger="demonstrator"):
        restarted = Auth("old-env-password", SECRET, store=store)  # the next start with ADMIN_PASSWORD still in .env
    assert store.get_setting(PASSWORD_KEY) == before
    assert restarted.check_password(NEW) and not restarted.check_password("old-env-password")
    assert "old-env-password" not in caplog.text


def test_migration_is_idempotent_across_restarts(tmp_path):
    store = Store(tmp_path / "db")
    Auth("old-env-password", SECRET, store=store)
    first = store.get_setting(PASSWORD_KEY)
    Auth("old-env-password", SECRET, store=store)
    assert store.get_setting(PASSWORD_KEY) == first  # not re-hashed / replaced on every start


def test_password_survives_a_restart_without_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("JWT_SECRET", "e" * 40)
    Auth("old-env-password", SECRET, store=Store(tmp_path / "db"))
    reopened = Auth.from_env(Store(tmp_path / "db"))  # the installer removed ADMIN_PASSWORD, app restarted
    assert reopened.has_password() and reopened.check_password("old-env-password")


# --- what the app logs at start (the installer reads these lines) -------------------------------------


def test_log_when_taken_over(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="demonstrator"):
        Auth("old-env-password", SECRET, store=Store(tmp_path / "db"))
    assert "login password taken over from ADMIN_PASSWORD" in caplog.text
    assert "ADMIN_PASSWORD ignored" not in caplog.text


def test_log_when_the_same_env_password_was_already_taken_over(tmp_path, caplog):
    Auth("old-env-password", SECRET, store=Store(tmp_path / "db"))
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="demonstrator"):
        Auth("old-env-password", SECRET, store=Store(tmp_path / "db"))  # a restart before the installer removed it
    assert "ADMIN_PASSWORD already taken over" in caplog.text
    assert "ADMIN_PASSWORD ignored" not in caplog.text and "taken over from" not in caplog.text
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_warning_when_a_different_env_password_is_ignored(tmp_path, caplog):
    store = Store(tmp_path / "db")
    Auth(None, SECRET, store=store).set_password(NEW)
    with caplog.at_level(logging.INFO, logger="demonstrator"):
        Auth("another-env-password", SECRET, store=store)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == ["ADMIN_PASSWORD ignored: a login password is already set (reset: install.sh --reset-password)"]
    assert "already taken over" not in caplog.text and "another-env-password" not in caplog.text


def test_no_log_without_env_password(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="demonstrator"):
        Auth(None, SECRET, store=Store(tmp_path / "db"))
    assert "ADMIN_PASSWORD" not in caplog.text


# --- rehash on login (newer Argon2 parameters) -----------------------------------------------------------


def test_outdated_hash_is_upgraded_on_a_successful_login(tmp_path):
    store = Store(tmp_path / "db")
    old = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(NEW)
    store.set_setting(PASSWORD_KEY, old)
    a = Auth(None, SECRET, store=store)
    assert not a.check_password("wrong password 12") and store.get_setting(PASSWORD_KEY) == old  # no rehash on failure
    assert a.check_password(NEW)
    upgraded = store.get_setting(PASSWORD_KEY)
    assert upgraded != old and not PasswordHasher().check_needs_rehash(upgraded)
    assert a.check_password(NEW) and store.get_setting(PASSWORD_KEY) == upgraded  # current: not rewritten again


def test_current_hash_is_not_rewritten_on_login(tmp_path):
    store = Store(tmp_path / "db")
    a = Auth(NEW, SECRET, store=store)
    before = store.get_setting(PASSWORD_KEY)
    assert a.check_password(NEW) and store.get_setting(PASSWORD_KEY) == before


def test_rehash_never_revives_a_password_reset_in_between(tmp_path, monkeypatch):
    """install.sh --reset-password deletes the hash; a login verified just before must not write it back."""
    store = Store(tmp_path / "db")
    store.set_setting(PASSWORD_KEY, PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(NEW))
    a = Auth(None, SECRET, store=store)
    real = a._hasher

    class ResetBeforeRehash:  # the reset lands between verify and the rehash write
        verify, check_needs_rehash = real.verify, real.check_needs_rehash

        def hash(self, password):
            store.delete_setting(PASSWORD_KEY)
            return real.hash(password)

    monkeypatch.setattr(a, "_hasher", ResetBeforeRehash())
    a.check_password(NEW)
    assert store.get_setting(PASSWORD_KEY) is None and not a.has_password()
