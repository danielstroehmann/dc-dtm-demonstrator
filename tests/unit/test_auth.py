from datetime import datetime, timedelta, timezone

import jwt
import pytest
from starlette.requests import Request
from starlette.responses import Response

from app.auth import ALGORITHM, COOKIE, SESSION_HOURS, Auth
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


def test_from_env(monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "pw-from-env")
    monkeypatch.setenv("JWT_SECRET", "e" * 40)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    a = Auth.from_env()
    assert a.check_password("pw-from-env") and a.secure_cookie is True
    monkeypatch.setenv("COOKIE_SECURE", "FALSE")
    assert Auth.from_env().secure_cookie is False


@pytest.mark.parametrize("missing", ["ADMIN_PASSWORD", "JWT_SECRET"])
def test_from_env_requires_password_and_secret(monkeypatch, missing):
    monkeypatch.setenv("ADMIN_PASSWORD", "pw")
    monkeypatch.setenv("JWT_SECRET", "e" * 40)
    monkeypatch.setenv(missing, "")
    with pytest.raises(RuntimeError, match=missing):
        Auth.from_env()
