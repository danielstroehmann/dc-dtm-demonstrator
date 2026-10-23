"""Single-password login (no username) with a signed JWT session cookie."""

import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Request

COOKIE = "session"
SESSION_HOURS = 12
ALGORITHM = "HS256"


class Auth:
    def __init__(self, password: str, secret: str, secure_cookie: bool = True):
        if len(secret) < 32:
            raise RuntimeError("JWT secret must be at least 32 characters")
        self._password = password.encode()
        self._secret = secret
        self.secure_cookie = secure_cookie

    @classmethod
    def from_env(cls) -> "Auth":
        from .config import required_env
        return cls(required_env("ADMIN_PASSWORD"), required_env("JWT_SECRET"),
                   os.environ.get("COOKIE_SECURE", "true").lower() != "false")

    def check_password(self, candidate: str) -> bool:
        return hmac.compare_digest(candidate.encode(), self._password)

    def issue(self) -> str:
        now = datetime.now(timezone.utc)
        return jwt.encode({"sub": "admin", "iat": now, "exp": now + timedelta(hours=SESSION_HOURS)},
                          self._secret, algorithm=ALGORITHM)

    def is_authenticated(self, request: Request) -> bool:
        token = request.cookies.get(COOKIE)
        if not token:
            return False
        try:
            claims = jwt.decode(token, self._secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
        except jwt.PyJWTError:
            return False
        return claims.get("sub") == "admin"

    def set_cookie(self, response, token: str) -> None:
        response.set_cookie(COOKIE, token, max_age=SESSION_HOURS * 3600, httponly=True,
                            secure=self.secure_cookie, samesite="strict")
