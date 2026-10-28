"""Single-password login (no username) with a signed JWT session cookie.

The password is not configured: whoever opens the app first sets it (author's decision, 2026-10-27). It is
stored as an Argon2id hash in the settings table; an ADMIN_PASSWORD from an older .env is taken over once."""

import logging
import os
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Request

COOKIE = "session"
SESSION_HOURS = 12
ALGORITHM = "HS256"
PASSWORD_KEY = "admin_password_hash"
MIN_PASSWORD = 12
MAX_PASSWORD = 256  # Argon2 hashes any length; a cap keeps a single request cheap
log = logging.getLogger("demonstrator")


def default_hasher() -> PasswordHasher:
    return PasswordHasher()


class Auth:
    def __init__(self, password: str | None, secret: str, secure_cookie: bool = True, store=None,
                 hasher: PasswordHasher | None = None):
        """store: where the hash lives (the app's Store); without one it is kept in memory (tests).
        password: an initial password, set only while none is stored (the .env migration).
        hasher: Argon2 with its default (deliberately slow) parameters unless a test injects cheaper ones."""
        if len(secret) < 32:
            raise RuntimeError("JWT secret must be at least 32 characters")
        self._secret = secret
        self.secure_cookie = secure_cookie
        self._store = store
        self._memory: dict[str, str] = {}
        self._hasher = hasher or default_hasher()
        if password:  # the installer reads these lines to tell the operator what happened
            if self.set_password(password):
                log.info("login password taken over from ADMIN_PASSWORD")
            elif self.check_password(password):
                log.info("ADMIN_PASSWORD already taken over")
            else:
                log.warning("ADMIN_PASSWORD ignored: a login password is already set (reset: install.sh --reset-password)")

    @classmethod
    def from_env(cls, store) -> "Auth":
        from .config import required_env
        return cls(os.environ.get("ADMIN_PASSWORD") or None, required_env("JWT_SECRET"),
                   os.environ.get("COOKIE_SECURE", "true").lower() != "false", store=store)

    def _hash(self) -> str | None:
        return self._store.get_setting(PASSWORD_KEY) if self._store else self._memory.get(PASSWORD_KEY)

    def has_password(self) -> bool:
        return self._hash() is not None

    def set_password(self, password: str) -> bool:
        """Sets the password if none is set yet – False if one exists (or another request was first)."""
        hashed = self._hasher.hash(password)
        if self._store:
            return self._store.set_setting_once(PASSWORD_KEY, hashed)
        return self._memory.setdefault(PASSWORD_KEY, hashed) == hashed

    def check_password(self, candidate: str) -> bool:
        stored = self._hash()
        if not stored or len(candidate) > MAX_PASSWORD:
            return False
        try:
            self._hasher.verify(stored, candidate)
        except (VerificationError, InvalidHashError):
            return False
        if self._store and self._hasher.check_needs_rehash(stored):  # newer Argon2 parameters
            self._store.update_setting(PASSWORD_KEY, self._hasher.hash(candidate))  # never revives a reset one
        return True

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
        # Lax: links opened from mail/chat keep the session; cross-site POSTs (CSRF) still get no cookie.
        response.set_cookie(COOKIE, token, max_age=SESSION_HOURS * 3600, httponly=True,
                            secure=self.secure_cookie, samesite="lax")
