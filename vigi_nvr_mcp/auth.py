"""Session management with hard lockout protection.

VIGI NVRs lock the account after roughly ten failed logins. Rules enforced here:

1. A failed login is never retried automatically.
2. ``data.time`` / ``data.max_time`` from a failed login are surfaced in the error.
3. -40401 on the login call is an auth failure (NvrAuthError); -40401 on an
   authenticated call is token expiry (NvrTokenExpired), handled by the client
   with at most one re-authentication per call.
4. The session token is cached in memory for the life of the process.
5. ``login()`` is an explicit operation; implicit logins (from ``token()``) stop
   after the first failure.
6. ``VIGI_NVR_LOGIN_DISABLED=true`` refuses every login before any network I/O.

In addition, a per-process failure budget (``VIGI_NVR_MAX_LOGIN_FAILURES``,
default 1) refuses all further logins once spent, and a challenge that already
reports the attempt counter at its maximum blocks the login.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import crypto
from .config import Settings
from .errors import NvrApiError, NvrAuthError, NvrLockoutGuard, NvrTransportError
from .transport import STOK_RE, UNAUTHORISED, NvrTransport

log = logging.getLogger(__name__)

ENCRYPT_TYPE = "2"
PASSWD_TYPE = "md5"  # noqa: S105 - protocol field value, not a secret
CHALLENGE_BODY: dict[str, Any] = {"user_management": {"get_encrypt_info": None}, "method": "do"}


class Challenge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    encrypt_type: list[str]
    key: str = Field(min_length=1, max_length=4096)
    nonce: str = Field(min_length=1, max_length=128)
    code: int | None = None
    time: int | None = None
    max_time: int | None = None


class LoginSuccess(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    stok: str = Field(pattern=STOK_RE.pattern)
    user_group: str | None = None


@dataclass(frozen=True)
class AuthState:
    token: str | None = None
    failed_logins: int = 0
    successful_logins: int = 0
    last_failure: dict[str, Any] | None = None


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class Authenticator:
    def __init__(self, settings: Settings, transport: NvrTransport) -> None:
        self._settings = settings
        self._transport = transport
        self._lock = asyncio.Lock()
        self._state = AuthState()

    # ---- public API ---------------------------------------------------------

    def status(self) -> dict[str, Any]:
        state = self._state
        return {
            "authenticated": state.token is not None,
            "failed_logins": state.failed_logins,
            "max_login_failures": self._settings.max_login_failures,
            "successful_logins": state.successful_logins,
            "login_disabled": self._settings.login_disabled,
            "last_failure": state.last_failure,
        }

    async def get_challenge(self) -> Challenge:
        reply = await self._transport.post_preauth(CHALLENGE_BODY, accept_codes=(UNAUTHORISED, 0))
        try:
            return Challenge.model_validate(reply.get("data"))
        except ValidationError:
            raise NvrTransportError(
                "NVR auth challenge is missing key, nonce or encrypt_type"
            ) from None

    async def login(self) -> str:
        """Explicit, single-attempt login. Replaces any cached token on success."""
        async with self._lock:
            return await self._login_locked(explicit=True)

    async def token(self) -> str:
        """Cached token, logging in implicitly only if no login has failed yet."""
        async with self._lock:
            if self._state.token is not None:
                return self._state.token
            return await self._login_locked(explicit=False)

    async def invalidate(self, token: str) -> None:
        """Drop ``token`` if it is still the cached one (called on expiry)."""
        async with self._lock:
            if self._state.token == token:
                self._state = replace(self._state, token=None)

    # ---- internals ----------------------------------------------------------

    def _guard(self, *, explicit: bool) -> None:
        settings, state = self._settings, self._state
        if settings.login_disabled:
            raise NvrLockoutGuard(
                "Login refused: VIGI_NVR_LOGIN_DISABLED=true. Authentication is frozen."
            )
        if state.failed_logins >= settings.max_login_failures:
            raise NvrLockoutGuard(
                f"Login refused: {state.failed_logins} failed login(s) in this process "
                f"(limit {settings.max_login_failures}). Fix the credentials, check the "
                "NVR's lockout state, then restart the server."
            )
        if not explicit and state.failed_logins > 0:
            raise NvrLockoutGuard(
                "Login refused: a previous login failed. Automatic logins are disabled; "
                "use the explicit nvr_login tool after fixing the cause."
            )

    async def _login_locked(self, *, explicit: bool) -> str:
        self._guard(explicit=explicit)
        challenge = await self.get_challenge()
        if ENCRYPT_TYPE not in challenge.encrypt_type:
            raise NvrApiError(
                UNAUTHORISED,
                message="NVR does not offer encrypt_type 2 (RSA/md5); this firmware "
                "is not supported. Inspect it with `vigi-nvr-mcp --check-auth`.",
            )
        if (
            challenge.time is not None
            and challenge.max_time is not None
            and challenge.time >= challenge.max_time
        ):
            raise NvrLockoutGuard(
                f"Login refused: NVR reports {challenge.time}/{challenge.max_time} failed "
                "attempts. The account is likely locked; wait for the lock to expire."
            )
        try:
            encrypted = crypto.encrypt_login_password(
                self._settings.nvr_password.get_secret_value(), challenge.nonce, challenge.key
            )
        except ValueError as exc:
            raise NvrTransportError(f"Cannot encrypt login: {exc}") from None
        body = {
            "method": "do",
            "login": {
                "username": self._settings.nvr_username,
                "password": encrypted,
                "passwdType": PASSWD_TYPE,
                "encrypt_type": ENCRYPT_TYPE,
            },
        }
        log.info("login attempt (explicit=%s)", explicit)
        try:
            reply = await self._transport.post_preauth(body, accept_codes=(0,))
        except NvrApiError as exc:
            raise self._record_failure(exc.code, exc.data) from None
        except NvrTransportError as exc:
            raise self._record_failure(
                None, None, note=f"{exc}; outcome unknown, counted as a failure"
            ) from None
        try:
            success = LoginSuccess.model_validate(reply)
        except ValidationError:
            raise NvrTransportError(
                "NVR login reply did not contain a valid session token"
            ) from None
        self._state = replace(
            self._state, token=success.stok, successful_logins=self._state.successful_logins + 1
        )
        log.info("login succeeded")
        return success.stok

    def _record_failure(
        self, code: int | None, data: Any, *, note: str | None = None
    ) -> NvrAuthError:
        data_dict = data if isinstance(data, dict) else {}
        attempts, max_attempts = (
            _int_or_none(data_dict.get("time")),
            _int_or_none(data_dict.get("max_time")),
        )
        failure = {
            "nvr_error_code": code,
            "failed_attempts": attempts,
            "max_attempts": max_attempts,
        }
        self._state = replace(
            self._state,
            token=None,
            failed_logins=self._state.failed_logins + 1,
            last_failure=failure,
        )
        counter = (
            f" NVR reports {attempts}/{max_attempts} failed attempts."
            if attempts is not None and max_attempts is not None
            else ""
        )
        message = note or f"Login rejected by NVR (error_code {code})."
        log.warning("login failed: code=%s attempts=%s/%s", code, attempts, max_attempts)
        return NvrAuthError(
            f"{message}{counter} Not retrying automatically.",
            code=code,
            time=attempts,
            max_time=max_attempts,
        )
