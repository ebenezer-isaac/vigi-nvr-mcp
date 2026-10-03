"""VIGI NVR session management with hard lockout protection.

VIGI NVRs lock the account after repeated failed logins. Rules enforced here:

1. A failed login is never retried automatically.
2. The lockout counters from a failed login (``data.time`` = attempts remaining,
   ``data.max_time``, ``data.sec_left`` while locked) are surfaced in the error.
3. -40401 on the login call is an auth failure (AuthFailed); -40401/-40403 on an
   authenticated call is token expiry (TokenExpired), which the client handles
   with at most one re-authentication per call.
4. The session token is cached in memory for the life of the process.
5. ``login()`` is explicit; implicit logins (via ``token()``) stop after the
   first failure or when the device reports few attempts remaining.
6. ``VIGI_NVR_LOGIN_DISABLED=true`` refuses every login before any network I/O.

The failure budget is held by the file-backed, cross-process
:class:`~vigi_nvr_mcp.core.breaker.LoginBreaker`. One login attempt is **reserved**
(an atomic, locked increment that survives restarts and crashes) *around the single
login POST*; the credential-free challenge and the pre-login device-counter guard
stay outside the reservation and spend no budget. On the happy path the reservation
is released ``SUCCESS``; on a rejected/failed POST it is released ``FAILURE``; a
pre-POST refusal (malformed challenge, device-reported lockout) releases ``ABORT``
so it never counts against the budget. On -40410 (nonce stale/reused) the login is
NOT resent; conservatively the reserved attempt is counted (``FAILURE``) and a
:class:`~vigi_nvr_mcp.core.errors.NonceInvalid` is raised.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import crypto
from .core import breaker
from .core.breaker import LoginBreaker, canonical_device_key
from .core.config import DeviceSettings
from .core.errors import (
    ApiError,
    AuthFailed,
    LockoutGuard,
    NonceInvalid,
    TransportError,
)
from .core.state import Outcome, Reservation
from .errors import (
    FACTORY_RESET,
    LOCKED_CODES,
    NONCE_INVALID,
    SUPER_PASSWORD_OK,
    UNAUTHORISED,
    error_symbol,
)
from .transport import STOK_RE, NvrTransport

log = logging.getLogger(__name__)

APP_NAME = "vigi-nvr-mcp"
PASSWD_TYPE = "md5"  # noqa: S105 - protocol field value, always "md5"
CHALLENGE_BODY: dict[str, Any] = {"user_management": {"get_encrypt_info": None}, "method": "do"}

# Implicit (automatic) logins stop when the device reports this few attempts left.
IMPLICIT_LOGIN_MIN_REMAINING = 3


class Challenge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    encrypt_type: list[str] = Field(min_length=1, max_length=8)
    key: str | None = Field(default=None, min_length=1, max_length=4096)
    nonce: str | None = Field(default=None, min_length=1, max_length=128)
    code: int | None = None
    time: int | None = None  # attempts remaining before lock
    max_time: int | None = None
    sec_left: int | None = None


class LoginSuccess(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    stok: str = Field(pattern=STOK_RE.pattern)
    user_group: str | None = None


@dataclass(frozen=True)
class AuthState:
    token: str | None = None


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def check_remaining_attempts(
    remaining: int | None,
    *,
    explicit: bool,
    max_attempts: int | None = None,
    lock_seconds_left: int | None = None,
) -> None:
    """Guard on the device-reported remaining-attempts counter (None = unknown).

    This is the pre-login device-side counter check; it spends no budget (the caller
    releases ``ABORT`` when it raises). Carries the device counters so the operator
    sees how long to wait.
    """
    if remaining is None:
        return
    if remaining <= 0:
        raise LockoutGuard(
            "Login refused: the device reports 0 login attempts remaining; the account is "
            "locked or about to be. Wait for the lock to expire.",
            attempts_left=remaining,
            max_attempts=max_attempts,
            lock_seconds_left=lock_seconds_left,
        )
    if not explicit and remaining < IMPLICIT_LOGIN_MIN_REMAINING:
        raise LockoutGuard(
            f"Login refused: the device reports only {remaining} attempt(s) remaining. "
            "Automatic login is suspended; use the explicit login tool if you are sure "
            "the credentials are correct.",
            attempts_left=remaining,
            max_attempts=max_attempts,
            lock_seconds_left=lock_seconds_left,
        )


class Authenticator:
    def __init__(self, settings: DeviceSettings, transport: NvrTransport) -> None:
        self._settings = settings
        self._transport = transport
        self._lock = asyncio.Lock()
        self._state = AuthState()
        state_dir = (
            Path(settings.state_dir) if settings.state_dir else breaker.default_state_dir(APP_NAME)
        )
        self._breaker = LoginBreaker(
            state_dir,
            canonical_device_key(settings.host),
            max_failures=settings.max_login_failures,
            login_disabled=settings.login_disabled,
            disabled_hint=f"{settings.env_name('LOGIN_DISABLED')}=true",
        )

    # ---- public API ---------------------------------------------------------

    def status(self) -> dict[str, Any]:
        info = self._breaker.status()
        return {
            "authenticated": self._state.token is not None,
            "failed_logins": info.get("failures", 0),
            "max_login_failures": info.get("max_failures", self._settings.max_login_failures),
            "successful_logins": info.get("successes", 0),
            "login_disabled": info.get("login_disabled", self._settings.login_disabled),
            "last_failure": info.get("last_failure"),
        }

    async def get_challenge(self) -> Challenge:
        """Fetch encrypt info. Pre-auth and harmless: never counts as a login attempt."""
        reply = await self._transport.post_preauth(CHALLENGE_BODY, accept_codes=(UNAUTHORISED, 0))
        try:
            return Challenge.model_validate(reply.get("data"))
        except ValidationError:
            raise TransportError("NVR auth challenge is malformed") from None

    async def login(self) -> str:
        """Explicit, single-attempt login. Replaces any cached token on success."""
        async with self._lock:
            return await self._login_locked(explicit=True)

    async def token(self) -> str:
        """Cached token; logs in implicitly only while policy allows."""
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

    async def _login_locked(self, *, explicit: bool) -> str:
        if not explicit:
            snap = self._breaker.status()
            if (
                snap.get("state") in ("open", "cooldown")
                or snap.get("failures")
                or snap.get("reserved")
            ):
                raise LockoutGuard(
                    "Automatic login is suspended after a prior failure or while the breaker "
                    "is open; use the explicit login tool once the cause is fixed."
                )
        res = self._breaker.reserve_attempt()  # LoginDisabled/BreakerOpen/Cooldown before any I/O
        try:
            return await self._attempt_with(res, explicit=explicit)
        except BaseException:
            if not res.resolved:
                res.release(Outcome.FAILURE)  # anything unexpected: fail closed
            raise

    async def _attempt_with(self, res: Reservation, *, explicit: bool) -> str:
        # Pre-POST section: the challenge, counter guard and crypto encoding spend no
        # budget, so a failure here releases ABORT (the login never reached the device).
        try:
            challenge = await self.get_challenge()
            check_remaining_attempts(
                challenge.time,
                explicit=explicit,
                max_attempts=challenge.max_time,
                lock_seconds_left=challenge.sec_left,
            )
            body, encrypt_type = self._build_login(challenge)
        except (ApiError, TransportError, LockoutGuard):
            res.release(Outcome.ABORT)
            raise

        log.info("login attempt (explicit=%s, encrypt_type=%s)", explicit, encrypt_type)
        try:
            reply = await self._transport.post_preauth(body, accept_codes=(0, SUPER_PASSWORD_OK))
        except TransportError as exc:
            res.release(Outcome.FAILURE, failure=self._failure_dict(None, None))
            self._state = AuthState(token=None)
            raise self._auth_failed(
                None, None, note=f"{exc}; outcome unknown, counted as a failure."
            ) from None
        except ApiError as exc:
            if exc.code == NONCE_INVALID:
                # The password was never evaluated; still, conservatively, this is a
                # spent attempt (no automatic resend). One login POST per explicit call.
                res.release(Outcome.FAILURE, failure=self._failure_dict(NONCE_INVALID, exc.data))
                self._state = AuthState(token=None)
                log.info("login nonce rejected (-40410); not resending (counted, retryable)")
                raise NonceInvalid(
                    "NVR rejected the login nonce (-40410) as stale or already used. "
                    "No automatic resend; fetch a fresh challenge and retry the login."
                ) from None
            res.release(Outcome.FAILURE, failure=self._failure_dict(exc.code, exc.data))
            self._state = AuthState(token=None)
            raise self._auth_failed(exc.code, exc.data) from None

        try:
            success = LoginSuccess.model_validate(reply)
        except ValidationError:
            res.release(Outcome.FAILURE, failure=self._failure_dict(None, None))
            self._state = AuthState(token=None)
            raise TransportError("NVR login reply did not contain a valid session token") from None
        self._state = AuthState(token=success.stok)
        res.release(Outcome.SUCCESS)
        log.info("login succeeded")
        return success.stok

    def _build_login(self, challenge: Challenge) -> tuple[dict[str, Any], str]:
        try:
            password_field, encrypt_type = crypto.encode_login_password(
                self._settings.password.get_secret_value(),
                offered=challenge.encrypt_type,
                nonce=challenge.nonce,
                key=challenge.key,
            )
        except ValueError as exc:
            raise TransportError(f"Cannot build login request: {exc}") from None
        body = {
            "method": "do",
            "login": {
                "username": self._settings.username,
                "password": password_field,
                "passwdType": PASSWD_TYPE,
                "encrypt_type": encrypt_type,
            },
        }
        return body, encrypt_type

    @staticmethod
    def _failure_dict(code: int | None, data: Any) -> dict[str, Any]:
        info = data if isinstance(data, dict) else {}
        return {
            "device_error_code": code,
            "attempts_left": _int_or_none(info.get("time")),
            "max_attempts": _int_or_none(info.get("max_time")),
            "lock_seconds_left": _int_or_none(info.get("sec_left")),
        }

    def _auth_failed(self, code: int | None, data: Any, *, note: str | None = None) -> AuthFailed:
        info = data if isinstance(data, dict) else {}
        remaining = _int_or_none(info.get("time"))
        max_attempts = _int_or_none(info.get("max_time"))
        sec_left = _int_or_none(info.get("sec_left"))
        symbol = error_symbol(code) if code is not None else "UNKNOWN"
        parts = [note or f"Login rejected by NVR (error_code {code} {symbol})."]
        if code == FACTORY_RESET:
            parts.append("The NVR is in factory-reset state; finish its setup wizard first.")
        if remaining is not None:
            total = f" of {max_attempts}" if max_attempts is not None else ""
            parts.append(f"{remaining}{total} login attempts left before lockout.")
        if sec_left is not None:
            parts.append(f"Account locked for another {sec_left} s.")
        parts.append("Not retrying automatically.")
        log.warning(
            "login failed: code=%s remaining=%s max=%s sec_left=%s",
            code,
            remaining,
            max_attempts,
            sec_left,
        )
        return AuthFailed(
            " ".join(parts),
            code=code,
            attempts_left=remaining,
            max_attempts=max_attempts,
            lock_seconds_left=sec_left,
            symbol=symbol,
            locked=code in LOCKED_CODES,
        )
