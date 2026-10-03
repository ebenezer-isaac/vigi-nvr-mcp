"""Typed exceptions and the TP-Link error-code table.

Codes and symbols come from the error table shipped in the VIGI NVR web UI
(``web-static/language/error.js``, firmware 1.1.3). TP-Link reuses the same
numbering across product lines, but meanings on routers and switches are
unverified.
"""

from __future__ import annotations

from typing import Any

# code -> (symbol, meaning). Login/session-relevant subset plus common argument errors.
ERROR_CODES: dict[int, tuple[str, str]] = {
    0: ("ENONE", "Success"),
    -40101: ("ESYSTEM", "System error"),
    -40105: ("ECODE", "Invalid code"),
    -40106: ("EINVINSTRUCT", "Invalid instruction or method"),
    -40107: ("EFORBID", "Operation forbidden"),
    -40109: ("ESYSBUSY", "System busy"),
    -40112: ("EDEVICEUPDATING", "Device is updating firmware"),
    -40203: ("EENTRYEXIST", "Entry already exists"),
    -40205: ("EENTRYNOTEXIST", "Entry does not exist"),
    -40209: ("EINVARG", "Invalid argument"),
    -40210: ("EINVFMT", "Invalid format (bad JSON or bad base64)"),
    -40211: ("ELACKARG", "Missing argument"),
    -40401: (
        "EUNAUTH",
        "Not authorised. On the challenge call this carries the encryption info (expected); "
        "on login it means wrong credentials; on an authenticated call it means the session "
        "token is invalid or expired",
    ),
    -40402: ("ECODEUNAUTH", "Verification code not authorised"),
    -40403: ("ESESSIONTIMEOUT", "Session timed out"),
    -40404: ("ESYSLOCKED", "Account temporarily locked after failed logins; see sec_left"),
    -40405: ("ESYSRESET", "Device is in factory-reset state; complete the setup wizard first"),
    -40406: ("ESYSCLIENTFULL", "Too many concurrent sessions"),
    -40407: ("ESYSCLIENTNORMAL", "Normal/logged-out sentinel seen inside the challenge"),
    -40408: ("ESYSLOCKEDFOREVER", "Account permanently locked"),
    -40409: ("ESUPERPWDSUCCESS", "Super/temporary password accepted"),
    -40410: ("ESYSNONCEINVALID", "Nonce stale or already used; fetch a new challenge"),
    -40411: ("EUSRUNSUPPORTED", "User type not supported"),
    -40412: ("ETMPPWD_EXPIRED", "Temporary password expired"),
    -40413: ("ETMSLOCKED_EPTMP", "Locked due to temporary-password misuse"),
    -70301: ("ENVRUMUSRBLANK", "Username is blank"),
    -70302: ("ENVRUMUSRNEXIST", "User does not exist"),
    -70303: ("ENVRUMUSRNAUTH", "User not authorised"),
    -70312: ("ENVRCUMPWDERR", "Password error"),
}

LOCKED_CODES = frozenset({-40404, -40408, -40413})
NONCE_INVALID = -40410
FACTORY_RESET = -40405


def describe_error_code(code: int) -> str:
    return ERROR_CODES.get(code, ("UNKNOWN", "Unknown device error code"))[1]


def error_symbol(code: int) -> str:
    return ERROR_CODES.get(code, ("UNKNOWN", ""))[0]


class DeviceError(Exception):
    """Base class. ``kind`` is the stable machine-readable code used in envelopes."""

    kind = "DEVICE_ERROR"

    def details(self) -> dict[str, Any]:
        return {}


class ConfigError(DeviceError):
    kind = "CONFIG_ERROR"


class TransportError(DeviceError):
    """Network, TLS, HTTP status or malformed-response failure."""

    kind = "TRANSPORT_ERROR"


class ApiError(DeviceError):
    kind = "DEVICE_API_ERROR"

    def __init__(self, code: int, message: str | None = None, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(
            message
            or f"Device returned error_code {code} ({error_symbol(code)}): "
            f"{describe_error_code(code)}"
        )

    def details(self) -> dict[str, Any]:
        return {
            "device_error_code": self.code,
            "symbol": error_symbol(self.code),
            "meaning": describe_error_code(self.code),
        }


class AuthFailed(DeviceError):
    """The login call itself was rejected. Never retried automatically."""

    kind = "AUTH_FAILED"

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        attempts_left: int | None = None,
        max_attempts: int | None = None,
        lock_seconds_left: int | None = None,
    ) -> None:
        self.code = code
        self.attempts_left = attempts_left
        self.max_attempts = max_attempts
        self.lock_seconds_left = lock_seconds_left
        super().__init__(message)

    @property
    def locked(self) -> bool:
        return self.code in LOCKED_CODES or self.attempts_left == 0

    def details(self) -> dict[str, Any]:
        return {
            "device_error_code": self.code,
            "symbol": error_symbol(self.code) if self.code is not None else None,
            "attempts_left": self.attempts_left,
            "max_attempts": self.max_attempts,
            "lock_seconds_left": self.lock_seconds_left,
            "locked": self.locked,
        }


class TokenExpired(DeviceError):
    """An authenticated call reported the session as invalid or timed out."""

    kind = "TOKEN_EXPIRED"


class LockoutGuard(DeviceError):
    """A login was refused locally to protect the account from lockout."""

    kind = "LOGIN_REFUSED"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class NotFound(DeviceError):
    kind = "NOT_FOUND"


class NotImplementedYet(DeviceError):
    kind = "NOT_IMPLEMENTED"


class PreconditionFailed(DeviceError):
    """A guarded write was refused because the live state did not match."""

    kind = "PRECONDITION_FAILED"

    def __init__(self, message: str, *, reason: str, context: dict[str, Any] | None = None) -> None:
        self.reason = reason
        self.context = dict(context or {})
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"reason": self.reason, **self.context}
