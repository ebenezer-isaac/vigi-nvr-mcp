"""Typed exceptions and the NVR error-code table.

Error-code meanings marked "observed" were seen on an NVR1016H (fw 1.1.3). The
rest are best-effort readings from other TP-Link firmware and community SDKs;
treat them as hints, not as documentation.
"""

from __future__ import annotations

from typing import Any

ERROR_CODES: dict[int, str] = {
    0: "OK",
    -40401: "Unauthorised: login required, credentials rejected, or session token "
    "invalid/expired (observed)",
    -40407: "Challenge sub-code returned with the encryption info (observed)",
    -40404: "Account temporarily locked after repeated failed logins "
    "(seen on other TP-Link firmware; unverified on VIGI NVRs)",
    -40106: "Invalid or unsupported request parameters (best-effort)",
    -40209: "Request rejected by the device; method or module not permitted (best-effort)",
    -40210: "Function not supported by this firmware (best-effort)",
    -70302: "Device-side operation failed or resource unavailable (best-effort)",
}


def describe_error_code(code: int) -> str:
    return ERROR_CODES.get(code, "Unknown NVR error code")


class NvrError(Exception):
    """Base class. ``kind`` is the stable machine-readable code used in envelopes."""

    kind = "NVR_ERROR"

    def details(self) -> dict[str, Any]:
        return {}


class NvrConfigError(NvrError):
    kind = "CONFIG_ERROR"


class NvrTransportError(NvrError):
    """Network, TLS, HTTP status or malformed-response failure."""

    kind = "TRANSPORT_ERROR"


class NvrApiError(NvrError):
    kind = "NVR_API_ERROR"

    def __init__(self, code: int, message: str | None = None, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(message or f"NVR returned error_code {code}: {describe_error_code(code)}")

    def details(self) -> dict[str, Any]:
        return {"nvr_error_code": self.code, "meaning": describe_error_code(self.code)}


class NvrAuthError(NvrError):
    """The login call itself was rejected. Never retried automatically."""

    kind = "AUTH_FAILED"

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        time: int | None = None,
        max_time: int | None = None,
    ) -> None:
        self.code = code
        self.time = time
        self.max_time = max_time
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {
            "nvr_error_code": self.code,
            "failed_attempts": self.time,
            "max_attempts": self.max_time,
            "attempts_remaining": (
                self.max_time - self.time
                if self.time is not None and self.max_time is not None
                else None
            ),
        }


class NvrTokenExpired(NvrError):
    """An authenticated (/stok=.../ds) call was answered with -40401."""

    kind = "TOKEN_EXPIRED"


class NvrLockoutGuard(NvrError):
    """A login was refused locally to protect the account from lockout."""

    kind = "LOGIN_REFUSED"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)
