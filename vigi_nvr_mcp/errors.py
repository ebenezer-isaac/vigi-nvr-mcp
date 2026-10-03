"""VIGI NVR error codes.

Curated meanings for the login/session-relevant codes from the NVR web UI's
``error.js`` (NVR1016H fw 1.1.3); every other code falls back to its symbol
from the vendored full catalog (``catalog.py``).
"""

from __future__ import annotations

from .catalog import symbol_for

# code -> (symbol, meaning)
ERROR_CODES: dict[int, tuple[str, str]] = {
    0: ("ENONE", "Success"),
    -40101: ("ESYSTEM", "System error"),
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
        "on login it means wrong credentials; on an authenticated call the session token "
        "is invalid or expired",
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
    -71521: ("ENVRCHMDELINVP", "Invalid channel delete parameter"),
}

UNAUTHORISED = -40401
SESSION_TIMEOUT = -40403
LOCKED = -40404
FACTORY_RESET = -40405
LOCKED_FOREVER = -40408
SUPER_PASSWORD_OK = -40409
NONCE_INVALID = -40410
LOCKED_CODES = frozenset({LOCKED, LOCKED_FOREVER, -40413})


def error_symbol(code: int) -> str:
    known = ERROR_CODES.get(code)
    if known is not None:
        return known[0]
    return symbol_for(code) or "UNKNOWN"


def describe_error_code(code: int) -> str:
    known = ERROR_CODES.get(code)
    return known[1] if known is not None else "No curated meaning; see symbol"
