"""F2/F3 — device lockout counters are not surfaced "exactly as reported".

Claim under attack: "...surface attempts_left/max_attempts/sec_left exactly as
the device reports them."

F2: when the pre-login breaker blocks because the *challenge* already reports the
account locked (``time``/``sec_left``), the raised ``LockoutGuard`` carries none
of the device counters -- ``details()`` is ``{}`` and there are no
attempts_left/max_attempts/lock_seconds_left attributes. ``check_remaining_attempts``
reads only ``challenge.time`` and embeds it in prose; ``max_time`` and
``sec_left`` are dropped entirely.

F3: when a login reply (``-40401``/``-40404``) carries the counters as JSON
strings -- a shape the authenticator's own ``Challenge`` model accepts via
pydantic lax coercion -- ``_record_failure`` uses ``_int_or_none`` and drops
every string value to ``None``, so they are not surfaced at all.
"""

from __future__ import annotations

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.core.errors import AuthFailed, LockoutGuard


# ---- F2: pre-login lockout guard drops the challenge counters ---------------


async def test_prelogin_lockout_surfaces_sec_left_and_max(make_auth, fake: FakeNvr) -> None:
    # The device's challenge says: 0 attempts left, max 10, locked for 1740s.
    fake.challenge_extra = {"time": 0, "max_time": 10, "sec_left": 1740}
    auth = make_auth()
    with pytest.raises(LockoutGuard) as info:
        await auth.login()
    assert fake.login_attempts == 0  # correctly made no login attempt
    details = info.value.details()
    # Claim: the counters the device reported must be surfaced.
    assert details.get("lock_seconds_left") == 1740, (
        "device-reported sec_left was dropped by the lockout guard: "
        f"{details!r}"
    )
    assert details.get("max_attempts") == 10
    assert details.get("attempts_left") == 0


# ---- F3: login-failure counters sent as strings are dropped -----------------


async def test_login_failure_string_counters_are_dropped(make_auth, fake: FakeNvr) -> None:
    # WON'T-FIX per orchestrator decision AL-F3 (fixer brief): there is no live
    # evidence the firmware *failure* reply uses string counters, so the strict
    # int parsing (_int_or_none) is kept and string counters drop to None. This
    # test is inverted to document the accepted behaviour pending a live capture
    # (Phase N5); revisit if the device is seen emitting string failure counters.
    fake.login_error = {
        "error_code": -40404,
        "data": {"time": "0", "max_time": "10", "sec_left": "1740"},
    }
    auth = make_auth()
    with pytest.raises(AuthFailed) as info:
        await auth.login()
    err = info.value
    assert err.lock_seconds_left is None
    assert err.max_attempts is None
    assert err.attempts_left is None
