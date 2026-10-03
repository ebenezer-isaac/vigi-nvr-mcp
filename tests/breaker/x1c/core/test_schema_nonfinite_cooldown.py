"""x1c / core — F2: the strict ledger schema admits non-finite floats, so a
hand-edited ``cooldown_until`` of ``Infinity``/``NaN`` produces a cooldown that
never counts down and is recoverable only by ``clear()`` (stuck breaker).

Claim under attack: "the ledger is strict-schema and any load failure (corrupt,
truncated, wrong types ..., unknown version, extra keys) refuses with
``StateUnavailable``/``BreakerOpen`` — never a raw exception, never a coercion ...
cooldown remaining is clamped >= 0".

``BreakerLedger`` (``breaker.py:79``) uses ``ConfigDict(strict=True, extra="forbid")``
but does NOT set ``allow_inf_nan=False`` — unlike ``DeviceSettings.timeout_seconds``
in ``config.py:104`` which explicitly does. ``json.loads`` accepts the ``Infinity``
and ``NaN`` tokens, and pydantic strict ``float`` accepts the resulting non-finite
values, so the load succeeds. ``_cooldown_remaining`` (``breaker.py:142``) then
computes ``inf - clock() == inf`` / ``nan - clock() == nan``; ``min(7200.0, inf|nan)``
clamps to ``7200.0`` on EVERY call regardless of the clock, so the cooldown never
reaches zero. The breaker refuses logins forever (``Cooldown``) until a human runs
``breaker --clear`` — a device left unreachable, from a value the writer itself can
never emit (``_cooldown_epoch`` clamps to a finite number).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigi_nvr_mcp.core.breaker import LoginBreaker
from vigi_nvr_mcp.core.errors import BreakerOpen, Cooldown


def _write_ledger(b: LoginBreaker, cooldown_until_token: str) -> None:
    b.path.parent.mkdir(parents=True, exist_ok=True)
    blob = (
        '{"version": 1, "key": "dev", "reserved": 0, "failures": 0, "successes": 0, '
        '"tripped": false, "last_failure": null, "last_update": 1.0, '
        f'"cooldown_until": {cooldown_until_token}}}'
    )
    # Sanity: the token really is in the file as a non-finite literal.
    assert cooldown_until_token in blob
    b.path.write_text(blob, encoding="utf-8")


@pytest.mark.parametrize("token", ["Infinity", "NaN"])
def test_nonfinite_cooldown_never_expires(tmp_path: Path, token: str) -> None:
    now = [1000.0]
    b = LoginBreaker(tmp_path, "dev", max_failures=5, clock=lambda: now[0])
    _write_ledger(b, token)

    # Advance the clock far beyond any real cooldown (MAX_COOLDOWN_S is 7200s).
    now[0] = 1000.0 + 10 ** 9

    remaining = b.status()["cooldown_remaining_s"]
    assert remaining == 0, (
        f"a hand-edited cooldown_until={token} still reports {remaining}s remaining "
        "after the clock advanced ~1e9s: the cooldown never counts down, so the "
        "breaker is stuck closed until a human runs `breaker --clear`. The strict "
        "schema should reject non-finite floats (config.py uses allow_inf_nan=False) "
        "or the clamp should force expiry."
    )
    # And a login should be admitted once the (bogus) cooldown has notionally passed.
    b.reserve_attempt()
