"""F2 — a wrongly-typed state file does NOT fail closed with a clear BreakerOpen.

The claim: "a corrupt, truncated, unreadable, unwritable or wrongly-typed state
file makes login impossible with a clear ``BreakerOpen`` error (fail closed)".

``LoginBreaker._load`` wraps only ``json.loads`` in ``try/except (OSError,
ValueError)``. The subsequent ``int(data.get("failed", 0))`` /
``int(data.get("successful", 0))`` coercions are unguarded, so a state file that
is valid JSON but holds a wrongly-typed numeric field behaves three different
wrong ways, none of them the promised BreakerOpen:

* ``{"failed": "oops"}``   -> uncaught ``ValueError``  (not BreakerOpen)
* ``{"failed": [1]}``      -> uncaught ``TypeError``   (not even in the caught set)
* ``{"failed": false}``    -> ``int(False) == 0`` -> breaker reads 0 failures and
                              FAILS OPEN: the login is allowed.

The uncaught exception also crashes ``breaker --show`` (``show`` only catches
``BreakerOpen``), i.e. the very command an operator runs to diagnose a stuck
breaker dies with a traceback instead of reporting ``state: open``.

Mocks/fakes only; writes a JSON file to a tmp dir, no device.
"""

from __future__ import annotations

import json

import pytest

from tests.helpers import NVR_PREFIX, nvr_env
from vigi_nvr_mcp.core import breaker as breaker_mod
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.core.errors import BreakerOpen, LockoutGuard


def _breaker(tmp_path) -> breaker_mod.LoginBreaker:
    settings: DeviceSettings = load_device_settings(NVR_PREFIX, nvr_env(STATE_DIR=str(tmp_path)))
    return breaker_mod.LoginBreaker(tmp_path, settings.host, settings)


def _write(brk: breaker_mod.LoginBreaker, payload: object) -> None:
    brk.path.write_text(json.dumps(payload), encoding="utf-8")


def test_nonnumeric_failed_raises_breakeropen_not_valueerror(tmp_path) -> None:
    brk = _breaker(tmp_path)
    _write(brk, {"failed": "oops", "successful": 0})
    # Claim: wrongly-typed -> BreakerOpen (fail closed). Reality: raw ValueError.
    with pytest.raises(BreakerOpen):
        brk.check(explicit=True)


def test_list_failed_raises_breakeropen_not_typeerror(tmp_path) -> None:
    brk = _breaker(tmp_path)
    _write(brk, {"failed": [1], "successful": 0})
    # int([1]) raises TypeError, which is not even in the except (OSError, ValueError).
    with pytest.raises(BreakerOpen):
        brk.check(explicit=True)


def test_boolean_false_failed_fails_open(tmp_path) -> None:
    """A wrongly-typed file that should fail closed instead ALLOWS the login."""
    brk = _breaker(tmp_path)
    _write(brk, {"failed": False, "successful": 0})
    # The claim says a wrongly-typed file "makes login impossible". int(False)==0,
    # so check() returns a clean ledger and the login is allowed -> fail OPEN.
    with pytest.raises((BreakerOpen, LockoutGuard)):
        brk.check(explicit=True)


def test_show_does_not_crash_on_wrongtyped_file(tmp_path) -> None:
    """``breaker --show`` must report the state, not crash with a traceback."""
    brk = _breaker(tmp_path)
    _write(brk, {"failed": "oops", "successful": 0})
    info = brk.show()  # show() only catches BreakerOpen; the ValueError escapes.
    assert info["state"] == "open"
