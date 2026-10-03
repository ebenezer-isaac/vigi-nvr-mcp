"""R2 auth-persist F2 — a wrongly-typed state file fails CLOSED (migrated to X1).

The finding: ``_load`` trusted field types outside the fail-closed guard, so
``{"failed":"oops"}`` raised a raw ``ValueError``, ``{"failed":[1]}`` a raw
``TypeError`` (crashing ``--show``), and the dangerous ``{"failed":false}`` coerced
to ``int(False)==0`` and FAILED OPEN (a corrupt file allowed a login).

X1 makes all three impossible by construction: the ledger is a strict pydantic model
(``strict=True``), so a non-numeric, list or **boolean** value is a ``ValidationError``
that the store maps to ``StateUnavailable`` -> the breaker refuses with ``BreakerOpen``
(never coerced, never fail-open), and ``status()`` reports ``state: open`` without
crashing. These tests now prove the fixed behaviour, with every assertion preserved
(fail-closed on each bad shape; ``false`` never fails open; ``--show`` never crashes).
"""

from __future__ import annotations

import json

import pytest

from tests.helpers import NVR_PREFIX, nvr_env
from vigi_nvr_mcp.core.breaker import LoginBreaker, canonical_device_key
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.core.errors import BreakerOpen


def _breaker(tmp_path) -> LoginBreaker:
    settings: DeviceSettings = load_device_settings(NVR_PREFIX, nvr_env(STATE_DIR=str(tmp_path)))
    return LoginBreaker(tmp_path, canonical_device_key(settings.host), max_failures=1)


def _base_ledger() -> dict:
    return {
        "version": 1,
        "key": "k",
        "reserved": 0,
        "failures": 0,
        "successes": 0,
        "tripped": False,
        "cooldown_until": None,
        "last_failure": None,
        "last_update": 1.0,
    }


def _write(brk: LoginBreaker, payload: object) -> None:
    brk.path.write_text(json.dumps(payload), encoding="utf-8")


def test_nonnumeric_count_fails_closed(tmp_path) -> None:
    brk = _breaker(tmp_path)
    _write(brk, {**_base_ledger(), "failures": "oops"})
    with pytest.raises(BreakerOpen):
        brk.reserve_attempt()


def test_list_count_fails_closed(tmp_path) -> None:
    brk = _breaker(tmp_path)
    _write(brk, {**_base_ledger(), "failures": [1]})
    with pytest.raises(BreakerOpen):
        brk.reserve_attempt()


def test_boolean_false_does_not_fail_open(tmp_path) -> None:
    """The dangerous case: ``false`` must NOT coerce to 0 and allow a login."""
    brk = _breaker(tmp_path)
    _write(brk, {**_base_ledger(), "failures": False})
    with pytest.raises(BreakerOpen):
        brk.reserve_attempt()


def test_show_does_not_crash_on_wrongtyped_file(tmp_path) -> None:
    brk = _breaker(tmp_path)
    _write(brk, {**_base_ledger(), "failures": "oops"})
    info = brk.status()  # must report, not crash
    assert info["state"] == "open"
