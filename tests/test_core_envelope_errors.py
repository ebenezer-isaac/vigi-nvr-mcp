from __future__ import annotations

import pytest

from tests.helpers import NVR_PREFIX, nvr_env
from vigi_nvr_mcp.auth import check_remaining_attempts
from vigi_nvr_mcp.core import envelope
from vigi_nvr_mcp.core.breaker import LoginBreaker
from vigi_nvr_mcp.core.config import load_device_settings
from vigi_nvr_mcp.core.errors import (
    ApiError,
    AuthFailed,
    LockoutGuard,
    LoginDisabled,
    PreconditionFailed,
    TokenExpired,
)
from vigi_nvr_mcp.core.state import Outcome
from vigi_nvr_mcp.core.tooling import run_tool
from vigi_nvr_mcp.core.write_gate import check_write_gate
from vigi_nvr_mcp.errors import ERROR_CODES, describe_error_code, error_symbol


def test_ok_shape() -> None:
    assert envelope.ok({"a": 1}) == {"success": True, "data": {"a": 1}, "error": None}
    assert envelope.ok([]) == {"success": True, "data": [], "error": None}


def test_fail_shape_and_details_copied() -> None:
    details = {"k": 1}
    result = envelope.fail("X", "m", details)
    details["k"] = 2
    assert result == {
        "success": False,
        "data": None,
        "error": {"code": "X", "message": "m", "details": {"k": 1}},
    }
    assert envelope.fail("X", "m")["error"]["details"] == {}


def test_auth_failed_surfaces_attempts_left_and_max() -> None:
    result = envelope.from_error(
        AuthFailed("bad", code=-40401, symbol="EUNAUTH", attempts_left=3, max_attempts=10)
    )
    assert result["error"]["code"] == "AUTH_FAILED"
    assert result["error"]["details"] == {
        "device_error_code": -40401,
        "symbol": "EUNAUTH",
        "attempts_left": 3,
        "max_attempts": 10,
        "lock_seconds_left": None,
        "locked": False,
    }


@pytest.mark.parametrize(
    ("kwargs", "locked"),
    [
        ({"locked": True}, True),
        ({"attempts_left": 0}, True),
        ({"lock_seconds_left": 60}, True),
        ({"attempts_left": 1}, False),
        ({}, False),
    ],
)
def test_auth_failed_locked_flag(kwargs: dict, locked: bool) -> None:
    assert AuthFailed("x", **kwargs).locked is locked


def test_api_error_includes_symbol_and_meaning() -> None:
    err = ApiError(-40209, symbol="EINVARG", meaning="Invalid argument")
    assert "EINVARG" in str(err)
    details = envelope.from_error(err)["error"]["details"]
    assert details == {
        "device_error_code": -40209,
        "symbol": "EINVARG",
        "meaning": "Invalid argument",
    }


def test_precondition_failed_details() -> None:
    err = PreconditionFailed("m", reason="UUID_MISMATCH", context={"channel_id": "1"})
    assert envelope.from_error(err)["error"]["details"] == {
        "reason": "UUID_MISMATCH",
        "channel_id": "1",
    }


def test_error_table_has_session_codes() -> None:
    for code, symbol in [
        (-40401, "EUNAUTH"),
        (-40403, "ESESSIONTIMEOUT"),
        (-40404, "ESYSLOCKED"),
        (-40405, "ESYSRESET"),
        (-40407, "ESYSCLIENTNORMAL"),
        (-40408, "ESYSLOCKEDFOREVER"),
        (-40410, "ESYSNONCEINVALID"),
        (-70302, "ENVRUMUSRNEXIST"),
        (-40106, "EINVINSTRUCT"),
    ]:
        assert ERROR_CODES[code][0] == symbol
    assert error_symbol(1) == "UNKNOWN"
    assert error_symbol(-71554) == "ENVRCHMAUTHFAIL"  # catalog fallback
    assert describe_error_code(1) == "No curated meaning; see symbol"
    assert describe_error_code(-40404).startswith("Account temporarily locked")


def test_error_kinds_are_distinct() -> None:
    kinds = {AuthFailed.kind, TokenExpired.kind, LockoutGuard.kind, ApiError.kind}
    assert len(kinds) == 4


# ---- write gate ---------------------------------------------------------------


def _settings(**overrides: str):
    return load_device_settings(NVR_PREFIX, nvr_env(**overrides))


def test_write_gate_read_passes() -> None:
    assert check_write_gate(_settings(), "get", False) is None


@pytest.mark.parametrize("confirm", [False, True, "true", 1])
def test_write_gate_refuses_when_disallowed(confirm: object) -> None:
    refusal = check_write_gate(_settings(), "set", confirm)
    assert refusal is not None
    assert "VIGI_NVR_ALLOW_WRITES" in refusal["error"]["message"]


@pytest.mark.parametrize("confirm", [False, "true", "yes", 1, None])
def test_write_gate_requires_literal_true(confirm: object) -> None:
    refusal = check_write_gate(_settings(ALLOW_WRITES="true"), "do", confirm)
    assert refusal is not None and "confirm_write" in refusal["error"]["message"]


def test_write_gate_passes_with_both_keys() -> None:
    assert check_write_gate(_settings(ALLOW_WRITES="true"), "delete", True) is None


# ---- lockout helpers (reserve/release breaker) --------------------------------


def test_reservation_records_outcomes_and_keeps_failures(tmp_path) -> None:
    b = LoginBreaker(tmp_path, "dev", max_failures=3)
    b.reserve_attempt().release(Outcome.FAILURE, failure={"x": 1})
    assert b.status()["failures"] == 1
    # A success bumps successes but never clears the sticky failures.
    b.reserve_attempt().release(Outcome.SUCCESS)
    assert b.status()["successes"] == 1
    assert b.status()["failures"] == 1


def test_login_disabled_guard_names_variable(tmp_path) -> None:
    b = LoginBreaker(
        tmp_path, "dev", login_disabled=True, disabled_hint="VIGI_NVR_LOGIN_DISABLED=true"
    )
    with pytest.raises(LoginDisabled, match="VIGI_NVR_LOGIN_DISABLED"):
        b.reserve_attempt()


@pytest.mark.parametrize(
    ("remaining", "explicit", "refused"),
    [
        (None, False, False),
        (0, True, True),
        (-1, True, True),
        (1, True, False),
        (1, False, True),
        (2, False, True),
        (3, False, False),
    ],
)
def test_remaining_attempt_guard(remaining, explicit, refused) -> None:
    if refused:
        with pytest.raises(LockoutGuard):
            check_remaining_attempts(remaining, explicit=explicit)
    else:
        check_remaining_attempts(remaining, explicit=explicit)


# ---- run_tool -----------------------------------------------------------------


async def test_run_tool_maps_errors_and_redacts() -> None:
    from vigi_nvr_mcp.core.errors import InvalidInput

    async def leaky():
        return {"stok": "s", "ok": 1}

    async def bad_input():
        raise InvalidInput("nope")

    async def stray_value_error():
        # A plain ValueError is NOT client input (e.g. a truncated vendored file);
        # it must become INTERNAL_ERROR, never be mislabelled INVALID_INPUT.
        raise ValueError("line 1 column 17 (char 16)")

    async def boom():
        raise RuntimeError("internal detail")

    assert (await run_tool("t", leaky))["data"] == {"stok": "<redacted>", "ok": 1}
    assert (await run_tool("t", bad_input))["error"]["code"] == "INVALID_INPUT"
    stray = await run_tool("t", stray_value_error)
    assert stray["error"]["code"] == "INTERNAL_ERROR"
    assert "char 16" not in stray["error"]["message"]
    internal = await run_tool("t", boom)
    assert internal["error"]["code"] == "INTERNAL_ERROR"
    assert "internal detail" not in internal["error"]["message"]


# ---- serial lock / transport masks / cli helpers ----------------------------------


async def test_serial_lock_serialises() -> None:
    import asyncio

    from vigi_nvr_mcp.core.serial import SerialLock

    lock, order = SerialLock(), []

    async def job(name: str) -> str:
        order.append(f"{name}-start")
        await asyncio.sleep(0)
        order.append(f"{name}-end")
        return name

    results = await asyncio.gather(lock.run(lambda: job("a")), lock.run(lambda: job("b")))
    assert results == ["a", "b"]
    assert order == ["a-start", "a-end", "b-start", "b-end"]
    assert lock.busy is False


def test_token_masks_are_registered_once_and_applied() -> None:
    from vigi_nvr_mcp.core import transport

    transport.register_token_mask(r"sid=\w+", "sid=<x>")
    transport.register_token_mask(r"sid=\w+", "sid=<x>")
    assert sum(p.pattern == r"sid=\w+" for p, _ in transport._MASKS) == 1
    assert transport.mask_tokens("/a?sid=abc123") == "/a?sid=<x>"


def test_cli_helpers(capsys) -> None:
    from vigi_nvr_mcp.core.cli import configure_logging, emit_envelope, emit_lines

    configure_logging("NOPE_LEVEL", {"NOPE_LEVEL": "bogus"})
    assert emit_envelope(envelope.ok({"a": 1})) == 0
    assert emit_envelope(envelope.fail("X", "m")) == 1
    assert emit_lines(["one", "two"]) == 0
    out = capsys.readouterr().out
    assert '"success": true' in out and out.rstrip().endswith("two")
