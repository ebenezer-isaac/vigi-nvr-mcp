from __future__ import annotations

import pytest

from tests.helpers import NVR_PREFIX, nvr_env
from tplink_local_mcp.core import envelope, lockout
from tplink_local_mcp.core.config import load_device_settings
from tplink_local_mcp.core.errors import (
    ERROR_CODES,
    ApiError,
    AuthFailed,
    LockoutGuard,
    PreconditionFailed,
    TokenExpired,
    describe_error_code,
    error_symbol,
)
from tplink_local_mcp.core.tooling import run_tool
from tplink_local_mcp.core.write_gate import check_write_gate


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
    result = envelope.from_error(AuthFailed("bad", code=-40401, attempts_left=3, max_attempts=10))
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
    ("code", "left", "locked"),
    [(-40404, None, True), (-40408, None, True), (-40401, 0, True), (-40401, 1, False)],
)
def test_auth_failed_locked_flag(code: int, left: int | None, locked: bool) -> None:
    assert AuthFailed("x", code=code, attempts_left=left).locked is locked


def test_api_error_includes_symbol_and_meaning() -> None:
    details = envelope.from_error(ApiError(-40209))["error"]["details"]
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
    assert describe_error_code(1) == "Unknown device error code"


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
    assert "TPLINK_NVR_ALLOW_WRITES" in refusal["error"]["message"]


@pytest.mark.parametrize("confirm", [False, "true", "yes", 1, None])
def test_write_gate_requires_literal_true(confirm: object) -> None:
    refusal = check_write_gate(_settings(ALLOW_WRITES="true"), "do", confirm)
    assert refusal is not None and "confirm_write" in refusal["error"]["message"]


def test_write_gate_passes_with_both_keys() -> None:
    assert check_write_gate(_settings(ALLOW_WRITES="true"), "delete", True) is None


# ---- lockout helpers ------------------------------------------------------------


def test_ledger_is_immutable_and_rebuilt() -> None:
    ledger = lockout.LoginLedger()
    after = lockout.record_failure(ledger, {"x": 1})
    assert (ledger.failed, after.failed) == (0, 1)
    assert lockout.record_success(after).successful == 1


def test_login_disabled_guard_names_variable() -> None:
    with pytest.raises(LockoutGuard, match="TPLINK_NVR_LOGIN_DISABLED"):
        lockout.check_login_allowed(
            lockout.LoginLedger(), _settings(LOGIN_DISABLED="true"), explicit=True
        )


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
            lockout.check_remaining_attempts(remaining, explicit=explicit)
    else:
        lockout.check_remaining_attempts(remaining, explicit=explicit)


# ---- run_tool -----------------------------------------------------------------


async def test_run_tool_maps_errors_and_redacts() -> None:
    async def leaky():
        return {"stok": "s", "ok": 1}

    async def bad_input():
        raise ValueError("nope")

    async def boom():
        raise RuntimeError("internal detail")

    assert (await run_tool("t", leaky))["data"] == {"stok": "<redacted>", "ok": 1}
    assert (await run_tool("t", bad_input))["error"]["code"] == "INVALID_INPUT"
    internal = await run_tool("t", boom)
    assert internal["error"]["code"] == "INTERNAL_ERROR"
    assert "internal detail" not in internal["error"]["message"]
