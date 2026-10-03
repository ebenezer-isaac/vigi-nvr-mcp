from __future__ import annotations

from vigi_nvr_mcp import envelope
from vigi_nvr_mcp.errors import (
    ERROR_CODES,
    NvrApiError,
    NvrAuthError,
    NvrLockoutGuard,
    NvrTokenExpired,
    describe_error_code,
)


def test_ok_shape() -> None:
    assert envelope.ok({"a": 1}) == {"success": True, "data": {"a": 1}, "error": None}


def test_ok_allows_falsy_data() -> None:
    assert envelope.ok([]) == {"success": True, "data": [], "error": None}


def test_fail_shape_and_default_details() -> None:
    assert envelope.fail("X", "msg") == {
        "success": False,
        "data": None,
        "error": {"code": "X", "message": "msg", "details": {}},
    }


def test_fail_copies_details() -> None:
    details = {"k": 1}
    result = envelope.fail("X", "m", details)
    details["k"] = 2
    assert result["error"]["details"] == {"k": 1}


def test_from_error_auth_surfaces_attempt_counters() -> None:
    result = envelope.from_error(NvrAuthError("bad", code=-40401, time=3, max_time=10))
    assert result["success"] is False
    assert result["error"]["code"] == "AUTH_FAILED"
    assert result["error"]["details"] == {
        "nvr_error_code": -40401,
        "failed_attempts": 3,
        "max_attempts": 10,
        "attempts_remaining": 7,
    }


def test_auth_error_without_counters_has_none_remaining() -> None:
    assert NvrAuthError("bad").details()["attempts_remaining"] is None


def test_from_error_api_error_includes_meaning() -> None:
    result = envelope.from_error(NvrApiError(-40106))
    assert result["error"]["code"] == "NVR_API_ERROR"
    assert result["error"]["details"]["nvr_error_code"] == -40106
    assert "-40106" in result["error"]["message"]


def test_error_kinds_are_distinct() -> None:
    kinds = {NvrAuthError.kind, NvrTokenExpired.kind, NvrLockoutGuard.kind, NvrApiError.kind}
    assert len(kinds) == 4


def test_error_table_covers_known_codes() -> None:
    for code in (0, -40401, -40407, -70302, -40106, -40209):
        assert code in ERROR_CODES
    assert describe_error_code(123456) == "Unknown NVR error code"
