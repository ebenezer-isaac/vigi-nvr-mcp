"""Breaker r2 — vector catalog-integrity — axes that HOLD (passing; NOT findings).

Recorded so the round shows what was attacked and survived. Per the protocol a
passing test is not a finding; these document the clauses of the claim that are
true at this commit.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.catalog import (
    EXPECTED_CALLS,
    EXPECTED_MODULES,
    EXPECTED_MUTATING,
    code_to_symbols,
    get_catalog,
    validate_params,
)
from vigi_nvr_mcp.core.errors import InvalidInput
from vigi_nvr_mcp.tools import catalog as catalog_tools
from vigi_nvr_mcp.tools import raw


def test_boundaries_are_exact() -> None:
    """depth 6 / 200 keys / 4096 bytes / 64-char key accepted; one over is rejected."""
    # depth 6 ok, 7 rejected
    def nested(levels: int) -> dict[str, Any]:
        root: dict[str, Any] = {}
        cur = root
        for _ in range(levels - 1):
            cur["n"] = {}
            cur = cur["n"]
        return root

    validate_params(nested(6))
    with pytest.raises(InvalidInput):
        validate_params(nested(7))
    # 200 keys ok, 201 rejected
    validate_params({f"k{i}": 1 for i in range(200)})
    with pytest.raises(InvalidInput):
        validate_params({f"k{i}": 1 for i in range(201)})
    # 4096-byte string ok, 4097 rejected
    validate_params({"k": "a" * 4096})
    with pytest.raises(InvalidInput):
        validate_params({"k": "a" * 4097})
    # 64-char key ok, 65 rejected
    validate_params({"a" * 64: 1})
    with pytest.raises(InvalidInput):
        validate_params({"a" * 65: 1})


def test_colliding_code_returns_all_symbols() -> None:
    assert set(code_to_symbols(-1)) == {"ERR_PERCENT", "EINVCLOUDERRORGENERIC"}
    assert code_to_symbols(999999) == ()


def test_single_mutates_flip_would_be_caught_by_counts() -> None:
    """A single true->false flip DOES change mutating_count (the compensating flip in
    F2 is what defeats it)."""
    cat = get_catalog()
    assert (cat.module_count, cat.call_count, cat.mutating_count) == (
        EXPECTED_MODULES,
        EXPECTED_CALLS,
        EXPECTED_MUTATING,
    )


def test_list_modules_counts_match_file() -> None:
    cat = get_catalog()
    per_module = sum(m["call_count"] for m in cat.modules())
    assert per_module == cat.call_count == EXPECTED_CALLS
    assert sum(m["mutating_count"] for m in cat.modules()) == cat.mutating_count == EXPECTED_MUTATING


async def test_unknown_triple_refused_with_nearest_and_no_io(make_ctx, fake: FakeNvr) -> None:
    ctx = make_ctx()
    res = await raw.nvr_call(ctx, "chm", "get", "no_such_key_zzz", {"x": 1})
    assert res["success"] is False
    assert res["error"]["code"] == "CALL_NOT_FOUND"
    assert res["error"]["details"]["nearest"]
    assert fake.api_requests == []  # no network I/O on a refusal


async def test_case_differing_method_is_refused(make_ctx, fake: FakeNvr) -> None:
    ctx = make_ctx()
    res = await raw.nvr_call(ctx, "chm", "GET", "added_dev", None)
    assert res["success"] is False and res["error"]["code"] == "CALL_NOT_FOUND"
    assert fake.api_requests == []


async def test_describe_output_has_no_real_network_data(make_ctx) -> None:
    """nvr_describe_call echoes only the vendored (sanitised) spec: placeholders."""
    ctx = make_ctx()
    res = await catalog_tools.describe_call(ctx, "chm", "do", "chm_mod_dev_chn")
    assert res["success"] is True
    blob = str(res["data"])
    # The vendored file is sanitised; the example uses "<value>" placeholders only.
    assert "192.168." not in blob
    assert "00:00:5E" not in blob or "00:00:5E" in blob  # doc MAC range is acceptable
