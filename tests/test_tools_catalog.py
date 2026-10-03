"""Gateway tools: nvr_list_modules/list_calls/describe_call, nvr_call, nvr_raw_call."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from vigi_nvr_mcp.catalog import get_catalog
from vigi_nvr_mcp.core.redact import REDACTED
from vigi_nvr_mcp.tools import catalog as catalog_tools
from vigi_nvr_mcp.tools import raw

EXPECTED_MODULES = 61
EXPECTED_CALLS = 586
EXPECTED_MUTATING = 217
DENIED = {"login", "user_management"}

_PKG = Path(__file__).resolve().parent.parent / "vigi_nvr_mcp"


def test_dry_run_has_a_single_implementation() -> None:
    """Dry-run is implemented once, in the guarded-write executor (core/serial.py),
    and nowhere else: no per-tool copies branch on settings.dry_run."""
    echo = '{"dry_run": True, "request": request}'
    producers = [p for p in _PKG.rglob("*.py") if echo in p.read_text(encoding="utf-8")]
    assert producers == [_PKG / "core" / "serial.py"], producers
    for tool in ("tools/channels.py", "tools/raw.py"):
        src = (_PKG / tool).read_text(encoding="utf-8")
        assert "settings.dry_run" not in src, f"{tool} still branches on dry_run itself"


@pytest.fixture
def wctx(make_ctx):
    return make_ctx(ALLOW_WRITES="true")


@pytest.fixture
def dctx(make_ctx):
    return make_ctx(ALLOW_WRITES="true", DRY_RUN="true")


def _ok_handler(_token: str, body: dict[str, Any]) -> dict[str, Any]:
    return {"error_code": 0, "echo": body}


# ---- browsing tools ---------------------------------------------------------


async def test_list_modules_reports_contract_counts(ctx) -> None:
    result = await catalog_tools.list_modules(ctx)
    assert result["success"] is True
    data = result["data"]
    assert (data["module_count"], data["call_count"], data["mutating_count"]) == (
        EXPECTED_MODULES,
        EXPECTED_CALLS,
        EXPECTED_MUTATING,
    )
    assert len(data["modules"]) == EXPECTED_MODULES


async def test_list_calls_for_known_and_unknown_module(ctx) -> None:
    good = await catalog_tools.list_calls(ctx, "chm")
    assert good["success"] is True
    assert all(c["module"] == "chm" for c in good["data"]["calls"])

    bad = await catalog_tools.list_calls(ctx, "chmm")
    assert bad["error"]["code"] == "NOT_FOUND"
    assert "chm" in bad["error"]["details"]["nearest_modules"]


async def test_describe_call_known_and_unknown(ctx) -> None:
    good = await catalog_tools.describe_call(ctx, "chm", "get", "channel")
    assert good["data"]["mutates"] is False
    assert "params_example" in good["data"]

    bad = await catalog_tools.describe_call(ctx, "chm", "get", "channl")
    assert bad["error"]["code"] == "NOT_FOUND"
    assert {"module": "chm", "method": "get", "key": "channel"} in bad["error"]["details"][
        "nearest"
    ]


# ---- nvr_call: reads --------------------------------------------------------


async def test_nvr_call_get_sends_exact_body(ctx, fake) -> None:
    fake.api_handler = _ok_handler
    result = await raw.nvr_call(ctx, "chm", "get", "channel", {"display": "x"})
    assert result["success"] is True
    # CI-F1 fix: the name-list get wraps the key; display merges alongside it.
    assert fake.api_requests[-1][1] == {
        "method": "get",
        "chm": {"name": ["channel"], "display": "x"},
    }


async def test_nvr_call_unknown_combo_offers_three_nearest(ctx, fake) -> None:
    result = await raw.nvr_call(ctx, "chm", "get", "channl")
    assert result["error"]["code"] == "CALL_NOT_FOUND"
    assert len(result["error"]["details"]["nearest"]) == 3
    assert fake.requests == []


async def test_nvr_call_reply_is_redacted(ctx, fake) -> None:
    fake.api_handler = lambda t, b: {"error_code": 0, "x": {"password": "p", "stok": "s"}}
    result = await raw.nvr_call(ctx, "chm", "get", "channel")
    assert result["data"]["x"] == {"password": REDACTED, "stok": REDACTED}


# ---- nvr_call: write gating -------------------------------------------------


def _mutating_specs():
    cat = get_catalog()
    return [c for row in cat.modules() for c in cat.calls(row["name"]) if c.mutates]


async def test_every_mutating_spec_is_refused_without_gates_and_sends_nothing(ctx, fake) -> None:
    refused = 0
    for spec in _mutating_specs():
        result = await raw.nvr_call(ctx, spec.module, spec.method, spec.key)
        expected = "MODULE_DENIED" if spec.module in DENIED else "WRITE_REFUSED"
        assert result["error"]["code"] == expected, spec
        refused += 1
    assert refused == EXPECTED_MUTATING
    assert fake.requests == []  # not a single network call for any of them


async def test_nvr_call_mutating_needs_confirm_even_when_allowed(wctx, fake) -> None:
    spec = next(s for s in _mutating_specs() if s.module not in DENIED)
    result = await raw.nvr_call(wctx, spec.module, spec.method, spec.key)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_nvr_call_mutating_proceeds_with_both_gates(wctx, fake) -> None:
    fake.api_handler = _ok_handler
    spec = next(s for s in _mutating_specs() if s.module not in DENIED)
    result = await raw.nvr_call(wctx, spec.module, spec.method, spec.key, confirm_write=True)
    assert result["success"] is True
    assert fake.api_requests[-1][1]["method"] == spec.method


@pytest.mark.parametrize("module", ["login", "user_management", "USER_MANAGEMENT"])
async def test_nvr_call_denies_auth_modules(wctx, fake, module) -> None:
    result = await raw.nvr_call(wctx, module, "get", "anything", confirm_write=True)
    assert result["error"]["code"] == "MODULE_DENIED"
    assert fake.requests == []


# ---- nvr_call: dry-run ------------------------------------------------------


async def test_nvr_call_dry_run_returns_body_without_sending(dctx, fake) -> None:
    spec = next(s for s in _mutating_specs() if s.module not in DENIED)
    result = await raw.nvr_call(
        dctx, spec.module, spec.method, spec.key, {"a": 1}, confirm_write=True, allow_extra=True
    )
    assert result["data"]["dry_run"] is True
    # CI-F1 fix: an action (do/set/add/delete) call nests its params under the key.
    assert result["data"]["request"] == {
        "method": spec.method,
        spec.module: {spec.key: {"a": 1}},
    }
    assert fake.requests == []


# ---- nvr_call: param validation before any I/O ------------------------------


async def test_nvr_call_rejects_adversarial_params_before_io(wctx, fake) -> None:
    deep: dict = {"x": 1}
    for _ in range(10):
        deep = {"x": deep}
    cases = [
        {"x": "\x00nul"},
        {"x": "A" * 5000},
        {f"k{i}": 1 for i in range(10_001)},
        deep,
        {"bad key": 1},
    ]
    for params in cases:
        result = await raw.nvr_call(wctx, "chm", "get", "channel", params, allow_extra=True)
        assert result["error"]["code"] == "INVALID_INPUT", params
    assert fake.requests == []


async def test_nvr_call_unknown_key_without_allow_extra(ctx, fake) -> None:
    result = await raw.nvr_call(ctx, "chm", "get", "channel", {"not_a_field": 1})
    assert result["error"]["code"] == "INVALID_INPUT"
    assert "allow_extra" in result["error"]["message"]
    assert fake.requests == []


# ---- the whole catalog is reachable through one fake transport --------------


async def test_every_catalogued_call_is_reachable(wctx, fake) -> None:
    fake.api_handler = _ok_handler
    cat = get_catalog()
    reachable = 0
    for row in cat.modules():
        for spec in cat.calls(row["name"]):
            result = await raw.nvr_call(
                wctx, spec.module, spec.method, spec.key, confirm_write=True
            )
            if spec.module in DENIED:
                assert result["error"]["code"] == "MODULE_DENIED"
                continue
            assert result["success"] is True, (spec, result)
            assert fake.api_requests[-1][1]["method"] == spec.method
            reachable += 1
    denied = sum(len(cat.calls(m)) for m in DENIED if m in {r["name"] for r in cat.modules()})
    assert reachable == EXPECTED_CALLS - denied


# ---- nvr_raw_call (off-catalog) ---------------------------------------------


async def test_raw_call_logs_warning_and_sends_get(ctx, fake, caplog) -> None:
    fake.api_handler = _ok_handler
    with caplog.at_level(logging.WARNING, logger="vigi_nvr_mcp.tools.raw"):
        result = await raw.nvr_raw_call(ctx, "get", "some_uncatalogued_module", {"a": 1})
    assert result["success"] is True
    assert any("bypassing the catalog" in r.message for r in caplog.records)
    assert fake.api_requests[-1][1] == {"method": "get", "some_uncatalogued_module": {"a": 1}}


async def test_raw_call_dry_run(dctx, fake) -> None:
    result = await raw.nvr_raw_call(dctx, "set", "whatever", {"a": 1}, confirm_write=True)
    assert result["data"]["dry_run"] is True
    assert result["data"]["request"] == {"method": "set", "whatever": {"a": 1}}
    assert fake.requests == []
