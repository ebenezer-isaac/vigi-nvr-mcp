"""Breaker r1 / catalog-gateway — Spec-N2 guarantees that are simply ABSENT.

At commit db9f786 (``refactor: standalone vigi-nvr-mcp layout``) the N2 "catalog
gateway" is not built: ``catalog.py`` is an error-code map only (no
``endpoints.json``, no ``Catalog.load`` / ``CallSpec`` / ``find`` / ``build_body``),
and ``nvr_call`` validates with ``client.validate_call`` (method in a 5-set,
module regex, params is dict/None, ``len(repr)`` <= 64 KiB) — nothing else.

These tests encode the CLAIMED guarantees so they fail here; they are catalogued
under "Not yet implemented (spec N2)" in FINDINGS.md rather than as defects of
existing code. They are kept so the fixer/builder sees the exact acceptance.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.tools import raw


# NI1 — unknown (module, method, key) refused with NO network call ----------------
async def test_unknown_module_is_refused_without_io(make_ctx, fake) -> None:
    ctx = make_ctx()
    result = await raw.nvr_call(ctx, "get", "totally_bogus_module_zzz", {"q": 1})
    # Claim: unknown combinations refused with no network call.
    assert result["success"] is False, "unknown module was accepted and executed"
    assert fake.requests == [], (
        f"unknown module reached the device: {[b for _, b in fake.api_requests]}"
    )


# NI2 — param limits: depth<=6, <=200 keys, strings<=4KiB, key charset, control chars
@pytest.mark.parametrize(
    ("label", "params"),
    [
        ("depth>6", {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}),
        ("200+ keys", {f"k{i}": 1 for i in range(300)}),
        ("4KiB+ string", {"s": "x" * 5000}),
        ("control char in value", {"s": "a\x00b"}),
        ("key outside [A-Za-z0-9_.-]", {"__proto__": 1}),
        ("newline in key", {"a\nb": 1}),
        ("unicode homoglyph key", {"аdmin": 1}),  # Cyrillic 'а'
    ],
)
async def test_param_boundaries_rejected_before_io(make_ctx, fake, label, params) -> None:
    ctx = make_ctx()
    result = await raw.nvr_call(ctx, "get", "system", params)
    assert result["error"] is not None and result["error"]["code"] == "INVALID_INPUT", (
        f"[{label}] accepted by the gateway: {result}"
    )
    assert fake.requests == [], f"[{label}] reached the device"


# NI3 — the catalog/introspection surface the claim and spec N2 require ------------
def test_catalog_gateway_surface_exists() -> None:
    import vigi_nvr_mcp.catalog as cat

    missing = [
        name
        for name in ("Catalog", "CallSpec", "load", "find", "build_body", "modules", "calls")
        if not hasattr(cat, name)
    ]
    assert missing == [], f"catalog.py is missing the N2 gateway surface: {missing}"
