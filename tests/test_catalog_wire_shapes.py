"""CI-F1: the catalog gateway reproduces the firmware's verified wire bodies.

Every (module, method, key) in the vendored inventory carries a :class:`shape`
that decides how the key wraps onto the wire. These tests pin the gateway
(``nvr_call``) and ``build_body`` to the VERIFIED firmware captures in
``discovery/channel-management.md`` and to representative request shapes extracted
from ``discovery/_tools/raw-calls.json`` (sanitised). If a shape regresses, a
catalogued call would go on the wire malformed; these catch it.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.catalog import get_catalog
from vigi_nvr_mcp.tools import raw

# (module, method, key, inner_params, verified_full_wire_body, mutating)
#
# gets: the key is the section/table read, so inner params are None and the body
# is fully determined by the shape. actions: inner params nest under the key.
# Sources: channel-management.md ("VERIFIED") and raw-calls.json request shapes.
VERIFIED_WIRE: list[tuple[str, str, str, dict[str, Any] | None, dict[str, Any], bool]] = [
    # chm added_dev is a table get (channel-management.md: {"chm":{"table":"added_dev"}})
    ("chm", "get", "added_dev", None, {"method": "get", "chm": {"table": "added_dev"}}, False),
    # upnpc/network/protocol upnp_status: table gets (raw-calls: ["table"]="upnp_status")
    (
        "upnpc",
        "get",
        "upnp_status",
        None,
        {"method": "get", "upnpc": {"table": "upnp_status"}},
        False,
    ),
    # function module_spec: scalar-name get (raw-calls: ["name"]="module_spec")
    (
        "function",
        "get",
        "module_spec",
        None,
        {"method": "get", "function": {"name": "module_spec"}},
        False,
    ),
    # device_info basic_info: scalar-name get (raw-calls evidence)
    (
        "device_info",
        "get",
        "basic_info",
        None,
        {"method": "get", "device_info": {"name": "basic_info"}},
        False,
    ),
    # chm delete-by-id, batched under the action key (channel-management.md VERIFIED)
    (
        "chm",
        "do",
        "chm_del_dev",
        {"ids": ["1", "2"]},
        {"method": "do", "chm": {"chm_del_dev": {"ids": ["1", "2"]}}},
        True,
    ),
    # chm move/replace channel (channel-management.md VERIFIED)
    (
        "chm",
        "do",
        "chm_mod_dev_chn",
        {"old_id": "9", "new_id": "1"},
        {"method": "do", "chm": {"chm_mod_dev_chn": {"old_id": "9", "new_id": "1"}}},
        True,
    ),
]


@pytest.mark.parametrize(
    ("module", "method", "key", "inner", "wire", "mutating"),
    VERIFIED_WIRE,
    ids=[f"{m}/{meth}/{k}" for m, meth, k, _, _, _ in VERIFIED_WIRE],
)
def test_build_body_matches_verified_wire(module, method, key, inner, wire, mutating) -> None:
    cat = get_catalog()
    spec = cat.find(module, method, key)
    assert cat.build_body(spec, inner, allow_extra=True) == wire


@pytest.mark.parametrize(
    ("module", "method", "key", "inner", "wire", "mutating"),
    VERIFIED_WIRE,
    ids=[f"{m}/{meth}/{k}" for m, meth, k, _, _, _ in VERIFIED_WIRE],
)
async def test_nvr_call_emits_verified_wire(
    make_ctx, fake: FakeNvr, module, method, key, inner, wire, mutating
) -> None:
    ctx = make_ctx(ALLOW_WRITES="true") if mutating else make_ctx()
    captured: list[dict[str, Any]] = []
    fake.api_handler = lambda _t, body: captured.append(body) or {"error_code": 0}
    result = await raw.nvr_call(ctx, module, method, key, inner, confirm_write=mutating)
    assert result["success"] is True, result
    assert captured[-1] == wire


async def test_describe_shows_the_full_wire_example(ctx) -> None:
    """nvr_describe_call's wire_example carries the action-key wrapper verbatim."""
    from vigi_nvr_mcp.tools import catalog as catalog_tools

    res = await catalog_tools.describe_call(ctx, "chm", "do", "chm_mod_dev_chn")
    example = res["data"]["wire_example"]
    assert set(example["chm"]) == {"chm_mod_dev_chn"}, example
    assert example["method"] == "do"
