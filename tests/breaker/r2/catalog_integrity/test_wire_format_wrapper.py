"""Breaker r2 — vector catalog-integrity — F1: the gateway's wire body drops the
catalogued action-key wrapper.

The N2 promise is that "every one of the 586 calls becomes reachable, validated and
write-gated through one gateway". A call is identified by (module, method, key); the
device dispatches a ``do``/``set``/``add``/``delete`` call by nesting its parameters
UNDER the action key, e.g. the VERIFIED capture (discovery/channel-management.md):

    {"method":"do","chm":{"chm_mod_dev_chn":{"old_id":"9","new_id":"1"}}}
    {"method":"do","chm":{"chm_del_dev":{"ids":["1","2"]}}}

``build_body`` builds ``{"method": spec.method, spec.module: params}`` and never
references ``spec.key``; every one of the 363 non-null ``params_example`` values
also omits the key wrapper. So following the catalog's own ``nvr_describe_call``
output produces a body with the action-key level MISSING, and — because the
unknown-top-level-key check is keyed off ``params_example`` — passing the CORRECT
wrapped body is rejected by default. Either way a catalogued mutating call cannot
be issued correctly through the generic gateway using the catalog's metadata.

Live run is the final judge (per the brief); the evidence here is the VERIFIED
firmware capture plus the deterministic body the gateway emits against a fake NVR.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.catalog import get_catalog
from vigi_nvr_mcp.core.errors import InvalidInput
from vigi_nvr_mcp.tools import raw

# VERIFIED firmware wire bodies (discovery/channel-management.md, "VERIFIED").
VERIFIED_MOVE = {"method": "do", "chm": {"chm_mod_dev_chn": {"old_id": "9", "new_id": "1"}}}


async def test_catalogued_mutating_call_matches_verified_wire(make_ctx, fake: FakeNvr) -> None:
    """nvr_call for chm/do/chm_mod_dev_chn, params in the catalog's example shape,
    must put the move params under the ``chm_mod_dev_chn`` key on the wire.

    It does not: the action-key level is dropped, so the device would never see a
    ``chm_mod_dev_chn`` request.
    """
    ctx = make_ctx(ALLOW_WRITES="true")
    captured: list[dict[str, Any]] = []
    fake.api_handler = lambda _tok, body: (captured.append(body) or {"error_code": 0})

    # The catalog's params_example for this call is {"old_id","new_id"} — follow it.
    await raw.nvr_call(
        ctx, "chm", "do", "chm_mod_dev_chn", {"old_id": "9", "new_id": "1"}, confirm_write=True
    )

    assert captured, "no request reached the device"
    assert captured[-1] == VERIFIED_MOVE, (
        "gateway body does not match the VERIFIED firmware capture; the "
        f"chm_mod_dev_chn action wrapper was dropped:\n sent    : {json.dumps(captured[-1])}\n "
        f"verified: {json.dumps(VERIFIED_MOVE)}"
    )


def test_correct_wrapped_body_is_not_rejected() -> None:
    """Passing the device-correct body (wrapper included) must be accepted.

    Instead build_body rejects it as an 'unknown parameter', because params_example
    lists the inner fields (old_id/new_id), not the action key.
    """
    cat = get_catalog()
    spec = cat.find("chm", "do", "chm_mod_dev_chn")
    try:
        body = cat.build_body(spec, {"chm_mod_dev_chn": {"old_id": "9", "new_id": "1"}})
    except InvalidInput as exc:  # pragma: no cover - this is the bug being shown
        pytest.fail(
            "the device-correct wrapped body was rejected by build_body "
            f"(so the only accepted shape is the wrong one): {exc}"
        )
    assert body == VERIFIED_MOVE, f"unexpected body: {json.dumps(body)}"


def test_every_example_round_trips_through_its_key() -> None:
    """For every catalogued call with a dict params_example, the example must be a
    body the gateway can send verbatim AND whose structure names the call's key.

    All 363 non-null examples omit the key, so none of them round-trips: the body
    the gateway emits for a ``do``/``set``/``add``/``delete`` call never contains the
    action key the firmware dispatches on.
    """
    cat = get_catalog()
    offenders: list[str] = []
    checked = 0
    for spec in cat._index.values():  # noqa: SLF001 - inventory introspection
        if spec.method == "get" or not isinstance(spec.params_example, dict):
            continue
        checked += 1
        body = cat.build_body(spec, spec.params_example, allow_extra=True)
        module_body = body[spec.module]
        # A correctly-formed action body nests everything under the action key.
        if not (isinstance(module_body, dict) and set(module_body) == {spec.key}):
            offenders.append(f"{spec.module}/{spec.method}/{spec.key}")
    assert checked > 0
    assert not offenders, (
        f"{len(offenders)}/{checked} mutating-style calls build a body that does not "
        f"nest under the action key (first 5: {offenders[:5]})"
    )
