"""Breaker r1 / catalog-gateway — F1: param validation crashes on nested input.

The claim: "params are rejected *before I/O* when they exceed depth 6 ... "
and (Master Plan invariant #5) "Never raise out of a tool".

The only param check that exists today is ``validate_call`` in ``client.py``:
``len(repr(params)) > 64 KiB``. ``repr()`` recurses, so a deeply-nested (but
tiny) params object raises ``RecursionError`` out of the gateway instead of
returning an ``{success, data, error}`` envelope. This is reachable by any MCP
client that controls the ``params`` argument (adversary goal: the argument is
attacker-supplied JSON), and the 64 KiB guard does not catch it because the
object is small.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.client import validate_call
from vigi_nvr_mcp.tools import raw


def _nest(depth: int) -> dict:
    root: dict = {}
    cur = root
    for _ in range(depth):
        nxt: dict = {}
        cur["a"] = nxt
        cur = nxt
    return root


async def test_nested_params_return_envelope_not_recursionerror(make_ctx, fake) -> None:
    ctx = make_ctx()
    deep = _nest(3000)  # ~48 KiB of repr, well under the 64 KiB guard
    try:
        # RECONCILED (N1->N2): the N1 generic gateway is now nvr_raw_call.
        result = await raw.nvr_raw_call(ctx, "get", "system", deep)
    except RecursionError:
        pytest.fail(
            "nvr_call raised RecursionError out of the tool (violates 'never raise "
            "out of a tool'); validate_call's len(repr(params)) guard recurses."
        )
    # A correct gateway rejects over-deep params as INVALID_INPUT before any I/O.
    assert result["success"] is False
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


def test_validate_call_crashes_on_depth_bomb() -> None:
    # Same root cause at the shared validator every typed tool funnels through.
    with pytest.raises(ValueError):
        # A depth-limited validator would raise ValueError ("too deep"); today it
        # raises RecursionError instead, so this assertion fails.
        validate_call("get", "system", _nest(4000))
