"""Breaker round 2 — vector write-gate-central.

F2: the round-2 claim says "``InvalidInput`` is the only error mapped to
``INVALID_INPUT``". The fixer hardened the *shared* wrapper ``run_tool`` to honour
that (``DeviceError`` by ``kind``; any other exception -> ``INTERNAL_ERROR`` with no
internals). But the per-tool ``except ValueError`` blocks in ``tools/raw.py`` were
left untouched, and they catch *any* ``ValueError`` — not just ``InvalidInput``.

``catalog.validate_params`` sizes strings with ``obj.encode("utf-8")``. A lone
UTF-16 surrogate (e.g. ``chr(0xD800)``) makes that raise ``UnicodeEncodeError`` — a
plain ``ValueError`` that is NOT an ``InvalidInput``. In ``nvr_raw_call``/``nvr_call``
it is caught by ``except ValueError`` and returned as
``{code: INVALID_INPUT, message: "<raw codec error incl. character position>"}``:

  * a non-``InvalidInput`` error is mapped to ``INVALID_INPUT`` (claim false), and
  * the internal codec message is leaked to the client (Master-Plan 1.8 /
    security: "error messages don't leak internals").

Lone surrogates survive a real MCP round-trip: ``json.loads('"\\ud800"')`` yields
the surrogate, so an LLM-supplied params value reaches this path (adversary-read).
No device I/O occurs. The assertions encode the claim and FAIL against current code.
"""

from __future__ import annotations

import json

import pytest

from tests.helpers import FakeNvr, nvr_env

# Lone high surrogate; valid in a Python/JSON string, not encodable as UTF-8.
# Built with chr() so this source file itself stays UTF-8 encodable.
SURROGATE = chr(0xD800)


def _no_leak(message: str) -> bool:
    low = message.lower()
    return "codec" not in low and "surrogate" not in low and "position" not in low


async def test_surrogate_param_not_mislabeled_and_no_leak_inner(make_ctx, fake: FakeNvr) -> None:
    """Inner function: a UnicodeEncodeError must not surface as INVALID_INPUT+leak."""
    from vigi_nvr_mcp.tools import raw

    ctx = make_ctx(ALLOW_WRITES="true")
    result = await raw.nvr_raw_call(ctx, "get", "system", {"k": SURROGATE})

    assert fake.api_requests == [], "a surrogate param must be rejected before any I/O"
    msg = result.get("error", {}).get("message", "")
    assert _no_leak(msg), (
        "internal codec error leaked to the client in an INVALID_INPUT envelope: " + repr(msg)
    )


async def test_surrogate_param_via_real_mcp_boundary(fake: FakeNvr) -> None:
    """Same path through the registered FastMCP tool (not the inner function).

    A lone surrogate crosses the JSON boundary intact, so this is the exact shape
    an LLM client can send.
    """
    from vigi_nvr_mcp.backend import NvrBackend
    from vigi_nvr_mcp.core.config import load_global_settings
    from vigi_nvr_mcp.server import MCP_ENV_PREFIX, build_server

    fake.api_handler = lambda t, b: {"error_code": 0}
    backend = NvrBackend.from_env(nvr_env(ALLOW_WRITES="true"), http_transport=fake.transport())
    mcp, _ = build_server(load_global_settings(MCP_ENV_PREFIX, {}), backend)

    raw_result = await mcp.call_tool(
        "nvr_raw_call", {"method": "get", "module": "system", "params": {"k": SURROGATE}}
    )
    structured = raw_result[1] if isinstance(raw_result, tuple) else raw_result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if not (isinstance(structured, dict) and "success" in structured):
        content = raw_result[0] if isinstance(raw_result, tuple) else raw_result
        structured = json.loads(content[0].text)

    msg = structured.get("error", {}).get("message", "")
    assert _no_leak(msg), (
        "internal codec error leaked through the registered nvr_raw_call tool: " + repr(msg)
    )
