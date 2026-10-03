"""Breaker r1 / config-cli-server — F5.

Claim under attack: "every registered tool returns a {success,data,error}
envelope and never raises into the MCP framework, including on ... cancelled
tasks".

``core.tooling.run_tool`` catches ``Exception`` but ``asyncio.CancelledError``
is a ``BaseException`` (since Python 3.8), so it (and ``KeyboardInterrupt``)
propagate out of every tool rather than becoming an envelope.

Note for the orchestrator: re-raising CancelledError is in fact the correct
cooperative-cancellation behaviour; this test witnesses that the *claim* is
over-broad, not that suppressing CancelledError would be desirable.
"""

from __future__ import annotations

import asyncio

from vigi_nvr_mcp.core.tooling import run_tool


async def test_run_tool_returns_envelope_on_cancelled_task() -> None:
    async def cancelled() -> None:
        raise asyncio.CancelledError()

    envelope = await run_tool("nvr_demo", cancelled)
    # The claim says a cancelled task still yields an envelope. It does not;
    # the await above re-raises CancelledError before this assertion is reached.
    assert envelope["success"] is False
    assert envelope["error"]["code"] == "INTERNAL_ERROR"
