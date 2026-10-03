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

import pytest

from vigi_nvr_mcp.core.tooling import run_tool


async def test_run_tool_propagates_cancelled_task() -> None:
    # WON'T-FIX per orchestrator decision CC-F5 (fixer brief): re-raising
    # CancelledError is the correct cooperative-cancellation behaviour; swallowing
    # it into an envelope would itself be a bug. The claim was over-broad. This
    # test is inverted to assert that run_tool lets CancelledError propagate.
    async def cancelled() -> None:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await run_tool("nvr_demo", cancelled)
