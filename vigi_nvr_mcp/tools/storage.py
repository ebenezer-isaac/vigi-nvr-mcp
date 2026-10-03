"""Storage read tools (harddisk_manage). Reply shapes are firmware-specific, so
the redacted raw reply is returned under ``data``."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import ToolContext, run_tool


async def list_disks(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("list_disks", ctx.client.list_disks)


async def get_recording_status(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("get_recording_status", ctx.client.get_recording_status)


def register(app: FastMCP, ctx: ToolContext) -> None:
    @app.tool(name="list_disks")
    async def _disks() -> dict[str, Any]:
        """Installed hard disks and their state (read-only, raw reply)."""
        return await list_disks(ctx)

    @app.tool(name="get_recording_status")
    async def _recording() -> dict[str, Any]:
        """Recording / storage status (read-only, raw reply)."""
        return await get_recording_status(ctx)
