"""NVR storage read tools (harddisk_manage). Reply shapes are firmware-specific,
so the redacted raw reply is returned under ``data``."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import ToolContext, run_tool


async def list_disks(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_list_disks", ctx.client.list_disks)


async def get_recording_status(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_get_recording_status", ctx.client.get_recording_status)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_list_disks")
    async def _disks() -> dict[str, Any]:
        """Installed hard disks and their state (read-only, raw reply)."""
        return await list_disks(ctx)

    @mcp.tool(name="nvr_get_recording_status")
    async def _recording() -> dict[str, Any]:
        """Recording / storage policy status (read-only, raw reply)."""
        return await get_recording_status(ctx)

    return ["nvr_list_disks", "nvr_get_recording_status"]
