"""NVR session and device read tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ....core.envelope import ok
from . import ToolContext, run_tool


async def nvr_login(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_login", ctx.client.login)


async def nvr_auth_status(ctx: ToolContext) -> dict[str, Any]:
    return ok(ctx.client.auth.status())


async def get_device_info(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_get_device_info", ctx.client.get_device_info)


async def get_module_spec(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_get_module_spec", ctx.client.get_module_spec)


async def get_system_info(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_get_system_info", ctx.client.get_system)


async def get_network_info(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_get_network_info", ctx.client.get_network)


async def get_video_resolutions(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_get_video_resolutions", ctx.client.get_video_resolutions)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_login")
    async def _login() -> dict[str, Any]:
        """Explicitly log in to the NVR (exactly one attempt, never retried).

        Normally unnecessary: the first NVR tool call logs in. After any failed
        login, automatic logins stop; fix the cause before calling this. Once the
        server's failure budget is spent it refuses until restarted.
        """
        return await nvr_login(ctx)

    @mcp.tool(name="nvr_auth_status")
    async def _status() -> dict[str, Any]:
        """NVR session state: authenticated, failed logins this process, the last
        failure's lockout counters and whether login is frozen. No network I/O."""
        return await nvr_auth_status(ctx)

    @mcp.tool(name="nvr_get_device_info")
    async def _device_info() -> dict[str, Any]:
        """NVR model, firmware and identity (read-only)."""
        return await get_device_info(ctx)

    @mcp.tool(name="nvr_get_module_spec")
    async def _module_spec() -> dict[str, Any]:
        """Capability spec: max channels, codecs, feature flags (read-only)."""
        return await get_module_spec(ctx)

    @mcp.tool(name="nvr_get_system_info")
    async def _system() -> dict[str, Any]:
        """System basics such as device name, time zone and session timeout (read-only)."""
        return await get_system_info(ctx)

    @mcp.tool(name="nvr_get_network_info")
    async def _network() -> dict[str, Any]:
        """NVR network configuration (read-only)."""
        return await get_network_info(ctx)

    @mcp.tool(name="nvr_get_video_resolutions")
    async def _resolutions() -> dict[str, Any]:
        """Main/minor stream resolution tables (read-only)."""
        return await get_video_resolutions(ctx)

    return [
        "nvr_login",
        "nvr_auth_status",
        "nvr_get_device_info",
        "nvr_get_module_spec",
        "nvr_get_system_info",
        "nvr_get_network_info",
        "nvr_get_video_resolutions",
    ]
