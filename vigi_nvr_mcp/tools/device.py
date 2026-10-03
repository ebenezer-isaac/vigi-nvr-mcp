"""Session and device read tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..envelope import ok
from . import ToolContext, run_tool


async def nvr_login(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_login", ctx.client.login)


async def nvr_auth_status(ctx: ToolContext) -> dict[str, Any]:
    return ok(ctx.client.auth.status())


async def get_device_info(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("get_device_info", ctx.client.get_device_info)


async def get_module_spec(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("get_module_spec", ctx.client.get_module_spec)


async def get_system_info(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("get_system_info", ctx.client.get_system)


async def get_network_info(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("get_network_info", ctx.client.get_network)


async def get_video_resolutions(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("get_video_resolutions", ctx.client.get_video_resolutions)


def register(app: FastMCP, ctx: ToolContext) -> None:
    @app.tool(name="nvr_login")
    async def _login() -> dict[str, Any]:
        """Explicitly log in to the NVR (exactly one attempt, never retried).

        Normally unnecessary: the first tool call logs in. After any failed login,
        automatic logins stop; fix the cause before calling this. If the server's
        failure budget is spent it refuses until restarted.
        """
        return await nvr_login(ctx)

    @app.tool(name="nvr_auth_status")
    async def _status() -> dict[str, Any]:
        """Session state: authenticated?, failed logins this process, last failure
        counters (failed_attempts/max_attempts) and whether login is frozen. No I/O."""
        return await nvr_auth_status(ctx)

    @app.tool(name="get_device_info")
    async def _device_info() -> dict[str, Any]:
        """Model, firmware and basic device information (read-only)."""
        return await get_device_info(ctx)

    @app.tool(name="get_module_spec")
    async def _module_spec() -> dict[str, Any]:
        """Capability/module specification advertised by the firmware (read-only)."""
        return await get_module_spec(ctx)

    @app.tool(name="get_system_info")
    async def _system() -> dict[str, Any]:
        """System settings such as time and maintenance info (read-only)."""
        return await get_system_info(ctx)

    @app.tool(name="get_network_info")
    async def _network() -> dict[str, Any]:
        """NVR network configuration (read-only)."""
        return await get_network_info(ctx)

    @app.tool(name="get_video_resolutions")
    async def _resolutions() -> dict[str, Any]:
        """Supported video resolutions (read-only)."""
        return await get_video_resolutions(ctx)
