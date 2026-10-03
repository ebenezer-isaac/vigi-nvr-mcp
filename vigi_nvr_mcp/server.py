"""Build the FastMCP app for one NVR."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .backend import NvrBackend
from .core.config import GlobalSettings
from .core.envelope import ok

MCP_ENV_PREFIX = "VIGI_MCP_"
STATUS_TOOL = "nvr_status"

INSTRUCTIONS = (
    "Tools for one local TP-Link VIGI NVR, all prefixed nvr_. Call nvr_status first. "
    "Reads are safe. Writes need the server's VIGI_NVR_ALLOW_WRITES=true AND "
    "confirm_write=true on the call; confirm with the operator first and run "
    "nvr_backup_config before any channel cleanup. Never retry a failed login: the "
    "NVR locks the admin account after repeated failures."
)


def build_server(settings: GlobalSettings, backend: NvrBackend) -> tuple[FastMCP, list[str]]:
    """Return the app and the names of every tool it registers."""
    mcp = FastMCP(
        name="vigi-nvr-mcp",
        instructions=INSTRUCTIONS,
        host=settings.mcp_host,
        port=settings.mcp_port,
    )
    names = backend.register_tools(mcp)

    @mcp.tool(name=STATUS_TOOL)
    async def _status() -> dict[str, Any]:
        """Healthcheck: reachability, offered auth scheme, the device's lockout
        counters, local session state and safety policy. Never logs in."""
        health = await backend.healthcheck()
        return ok({"version": __version__, "health": health}) if health["success"] else health

    return mcp, [*names, STATUS_TOOL]
