"""Build the FastMCP app for one NVR."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .backend import NvrBackend
from .catalog import validate_catalogs
from .core.config import GlobalSettings
from .core.envelope import fail, ok

log = logging.getLogger(__name__)

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
    validate_catalogs()  # fail loudly at startup if a vendored catalog is corrupt
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
        # Same safety net as run_tool: a non-DeviceError must never raise into the
        # MCP framework. CancelledError (BaseException) is left to propagate.
        try:
            health = await backend.healthcheck()
            return ok({"version": __version__, "health": health}) if health["success"] else health
        except Exception:
            log.exception("%s raised an unexpected error", STATUS_TOOL)
            return fail("INTERNAL_ERROR", "Unexpected server error; see server logs.")

    return mcp, [*names, STATUS_TOOL]
