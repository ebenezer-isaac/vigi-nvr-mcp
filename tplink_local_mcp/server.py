"""Server bootstrap: discover configured backends and build the FastMCP app.

A backend whose ``<PREFIX>HOST`` is unset is not registered (logged at startup).
A backend whose settings are present but invalid aborts startup (fail fast).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .core.backend import DeviceBackend
from .core.config import GlobalSettings
from .core.envelope import ok
from .devices import all_backends

log = logging.getLogger(__name__)

INSTRUCTIONS = (
    "Local tools for TP-Link devices. Tools are prefixed by device: nvr_ (VIGI NVR), "
    "router_ (Archer), switch_ (Easy Smart). Call tplink_status to see which devices "
    "are configured. Reads are safe. Writes need the server's <PREFIX>ALLOW_WRITES=true "
    "AND confirm_write=true; confirm with the operator first. Never retry a failed "
    "login: the devices lock the admin account after repeated failures."
)


@dataclass(frozen=True)
class Discovery:
    configured: tuple[DeviceBackend, ...]
    skipped: tuple[DeviceBackend, ...]


def discover_backends(
    environ: Mapping[str, str], candidates: Sequence[DeviceBackend] | None = None
) -> Discovery:
    configured: list[DeviceBackend] = []
    skipped: list[DeviceBackend] = []
    for backend in candidates if candidates is not None else all_backends():
        if backend.is_configured(environ):
            configured = [*configured, backend.configure(environ)]
            log.info("backend %s configured (%sHOST set)", backend.name, backend.settings_prefix)
        else:
            skipped = [*skipped, backend]
            log.info(
                "backend %s not configured (%sHOST unset); skipping",
                backend.name,
                backend.settings_prefix,
            )
    return Discovery(configured=tuple(configured), skipped=tuple(skipped))


async def status_report(discovery: Discovery, tools: Mapping[str, list[str]]) -> dict[str, Any]:
    backends = []
    for backend in discovery.configured:
        backends.append(
            {
                "name": backend.name,
                "configured": True,
                "tool_prefix": backend.tool_prefix,
                "tools": list(tools.get(backend.name, [])),
                "health": await backend.healthcheck(),
            }
        )
    for backend in discovery.skipped:
        backends.append(
            {
                "name": backend.name,
                "configured": False,
                "tool_prefix": backend.tool_prefix,
                "hint": f"set {backend.settings_prefix}HOST to enable",
            }
        )
    return ok({"version": __version__, "backends": backends})


def build_server(settings: GlobalSettings, discovery: Discovery) -> FastMCP:
    mcp = FastMCP(
        name="tplink-local-mcp",
        instructions=INSTRUCTIONS,
        host=settings.mcp_host,
        port=settings.mcp_port,
    )
    tools: dict[str, list[str]] = {}
    for backend in discovery.configured:
        tools = {**tools, backend.name: backend.register_tools(mcp)}

    @mcp.tool(name="tplink_status")
    async def _status() -> dict[str, Any]:
        """Which device backends are configured, their tools, and a healthcheck for
        each. Healthchecks never log in (NVR: pre-auth challenge only)."""
        return await status_report(discovery, tools)

    return mcp
