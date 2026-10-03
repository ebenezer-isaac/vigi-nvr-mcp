"""The DeviceBackend interface and a base for backends awaiting protocol discovery."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from mcp.server.fastmcp import FastMCP

from .config import DeviceSettings, host_is_set, load_device_settings
from .envelope import fail

log = logging.getLogger(__name__)


@runtime_checkable
class DeviceBackend(Protocol):
    """One device family.

    A backend is created unconfigured; ``configure(environ)`` validates its
    ``<settings_prefix>*`` variables and returns a NEW configured instance.
    ``healthcheck`` must never attempt a login (lockout risk).
    """

    name: str
    settings_prefix: str
    tool_prefix: str

    def is_configured(self, environ: Mapping[str, str]) -> bool: ...

    def configure(self, environ: Mapping[str, str]) -> DeviceBackend: ...

    def register_tools(self, mcp: FastMCP) -> list[str]: ...

    async def healthcheck(self) -> dict[str, Any]: ...

    async def aclose(self) -> None: ...


class PendingBackend:
    """Scaffold for a device family whose protocol has not been captured yet.

    It validates its settings (so typos fail fast) but registers no tools and
    reports NOT_IMPLEMENTED from its healthcheck. It never contacts the device.
    """

    name = "pending"
    settings_prefix = "TPLINK_PENDING_"
    tool_prefix = "pending_"
    description = "pending protocol discovery"

    def __init__(self, settings: DeviceSettings | None = None) -> None:
        self.settings = settings

    def is_configured(self, environ: Mapping[str, str]) -> bool:
        return host_is_set(self.settings_prefix, environ)

    def configure(self, environ: Mapping[str, str]) -> PendingBackend:
        return type(self)(load_device_settings(self.settings_prefix, environ))

    def register_tools(self, mcp: FastMCP) -> list[str]:
        log.warning(
            "%s backend is configured but %s; no %s* tools registered",
            self.name,
            self.description,
            self.tool_prefix,
        )
        return []

    async def healthcheck(self) -> dict[str, Any]:
        return fail(
            "NOT_IMPLEMENTED",
            f"The {self.name} backend is a scaffold ({self.description}). "
            "No request was sent to the device.",
        )

    async def aclose(self) -> None:
        return None
