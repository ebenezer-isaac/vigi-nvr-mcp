"""High-level NVR client: generic ``call`` plus typed read helpers.

Only the envelope (``{"method": ..., "<module>": {...}}``) and the auth flow are
verified against real firmware. The module/parameter bodies in ``READ_QUERIES``
follow TP-Link's usual conventions but are UNVERIFIED for VIGI NVRs; they are
kept in one table so they can be corrected from a capture without touching
anything else. ``nvr_call`` remains the escape hatch for any other query.
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any

from .auth import Authenticator
from .config import Settings
from .errors import NvrTokenExpired
from .transport import NvrTransport

METHODS = frozenset({"get", "set", "do", "add", "delete"})
MODULE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
MAX_PARAM_BYTES = 64 * 1024

# name -> (method, module, params). UNVERIFIED shapes; see module docstring.
READ_QUERIES: MappingProxyType[str, tuple[str, str, dict[str, Any]]] = MappingProxyType(
    {
        "device_info": ("get", "device_info", {"name": ["basic_info"]}),
        "module_spec": ("get", "function", {"name": ["module_spec"]}),
        "channels": ("get", "channel_manage", {"table": ["channel_list"]}),
        "video_resolutions": ("get", "video", {"name": ["resolution_list"]}),
        "disks": ("get", "harddisk_manage", {"table": ["hd_info"]}),
        "recording_status": ("get", "harddisk_manage", {"name": ["harddisk"]}),
        "network": ("get", "network", {"name": ["lan"]}),
        "system": ("get", "system", {"name": ["basic"]}),
    }
)

# TODO(channel-delete): the discovery agent will document the primitive used by
# the vendor UI to delete/move a channel. Fill this with (method, module) and a
# params builder, then wire tools/channels.py::remove_channel to it.
CHANNEL_DELETE_PRIMITIVE: tuple[str, str] | None = None


def validate_call(method: str, module: str, params: Any) -> None:
    if method not in METHODS:
        raise ValueError(f"method must be one of {sorted(METHODS)}")
    if not isinstance(module, str) or not MODULE_RE.fullmatch(module):
        raise ValueError("module must match ^[A-Za-z][A-Za-z0-9_]{0,63}$")
    if module == "method":
        raise ValueError("module must not be 'method'")
    if params is not None and not isinstance(params, dict):
        raise ValueError("params must be an object or null")
    if params is not None and len(repr(params)) > MAX_PARAM_BYTES:
        raise ValueError("params too large")


class NvrClient:
    def __init__(self, settings: Settings, transport: NvrTransport, auth: Authenticator) -> None:
        self.settings = settings
        self.auth = auth
        self._transport = transport

    async def aclose(self) -> None:
        await self._transport.aclose()

    async def login(self) -> dict[str, Any]:
        await self.auth.login()
        return self.auth.status()

    async def call(self, method: str, module: str, params: dict[str, Any] | None) -> dict[str, Any]:
        """Send one request; on token expiry re-authenticate once and resend once."""
        validate_call(method, module, params)
        body = {"method": method, module: params}
        token = await self.auth.token()
        try:
            return await self._transport.post_api(token, body)
        except NvrTokenExpired:
            await self.auth.invalidate(token)
        fresh = await self.auth.token()
        return await self._transport.post_api(fresh, body)

    async def query(self, name: str) -> dict[str, Any]:
        method, module, params = READ_QUERIES[name]
        return await self.call(method, module, params)

    async def get_device_info(self) -> dict[str, Any]:
        return await self.query("device_info")

    async def get_module_spec(self) -> dict[str, Any]:
        return await self.query("module_spec")

    async def get_video_resolutions(self) -> dict[str, Any]:
        return await self.query("video_resolutions")

    async def list_disks(self) -> dict[str, Any]:
        return await self.query("disks")

    async def get_recording_status(self) -> dict[str, Any]:
        return await self.query("recording_status")

    async def get_network(self) -> dict[str, Any]:
        return await self.query("network")

    async def get_system(self) -> dict[str, Any]:
        return await self.query("system")

    async def list_channels(self) -> list[dict[str, Any]]:
        """Channel rows (unredacted; callers must redact before exposing)."""
        return extract_rows(await self.query("channels"))


def _unwrap_row(item: Any) -> dict[str, Any] | None:
    """TP-Link tables often wrap each row as ``{"<row_key>": {...}}``."""
    if not isinstance(item, dict):
        return None
    if len(item) == 1:
        ((row_key, inner),) = item.items()
        if isinstance(inner, dict):
            return {"_row_key": row_key, **inner}
    return dict(item)


def extract_rows(reply: Any, *, marker: str = "uuid", _depth: int = 0) -> list[dict[str, Any]]:
    """Find the first list of row objects in which any row carries ``marker``."""
    if _depth > 16:
        return []
    if isinstance(reply, list):
        rows = [r for r in (_unwrap_row(i) for i in reply) if r is not None]
        if rows and any(marker in r for r in rows):
            return rows
        for item in reply:
            found = extract_rows(item, marker=marker, _depth=_depth + 1)
            if found:
                return found
        return []
    if isinstance(reply, dict):
        for value in reply.values():
            found = extract_rows(value, marker=marker, _depth=_depth + 1)
            if found:
                return found
    return []
