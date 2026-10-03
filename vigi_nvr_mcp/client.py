"""High-level VIGI NVR client: generic ``call`` plus typed read helpers.

The envelope (``{"method": ..., "<module>": {...}}``) and auth flow are verified
against a live NVR1016H (fw 1.1.3). Module/section names in ``READ_QUERIES`` were
extracted statically from that firmware's web client; the exact request
parameters for each are not yet live-verified, so they live in one table for
easy correction. ``nvr_call`` remains the escape hatch for anything else.

Wire URL-encoding of string values is handled entirely by the transport.
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any

from .auth import Authenticator
from .core.config import DeviceSettings
from .core.errors import TokenExpired
from .transport import NvrTransport

METHODS = frozenset({"get", "set", "do", "add", "delete"})
MODULE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
MAX_PARAM_BYTES = 64 * 1024


# Verified channel primitives (vendor ConfCameraConnect page, fw 1.1.3).
# Delete is by channel id, batched:   {"method":"do","chm":{"chm_del_dev":{"ids":["7"]}}}
# Move REPLACES whatever occupies new_id: {"method":"do","chm":{"chm_mod_dev_chn":
#                                          {"old_id":"9","new_id":"1"}}}
CHANNEL_TABLE = ("get", "chm", {"table": "added_dev"})
CHANNEL_DELETE = ("do", "chm", "chm_del_dev")
CHANNEL_MOVE = ("do", "chm", "chm_mod_dev_chn")
# Config backup: {"method":"do","system":{"download_conf":null}} -> {"url": ...}
CONFIG_BACKUP = ("do", "system", "download_conf")

# name -> (method, module, params). Sections from static extraction; see docstring.
READ_QUERIES: MappingProxyType[str, tuple[str, str, dict[str, Any]]] = MappingProxyType(
    {
        "device_info": ("get", "device_info", {"name": ["basic_info"]}),
        "module_spec": ("get", "function", {"name": ["module_spec"]}),
        "channels": CHANNEL_TABLE,
        "video_resolutions": ("get", "video", {"name": ["main_res", "minor_res"]}),
        "disks": ("get", "harddisk_manage", {"table": "hd_info"}),
        "recording_status": ("get", "harddisk_manage", {"name": ["harddisk"]}),
        "network": ("get", "network", {"name": ["wan"]}),
        "system": ("get", "system", {"name": ["basic"]}),
    }
)


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
    def __init__(
        self, settings: DeviceSettings, transport: NvrTransport, auth: Authenticator
    ) -> None:
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
        except TokenExpired:
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

    async def delete_channels(self, ids: list[str]) -> dict[str, Any]:
        """Unbind channels by id. Mutating: callers must apply the write gate."""
        method, module, action = CHANNEL_DELETE
        return await self.call(method, module, {action: {"ids": list(ids)}})

    async def move_channel(self, old_id: str, new_id: str) -> dict[str, Any]:
        """Move a binding to another slot (replaces any occupant). Mutating."""
        method, module, action = CHANNEL_MOVE
        return await self.call(method, module, {action: {"old_id": old_id, "new_id": new_id}})

    async def request_config_backup(self) -> dict[str, Any]:
        """Ask the NVR to prepare a config backup; reply carries a relative ``url``."""
        method, module, action = CONFIG_BACKUP
        return await self.call(method, module, {action: None})

    async def download_session_file(self, relative_url: str) -> bytes:
        token = await self.auth.token()
        return await self._transport.get_session_file(token, relative_url)


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
