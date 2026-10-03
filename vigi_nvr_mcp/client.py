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
from .catalog import validate_params
from .core.config import DeviceSettings
from .core.errors import InvalidInput, TokenExpired
from .transport import NvrTransport

METHODS = frozenset({"get", "set", "do", "add", "delete", "forward"})
MODULE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


# Verified channel primitives (vendor ConfCameraConnect page, fw 1.1.3).
# Delete is by channel id, batched:   {"method":"do","chm":{"chm_del_dev":{"ids":["7"]}}}
# Move REPLACES whatever occupies new_id: {"method":"do","chm":{"chm_mod_dev_chn":
#                                          {"old_id":"9","new_id":"1"}}}
# Sections of the unusual_detection module that read as event/alert states
# (static extraction; unverified until first live run).
UNUSUAL_SECTIONS = (
    "login_error",
    "hd_error",
    "hd_lack",
    "hd_miss",
    "ip_conflict",
    "vedio_miss",
    "fan_work_abnormal",
)

CHANNEL_TABLE = ("get", "chm", {"table": "added_dev"})
CHANNEL_DELETE = ("do", "chm", "chm_del_dev")
CHANNEL_MOVE = ("do", "chm", "chm_mod_dev_chn")
# Config backup: {"method":"do","system":{"download_conf":null}} -> {"url": ...}
CONFIG_BACKUP = ("do", "system", "download_conf")

# name -> (method, module, params). Sections from static extraction; see docstring.
# The entries below marked "unverified" were extracted statically from the web
# client (endpoints.json) and have not been confirmed against a live NVR yet; the
# module/method are grounded in the inventory but the exact section params may
# need correcting after the first live run (Phase N5).
READ_QUERIES: MappingProxyType[str, tuple[str, str, dict[str, Any] | None]] = MappingProxyType(
    {
        "device_info": ("get", "device_info", {"name": ["basic_info"]}),
        "module_spec": ("get", "function", {"name": ["module_spec"]}),
        "channels": CHANNEL_TABLE,
        "video_resolutions": ("get", "video", {"name": ["main_res", "minor_res"]}),
        "disks": ("get", "harddisk_manage", {"table": "hd_info"}),
        "recording_status": ("get", "harddisk_manage", {"name": ["harddisk"]}),
        "network": ("get", "network", {"name": ["wan"]}),
        "system": ("get", "system", {"name": ["basic"]}),
        # --- N3 typed reads (unverified until first live run) ---
        "video_config": ("get", "video", {"name": ["main_res", "minor_res"]}),
        "advance_settings": ("get", "advance_settings", {"name": ["advance_settings"]}),
        "storage_plan": ("get", "plan_advance", {"name": ["plan_advance"]}),
        "record_plan": ("get", "record_plan", {"name": ["record_plan"]}),
        "users": ("get", "user_management", {"name": ["user_management"]}),
        "firewall": ("get", "firewall", {"name": ["blacklist", "whitelist", "ipctrl"]}),
        "firewall_protocol": ("get", "protocol", {"table": "table"}),
        "cloud_status": ("get", "cloud_status", None),
        "cloud_config": ("get", "cloud_config", {"name": ["bind", "info"]}),
        "time": ("get", "system", {"name": ["clock_status", "date", "dst"]}),
        "events": ("get", "unusual_detection", {"name": list(UNUSUAL_SECTIONS)}),
    }
)


def validate_call(method: str, module: str, params: Any) -> None:
    """Validate an outbound call before any I/O. Raises ``InvalidInput`` (a
    ``ValueError``) so it maps to an ``INVALID_INPUT`` envelope.

    Params are checked by the catalog's structural validator (depth <= 6 checked
    before any recursion-prone work, <= 200 keys, strings <= 4 KB, no control
    chars, keys ``[A-Za-z0-9_.-]{1,64}``), replacing the old ``len(repr(params))``
    guard that itself recursed and could raise ``RecursionError`` on a depth bomb.
    """
    if method not in METHODS:
        raise InvalidInput(f"method must be one of {sorted(METHODS)}")
    if not isinstance(module, str) or not MODULE_RE.fullmatch(module):
        raise InvalidInput("module must match ^[A-Za-z][A-Za-z0-9_]{0,63}$")
    if module == "method":
        raise InvalidInput("module must not be 'method'")
    validate_params(params)


class NvrClient:
    def __init__(
        self, settings: DeviceSettings, transport: NvrTransport, auth: Authenticator
    ) -> None:
        self.settings = settings
        self.auth = auth
        self._transport = transport

    async def aclose(self) -> None:
        await self._transport.aclose()

    @property
    def observed_fingerprint(self) -> str | None:
        return self._transport.observed_fingerprint

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

    async def get_image_config(self, channel: int) -> dict[str, dict[str, Any]]:
        """Image/OSD/privacy-mask/ROI config for one channel.

        Four reads (image, OSD, cover, ROI), keyed by module in the result.
        Per-channel sections use the ``chn<N>_<section>`` convention.
        Unverified until first live run.
        """
        n = int(channel)
        out: dict[str, dict[str, Any]] = {}
        out["image"] = await self.call(
            "get", "image", {"name": [f"chn{n}_common", f"chn{n}_switch"]}
        )
        out["OSD"] = await self.call("get", "OSD", {"name": [f"chn{n}_name", f"chn{n}_basic"]})
        out["cover"] = await self.call("get", "cover", {"name": [f"chn{n}_cover"]})
        out["ROI"] = await self.call("get", "ROI", {"name": [f"chn{n}_main_roi", f"chn{n}_on_off"]})
        return out

    async def get_detection_config(self, channel: int, module: str) -> dict[str, Any]:
        """One detection module's config for one channel (read-only).

        ``module`` is one of the twelve ``*_detection`` modules. Unverified until
        first live run.
        """
        n = int(channel)
        return await self.call("get", module, {"name": [f"chn{n}_region_info"]})

    async def search_recordings(self, channel: int, date: str) -> dict[str, Any]:
        """Recorded segments for one channel on one ``YYYY-MM-DD`` day (read-only).

        Issued as a ``get`` so it can never trip the write gate. Unverified until
        first live run.
        """
        return await self.call("get", "playback", {"channel": str(int(channel)), "date": date})

    async def get_storage(self) -> dict[str, dict[str, Any]]:
        """Disks plus recording/overwrite policy. Unverified until first live run."""
        return {
            "disks": await self.query("disks"),
            "plan_advance": await self.query("storage_plan"),
            "record_plan": await self.query("record_plan"),
        }

    async def get_users(self) -> dict[str, Any]:
        return await self.query("users")

    async def get_firewall(self) -> dict[str, dict[str, Any]]:
        return {
            "firewall": await self.query("firewall"),
            "protocol": await self.query("firewall_protocol"),
        }

    async def get_cloud_status(self) -> dict[str, dict[str, Any]]:
        return {
            "cloud_status": await self.query("cloud_status"),
            "cloud_config": await self.query("cloud_config"),
        }

    async def get_time(self) -> dict[str, Any]:
        return await self.query("time")

    async def list_events(self) -> dict[str, Any]:
        return await self.query("events")

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
