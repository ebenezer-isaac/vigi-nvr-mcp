"""Per-channel detection configuration (read-only).

One tool covers all twelve detection modules via a ``kind`` enum. The request
section names are from static extraction and unverified until the first live run.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict

from . import ToolContext, run_tool
from .shared import DetectionInput, DetectionKind, parse_input, require_section, with_raw


class DetectionConfig(BaseModel):
    """Normalised detection config: which channel, which kind, and the enable flag
    plus the module's echoed configuration block."""

    model_config = ConfigDict(extra="ignore")
    channel: int
    kind: str
    module: str
    enabled: bool | None = None
    config: dict[str, Any]


_ENABLE_KEYS = ("enabled", "enable", "switch", "on_off")
_TRUTHY = {"1", "on", "true", "enabled", "enable", "yes"}


def _enabled_flag(section: dict[str, Any]) -> bool | None:
    for key in _ENABLE_KEYS:
        if key in section:
            value = section[key]
            if isinstance(value, bool):
                return value
            if isinstance(value, int):
                return value != 0
            if isinstance(value, str):
                return value.strip().lower() in _TRUTHY
    return None


def normalise_detection(channel: int, kind: DetectionKind, reply: Any) -> DetectionConfig:
    section = require_section(reply, kind.module)
    return DetectionConfig(
        channel=channel,
        kind=kind.value,
        module=kind.module,
        enabled=_enabled_flag(section),
        config=section,
    )


async def get_detection_config(
    ctx: ToolContext, channel: int, kind: str, include_raw: bool = False
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        args = parse_input(DetectionInput, channel=channel, kind=kind)
        reply = await ctx.client.get_detection_config(args.channel, args.kind.module)
        model = normalise_detection(args.channel, args.kind, reply)
        return with_raw(model.model_dump(), reply, include_raw)

    return await run_tool("nvr_get_detection_config", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_get_detection_config")
    async def _detection(channel: int, kind: str, include_raw: bool = False) -> dict[str, Any]:
        """Detection configuration for one channel (1-16) and one detection kind
        (read-only). kind is one of: motion, people, vehicle, linecross, intrusion,
        region_entrance, region_exiting, loitering, abandon_and_taken, scene_change,
        audio_exception, tamper. include_raw=true adds the raw device reply under
        data.raw. Refuses an unknown kind or an out-of-range channel."""
        return await get_detection_config(ctx, channel, kind, include_raw)

    return ["nvr_get_detection_config"]
