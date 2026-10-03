"""Per-channel media configuration reads: video streams and image/OSD/mask/ROI.

Request section names were extracted statically from the web client and are not
yet confirmed against a live NVR (see ``client.READ_QUERIES``); the normalised
output shapes here are therefore permissive. All calls are ``get`` (read-only).
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict

from . import ToolContext, run_tool
from .shared import ChannelInput, decode_name, parse_input, require_section, with_raw

Json = dict[str, Any] | list[Any] | None


class VideoConfig(BaseModel):
    """Main/minor stream tables plus advanced per-channel settings."""

    model_config = ConfigDict(extra="ignore")
    main_res: Json = None
    minor_res: Json = None
    advance_settings: Json = None


class ImageConfig(BaseModel):
    """One channel's image, OSD, privacy-mask (cover) and ROI config."""

    model_config = ConfigDict(extra="ignore")
    channel: int
    image: dict[str, Any]
    osd: dict[str, Any]
    privacy_mask: dict[str, Any]
    roi: dict[str, Any]


def normalise_video(video_reply: Any, advance_reply: Any) -> VideoConfig:
    section = require_section(video_reply, "video")
    advance = advance_reply.get("advance_settings") if isinstance(advance_reply, dict) else None
    return VideoConfig(
        main_res=section.get("main_res"),
        minor_res=section.get("minor_res"),
        advance_settings=advance,
    )


def _decode_osd(osd: dict[str, Any]) -> dict[str, Any]:
    """Decode any ``name`` leaves one level deep (OSD carries channel names)."""
    out: dict[str, Any] = {}
    for key, value in osd.items():
        if isinstance(value, dict) and "name" in value:
            out[key] = {**value, "name": decode_name(value["name"])}
        elif key == "name":
            out[key] = decode_name(value)
        else:
            out[key] = value
    return out


def normalise_image(channel: int, replies: dict[str, Any]) -> ImageConfig:
    return ImageConfig(
        channel=channel,
        image=require_section(replies["image"], "image"),
        osd=_decode_osd(require_section(replies["OSD"], "OSD")),
        privacy_mask=require_section(replies["cover"], "cover"),
        roi=require_section(replies["ROI"], "ROI"),
    )


async def get_video_config(ctx: ToolContext, include_raw: bool = False) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        video_reply = await ctx.client.query("video_config")
        advance_reply = await ctx.client.query("advance_settings")
        model = normalise_video(video_reply, advance_reply)
        return with_raw(
            model.model_dump(),
            {"video": video_reply, "advance_settings": advance_reply},
            include_raw,
        )

    return await run_tool("nvr_get_video_config", action)


async def get_image_config(
    ctx: ToolContext, channel: int, include_raw: bool = False
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        args = parse_input(ChannelInput, channel=channel)
        replies = await ctx.client.get_image_config(args.channel)
        model = normalise_image(args.channel, replies)
        return with_raw(model.model_dump(), replies, include_raw)

    return await run_tool("nvr_get_image_config", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_get_video_config")
    async def _video(include_raw: bool = False) -> dict[str, Any]:
        """Per-channel video stream configuration: main/minor resolution, codec and
        bitrate tables plus advanced encoder settings (read-only). Pass
        include_raw=true to also get the unprocessed device reply under data.raw."""
        return await get_video_config(ctx, include_raw)

    @mcp.tool(name="nvr_get_image_config")
    async def _image(channel: int, include_raw: bool = False) -> dict[str, Any]:
        """Image, OSD, privacy-mask (cover) and ROI configuration for one channel
        (1-16), read-only. include_raw=true adds the raw device reply at data.raw."""
        return await get_image_config(ctx, channel, include_raw)

    return ["nvr_get_video_config", "nvr_get_image_config"]
