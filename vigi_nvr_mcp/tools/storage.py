"""NVR storage and recording reads (harddisk_manage, plan_advance, record_plan,
playback). Reply shapes are firmware-specific and unverified until the first live
run, so normalisation is permissive and the redacted raw reply is available via
include_raw. All calls are ``get`` (read-only)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict

from ..client import extract_rows
from . import ToolContext, run_tool
from .shared import DateInput, parse_input, require_section, with_raw

Json = dict[str, Any] | list[Any] | None


class StorageInfo(BaseModel):
    """Disks plus the recording/overwrite policy."""

    model_config = ConfigDict(extra="ignore")
    disks: list[dict[str, Any]]
    overwrite_policy: Json = None
    record_plan: Json = None


class RecordingSearch(BaseModel):
    """Recorded segments for one channel on one day."""

    model_config = ConfigDict(extra="ignore")
    channel: int
    date: str
    segment_count: int
    segments: list[dict[str, Any]]


async def list_disks(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_list_disks", ctx.client.list_disks)


async def get_recording_status(ctx: ToolContext) -> dict[str, Any]:
    return await run_tool("nvr_get_recording_status", ctx.client.get_recording_status)


def normalise_storage(replies: dict[str, Any]) -> StorageInfo:
    disk_section = require_section(replies.get("disks"), "harddisk_manage")
    plan = replies.get("plan_advance")
    record = replies.get("record_plan")
    return StorageInfo(
        disks=extract_rows(disk_section, marker="total_space") or [],
        overwrite_policy=plan.get("plan_advance") if isinstance(plan, dict) else None,
        record_plan=record.get("record_plan") if isinstance(record, dict) else None,
    )


def normalise_recordings(channel: int, date: str, reply: Any) -> RecordingSearch:
    segments = extract_rows(reply, marker="start_time")
    if not segments:
        segments = extract_rows(reply, marker="start")
    return RecordingSearch(
        channel=channel, date=date, segment_count=len(segments), segments=segments
    )


async def get_storage(ctx: ToolContext, include_raw: bool = False) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        replies = await ctx.client.get_storage()
        return with_raw(normalise_storage(replies).model_dump(), replies, include_raw)

    return await run_tool("nvr_get_storage", action)


async def search_recordings(
    ctx: ToolContext, channel: int, date: str, include_raw: bool = False
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        args = parse_input(DateInput, channel=channel, date=date)
        reply = await ctx.client.search_recordings(args.channel, args.date)
        model = normalise_recordings(args.channel, args.date, reply)
        return with_raw(model.model_dump(), reply, include_raw)

    return await run_tool("nvr_search_recordings", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_list_disks")
    async def _disks() -> dict[str, Any]:
        """Installed hard disks and their state (read-only, raw reply)."""
        return await list_disks(ctx)

    @mcp.tool(name="nvr_get_recording_status")
    async def _recording() -> dict[str, Any]:
        """Recording / storage policy status (read-only, raw reply)."""
        return await get_recording_status(ctx)

    @mcp.tool(name="nvr_get_storage")
    async def _storage(include_raw: bool = False) -> dict[str, Any]:
        """Disks (status, capacity, free space, health) plus the overwrite and
        recording-plan policy (read-only). include_raw=true adds the raw reply at
        data.raw."""
        return await get_storage(ctx, include_raw)

    @mcp.tool(name="nvr_search_recordings")
    async def _search(channel: int, date: str, include_raw: bool = False) -> dict[str, Any]:
        """List recorded video segments for one channel (1-16) on one calendar day
        (date as YYYY-MM-DD), read-only. Returns each segment's start/end/type.
        include_raw=true adds the raw device reply under data.raw."""
        return await search_recordings(ctx, channel, date, include_raw)

    return [
        "nvr_list_disks",
        "nvr_get_recording_status",
        "nvr_get_storage",
        "nvr_search_recordings",
    ]
