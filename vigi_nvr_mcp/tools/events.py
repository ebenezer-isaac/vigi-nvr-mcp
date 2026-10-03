"""Best-effort event / alert listing (read-only).

The NVR has no single verified event-log read; this normalises the
``unusual_detection`` state sections into a flat, filterable list. Section names
and shapes are unverified until the first live run, so normalisation is lenient.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict

from . import ToolContext, run_tool
from .shared import SinceInput, parse_input, require_section, with_raw

_TIME_KEYS = ("time", "timestamp", "datetime", "date", "last_time", "start_time")


class Event(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: str
    time: str | None = None
    channel: Any = None
    detail: dict[str, Any]


class EventList(BaseModel):
    model_config = ConfigDict(extra="ignore")
    since: str | None = None
    event_count: int
    events: list[Event]


def _event_time(entry: dict[str, Any]) -> str | None:
    for key in _TIME_KEYS:
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _parse_iso(value: str | None) -> datetime | None:
    """Parse an ISO-8601 instant, treating a naive value as UTC so naive and
    timezone-aware timestamps remain comparable."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _entries(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def normalise_events(reply: Any, since: str | None) -> EventList:
    section = require_section(reply, "unusual_detection")
    since_dt = _parse_iso(since)
    events: list[Event] = []
    for source, value in section.items():
        for entry in _entries(value):
            when = _event_time(entry)
            if since_dt is not None:
                entry_dt = _parse_iso(when)
                if entry_dt is not None and entry_dt < since_dt:
                    continue
            events.append(
                Event(
                    source=source,
                    time=when,
                    channel=entry.get("channel") or entry.get("chn"),
                    detail=entry,
                )
            )
    return EventList(since=since, event_count=len(events), events=events)


async def list_events(
    ctx: ToolContext, since: str | None = None, include_raw: bool = False
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        args = parse_input(SinceInput, since=since)
        reply = await ctx.client.list_events()
        model = normalise_events(reply, args.since)
        return with_raw(model.model_dump(), reply, include_raw)

    return await run_tool("nvr_list_events", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_list_events")
    async def _events(since: str | None = None, include_raw: bool = False) -> dict[str, Any]:
        """Best-effort list of recent NVR events/alerts (disk, network, video-loss
        and similar), read-only. Pass since as an ISO-8601 timestamp to drop older
        events that carry a parseable time. include_raw=true adds the raw reply at
        data.raw."""
        return await list_events(ctx, since, include_raw)

    return ["nvr_list_events"]
