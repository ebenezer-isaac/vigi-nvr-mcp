"""System-level reads: users, firewall, cloud status and time (all read-only).

Request sections are from static extraction and unverified until the first live
run; normalisation is permissive and the redacted raw reply is available via
include_raw. ``nvr_get_users`` returns names and groups only - never credentials.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict

from . import ToolContext, run_tool
from .shared import decode_name, require_section, with_raw

Json = dict[str, Any] | list[Any] | None
_NAME_KEYS = ("name", "user_name", "username")
_GROUP_KEYS = ("group", "user_group", "level", "role")


class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    group: str | None = None


class Users(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_count: int
    users: list[User]


class Firewall(BaseModel):
    model_config = ConfigDict(extra="ignore")
    firewall: dict[str, Any]
    protocol: Json = None


class CloudStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")
    bound: bool | None = None
    status: dict[str, Any]
    config: dict[str, Any]


class TimeInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    clock_status: Json = None
    date: Json = None
    dst: Json = None


def _first(entry: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if entry.get(key) not in (None, ""):
            return entry[key]
    return None


def _user_rows(section: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for value in section.values():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, dict) and _first(item, _NAME_KEYS) is not None:
                rows.append(item)
    return rows


def normalise_users(reply: Any) -> Users:
    section = require_section(reply, "user_management")
    users = [
        User(name=str(decode_name(_first(r, _NAME_KEYS))), group=_opt_str(_first(r, _GROUP_KEYS)))
        for r in _user_rows(section)
    ]
    return Users(user_count=len(users), users=users)


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def normalise_firewall(replies: dict[str, Any]) -> Firewall:
    protocol = replies.get("protocol")
    return Firewall(
        firewall=require_section(replies["firewall"], "firewall"),
        protocol=protocol.get("protocol") if isinstance(protocol, dict) else None,
    )


def _bound_flag(status: dict[str, Any], config: dict[str, Any]) -> bool | None:
    for block in (status, config):
        for key in ("bind", "bound", "is_bind", "bind_status"):
            if key in block:
                value = block[key]
                if isinstance(value, bool):
                    return value
                if isinstance(value, int):
                    return value != 0
                if isinstance(value, str):
                    return value.strip().lower() in {"1", "true", "bound", "yes", "on"}
    return None


def normalise_cloud(replies: dict[str, Any]) -> CloudStatus:
    status = require_section(replies["cloud_status"], "cloud_status")
    config = require_section(replies["cloud_config"], "cloud_config")
    return CloudStatus(bound=_bound_flag(status, config), status=status, config=config)


def normalise_time(reply: Any) -> TimeInfo:
    section = require_section(reply, "system")
    return TimeInfo(
        clock_status=section.get("clock_status"),
        date=section.get("date"),
        dst=section.get("dst"),
    )


async def get_users(ctx: ToolContext, include_raw: bool = False) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        reply = await ctx.client.get_users()
        return with_raw(normalise_users(reply).model_dump(), reply, include_raw)

    return await run_tool("nvr_get_users", action)


async def get_firewall(ctx: ToolContext, include_raw: bool = False) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        replies = await ctx.client.get_firewall()
        return with_raw(normalise_firewall(replies).model_dump(), replies, include_raw)

    return await run_tool("nvr_get_firewall", action)


async def get_cloud_status(ctx: ToolContext, include_raw: bool = False) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        replies = await ctx.client.get_cloud_status()
        return with_raw(normalise_cloud(replies).model_dump(), replies, include_raw)

    return await run_tool("nvr_get_cloud_status", action)


async def get_time(ctx: ToolContext, include_raw: bool = False) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        reply = await ctx.client.get_time()
        return with_raw(normalise_time(reply).model_dump(), reply, include_raw)

    return await run_tool("nvr_get_time", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_get_users")
    async def _users(include_raw: bool = False) -> dict[str, Any]:
        """NVR user accounts: names and groups only (credentials are never
        returned), read-only. include_raw=true adds the redacted raw reply at
        data.raw."""
        return await get_users(ctx, include_raw)

    @mcp.tool(name="nvr_get_firewall")
    async def _firewall(include_raw: bool = False) -> dict[str, Any]:
        """Firewall configuration: allow/deny lists and protocol/service exposure
        (read-only). include_raw=true adds the raw reply at data.raw."""
        return await get_firewall(ctx, include_raw)

    @mcp.tool(name="nvr_get_cloud_status")
    async def _cloud(include_raw: bool = False) -> dict[str, Any]:
        """TP-Link cloud (TP-Link ID) binding and connection status (read-only).
        include_raw=true adds the raw reply at data.raw."""
        return await get_cloud_status(ctx, include_raw)

    @mcp.tool(name="nvr_get_time")
    async def _time(include_raw: bool = False) -> dict[str, Any]:
        """Device time, time zone, NTP and DST configuration (read-only).
        include_raw=true adds the raw reply at data.raw."""
        return await get_time(ctx, include_raw)

    return ["nvr_get_users", "nvr_get_firewall", "nvr_get_cloud_status", "nvr_get_time"]
