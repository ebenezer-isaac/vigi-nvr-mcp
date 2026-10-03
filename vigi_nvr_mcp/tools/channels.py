"""Channel tools. Credentials (``ciphertext``, passwords) are never exposed:
there is deliberately no option to include them."""

from __future__ import annotations

import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from .. import client as client_module
from ..envelope import fail
from ..errors import NvrNotFound
from ..redact import redact
from . import ToolContext, run_tool

CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
ID_FIELDS = ("id", "channel_id", "chn_id", "_row_key")


def row_id(row: dict[str, Any]) -> str | None:
    for field in ID_FIELDS:
        if row.get(field) not in (None, ""):
            return str(row[field])
    return None


def is_stale(row: dict[str, Any]) -> bool:
    """Offline (``online == "0"``) or not connected (``conn_status != "0"``)."""
    online = row.get("online")
    conn = row.get("conn_status")
    return (online is not None and str(online) == "0") or (conn is not None and str(conn) != "0")


def find_duplicates(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Group rows by ``uuid``; groups with more than one row are duplicates.

    Pure: the input rows are not modified; returned rows are redacted copies
    annotated with ``stale`` and ``channel_id``.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        uuid = row.get("uuid")
        if uuid in (None, ""):
            continue
        key = str(uuid)
        groups = {**groups, key: [*groups.get(key, []), row]}
    duplicates = []
    for uuid in sorted(groups):
        members = groups[uuid]
        if len(members) < 2:
            continue
        annotated = [{**redact(r), "channel_id": row_id(r), "stale": is_stale(r)} for r in members]
        duplicates.append(
            {
                "uuid": uuid,
                "count": len(members),
                "stale_channel_ids": [a["channel_id"] for a in annotated if a["stale"]],
                "live_channel_ids": [a["channel_id"] for a in annotated if not a["stale"]],
                "rows": annotated,
            }
        )
    return {
        "total_rows": len(rows),
        "rows_without_uuid": sum(1 for r in rows if r.get("uuid") in (None, "")),
        "duplicate_group_count": len(duplicates),
        "groups": duplicates,
    }


def _validate_id(channel_id: str | int) -> str:
    text = str(channel_id).strip()
    if not CHANNEL_ID_RE.fullmatch(text):
        raise ValueError("channel id must be 1-64 characters of [A-Za-z0-9_-]")
    return text


async def list_channels(ctx: ToolContext) -> dict[str, Any]:
    async def action() -> list[dict[str, Any]]:
        rows = await ctx.client.list_channels()
        return [{**r, "channel_id": row_id(r)} for r in rows]

    return await run_tool("list_channels", action)


async def get_channel(ctx: ToolContext, channel_id: str | int) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        wanted = _validate_id(channel_id)
        for row in await ctx.client.list_channels():
            if row_id(row) == wanted:
                return {**row, "channel_id": wanted}
        raise NvrNotFound(f"No channel with id '{wanted}'.")

    return await run_tool("get_channel", action)


async def find_duplicate_channels(ctx: ToolContext) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        return find_duplicates(await ctx.client.list_channels())

    return await run_tool("find_duplicate_channels", action)


async def remove_channel(
    ctx: ToolContext, channel_id: str | int, confirm_write: bool = False
) -> dict[str, Any]:
    try:
        _validate_id(channel_id)
    except ValueError as exc:
        return fail("INVALID_INPUT", str(exc))
    # TODO(channel-delete): once client.CHANNEL_DELETE_PRIMITIVE is documented,
    # apply raw.check_write_gate(ctx, method, confirm_write) and call it here.
    if client_module.CHANNEL_DELETE_PRIMITIVE is None:
        return fail(
            "NOT_IMPLEMENTED",
            "Channel removal is not implemented yet: the delete primitive for this "
            "firmware has not been verified. No request was sent.",
            {"channel_id": str(channel_id), "confirm_write": confirm_write},
        )
    return fail("NOT_IMPLEMENTED", "Delete primitive declared but not wired.")


def register(app: FastMCP, ctx: ToolContext) -> None:
    @app.tool(name="list_channels")
    async def _list() -> dict[str, Any]:
        """All NVR channels. Credential fields are always redacted."""
        return await list_channels(ctx)

    @app.tool(name="get_channel")
    async def _get(channel_id: str) -> dict[str, Any]:
        """One channel by id (credential fields redacted)."""
        return await get_channel(ctx, channel_id)

    @app.tool(name="find_duplicate_channels")
    async def _dupes() -> dict[str, Any]:
        """Group channels by device uuid and flag duplicates. Within a group, rows
        with online="0" or conn_status!="0" are marked stale (removal candidates)."""
        return await find_duplicate_channels(ctx)

    @app.tool(name="remove_channel")
    async def _remove(channel_id: str, confirm_write: bool = False) -> dict[str, Any]:
        """NOT YET IMPLEMENTED: always returns NOT_IMPLEMENTED and sends nothing.
        Will require VIGI_NVR_ALLOW_WRITES=true and confirm_write=true."""
        return await remove_channel(ctx, channel_id, confirm_write)
