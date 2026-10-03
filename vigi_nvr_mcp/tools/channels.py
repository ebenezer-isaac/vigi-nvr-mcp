"""NVR channel tools.

Credentials (``ciphertext``, passwords) are never exposed: there is deliberately
no option to include them. The two mutating tools (remove, move) are guarded by:

1. the two-key write gate (``VIGI_NVR_ALLOW_WRITES`` + ``confirm_write=true``);
2. ``expected_uuid`` must match the live row, re-read immediately before writing;
3. move refuses an occupied target slot (the firmware would silently replace it);
4. ``VIGI_NVR_DRY_RUN=true`` returns the exact request without sending it.

Both return the before/after rows (redacted). Take ``nvr_backup_config`` first.
"""

from __future__ import annotations

import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from .. import client as client_module
from ..core.envelope import fail
from ..core.errors import NotFound, PreconditionFailed
from ..core.redact import redact
from ..core.write_gate import check_write_gate
from ..planning import build_cleanup_plan
from . import ToolContext, run_tool

CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
UUID_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
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


def validate_channel_id(channel_id: object) -> str:
    if isinstance(channel_id, bool) or not isinstance(channel_id, str | int):
        raise ValueError("channel id must be 1-64 characters of [A-Za-z0-9_-]")
    text = str(channel_id).strip()
    if not CHANNEL_ID_RE.fullmatch(text):
        raise ValueError("channel id must be 1-64 characters of [A-Za-z0-9_-]")
    return text


def validate_uuid(value: object) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value.strip()):
        raise ValueError("expected_uuid must be 1-128 printable characters")
    return value.strip()


def _find(rows: list[dict[str, Any]], channel_id: str) -> dict[str, Any] | None:
    return next((r for r in rows if row_id(r) == channel_id), None)


def _public(row: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if row is None else {**redact(row), "channel_id": row_id(row)}


def _require_uuid(row: dict[str, Any] | None, channel_id: str, expected: str) -> dict[str, Any]:
    if row is None:
        raise NotFound(f"No channel with id '{channel_id}'.")
    actual = str(row.get("uuid", ""))
    if actual != expected:
        raise PreconditionFailed(
            f"Channel '{channel_id}' uuid does not match expected_uuid; the binding changed "
            "since it was inspected. Re-read the channel list.",
            reason="UUID_MISMATCH",
            context={"channel_id": channel_id, "actual_uuid": actual},
        )
    return row


async def list_channels(ctx: ToolContext) -> dict[str, Any]:
    async def action() -> list[dict[str, Any]]:
        rows = await ctx.client.list_channels()
        return [{**r, "channel_id": row_id(r)} for r in rows]

    return await run_tool("nvr_list_channels", action)


async def get_channel(ctx: ToolContext, channel_id: str | int) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        wanted = validate_channel_id(channel_id)
        row = _find(await ctx.client.list_channels(), wanted)
        if row is None:
            raise NotFound(f"No channel with id '{wanted}'.")
        return {**row, "channel_id": wanted}

    return await run_tool("nvr_get_channel", action)


async def find_duplicate_channels(ctx: ToolContext) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        return find_duplicates(await ctx.client.list_channels())

    return await run_tool("nvr_find_duplicate_channels", action)


async def plan_channel_cleanup(ctx: ToolContext) -> dict[str, Any]:
    """Read-only: an ordered, resumable plan to remove ghosts and pack cameras ≤ 8."""

    async def action() -> dict[str, Any]:
        rows = await ctx.client.list_channels()
        return build_cleanup_plan(rows).model_dump(mode="json")

    return await run_tool("nvr_plan_channel_cleanup", action)


async def remove_channel(
    ctx: ToolContext, channel_id: str | int, expected_uuid: str, confirm_write: bool = False
) -> dict[str, Any]:
    try:
        cid, uuid = validate_channel_id(channel_id), validate_uuid(expected_uuid)
    except ValueError as exc:
        return fail("INVALID_INPUT", str(exc))
    method, module, action_name = client_module.CHANNEL_DELETE
    refusal = check_write_gate(ctx.settings, method, confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        before = _require_uuid(_find(await ctx.client.list_channels(), cid), cid, uuid)
        request = {"method": method, module: {action_name: {"ids": [cid]}}}
        if ctx.settings.dry_run:
            return {"dry_run": True, "request": request, "before": _public(before), "after": None}
        response = await ctx.client.delete_channels([cid])
        after = _find(await ctx.client.list_channels(), cid)
        return {
            "dry_run": False,
            "request": request,
            "response": response,
            "before": _public(before),
            "after": _public(after),
            "removed": after is None or str(after.get("uuid", "")) != uuid,
        }

    return await run_tool("nvr_remove_channel", lambda: ctx.writes.run(action))


async def move_channel(
    ctx: ToolContext,
    old_id: str | int,
    new_id: str | int,
    expected_uuid: str,
    confirm_write: bool = False,
) -> dict[str, Any]:
    try:
        src, dst = validate_channel_id(old_id), validate_channel_id(new_id)
        uuid = validate_uuid(expected_uuid)
    except ValueError as exc:
        return fail("INVALID_INPUT", str(exc))
    if src == dst:
        return fail("INVALID_INPUT", "old_id and new_id must differ")
    method, module, action_name = client_module.CHANNEL_MOVE
    refusal = check_write_gate(ctx.settings, method, confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        rows = await ctx.client.list_channels()
        source = _require_uuid(_find(rows, src), src, uuid)
        occupant = _find(rows, dst)
        if occupant is not None:
            raise PreconditionFailed(
                f"Target channel '{dst}' is occupied. The firmware would replace its binding; "
                "remove it first (nvr_remove_channel) and retry.",
                reason="TARGET_OCCUPIED",
                context={"new_id": dst, "occupant": _public(occupant)},
            )
        request = {"method": method, module: {action_name: {"old_id": src, "new_id": dst}}}
        before = {"source": _public(source), "target": None}
        if ctx.settings.dry_run:
            return {"dry_run": True, "request": request, "before": before, "after": None}
        response = await ctx.client.move_channel(src, dst)
        after_rows = await ctx.client.list_channels()
        after = {
            "source": _public(_find(after_rows, src)),
            "target": _public(_find(after_rows, dst)),
        }
        target = after["target"]
        moved = target is not None and str(target.get("uuid", "")) == uuid
        return {
            "dry_run": False,
            "request": request,
            "response": response,
            "before": before,
            "after": after,
            "moved": moved,
        }

    return await run_tool("nvr_move_channel", lambda: ctx.writes.run(action))


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_list_channels")
    async def _list() -> dict[str, Any]:
        """All bound NVR channels (chm added_dev). Credential fields always redacted."""
        return await list_channels(ctx)

    @mcp.tool(name="nvr_get_channel")
    async def _get(channel_id: str) -> dict[str, Any]:
        """One channel by id (credential fields redacted)."""
        return await get_channel(ctx, channel_id)

    @mcp.tool(name="nvr_find_duplicate_channels")
    async def _dupes() -> dict[str, Any]:
        """Group channels by device uuid and flag duplicates. Within a group, rows
        with online="0" or conn_status!="0" are marked stale (removal candidates)."""
        return await find_duplicate_channels(ctx)

    @mcp.tool(name="nvr_plan_channel_cleanup")
    async def _plan() -> dict[str, Any]:
        """Read-only. Produce an ordered, resumable cleanup plan: back up config, remove
        every ghost (one call each), re-read, then move each real camera stranded above
        slot 8 into the lowest confirmed-empty low slot. Each step lists the exact tool,
        arguments and the precondition to verify from the previous step; also returns a
        summary (counts, final layout) and an unsafe_if list of conditions that block
        moves (two real cameras share a uuid, more than 8 real cameras, an online ghost).
        Nothing is written; hand each step to the matching write tool yourself."""
        return await plan_channel_cleanup(ctx)

    @mcp.tool(name="nvr_remove_channel")
    async def _remove(
        channel_id: str, expected_uuid: str, confirm_write: bool = False
    ) -> dict[str, Any]:
        """Unbind one channel (chm_del_dev). DESTRUCTIVE. Requires
        VIGI_NVR_ALLOW_WRITES=true, confirm_write=true and expected_uuid equal to
        the live row's uuid. Honours VIGI_NVR_DRY_RUN. Run nvr_backup_config first.
        Returns before/after rows."""
        return await remove_channel(ctx, channel_id, expected_uuid, confirm_write)

    @mcp.tool(name="nvr_move_channel")
    async def _move(
        old_id: str, new_id: str, expected_uuid: str, confirm_write: bool = False
    ) -> dict[str, Any]:
        """Move a binding to another channel slot (chm_mod_dev_chn), keeping its
        credentials and settings. Refuses if new_id is occupied (the firmware would
        replace it). Same gates as nvr_remove_channel. Returns before/after rows."""
        return await move_channel(ctx, old_id, new_id, expected_uuid, confirm_write)

    return [
        "nvr_list_channels",
        "nvr_get_channel",
        "nvr_find_duplicate_channels",
        "nvr_plan_channel_cleanup",
        "nvr_remove_channel",
        "nvr_move_channel",
    ]
