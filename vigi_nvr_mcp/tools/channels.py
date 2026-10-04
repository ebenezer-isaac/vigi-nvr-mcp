"""NVR channel tools.

Credentials (``ciphertext``, passwords) are never exposed in returns: they are
redacted. The mutating tools (remove, move, set-credentials, renumber) are guarded
by:

1. the two-key write gate (``VIGI_NVR_ALLOW_WRITES`` + ``confirm_write=true``);
2. ``expected_uuid`` must match the live row, re-read immediately before writing;
3. remove refuses a live (``online=="1"``) row unless ``force=true``;
4. move refuses an occupied target slot (the firmware would silently replace it);
5. ``VIGI_NVR_DRY_RUN=true`` returns the exact request without sending it (the
   central guarded-write executor does this for every mutating tool).

Both return the before/after rows (redacted). Take ``nvr_backup_config`` first.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from .. import client as client_module
from .. import crypto
from ..core.errors import InvalidInput, NotFound, PreconditionFailed
from ..core.redact import redact
from ..core.types import ConfirmWrite
from ..core.write_gate import check_write_gate
from ..planning import build_cleanup_plan
from . import ToolContext, run_tool


class ChannelOnline(PreconditionFailed):
    """Refused removing an online (live) channel without ``force=True``."""

    kind = "CHANNEL_ONLINE"


CHANNEL_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
UUID_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
USERNAME_RE = re.compile(r"^[\x21-\x7e]{1,64}$")  # printable ASCII, no spaces/controls
ID_FIELDS = ("id", "channel_id", "chn_id", "_row_key")

# RSA-1024 PKCS#1 v1.5 fits key_size/8 - 11 = 117 plaintext bytes; the channel
# password is encrypted directly (not hashed first), so cap it below that.
MAX_PASSWORD_BYTES = 117
# After the edit the firmware reports a transient "authenticating" state
# (auth_result -71558) before it settles; poll the channel list until it does.
SETTLE_ATTEMPTS = 8
SETTLE_INTERVAL_S = 2.0


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
        raise InvalidInput("channel id must be 1-64 characters of [A-Za-z0-9_-]")
    text = str(channel_id).strip()
    if not CHANNEL_ID_RE.fullmatch(text):
        raise InvalidInput("channel id must be 1-64 characters of [A-Za-z0-9_-]")
    return text


def validate_uuid(value: object) -> str:
    if not isinstance(value, str) or not UUID_RE.fullmatch(value.strip()):
        raise InvalidInput("expected_uuid must be 1-128 printable characters")
    return value.strip()


def validate_username(value: object) -> str:
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value.strip()):
        raise InvalidInput("username must be 1-64 printable ASCII characters (no spaces)")
    return value.strip()


def validate_ipv4(value: object) -> str:
    """Validate a dotted-quad IPv4 address (rejects CIDR, ports, IPv6, hostnames)."""
    if not isinstance(value, str):
        raise InvalidInput("new_ip must be a dotted-quad IPv4 address")
    text = value.strip()
    try:
        addr = ipaddress.IPv4Address(text)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise InvalidInput("new_ip must be a valid IPv4 address") from exc
    return str(addr)


def validate_password(value: object) -> str:
    """Validate (never log) a channel password. Returned verbatim: it is encrypted,
    not trimmed, so leading/trailing characters are significant."""
    if not isinstance(value, str) or value == "":
        raise InvalidInput("password must be a non-empty string")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise InvalidInput("password must not contain control characters")
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise InvalidInput(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    return value


def build_edit_dev_row(row: dict[str, Any], username: str, ciphertext: str) -> dict[str, Any]:
    """Pure builder for a ``chm_edit_dev`` device row.

    Returns a NEW dict: every client-only ``_``-prefixed key (e.g. ``_row_key``)
    removed, with ``username`` and ``ciphertext`` overwritten. The caller's row is
    never mutated.
    """
    cleaned = {k: v for k, v in row.items() if not str(k).startswith("_")}
    return {**cleaned, "username": username, "ciphertext": ciphertext}


def build_add_dev(
    connect_prot: str, ip: str, port: str, username: str, ciphertext: str
) -> dict[str, Any]:
    """Pure builder for one ``chm_add_dev_list`` device entry (verified wire fields)."""
    return {
        "connect_prot": connect_prot,
        "ip": ip,
        "port": port,
        "username": username,
        "ciphertext": ciphertext,
        "passwd_strength": "low",
    }


def _delete_request(channel_id: str) -> dict[str, Any]:
    method, module, action_name = client_module.CHANNEL_DELETE
    return {"method": method, module: {action_name: {"ids": [channel_id]}}}


def _add_request(device: dict[str, Any]) -> dict[str, Any]:
    method, module, action_name = client_module.CHANNEL_ADD
    return {"method": method, module: {action_name: {"device_list": [device]}}}


def _edit_request(edit_row: dict[str, Any]) -> dict[str, Any]:
    method, module, action_name = client_module.CHANNEL_EDIT
    return {"method": method, module: {action_name: edit_row}}


def is_settled(row: dict[str, Any]) -> bool:
    """Channel is connected and authenticated: conn_status == auth_result == "0"."""
    return str(row.get("conn_status", "")) == "0" and str(row.get("auth_result", "")) == "0"


async def _poll_until_settled(client: Any, channel_id: str) -> dict[str, Any] | None:
    """Re-read the channel list until the target settles (or attempts run out).

    Returns the last observed row (possibly still unsettled or ``None``). The
    transient ``auth_result == -71558`` state is treated as "still settling", never
    an error, per the verified protocol.
    """
    last: dict[str, Any] | None = None
    for attempt in range(SETTLE_ATTEMPTS):
        last = _find(await client.list_channels(), channel_id)
        if last is not None and is_settled(last):
            return last
        if attempt + 1 < SETTLE_ATTEMPTS:
            await asyncio.sleep(SETTLE_INTERVAL_S)
    return last


def _find(rows: list[dict[str, Any]], channel_id: str) -> dict[str, Any] | None:
    return next((r for r in rows if row_id(r) == channel_id), None)


def _find_by_uuid(rows: list[dict[str, Any]], uuid: str) -> dict[str, Any] | None:
    return next((r for r in rows if str(r.get("uuid", "")) == uuid), None)


async def _poll_for_uuid(client: Any, uuid: str) -> dict[str, Any] | None:
    """Re-read the channel list until a row with ``uuid`` appears (or attempts run out).

    After a delete+re-add the camera is rediscovered and rebound into a fresh slot;
    it can take a moment to reappear, so poll rather than reading once.
    """
    last: dict[str, Any] | None = None
    for attempt in range(SETTLE_ATTEMPTS):
        last = _find_by_uuid(await client.list_channels(), uuid)
        if last is not None:
            return last
        if attempt + 1 < SETTLE_ATTEMPTS:
            await asyncio.sleep(SETTLE_INTERVAL_S)
    return last


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
    ctx: ToolContext,
    channel_id: str | int,
    expected_uuid: str,
    confirm_write: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    method, module, action_name = client_module.CHANNEL_DELETE
    refusal = check_write_gate(ctx.settings, method, confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        # Validate inside run_tool so an InvalidInput maps there (single mapper).
        cid, uuid = validate_channel_id(channel_id), validate_uuid(expected_uuid)
        request = {"method": method, module: {action_name: {"ids": [cid]}}}

        async def write() -> dict[str, Any]:
            before = _require_uuid(_find(await ctx.client.list_channels(), cid), cid, uuid)
            if not force and str(before.get("online", "")) == "1":
                raise ChannelOnline(
                    f"Channel '{cid}' is online (a live camera). Refusing to unbind it without "
                    "force=true; confirm it is really a ghost, or pass force=true to override.",
                    reason="CHANNEL_ONLINE",
                    context={"channel_id": cid, "online": str(before.get("online", ""))},
                )
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

        return await ctx.writes.run(request, write)

    return await run_tool("nvr_remove_channel", action)


async def move_channel(
    ctx: ToolContext,
    old_id: str | int,
    new_id: str | int,
    expected_uuid: str,
    confirm_write: bool = False,
) -> dict[str, Any]:
    method, module, action_name = client_module.CHANNEL_MOVE
    refusal = check_write_gate(ctx.settings, method, confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        # Validate inside run_tool so an InvalidInput maps there (single mapper).
        src, dst = validate_channel_id(old_id), validate_channel_id(new_id)
        uuid = validate_uuid(expected_uuid)
        if src == dst:
            raise InvalidInput("old_id and new_id must differ")
        request = {"method": method, module: {action_name: {"old_id": src, "new_id": dst}}}

        async def write() -> dict[str, Any]:
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
            before = {"source": _public(source), "target": None}
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

        return await ctx.writes.run(request, write)

    return await run_tool("nvr_move_channel", action)


async def set_channel_credentials(
    ctx: ToolContext,
    channel_id: str | int,
    expected_uuid: str,
    username: str,
    password: str,
    confirm_write: bool = False,
) -> dict[str, Any]:
    method, module, action_name = client_module.CHANNEL_EDIT
    refusal = check_write_gate(ctx.settings, method, confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        # Validate inside run_tool so an InvalidInput maps there (single mapper).
        cid, uuid = validate_channel_id(channel_id), validate_uuid(expected_uuid)
        uname, pwd = validate_username(username), validate_password(password)
        pubkey = await ctx.client.device_password_pubkey()

        def build(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
            # RSA PKCS#1 v1.5 is randomised, so each call yields a fresh ciphertext.
            edit_row = build_edit_dev_row(row, uname, crypto.rsa_encrypt_pkcs1v15(pubkey, pwd))
            return {"method": method, module: {action_name: edit_row}}, edit_row

        # Safe reads (channel list + static pubkey) so dry-run can echo the exact
        # payload. The write itself still runs under the serial lock below.
        preview = _require_uuid(_find(await ctx.client.list_channels(), cid), cid, uuid)
        request, _ = build(preview)

        async def write() -> dict[str, Any]:
            before = _require_uuid(_find(await ctx.client.list_channels(), cid), cid, uuid)
            send_request, edit_row = build(before)
            response = await ctx.client.set_channel_credentials(edit_row)
            after = await _poll_until_settled(ctx.client, cid)
            return {
                "dry_run": False,
                "request": send_request,
                "response": response,
                "before": _public(before),
                "after": _public(after),
                "settled": after is not None and is_settled(after),
            }

        return await ctx.writes.run(request, write)

    return await run_tool("nvr_set_channel_credentials", action)


def _build_renumber_plan(
    row: dict[str, Any], channel_id: str, new_ip: str, username: str, pubkey: str, password: str
) -> dict[str, Any]:
    """Build the three planned requests (delete, re-add, rename) for a renumber.

    Used to echo the plan under dry-run. The rename here is a TEMPLATE built from the
    current row (its id is still the old one); the real rename targets the new slot id
    discovered after the re-add. Credential fields are redacted by ``run_tool``.
    """
    device = build_add_dev(
        str(row.get("connect_prot", "")),
        new_ip,
        str(row.get("port", "")),
        username,
        crypto.rsa_encrypt_pkcs1v15(pubkey, password),
    )
    rename_row = {
        **build_edit_dev_row(row, username, crypto.rsa_encrypt_pkcs1v15(pubkey, password)),
        "name": str(row.get("name", "")),
    }
    return {
        "delete": _delete_request(channel_id),
        "add": _add_request(device),
        "rename": _edit_request(rename_row),
    }


async def renumber_channel(
    ctx: ToolContext,
    channel_id: str | int,
    expected_uuid: str,
    new_ip: str,
    username: str,
    password: str,
    confirm_write: bool = False,
) -> dict[str, Any]:
    # chm_edit_dev silently ignores the ``ip`` field (ip is discovery-derived, not
    # editable), so re-pointing a camera to a new IP is delete + re-add + rename.
    method = client_module.CHANNEL_DELETE[0]
    refusal = check_write_gate(ctx.settings, method, confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        # Validate inside run_tool so an InvalidInput maps there (single mapper).
        cid, uuid = validate_channel_id(channel_id), validate_uuid(expected_uuid)
        target_ip = validate_ipv4(new_ip)
        uname, pwd = validate_username(username), validate_password(password)
        pubkey = await ctx.client.device_password_pubkey()

        # Safe reads (channel list + static pubkey) so dry-run can echo the exact plan.
        preview = _require_uuid(_find(await ctx.client.list_channels(), cid), cid, uuid)
        request = _build_renumber_plan(preview, cid, target_ip, uname, pubkey, pwd)

        async def write() -> dict[str, Any]:
            before = _require_uuid(_find(await ctx.client.list_channels(), cid), cid, uuid)
            orig_name = str(before.get("name", ""))
            connect_prot = str(before.get("connect_prot", ""))
            port = str(before.get("port", ""))

            # 1. Delete the existing binding (does not change the camera's own IP).
            del_req = _delete_request(cid)
            del_resp = await ctx.client.delete_channels([cid])

            # 2. Re-add at the new IP (lands in the first empty slot; name resets).
            device = build_add_dev(
                connect_prot, target_ip, port, uname, crypto.rsa_encrypt_pkcs1v15(pubkey, pwd)
            )
            add_req = _add_request(device)
            add_resp = await ctx.client.add_channel(device)

            # 3. Find the re-added row by uuid to learn its new channel id.
            readded = await _poll_for_uuid(ctx.client, uuid)
            if readded is None:
                raise PreconditionFailed(
                    f"The camera did not re-appear after re-add at '{target_ip}'. It may be "
                    "unreachable at the new IP; verify the DHCP reservation and that the camera "
                    "rebooted onto it, then re-read the channel list.",
                    reason="READD_NOT_FOUND",
                    context={"expected_uuid": uuid, "new_ip": target_ip},
                )
            new_cid = row_id(readded)

            # 4. Restore the original name and re-assert auth (fresh ciphertext).
            edit_row = {
                **build_edit_dev_row(readded, uname, crypto.rsa_encrypt_pkcs1v15(pubkey, pwd)),
                "name": orig_name,
            }
            rename_req = _edit_request(edit_row)
            rename_resp = await ctx.client.set_channel_credentials(edit_row)

            # 5. Poll until connected+authenticated (transient -71558/-71560 is not failure).
            after = await _poll_until_settled(ctx.client, new_cid)
            return {
                "dry_run": False,
                "requests": {"delete": del_req, "add": add_req, "rename": rename_req},
                "responses": {"delete": del_resp, "add": add_resp, "rename": rename_resp},
                "before": _public(before),
                "after": _public(after),
                "new_channel_id": new_cid,
                "settled": after is not None and is_settled(after),
            }

        return await ctx.writes.run(request, write)

    return await run_tool("nvr_renumber_channel", action)


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
        channel_id: str,
        expected_uuid: str,
        confirm_write: ConfirmWrite = False,
        force: bool = False,
    ) -> dict[str, Any]:
        """Unbind one channel (chm_del_dev). DESTRUCTIVE. Requires
        VIGI_NVR_ALLOW_WRITES=true, confirm_write=true and expected_uuid equal to
        the live row's uuid. Refuses a row whose live online=="1" (a connected
        camera) unless force=true. Honours VIGI_NVR_DRY_RUN. Run nvr_backup_config
        first. Returns before/after rows."""
        return await remove_channel(ctx, channel_id, expected_uuid, confirm_write, force)

    @mcp.tool(name="nvr_move_channel")
    async def _move(
        old_id: str, new_id: str, expected_uuid: str, confirm_write: ConfirmWrite = False
    ) -> dict[str, Any]:
        """Move a binding to another channel slot (chm_mod_dev_chn), keeping its
        credentials and settings. Refuses if new_id is occupied (the firmware would
        replace it). Same gates as nvr_remove_channel. Returns before/after rows."""
        return await move_channel(ctx, old_id, new_id, expected_uuid, confirm_write)

    @mcp.tool(name="nvr_set_channel_credentials")
    async def _set_creds(
        channel_id: str,
        expected_uuid: str,
        username: str,
        password: str,
        confirm_write: ConfirmWrite = False,
    ) -> dict[str, Any]:
        """Re-authenticate a bound channel (camera) by pushing a username and an
        RSA-encrypted password to it (chm_edit_dev), recovering a camera whose
        stored credentials went stale. The password is encrypted with the device's
        fixed public key and is never logged; credential fields in the returned
        before/after rows are redacted. Same gates as nvr_remove_channel
        (VIGI_NVR_ALLOW_WRITES=true, confirm_write=true, expected_uuid must match
        the live row) and honours VIGI_NVR_DRY_RUN. After the edit it polls until the
        channel reports connected+authenticated (conn_status==auth_result=="0");
        the transient "authenticating" state is not treated as a failure. Returns
        before/after status and whether the channel settled."""
        return await set_channel_credentials(
            ctx, channel_id, expected_uuid, username, password, confirm_write
        )

    @mcp.tool(name="nvr_renumber_channel")
    async def _renumber(
        channel_id: str,
        expected_uuid: str,
        new_ip: str,
        username: str,
        password: str,
        confirm_write: ConfirmWrite = False,
    ) -> dict[str, Any]:
        """Re-point an already-bound channel to a NEW camera IP. DESTRUCTIVE and the
        channel id CHANGES: the firmware's chm_edit_dev silently ignores the ip field
        (ip is discovery-derived), so this unbinds the channel (chm_del_dev), re-adds
        it at new_ip (chm_add_dev_list, which lands in the first empty slot and resets
        the name to the model default), finds the re-added row by its uuid, then
        restores the original name and re-asserts auth (chm_edit_dev). It does NOT
        change the camera's own IP/DHCP: the caller must ensure the camera is already
        reachable at new_ip (e.g. a DHCP reservation + reboot) BEFORE calling. Same
        gates as nvr_remove_channel (VIGI_NVR_ALLOW_WRITES=true, confirm_write=true,
        expected_uuid must match the live row) and honours VIGI_NVR_DRY_RUN (echoes the
        planned delete+add+rename requests). The password is RSA-encrypted with the
        device key and never logged; credential fields in the result are redacted. After
        the re-add it polls until the channel reports connected+authenticated
        (conn_status==auth_result=="0"); the transient "authenticating" states
        (auth_result -71558/-71560) are not failures. Run nvr_backup_config first.
        Returns before/after rows, the new_channel_id and whether it settled."""
        return await renumber_channel(
            ctx, channel_id, expected_uuid, new_ip, username, password, confirm_write
        )

    return [
        "nvr_list_channels",
        "nvr_get_channel",
        "nvr_find_duplicate_channels",
        "nvr_plan_channel_cleanup",
        "nvr_remove_channel",
        "nvr_move_channel",
        "nvr_set_channel_credentials",
        "nvr_renumber_channel",
    ]
