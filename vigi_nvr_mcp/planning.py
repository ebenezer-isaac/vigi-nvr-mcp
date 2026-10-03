"""Pure planning for a safe channel cleanup.

``build_cleanup_plan(rows)`` turns a live ``added_dev`` snapshot into an ordered,
resumable plan an LLM client can execute verbatim, one step at a time. It performs
**no I/O** and never mutates its input; the tool wrapper in ``tools/channels.py``
is the only place that talks to a device.

The plan always (a) backs up the config, (b) removes every ghost binding, one call
per ghost, (c) re-reads the table, (d) moves each real camera stranded in a slot
above ``MAX_LOW_SLOT`` into the lowest confirmed-empty low slot, re-reading between
each move, and (e) ends with a final list. Every step carries the exact tool
arguments plus the ``precondition`` the client must confirm from the previous
step's result.

Ghost rule (from ``01-NVR-SPEC.md`` N3): a row is a ghost iff another row shares
its ``uuid`` AND it is offline (``online == "0"``) AND ``conn_status != "0"`` AND
(``auth_result == "1"`` OR its name is a bare model code). A matching row that is
*online* is never auto-removed; it is surfaced under ``unsafe_if`` instead.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

MAX_LOW_SLOT = 8
ID_FIELDS = ("id", "channel_id", "chn_id", "_row_key")
# A bare vendor model code used as a name, e.g. "C340WS": all caps/digits, has a
# digit, no spaces. Human names ("Front Gate") never match.
GENERIC_NAME_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{1,30}")

BLOCKING_CONDITIONS = frozenset({"MORE_THAN_8_REAL_CAMERAS", "TWO_REAL_CAMERAS_SHARE_UUID"})


class PlanStep(BaseModel):
    step: int
    tool: str
    args: dict[str, Any]
    rationale: str
    precondition: str


class UnsafeCondition(BaseModel):
    condition: str
    detail: str
    affected_ids: list[str] = Field(default_factory=list)


class LayoutEntry(BaseModel):
    slot: int
    source_id: str | None
    uuid: str
    name: str | None


class PlanSummary(BaseModel):
    total_rows: int
    real_cameras: int
    ghosts_to_remove: int
    online_ghosts_flagged: int
    moves: int
    final_channel_count: int
    final_layout: list[LayoutEntry]


class CleanupPlan(BaseModel):
    steps: list[PlanStep]
    summary: PlanSummary
    unsafe_if: list[UnsafeCondition]
    resumable: bool = True


def _norm(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _row_id(row: dict[str, Any]) -> str | None:
    for field in ID_FIELDS:
        value = row.get(field)
        if value not in (None, ""):
            return str(value).strip()
    return None


def _slot(row: dict[str, Any]) -> int | None:
    rid = _row_id(row)
    if rid is None:
        return None
    try:
        return int(rid)
    except ValueError:
        return None


def _is_generic_name(row: dict[str, Any]) -> bool:
    name = _norm(row.get("name"))
    if not name:
        return True
    for field in ("model", "vender"):
        other = _norm(row.get(field))
        if other and name.casefold() == other.casefold():
            return True
    return bool(GENERIC_NAME_RE.fullmatch(name)) and any(ch.isdigit() for ch in name)


def _classify(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Split rows into (removable ghosts, online ghosts to flag, real cameras)."""
    counts: dict[str, int] = {}
    for row in rows:
        uuid = _norm(row.get("uuid"))
        if uuid:
            counts[uuid] = counts.get(uuid, 0) + 1
    ghosts: list[dict[str, Any]] = []
    online_ghosts: list[dict[str, Any]] = []
    reals: list[dict[str, Any]] = []
    for row in rows:
        uuid = _norm(row.get("uuid"))
        has_duplicate = bool(uuid) and counts.get(uuid, 0) > 1
        conn = _norm(row.get("conn_status"))
        ghost_like = (
            has_duplicate
            and conn not in ("", "0")
            and (_norm(row.get("auth_result")) == "1" or _is_generic_name(row))
        )
        online = _norm(row.get("online"))
        if ghost_like and online == "0":
            ghosts.append(row)
        elif ghost_like and online == "1":
            online_ghosts.append(row)
        else:
            reals.append(row)
    return ghosts, online_ghosts, reals


def _sort_key(row: dict[str, Any]) -> tuple[int, str]:
    slot = _slot(row)
    return (slot if slot is not None else 1 << 30, _row_id(row) or "")


def _detect_unsafe(
    online_ghosts: list[dict[str, Any]],
    reals: list[dict[str, Any]],
    movers: list[dict[str, Any]],
) -> list[UnsafeCondition]:
    unsafe: list[UnsafeCondition] = []
    if online_ghosts:
        unsafe.append(
            UnsafeCondition(
                condition="GHOST_ONLINE",
                detail=(
                    "A ghost-looking binding is reporting online, so it is NOT auto-removed. "
                    "Inspect it; if it is truly stale, remove it manually with force=true."
                ),
                affected_ids=[i for g in online_ghosts if (i := _row_id(g)) is not None],
            )
        )
    if len(reals) > MAX_LOW_SLOT:
        unsafe.append(
            UnsafeCondition(
                condition="MORE_THAN_8_REAL_CAMERAS",
                detail=(
                    f"{len(reals)} real cameras exceed the {MAX_LOW_SLOT} low slots; packing is "
                    "ambiguous. No moves are planned — re-home manually."
                ),
                affected_ids=[i for r in reals if (i := _row_id(r)) is not None],
            )
        )
    real_counts: dict[str, int] = {}
    for row in reals:
        uuid = _norm(row.get("uuid"))
        if uuid:
            real_counts[uuid] = real_counts.get(uuid, 0) + 1
    ambiguous = sorted(
        {u for m in movers if (u := _norm(m.get("uuid"))) and real_counts.get(u, 0) > 1}
    )
    if ambiguous:
        unsafe.append(
            UnsafeCondition(
                condition="TWO_REAL_CAMERAS_SHARE_UUID",
                detail=(
                    "Two real cameras share a uuid, so a move's expected_uuid cannot identify one "
                    "unambiguously. No moves are planned — resolve the duplicate first."
                ),
                affected_ids=[
                    i
                    for r in reals
                    if _norm(r.get("uuid")) in ambiguous and (i := _row_id(r)) is not None
                ],
            )
        )
    return unsafe


def build_cleanup_plan(rows: list[dict[str, Any]]) -> CleanupPlan:
    """Build the ordered cleanup plan. Pure: ``rows`` is never mutated."""
    rows = [dict(r) for r in rows]
    ghosts, online_ghosts, reals = _classify(rows)
    movers = sorted(
        (r for r in reals if (s := _slot(r)) is not None and s > MAX_LOW_SLOT),
        key=_sort_key,
    )
    unsafe = _detect_unsafe(online_ghosts, reals, movers)
    moves_blocked = any(c.condition in BLOCKING_CONDITIONS for c in unsafe)

    occupied_after = {
        s for r in reals if (s := _slot(r)) is not None and 1 <= s <= MAX_LOW_SLOT
    } | {s for g in online_ghosts if (s := _slot(g)) is not None and 1 <= s <= MAX_LOW_SLOT}
    free_slots = [s for s in range(1, MAX_LOW_SLOT + 1) if s not in occupied_after]

    assignments: list[tuple[dict[str, Any], int]] = []
    if not moves_blocked:
        pool = list(free_slots)
        for mover in movers:
            if not pool:
                break
            assignments.append((mover, pool.pop(0)))

    steps = _build_steps(sorted(ghosts, key=_sort_key), assignments)
    summary = _build_summary(rows, reals, ghosts, online_ghosts, assignments)
    return CleanupPlan(steps=steps, summary=summary, unsafe_if=unsafe)


def _build_steps(
    ghosts: list[dict[str, Any]],
    assignments: list[tuple[dict[str, Any], int]],
) -> list[PlanStep]:
    steps: list[PlanStep] = []

    def add(tool: str, args: dict[str, Any], rationale: str, precondition: str) -> None:
        steps.append(
            PlanStep(
                step=len(steps) + 1,
                tool=tool,
                args=args,
                rationale=rationale,
                precondition=precondition,
            )
        )

    add(
        "nvr_backup_config",
        {},
        "Download a full config backup before any destructive change so the estate can be "
        "restored if a step surprises us.",
        "None — this is the first step.",
    )
    for ghost in ghosts:
        gid, guid = _row_id(ghost), _norm(ghost.get("uuid"))
        add(
            "nvr_remove_channel",
            {"channel_id": gid, "expected_uuid": guid, "confirm_write": True},
            f"Remove the ghost binding in slot {gid} (offline duplicate of uuid {guid}).",
            f"Channel {gid} is still present with uuid {guid}; the previous step returned success.",
        )

    if not assignments:
        removed = ", ".join(_row_id(g) or "?" for g in ghosts) or "none"
        add(
            "nvr_list_channels",
            {},
            "Final verification of the channel table.",
            f"Every preceding step returned success (ghosts removed: {removed}).",
        )
        return steps

    removed = ", ".join(_row_id(g) or "?" for g in ghosts) or "none"
    add(
        "nvr_list_channels",
        {},
        "Re-read the live table so each move targets a confirmed-empty low slot.",
        f"All removal steps returned removed:true (channels removed: {removed}).",
    )
    last = len(assignments) - 1
    for index, (mover, slot) in enumerate(assignments):
        oid, muid = _row_id(mover), _norm(mover.get("uuid"))
        add(
            "nvr_move_channel",
            {
                "old_id": oid,
                "new_id": str(slot),
                "expected_uuid": muid,
                "confirm_write": True,
            },
            f"Re-home the camera in slot {oid} into free low slot {slot}, preserving its binding.",
            f"Slot {slot} is empty in the latest list AND channel {oid} shows uuid {muid}.",
        )
        add(
            "nvr_list_channels",
            {},
            "Final verification: confirm the new layout."
            if index == last
            else "Verify this move and refresh state before the next move.",
            f"The move of channel {oid} to slot {slot} returned moved:true.",
        )
    return steps


def _build_summary(
    rows: list[dict[str, Any]],
    reals: list[dict[str, Any]],
    ghosts: list[dict[str, Any]],
    online_ghosts: list[dict[str, Any]],
    assignments: list[tuple[dict[str, Any], int]],
) -> PlanSummary:
    occupant: dict[int, dict[str, Any]] = {}
    for row in reals:
        slot = _slot(row)
        if slot is not None and 1 <= slot <= MAX_LOW_SLOT:
            occupant[slot] = row
    for ghost in online_ghosts:
        slot = _slot(ghost)
        if slot is not None and 1 <= slot <= MAX_LOW_SLOT and slot not in occupant:
            occupant[slot] = ghost
    for mover, slot in assignments:
        occupant[slot] = mover

    layout = [
        LayoutEntry(
            slot=slot,
            source_id=_row_id(occupant[slot]) if slot in occupant else None,
            uuid=_norm(occupant[slot].get("uuid")) if slot in occupant else "",
            name=(_norm(occupant[slot].get("name")) or None) if slot in occupant else None,
        )
        for slot in range(1, MAX_LOW_SLOT + 1)
    ]
    return PlanSummary(
        total_rows=len(rows),
        real_cameras=len(reals),
        ghosts_to_remove=len(ghosts),
        online_ghosts_flagged=len(online_ghosts),
        moves=len(assignments),
        final_channel_count=sum(1 for entry in layout if entry.source_id is not None),
        final_layout=layout,
    )
