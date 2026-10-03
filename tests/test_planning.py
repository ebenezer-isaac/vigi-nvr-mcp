"""Tests for the pure cleanup planner and the read-only tool wrapper.

The owner-pattern fixture is anonymised: synthetic uuids, no MACs, no real names.
14 rows — ghosts at 1,2,7,8,13,14 (3 uuids), real-but-offline at 9,10,12, a real
online camera at 11, two legitimately shared-uuid online rows at 5 and 6, and two
plain online cameras at 3,4 already in low slots.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from vigi_nvr_mcp.planning import build_cleanup_plan
from vigi_nvr_mcp.tools import channels

U_A, U_D, U_E, U_F = "uuid-a1", "uuid-d1", "uuid-e1", "uuid-f1"
U_B, U_C, U_SHARED = "uuid-b1", "uuid-c1", "uuid-shared"


def _ghost(cid: str, uuid: str) -> dict[str, Any]:
    return {
        "id": cid,
        "uuid": uuid,
        "online": "0",
        "conn_status": "4",
        "auth_result": "1",
        "name": "C340WS",
    }


def _cam(cid: str, uuid: str, name: str, *, online: str, conn: str) -> dict[str, Any]:
    return {
        "id": cid,
        "uuid": uuid,
        "online": online,
        "conn_status": conn,
        "auth_result": "0",
        "name": name,
    }


def owner_rows() -> list[dict[str, Any]]:
    return [
        _ghost("1", U_A),
        _ghost("2", U_A),
        _cam("3", U_B, "Backyard", online="1", conn="0"),
        _cam("4", U_C, "Garage", online="1", conn="0"),
        _cam("5", U_SHARED, "Lobby East", online="1", conn="0"),
        _cam("6", U_SHARED, "Lobby West", online="1", conn="0"),
        _ghost("7", U_D),
        _ghost("8", U_D),
        _cam("9", U_A, "Front Gate", online="0", conn="1"),
        _cam("10", U_D, "Driveway", online="0", conn="1"),
        _cam("11", U_E, "Side Path", online="1", conn="0"),
        _cam("12", U_F, "Garden", online="0", conn="1"),
        _ghost("13", U_F),
        _ghost("14", U_F),
    ]


def _digest(plan) -> list[tuple[str, dict[str, Any]]]:
    return [(s.tool, s.args) for s in plan.steps]


# ---- the owner pattern: exact ordered plan ----------------------------------


def test_owner_plan_is_exact_ordered_sequence() -> None:
    rows = owner_rows()
    snapshot = copy.deepcopy(rows)
    plan = build_cleanup_plan(rows)
    assert rows == snapshot  # planner never mutates its input

    assert _digest(plan) == [
        ("nvr_backup_config", {}),
        ("nvr_remove_channel", {"channel_id": "1", "expected_uuid": U_A, "confirm_write": True}),
        ("nvr_remove_channel", {"channel_id": "2", "expected_uuid": U_A, "confirm_write": True}),
        ("nvr_remove_channel", {"channel_id": "7", "expected_uuid": U_D, "confirm_write": True}),
        ("nvr_remove_channel", {"channel_id": "8", "expected_uuid": U_D, "confirm_write": True}),
        ("nvr_remove_channel", {"channel_id": "13", "expected_uuid": U_F, "confirm_write": True}),
        ("nvr_remove_channel", {"channel_id": "14", "expected_uuid": U_F, "confirm_write": True}),
        ("nvr_list_channels", {}),
        (
            "nvr_move_channel",
            {"old_id": "9", "new_id": "1", "expected_uuid": U_A, "confirm_write": True},
        ),
        ("nvr_list_channels", {}),
        (
            "nvr_move_channel",
            {"old_id": "10", "new_id": "2", "expected_uuid": U_D, "confirm_write": True},
        ),
        ("nvr_list_channels", {}),
        (
            "nvr_move_channel",
            {"old_id": "11", "new_id": "7", "expected_uuid": U_E, "confirm_write": True},
        ),
        ("nvr_list_channels", {}),
        (
            "nvr_move_channel",
            {"old_id": "12", "new_id": "8", "expected_uuid": U_F, "confirm_write": True},
        ),
        ("nvr_list_channels", {}),
    ]


def test_owner_plan_is_safe_and_summarised() -> None:
    plan = build_cleanup_plan(owner_rows())
    assert plan.unsafe_if == []  # 5 and 6 share a uuid but are both online -> not flagged
    assert plan.resumable is True
    s = plan.summary
    assert (s.total_rows, s.real_cameras, s.ghosts_to_remove, s.moves) == (14, 8, 6, 0 + 4)
    assert s.online_ghosts_flagged == 0
    assert s.final_channel_count == 8
    layout = {e.slot: e.source_id for e in s.final_layout}
    assert layout == {1: "9", 2: "10", 3: "3", 4: "4", 5: "5", 6: "6", 7: "11", 8: "12"}


def test_shared_uuid_online_pair_never_removed_or_flagged() -> None:
    plan = build_cleanup_plan(owner_rows())
    removed = [s.args["channel_id"] for s in plan.steps if s.tool == "nvr_remove_channel"]
    assert "5" not in removed and "6" not in removed
    moved = [s.args["old_id"] for s in plan.steps if s.tool == "nvr_move_channel"]
    assert "5" not in moved and "6" not in moved


def test_preconditions_reference_prior_results() -> None:
    plan = build_cleanup_plan(owner_rows())
    assert plan.steps[0].precondition.startswith("None")
    move = next(s for s in plan.steps if s.tool == "nvr_move_channel")
    assert "empty" in move.precondition and "uuid" in move.precondition


# ---- edge cases -------------------------------------------------------------


def test_no_ghosts_gives_backup_plus_list_only() -> None:
    rows = [
        _cam("1", "uuid-1", "A", online="1", conn="0"),
        _cam("2", "uuid-2", "B", online="1", conn="0"),
    ]
    plan = build_cleanup_plan(rows)
    assert _digest(plan) == [("nvr_backup_config", {}), ("nvr_list_channels", {})]
    assert plan.unsafe_if == []
    assert plan.summary.moves == 0


def test_real_camera_already_low_is_never_moved() -> None:
    rows = [
        _cam("2", "uuid-2", "Already Low", online="1", conn="0"),
        _cam("9", "uuid-9", "Stranded", online="0", conn="1"),
    ]
    plan = build_cleanup_plan(rows)
    moves = [
        (s.args["old_id"], s.args["new_id"]) for s in plan.steps if s.tool == "nvr_move_channel"
    ]
    assert moves == [("9", "1")]  # slot 2 stays put; 9 fills the lowest free slot (1)


def test_nine_real_cameras_blocks_moves_and_is_flagged() -> None:
    rows = [_cam(str(i), f"uuid-{i}", f"Cam {i}", online="1", conn="0") for i in range(1, 9)]
    rows.append(_cam("9", "uuid-9", "Stranded", online="0", conn="1"))  # 9th real camera
    plan = build_cleanup_plan(rows)
    assert [s.tool for s in plan.steps if s.tool == "nvr_move_channel"] == []
    conditions = {c.condition for c in plan.unsafe_if}
    assert "MORE_THAN_8_REAL_CAMERAS" in conditions
    assert plan.summary.real_cameras == 9


def test_two_movers_sharing_uuid_block_moves() -> None:
    rows = [
        _cam("9", "dup-uuid", "Cam A", online="0", conn="1"),
        _cam("10", "dup-uuid", "Cam B", online="0", conn="1"),
    ]
    plan = build_cleanup_plan(rows)
    assert [s for s in plan.steps if s.tool == "nvr_move_channel"] == []
    flagged = {c.condition for c in plan.unsafe_if}
    assert "TWO_REAL_CAMERAS_SHARE_UUID" in flagged
    affected = next(c for c in plan.unsafe_if if c.condition == "TWO_REAL_CAMERAS_SHARE_UUID")
    assert set(affected.affected_ids) == {"9", "10"}


def test_online_ghost_is_flagged_not_removed() -> None:
    rows = [
        {
            "id": "1",
            "uuid": "g",
            "online": "1",
            "conn_status": "4",
            "auth_result": "1",
            "name": "C340WS",
        },
        _cam("9", "g", "Real", online="0", conn="1"),
    ]
    plan = build_cleanup_plan(rows)
    removed = [s.args["channel_id"] for s in plan.steps if s.tool == "nvr_remove_channel"]
    assert "1" not in removed
    online_ghost = next(c for c in plan.unsafe_if if c.condition == "GHOST_ONLINE")
    assert online_ghost.affected_ids == ["1"]
    assert plan.summary.online_ghosts_flagged == 1


def test_integer_ids_produce_the_same_plan_as_string_ids() -> None:
    int_rows = [{**r, "id": int(r["id"])} for r in owner_rows()]
    assert _digest(build_cleanup_plan(int_rows)) == _digest(build_cleanup_plan(owner_rows()))


def test_plan_is_json_serialisable_and_round_trips() -> None:
    plan = build_cleanup_plan(owner_rows())
    text = plan.model_dump_json()
    reloaded = json.loads(text)
    assert reloaded["steps"][0]["tool"] == "nvr_backup_config"
    assert reloaded["summary"]["real_cameras"] == 8
    assert isinstance(reloaded["unsafe_if"], list)


def test_plan_is_idempotent() -> None:
    first = build_cleanup_plan(owner_rows())
    second = build_cleanup_plan(owner_rows())
    assert first.model_dump() == second.model_dump()


def test_replanning_already_clean_state_has_no_writes() -> None:
    """After the plan has run, re-planning the packed layout asks only for backup+list."""
    clean = [
        _cam("1", U_A, "Front Gate", online="1", conn="0"),
        _cam("2", U_D, "Driveway", online="1", conn="0"),
        _cam("3", U_B, "Backyard", online="1", conn="0"),
    ]
    plan = build_cleanup_plan(clean)
    assert [s.tool for s in plan.steps] == ["nvr_backup_config", "nvr_list_channels"]


# ---- the tool wrapper -------------------------------------------------------


async def test_plan_tool_returns_envelope(make_ctx, fake) -> None:
    fake.api_handler = lambda token, body: {"error_code": 0, "chm": {"added_dev": owner_rows()}}
    result = await channels.plan_channel_cleanup(make_ctx())
    assert set(result) == {"success", "data", "error"}
    assert result["success"] is True
    steps = result["data"]["steps"]
    assert steps[0]["tool"] == "nvr_backup_config"
    assert len([s for s in steps if s["tool"] == "nvr_move_channel"]) == 4
    assert result["data"]["unsafe_if"] == []


@pytest.mark.parametrize("bad", [[], [{"id": "1"}], [{"id": "1", "uuid": ""}]])
async def test_plan_tool_handles_degenerate_tables(make_ctx, fake, bad) -> None:
    fake.api_handler = lambda token, body: {"error_code": 0, "chm": {"added_dev": bad}}
    result = await channels.plan_channel_cleanup(make_ctx())
    assert result["success"] is True
    assert result["data"]["steps"][0]["tool"] == "nvr_backup_config"
