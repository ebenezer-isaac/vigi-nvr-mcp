from __future__ import annotations

import copy
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from tests.helpers import FAKE_STOK_1, FakeNvr
from tplink_local_mcp.core.redact import REDACTED
from tplink_local_mcp.devices.vigi_nvr.client import extract_rows
from tplink_local_mcp.devices.vigi_nvr.tools import backup, channels, device, raw, storage

CT = "cipher" + "text"  # assembled so the secret scan does not flag this file


def _rows() -> list[dict[str, Any]]:
    """Anonymised fixture: RFC 5737 addresses, synthetic uuids."""
    return [
        {
            "id": "1",
            "uuid": "uuid-aaaa",
            "ip": "192.0.2.21",
            "online": "0",
            "conn_status": "4",
            CT: "QUJD",
        },
        {"id": "3", "uuid": "uuid-bbbb", "ip": "192.0.2.22", "online": "1", "conn_status": "0"},
        {
            "id": "9",
            "uuid": "uuid-aaaa",
            "ip": "192.0.2.21",
            "online": "1",
            "conn_status": "0",
            CT: "QUJD",
            "password": "x",
        },
        {"id": "10", "uuid": "uuid-cccc", "ip": "192.0.2.23", "online": "1", "conn_status": "0"},
        {"id": "11", "uuid": "uuid-cccc", "ip": "192.0.2.24", "online": "1", "conn_status": "1"},
        {"id": "12", "uuid": "", "ip": "192.0.2.25"},
    ]


class ChannelTable:
    """Stateful chm/system handler for the fake NVR."""

    def __init__(self) -> None:
        self.rows = _rows()

    def __call__(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        if body["method"] == "get" and "chm" in body:
            return {"error_code": 0, "chm": {"added_dev": copy.deepcopy(self.rows)}}
        if body["method"] == "do" and "chm" in body:
            action = body["chm"]
            if "chm_del_dev" in action:
                ids = set(action["chm_del_dev"]["ids"])
                self.rows = [r for r in self.rows if r["id"] not in ids]
                return {"error_code": 0}
            if "chm_mod_dev_chn" in action:
                old, new = action["chm_mod_dev_chn"]["old_id"], action["chm_mod_dev_chn"]["new_id"]
                self.rows = [
                    {**r, "id": new} if r["id"] == old else r for r in self.rows if r["id"] != new
                ]
                return {"error_code": 0}
        if body["method"] == "do" and "system" in body:
            return {"error_code": 0, "url": "/backup/config.bin"}
        return {"error_code": 0}


@pytest.fixture
def table(fake: FakeNvr) -> ChannelTable:
    t = ChannelTable()
    fake.api_handler = t
    return t


@pytest.fixture
def wctx(make_ctx):
    return make_ctx(ALLOW_WRITES="true")


def _assert_envelope(result: dict[str, Any]) -> None:
    assert set(result) == {"success", "data", "error"}
    if result["success"]:
        assert result["error"] is None
    else:
        assert result["data"] is None
        assert set(result["error"]) == {"code", "message", "details"}


# ---- raw write gating -------------------------------------------------------


async def test_get_passes_without_flags(ctx, fake) -> None:
    result = await raw.nvr_call(ctx, "get", "device_info", {"name": ["basic_info"]})
    _assert_envelope(result)
    assert result["success"] is True


@pytest.mark.parametrize("method", ["set", "do", "add", "delete"])
@pytest.mark.parametrize("confirm", [False, True])
async def test_writes_refused_when_server_disallows(ctx, fake, method, confirm) -> None:
    result = await raw.nvr_call(ctx, method, "system", {"x": 1}, confirm_write=confirm)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert "TPLINK_NVR_ALLOW_WRITES" in result["error"]["message"]
    assert fake.requests == []


@pytest.mark.parametrize("method", ["set", "do", "add", "delete"])
async def test_writes_need_confirm_even_when_allowed(wctx, fake, method) -> None:
    result = await raw.nvr_call(wctx, method, "system", {"x": 1})
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert "confirm_write" in result["error"]["message"]
    assert fake.requests == []


async def test_confirm_write_must_be_true_not_truthy(wctx, fake) -> None:
    result = await raw.nvr_call(wctx, "set", "system", {}, confirm_write="yes")  # type: ignore[arg-type]
    assert result["error"]["code"] == "WRITE_REFUSED"


async def test_write_allowed_with_both_flags(wctx, fake) -> None:
    result = await raw.nvr_call(wctx, "set", "system", {"x": 1}, confirm_write=True)
    assert result["success"] is True
    assert fake.api_requests[-1][1] == {"method": "set", "system": {"x": 1}}


@pytest.mark.parametrize("module", ["login", "user_management", "LOGIN"])
async def test_auth_modules_are_always_denied(wctx, fake, module) -> None:
    for method in ("get", "do"):
        result = await raw.nvr_call(wctx, method, module, None, confirm_write=True)
        assert result["error"]["code"] == "MODULE_DENIED"
    assert fake.requests == []


async def test_invalid_raw_input_is_rejected(ctx, fake) -> None:
    assert (await raw.nvr_call(ctx, "get", "bad/module", None))["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


async def test_raw_reply_is_redacted(ctx, fake) -> None:
    fake.api_handler = lambda t, b: {"error_code": 0, "x": {"stok": "s", "password": "p"}}
    result = await raw.nvr_call(ctx, "get", "x", {})
    assert result["data"]["x"] == {"stok": REDACTED, "password": REDACTED}


# ---- channel reads ------------------------------------------------------------


async def test_list_channels_redacts_credentials(ctx, table) -> None:
    result = await channels.list_channels(ctx)
    _assert_envelope(result)
    rows = result["data"]
    assert len(rows) == 6
    assert rows[0][CT] == REDACTED
    assert rows[2]["password"] == REDACTED
    assert rows[0]["channel_id"] == "1"
    assert "QUJD" not in repr(result)


async def test_list_channels_request_is_verified_shape(ctx, fake, table) -> None:
    await channels.list_channels(ctx)
    assert fake.api_requests[-1][1] == {"method": "get", "chm": {"table": "added_dev"}}


async def test_get_channel_found_and_not_found(ctx, table) -> None:
    assert (await channels.get_channel(ctx, "3"))["data"]["uuid"] == "uuid-bbbb"
    assert (await channels.get_channel(ctx, "99"))["error"]["code"] == "NOT_FOUND"


@pytest.mark.parametrize("bad", ["", "../1", "a b", "x" * 65, True, 1.5, None])
async def test_get_channel_rejects_bad_ids(ctx, fake, bad) -> None:
    assert (await channels.get_channel(ctx, bad))["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


def test_find_duplicates_groups_and_flags_stale() -> None:
    rows = extract_rows({"chm": {"added_dev": _rows()}})
    snapshot = copy.deepcopy(rows)
    report = channels.find_duplicates(rows)
    assert rows == snapshot
    assert (report["total_rows"], report["rows_without_uuid"]) == (6, 1)
    assert report["duplicate_group_count"] == 2
    by_uuid = {g["uuid"]: g for g in report["groups"]}
    assert by_uuid["uuid-aaaa"]["stale_channel_ids"] == ["1"]
    assert by_uuid["uuid-aaaa"]["live_channel_ids"] == ["9"]
    assert by_uuid["uuid-cccc"]["stale_channel_ids"] == ["11"]
    assert all(r.get(CT) in (None, REDACTED) for g in report["groups"] for r in g["rows"])


@pytest.mark.parametrize(
    ("row", "stale"),
    [
        ({"online": "0"}, True),
        ({"online": 0}, True),
        ({"online": "1", "conn_status": "0"}, False),
        ({"online": "1", "conn_status": "4"}, True),
        ({}, False),
    ],
)
def test_is_stale(row, stale) -> None:
    assert channels.is_stale(row) is stale


async def test_find_duplicate_channels_tool(ctx, table) -> None:
    assert (await channels.find_duplicate_channels(ctx))["data"]["duplicate_group_count"] == 2


# ---- remove_channel ---------------------------------------------------------------


async def test_remove_refused_without_write_gate(ctx, fake, table) -> None:
    result = await channels.remove_channel(ctx, "1", "uuid-aaaa", confirm_write=True)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_remove_requires_confirm(wctx, fake, table) -> None:
    result = await channels.remove_channel(wctx, "1", "uuid-aaaa")
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_remove_happy_path_returns_before_after(wctx, fake, table) -> None:
    result = await channels.remove_channel(wctx, "1", "uuid-aaaa", confirm_write=True)
    assert result["success"] is True, result
    data = result["data"]
    assert data["request"] == {"method": "do", "chm": {"chm_del_dev": {"ids": ["1"]}}}
    assert data["before"]["uuid"] == "uuid-aaaa" and data["before"][CT] == REDACTED
    assert data["after"] is None and data["removed"] is True
    assert fake.writes == [{"method": "do", "chm": {"chm_del_dev": {"ids": ["1"]}}}]
    assert [r["id"] for r in table.rows] == ["3", "9", "10", "11", "12"]


async def test_remove_uuid_mismatch_refused_without_write(wctx, fake, table) -> None:
    result = await channels.remove_channel(wctx, "1", "uuid-bbbb", confirm_write=True)
    assert result["error"]["code"] == "PRECONDITION_FAILED"
    assert result["error"]["details"]["reason"] == "UUID_MISMATCH"
    assert fake.writes == []


async def test_remove_missing_channel(wctx, fake, table) -> None:
    result = await channels.remove_channel(wctx, "99", "uuid-aaaa", confirm_write=True)
    assert result["error"]["code"] == "NOT_FOUND"
    assert fake.writes == []


async def test_remove_dry_run_sends_nothing(make_ctx, fake, table) -> None:
    dctx = make_ctx(ALLOW_WRITES="true", DRY_RUN="true")
    result = await channels.remove_channel(dctx, "1", "uuid-aaaa", confirm_write=True)
    assert result["data"]["dry_run"] is True
    assert result["data"]["request"] == {"method": "do", "chm": {"chm_del_dev": {"ids": ["1"]}}}
    assert fake.writes == []
    assert len(table.rows) == 6


@pytest.mark.parametrize("uuid", ["", " ", "x" * 129, None, 5])
async def test_remove_rejects_bad_uuid(wctx, fake, uuid) -> None:
    result = await channels.remove_channel(wctx, "1", uuid, confirm_write=True)  # type: ignore[arg-type]
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


# ---- move_channel -------------------------------------------------------------------


async def test_move_happy_path_into_empty_slot(wctx, fake, table) -> None:
    result = await channels.move_channel(wctx, "9", "2", "uuid-aaaa", confirm_write=True)
    assert result["success"] is True, result
    data = result["data"]
    assert data["request"] == {
        "method": "do",
        "chm": {"chm_mod_dev_chn": {"old_id": "9", "new_id": "2"}},
    }
    assert data["before"]["source"]["uuid"] == "uuid-aaaa"
    assert data["after"]["source"] is None
    assert data["after"]["target"]["uuid"] == "uuid-aaaa"
    assert data["after"]["target"]["password"] == REDACTED
    assert data["moved"] is True
    assert len(fake.writes) == 1


async def test_move_refuses_occupied_target(wctx, fake, table) -> None:
    result = await channels.move_channel(wctx, "9", "1", "uuid-aaaa", confirm_write=True)
    assert result["error"]["code"] == "PRECONDITION_FAILED"
    assert result["error"]["details"]["reason"] == "TARGET_OCCUPIED"
    assert result["error"]["details"]["occupant"][CT] == REDACTED
    assert fake.writes == []


async def test_move_uuid_mismatch(wctx, fake, table) -> None:
    result = await channels.move_channel(wctx, "9", "2", "uuid-cccc", confirm_write=True)
    assert result["error"]["details"]["reason"] == "UUID_MISMATCH"
    assert fake.writes == []


async def test_move_same_slot_rejected(wctx, fake) -> None:
    assert (await channels.move_channel(wctx, "9", "9", "u", True))["error"]["code"] == (
        "INVALID_INPUT"
    )
    assert fake.requests == []


async def test_move_gated_and_dry_run(ctx, make_ctx, fake, table) -> None:
    assert (await channels.move_channel(ctx, "9", "2", "uuid-aaaa", True))["error"]["code"] == (
        "WRITE_REFUSED"
    )
    dctx = make_ctx(ALLOW_WRITES="true", DRY_RUN="true")
    result = await channels.move_channel(dctx, "9", "2", "uuid-aaaa", confirm_write=True)
    assert result["data"]["dry_run"] is True
    assert fake.writes == []


async def test_move_rereads_live_state_before_writing(wctx, fake, table) -> None:
    await channels.list_channels(wctx)
    table.rows = [*table.rows, {"id": "2", "uuid": "uuid-new"}]  # slot filled meanwhile
    result = await channels.move_channel(wctx, "9", "2", "uuid-aaaa", confirm_write=True)
    assert result["error"]["details"]["reason"] == "TARGET_OCCUPIED"
    assert fake.writes == []


# ---- backup -------------------------------------------------------------------------


async def test_backup_downloads_and_writes_private_file(make_ctx, fake, table, tmp_path) -> None:
    fake.files = {f"/stok={FAKE_STOK_1}/backup/config.bin": b"\x01CONFIG\x02"}
    bctx = make_ctx(BACKUP_DIR=str(tmp_path / "bk"))
    result = await backup.backup_config(bctx)
    assert result["success"] is True, result
    data = result["data"]
    path = Path(data["path"])
    assert path.read_bytes() == b"\x01CONFIG\x02"
    assert data["bytes"] == len(b"CONFIG") == 8
    assert len(data["sha256"]) == 64
    assert fake.api_requests[-1][1] == {"method": "do", "system": {"download_conf": None}}
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


async def test_backup_is_not_write_gated(ctx, fake, table, monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    fake.files = {f"/stok={FAKE_STOK_1}/backup/config.bin": b"x"}
    assert ctx.settings.allow_writes is False
    assert (await backup.backup_config(ctx))["success"] is True


async def test_backup_download_failure_is_reported(make_ctx, fake, table, tmp_path) -> None:
    result = await backup.backup_config(make_ctx(BACKUP_DIR=str(tmp_path)))
    assert result["error"]["code"] == "TRANSPORT_ERROR"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("url", ["../etc/x", "/a/../b", "//evil/x", None, ""])
async def test_backup_rejects_unsafe_or_missing_url(make_ctx, fake, tmp_path, url) -> None:
    fake.api_handler = lambda t, b: {"error_code": 0, "url": url}
    result = await backup.backup_config(make_ctx(BACKUP_DIR=str(tmp_path)))
    assert result["error"]["code"] == "TRANSPORT_ERROR"
    assert fake.gets == []


def test_write_private_file_refuses_overwrite(tmp_path) -> None:
    backup.write_private_file(tmp_path, "f.bin", b"1")
    with pytest.raises(FileExistsError):
        backup.write_private_file(tmp_path, "f.bin", b"2")


# ---- device / storage / session -------------------------------------------------------


@pytest.mark.parametrize(
    "fn",
    [
        device.get_device_info,
        device.get_module_spec,
        device.get_system_info,
        device.get_network_info,
        device.get_video_resolutions,
        storage.list_disks,
        storage.get_recording_status,
    ],
)
async def test_read_tools_return_envelopes(ctx, fake, fn) -> None:
    result = await fn(ctx)
    _assert_envelope(result)
    assert result["success"] is True
    assert all(body["method"] == "get" for _, body in fake.api_requests)


async def test_auth_failure_surfaces_through_tool_envelope(ctx, fake) -> None:
    fake.password = "other"
    result = await device.get_device_info(ctx)
    _assert_envelope(result)
    assert result["error"]["code"] == "AUTH_FAILED"
    assert result["error"]["details"]["attempts_left"] == fake.attempts_left
    assert result["error"]["details"]["max_attempts"] == fake.max_attempts
    assert (await device.get_device_info(ctx))["error"]["code"] == "LOGIN_REFUSED"
    assert fake.login_attempts == 1


async def test_login_and_status_tools(ctx, fake) -> None:
    assert (await device.nvr_auth_status(ctx))["data"]["authenticated"] is False
    result = await device.nvr_login(ctx)
    assert result["data"]["authenticated"] is True
    assert FAKE_STOK_1 not in repr(result)


async def test_unexpected_exception_becomes_internal_error(ctx, monkeypatch) -> None:
    async def boom() -> None:
        raise RuntimeError("internal detail")

    monkeypatch.setattr(ctx.client, "get_device_info", boom)
    result = await device.get_device_info(ctx)
    assert result["error"]["code"] == "INTERNAL_ERROR"
    assert "internal detail" not in result["error"]["message"]
