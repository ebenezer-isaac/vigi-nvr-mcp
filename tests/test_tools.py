from __future__ import annotations

import copy
from typing import Any

import pytest

from tests.helpers import FAKE_STOK_1, FakeNvr
from vigi_nvr_mcp.redact import REDACTED
from vigi_nvr_mcp.tools import ToolContext, channels, device, raw, storage

CT = "cipher" + "text"


def _channel_reply() -> dict[str, Any]:
    """Anonymised fixture: RFC 5737 addresses, synthetic uuids."""
    return {
        "error_code": 0,
        "channel_manage": {
            "channel_list": [
                {
                    "chn_1": {
                        "id": "1",
                        "uuid": "uuid-aaaa",
                        "ip": "192.0.2.21",
                        "online": "1",
                        "conn_status": "0",
                        CT: "QUJD",
                        "password": "x",
                    }
                },
                {
                    "chn_2": {
                        "id": "2",
                        "uuid": "uuid-aaaa",
                        "ip": "192.0.2.21",
                        "online": "0",
                        "conn_status": "1",
                        CT: "QUJD",
                    }
                },
                {
                    "chn_3": {
                        "id": "3",
                        "uuid": "uuid-bbbb",
                        "ip": "192.0.2.22",
                        "online": "1",
                        "conn_status": "0",
                    }
                },
                {
                    "chn_4": {
                        "id": "4",
                        "uuid": "uuid-cccc",
                        "ip": "192.0.2.23",
                        "online": "1",
                        "conn_status": "0",
                    }
                },
                {
                    "chn_5": {
                        "id": "5",
                        "uuid": "uuid-cccc",
                        "ip": "192.0.2.24",
                        "online": "1",
                        "conn_status": "2",
                    }
                },
                {"chn_6": {"id": "6", "uuid": "", "ip": "192.0.2.25"}},
            ]
        },
    }


@pytest.fixture
def ctx(client) -> ToolContext:
    return ToolContext(settings=client.settings, client=client)


@pytest.fixture
def ctx_writes(make_settings, make_client) -> ToolContext:
    s = make_settings(VIGI_NVR_ALLOW_WRITES="true")
    return ToolContext(settings=s, client=make_client(s))


def _assert_envelope(result: dict[str, Any]) -> None:
    assert set(result) == {"success", "data", "error"}
    if result["success"]:
        assert result["error"] is None
    else:
        assert result["data"] is None
        assert set(result["error"]) == {"code", "message", "details"}


# ---- write gating -----------------------------------------------------------


async def test_get_passes_without_flags(ctx, fake: FakeNvr) -> None:
    result = await raw.nvr_call(ctx, "get", "device_info", {"name": ["basic_info"]})
    _assert_envelope(result)
    assert result["success"] is True


@pytest.mark.parametrize("method", ["set", "do", "add", "delete"])
@pytest.mark.parametrize("confirm", [False, True])
async def test_writes_refused_when_server_disallows(ctx, fake, method, confirm) -> None:
    result = await raw.nvr_call(ctx, method, "system", {"x": 1}, confirm_write=confirm)
    _assert_envelope(result)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert "VIGI_NVR_ALLOW_WRITES" in result["error"]["message"]
    assert fake.requests == []


@pytest.mark.parametrize("method", ["set", "do", "add", "delete"])
async def test_writes_need_confirm_even_when_allowed(ctx_writes, fake, method) -> None:
    result = await raw.nvr_call(ctx_writes, method, "system", {"x": 1})
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert "confirm_write" in result["error"]["message"]
    assert fake.requests == []


async def test_confirm_write_must_be_true_not_truthy(ctx_writes, fake) -> None:
    result = await raw.nvr_call(ctx_writes, "set", "system", {}, confirm_write="yes")  # type: ignore[arg-type]
    assert result["error"]["code"] == "WRITE_REFUSED"


async def test_write_allowed_with_both_flags(ctx_writes, fake) -> None:
    result = await raw.nvr_call(ctx_writes, "set", "system", {"x": 1}, confirm_write=True)
    assert result["success"] is True
    assert fake.api_requests[-1][1] == {"method": "set", "system": {"x": 1}}


@pytest.mark.parametrize("module", ["login", "user_management", "LOGIN"])
async def test_auth_modules_are_always_denied(ctx_writes, fake, module) -> None:
    for method in ("get", "do"):
        result = await raw.nvr_call(ctx_writes, method, module, None, confirm_write=True)
        assert result["error"]["code"] == "MODULE_DENIED"
    assert fake.requests == []


async def test_invalid_raw_input_is_rejected(ctx, fake) -> None:
    result = await raw.nvr_call(ctx, "get", "bad/module", None)
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


async def test_raw_reply_is_redacted(ctx, fake) -> None:
    fake.api_handler = lambda t, b: {"error_code": 0, "x": {"stok": "s", "password": "p"}}
    result = await raw.nvr_call(ctx, "get", "x", {})
    assert result["data"]["x"] == {"stok": REDACTED, "password": REDACTED}


# ---- channels -------------------------------------------------------------


async def test_list_channels_redacts_credentials(ctx, fake) -> None:
    fake.api_handler = lambda t, b: _channel_reply()
    result = await channels.list_channels(ctx)
    _assert_envelope(result)
    rows = result["data"]
    assert len(rows) == 6
    assert rows[0][CT] == REDACTED
    assert rows[0]["password"] == REDACTED
    assert rows[0]["channel_id"] == "1"
    assert "QUJD" not in repr(result)


async def test_get_channel_found_and_not_found(ctx, fake) -> None:
    fake.api_handler = lambda t, b: _channel_reply()
    found = await channels.get_channel(ctx, "3")
    assert found["data"]["uuid"] == "uuid-bbbb"
    missing = await channels.get_channel(ctx, "99")
    assert missing["error"]["code"] == "NOT_FOUND"


@pytest.mark.parametrize("bad", ["", "../1", "a b", "x" * 65])
async def test_get_channel_rejects_bad_ids(ctx, fake, bad) -> None:
    result = await channels.get_channel(ctx, bad)
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


def test_find_duplicates_groups_and_flags_stale() -> None:
    from vigi_nvr_mcp.client import extract_rows

    rows = extract_rows(_channel_reply())
    snapshot = copy.deepcopy(rows)
    report = channels.find_duplicates(rows)
    assert rows == snapshot  # pure
    assert report["total_rows"] == 6
    assert report["rows_without_uuid"] == 1
    assert report["duplicate_group_count"] == 2
    by_uuid = {g["uuid"]: g for g in report["groups"]}
    assert set(by_uuid) == {"uuid-aaaa", "uuid-cccc"}
    assert by_uuid["uuid-aaaa"]["stale_channel_ids"] == ["2"]
    assert by_uuid["uuid-aaaa"]["live_channel_ids"] == ["1"]
    assert by_uuid["uuid-cccc"]["stale_channel_ids"] == ["5"]  # conn_status != "0"
    assert all(r.get(CT) in (None, REDACTED) for g in report["groups"] for r in g["rows"])


@pytest.mark.parametrize(
    ("row", "stale"),
    [
        ({"online": "0"}, True),
        ({"online": 0}, True),
        ({"online": "1", "conn_status": "0"}, False),
        ({"online": "1", "conn_status": "3"}, True),
        ({}, False),
    ],
)
def test_is_stale(row, stale) -> None:
    assert channels.is_stale(row) is stale


def test_find_duplicates_empty() -> None:
    assert channels.find_duplicates([])["duplicate_group_count"] == 0


async def test_find_duplicate_channels_tool(ctx, fake) -> None:
    fake.api_handler = lambda t, b: _channel_reply()
    result = await channels.find_duplicate_channels(ctx)
    assert result["success"] is True
    assert result["data"]["duplicate_group_count"] == 2


@pytest.mark.parametrize("confirm", [False, True])
async def test_remove_channel_is_a_stub_that_sends_nothing(ctx_writes, fake, confirm) -> None:
    result = await channels.remove_channel(ctx_writes, "2", confirm_write=confirm)
    assert result["error"]["code"] == "NOT_IMPLEMENTED"
    assert fake.requests == []


# ---- device / storage / session --------------------------------------------


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
    assert result["error"]["details"]["max_attempts"] == fake.fail_max_time
    again = await device.get_device_info(ctx)
    assert again["error"]["code"] == "LOGIN_REFUSED"
    assert fake.login_attempts == 1


async def test_login_and_status_tools(ctx, fake) -> None:
    before = await device.nvr_auth_status(ctx)
    assert before["data"]["authenticated"] is False
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
