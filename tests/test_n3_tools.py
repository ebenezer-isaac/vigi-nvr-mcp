"""Tests for the Phase N3 typed read tools.

All fixtures are anonymised (RFC 5737 addresses, placeholder names/uuids). Each
tool is checked for: fixture -> normalised model, malformed/missing section ->
PROTOCOL_ERROR envelope (never an exception), unexpected error_code -> mapped
meaning, read-only (only ``get`` reaches the wire), input validation before any
network call, and URL-decoded names.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.core.redact import REDACTED
from vigi_nvr_mcp.tools import detection, events, media, storage, system
from vigi_nvr_mcp.tools.shared import DetectionKind, decode_name

PW = "S3cr3t" + "CamPw"  # distinctive value (not the field name) for leak checks

# --- canned device replies, keyed by module ----------------------------------


def _replies() -> dict[str, dict[str, Any]]:
    return {
        "video": {
            "error_code": 0,
            "video": {
                "main_res": {
                    "chn1": {"resolution": "2592x1944", "codec": "h265", "bitrate": "4096"}
                },
                "minor_res": {"chn1": {"resolution": "640x480", "codec": "h264"}},
            },
        },
        "advance_settings": {"error_code": 0, "advance_settings": {"chn1": {"smart_codec": "1"}}},
        "image": {"error_code": 0, "image": {"chn1_common": {"brightness": "50"}}},
        "OSD": {"error_code": 0, "OSD": {"chn1_name": {"name": "Front Door"}}},
        "cover": {"error_code": 0, "cover": {"chn1_cover": {"enable": "0"}}},
        "ROI": {"error_code": 0, "ROI": {"chn1_on_off": {"enable": "1"}}},
        "harddisk_manage": {
            "error_code": 0,
            "harddisk_manage": {
                "hd_info": [
                    {
                        "disk_id": "1",
                        "total_space": "2000000",
                        "free_space": "500000",
                        "status": "1",
                    }
                ]
            },
        },
        "plan_advance": {"error_code": 0, "plan_advance": {"overwrite": "1"}},
        "record_plan": {"error_code": 0, "record_plan": {"chn1": "24x7"}},
        "playback": {
            "error_code": 0,
            "playback": {
                "segments": [
                    {
                        "start_time": "2026-10-03T00:00:00",
                        "end_time": "2026-10-03T01:00:00",
                        "type": "continuous",
                    }
                ]
            },
        },
        "unusual_detection": {
            "error_code": 0,
            "unusual_detection": {
                "login_error": [{"time": "2026-10-03T10:00:00Z", "channel": "1"}],
                "hd_error": [{"time": "2026-09-01T00:00:00Z"}],
            },
        },
        "user_management": {
            "error_code": 0,
            "user_management": {
                "root": {"name": "operator", "group": "root", "password": PW},
                "user1": {"name": "viewer", "group": "guest"},
            },
        },
        "firewall": {
            "error_code": 0,
            "firewall": {"blacklist": [], "whitelist": [], "ipctrl": {"enable": "0"}},
        },
        "protocol": {"error_code": 0, "protocol": {"table": [{"name": "onvif", "enable": "1"}]}},
        "cloud_status": {"error_code": 0, "cloud_status": {"online": "1"}},
        "cloud_config": {
            "error_code": 0,
            "cloud_config": {"bind": "1", "info": {"account": "a@b"}},
        },
        "system": {
            "error_code": 0,
            "system": {
                "clock_status": {"seconds_from_1970": "1760000000"},
                "date": {"zone_id": "Asia/Kolkata"},
                "dst": {"dst_savings": "0"},
            },
        },
    }


def _module_of(body: dict[str, Any]) -> str:
    return next(k for k in body if k != "method")


def install(fake: FakeNvr, replies: dict[str, dict[str, Any]] | None = None) -> None:
    table = replies if replies is not None else _replies()

    def handler(token: str, body: dict[str, Any]) -> dict[str, Any]:
        module = _module_of(body)
        return table.get(module, {"error_code": 0})

    fake.api_handler = handler


@pytest.fixture
def wired(fake: FakeNvr) -> FakeNvr:
    install(fake)
    return fake


def _assert_envelope(result: dict[str, Any]) -> None:
    assert set(result) == {"success", "data", "error"}
    if result["success"]:
        assert result["error"] is None
    else:
        assert result["data"] is None
        assert set(result["error"]) == {"code", "message", "details"}


# --- happy paths -------------------------------------------------------------


async def test_video_config(ctx, wired) -> None:
    result = await media.get_video_config(ctx)
    _assert_envelope(result)
    data = result["data"]
    assert data["main_res"]["chn1"]["codec"] == "h265"
    assert data["advance_settings"]["chn1"]["smart_codec"] == "1"
    assert "raw" not in data


async def test_image_config_decodes_names(ctx, wired) -> None:
    result = await media.get_image_config(ctx, 1)
    _assert_envelope(result)
    data = result["data"]
    assert data["channel"] == 1
    assert data["image"]["chn1_common"]["brightness"] == "50"
    # name carried a space: encoded as %20 on the wire, decoded by the transport.
    assert data["osd"]["chn1_name"]["name"] == "Front Door"
    assert data["privacy_mask"]["chn1_cover"]["enable"] == "0"
    assert data["roi"]["chn1_on_off"]["enable"] == "1"


async def test_detection_config_enabled_flag(ctx, fake) -> None:
    install(fake, {"motion_detection": {"error_code": 0, "motion_detection": {"enabled": "1"}}})
    result = await detection.get_detection_config(ctx, 3, "motion")
    _assert_envelope(result)
    data = result["data"]
    assert (data["channel"], data["kind"], data["module"]) == (3, "motion", "motion_detection")
    assert data["enabled"] is True


@pytest.mark.parametrize("kind", [k.value for k in DetectionKind])
async def test_detection_all_kinds_reach_their_module(ctx, fake, kind) -> None:
    install(fake, {})  # any module -> {"error_code": 0}
    result = await detection.get_detection_config(ctx, 1, kind)
    # {"error_code": 0} has no module section -> a clean PROTOCOL_ERROR, not a crash.
    assert result["error"]["code"] == "PROTOCOL_ERROR"
    module = DetectionKind(kind).module
    assert fake.api_requests[-1][1] == {"method": "get", module: {"name": ["chn1_region_info"]}}


async def test_get_storage(ctx, wired) -> None:
    result = await storage.get_storage(ctx)
    _assert_envelope(result)
    data = result["data"]
    assert data["disks"][0]["disk_id"] == "1"
    assert data["overwrite_policy"] == {"overwrite": "1"}
    assert data["record_plan"] == {"chn1": "24x7"}


async def test_search_recordings(ctx, wired) -> None:
    result = await storage.search_recordings(ctx, 1, "2026-10-03")
    _assert_envelope(result)
    data = result["data"]
    assert (data["channel"], data["date"], data["segment_count"]) == (1, "2026-10-03", 1)
    assert data["segments"][0]["type"] == "continuous"


async def test_list_events_and_since_filter(ctx, wired) -> None:
    allv = await events.list_events(ctx)
    assert allv["data"]["event_count"] == 2
    recent = await events.list_events(ctx, since="2026-10-01T00:00:00Z")
    sources = {e["source"] for e in recent["data"]["events"]}
    assert recent["data"]["event_count"] == 1 and sources == {"login_error"}


async def test_get_users_names_and_groups_only(ctx, wired) -> None:
    result = await system.get_users(ctx)
    _assert_envelope(result)
    data = result["data"]
    assert data["user_count"] == 2
    by_name = {u["name"]: u["group"] for u in data["users"]}
    assert by_name == {"operator": "root", "viewer": "guest"}
    assert PW not in repr(result)  # password never surfaces


async def test_get_users_raw_is_redacted(ctx, wired) -> None:
    result = await system.get_users(ctx, include_raw=True)
    raw = result["data"]["raw"]["user_management"]["root"]
    assert raw["password"] == REDACTED
    assert PW not in repr(result)


async def test_get_firewall(ctx, wired) -> None:
    result = await system.get_firewall(ctx)
    _assert_envelope(result)
    assert result["data"]["firewall"]["ipctrl"] == {"enable": "0"}
    assert result["data"]["protocol"] == {"table": [{"name": "onvif", "enable": "1"}]}


async def test_get_cloud_status(ctx, wired) -> None:
    result = await system.get_cloud_status(ctx)
    _assert_envelope(result)
    assert result["data"]["bound"] is True
    assert result["data"]["status"] == {"online": "1"}


async def test_get_time(ctx, wired) -> None:
    result = await system.get_time(ctx)
    _assert_envelope(result)
    assert result["data"]["date"] == {"zone_id": "Asia/Kolkata"}


# --- include_raw -------------------------------------------------------------


async def test_include_raw_attaches_raw(ctx, wired) -> None:
    assert "raw" in (await media.get_video_config(ctx, include_raw=True))["data"]
    assert "raw" in (await system.get_time(ctx, include_raw=True))["data"]
    assert (
        "raw" in (await storage.search_recordings(ctx, 1, "2026-10-03", include_raw=True))["data"]
    )


# --- malformed / missing -> PROTOCOL_ERROR -----------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda ctx: media.get_video_config(ctx),
        lambda ctx: media.get_image_config(ctx, 1),
        lambda ctx: storage.get_storage(ctx),
        lambda ctx: system.get_time(ctx),
        lambda ctx: system.get_users(ctx),
        lambda ctx: system.get_firewall(ctx),
        lambda ctx: system.get_cloud_status(ctx),
        lambda ctx: events.list_events(ctx),
    ],
)
async def test_missing_section_is_protocol_error(ctx, fake, call) -> None:
    install(fake, {})  # every module answers error_code 0 with no section
    result = await call(ctx)
    _assert_envelope(result)
    assert result["error"]["code"] == "PROTOCOL_ERROR"


async def test_non_dict_section_is_protocol_error(ctx, fake) -> None:
    install(fake, {"system": {"error_code": 0, "system": "not-an-object"}})
    result = await system.get_time(ctx)
    assert result["error"]["code"] == "PROTOCOL_ERROR"


# --- unexpected error_code -> mapped meaning ---------------------------------


async def test_unexpected_error_code_is_mapped(ctx, fake) -> None:
    install(fake, {"system": {"error_code": -40209}})
    result = await system.get_time(ctx)
    _assert_envelope(result)
    assert result["error"]["code"] == "DEVICE_API_ERROR"
    details = result["error"]["details"]
    assert details["device_error_code"] == -40209
    assert details["symbol"] == "EINVARG"
    assert "Invalid argument" in details["meaning"]


# --- read-only invariant -----------------------------------------------------


async def test_all_reads_send_only_get(wired, make_ctx) -> None:
    ctx = make_ctx()
    await media.get_video_config(ctx)
    await media.get_image_config(ctx, 1)
    await detection.get_detection_config(ctx, 1, "people")
    await storage.get_storage(ctx)
    await storage.search_recordings(ctx, 1, "2026-10-03")
    await events.list_events(ctx)
    await system.get_users(ctx)
    await system.get_firewall(ctx)
    await system.get_cloud_status(ctx)
    await system.get_time(ctx)
    assert wired.api_requests, "expected at least one API request"
    assert all(body["method"] == "get" for _, body in wired.api_requests)
    assert wired.writes == []


# --- input validation happens before any network call ------------------------


@pytest.mark.parametrize("channel", [0, 17, -1, 100])
async def test_image_config_rejects_out_of_range_channel(ctx, fake, channel) -> None:
    install(fake)
    result = await media.get_image_config(ctx, channel)
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


async def test_detection_rejects_unknown_kind(ctx, fake) -> None:
    install(fake)
    result = await detection.get_detection_config(ctx, 1, "banana")
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


@pytest.mark.parametrize("date", ["03-10-2026", "2026/10/03", "today", "", "2026-1-1"])
async def test_search_rejects_bad_date(ctx, fake, date) -> None:
    install(fake)
    result = await storage.search_recordings(ctx, 1, date)
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


@pytest.mark.parametrize("since", ["not-a-date", "10:00", "2026-13", "yesterday"])
async def test_events_rejects_bad_since(ctx, fake, since) -> None:
    install(fake)
    result = await events.list_events(ctx, since=since)
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


async def test_events_accepts_valid_iso_forms(ctx, wired) -> None:
    for since in ("2026-10-03", "2026-10-03T10:00:00", "2026-10-03T10:00:00Z", "2026-10-03 10:00"):
        result = await events.list_events(ctx, since=since)
        _assert_envelope(result)
        assert result["success"] is True


# --- unit: helpers -----------------------------------------------------------


def test_decode_name_defensive() -> None:
    assert decode_name("Front%20Door") == "Front Door"
    assert decode_name("plain") == "plain"
    assert decode_name(123) == 123


def test_detection_kind_module_mapping() -> None:
    assert DetectionKind.motion.module == "motion_detection"
    assert DetectionKind.abandon_and_taken.module == "abandonandtaken_detection"
    assert DetectionKind.region_entrance.module == "regionentrance_detection"
    assert len(list(DetectionKind)) == 12
