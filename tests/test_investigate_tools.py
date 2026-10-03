"""Tool-level tests for the N7b investigation primitives.

The ffmpeg-driven tools (contact sheet, sampled frames, re-encode export) run a
*real* subprocess: a fake ffmpeg/ffprobe written as a Python script and invoked
via the interpreter, exactly as test_media_runner drives it. The fake writes a
single file, or a numbered set when the output path is a %0Nd pattern, and emits a
smaller file when re-encoding (libx264 in argv) so target-fit can be exercised. No
network, no real ffmpeg.
"""

from __future__ import annotations

import base64
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from vigi_nvr_mcp.backend import NvrBackend
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings, load_global_settings
from vigi_nvr_mcp.core.errors import NotFound
from vigi_nvr_mcp.investigate.windows import Window
from vigi_nvr_mcp.media.ffmpeg import FfmpegRunner
from vigi_nvr_mcp.server import MCP_ENV_PREFIX, build_server
from vigi_nvr_mcp.tools import ToolContext
from vigi_nvr_mcp.tools import export as export_tool
from vigi_nvr_mcp.tools import investigate as inv

PW = "p@ss" + "/w+d"
RTSP = {"RTSP_USERNAME": "viewer", "RTSP_PASSWORD": PW}
START = "2026-10-03T12:00:00Z"
END = "2026-10-03T12:00:10Z"

FAKE_FFMPEG = """\
import os, sys
mode = os.environ.get("FAKE_MODE", "ok")
argv = sys.argv[1:]
out = argv[-1]
if mode == "fail":
    sys.stderr.write("boom\\n"); sys.exit(2)
if mode == "nofootage":
    sys.stderr.write("404 Not Found\\n"); sys.exit(1)
size = int(os.environ.get("FAKE_SIZE", "64"))
reenc = int(os.environ.get("FAKE_REENC_SIZE", "16"))
is_reenc = "libx264" in argv
if "%" in out:
    n = int(argv[argv.index("-frames:v") + 1]) if "-frames:v" in argv else 1
    for i in range(n):
        open(out % i, "wb").write(b"J" * size)
    sys.exit(0)
open(out, "wb").write(b"R" * (reenc if is_reenc else size))
sys.exit(0)
"""

FAKE_FFPROBE = """\
import json, sys
print(json.dumps({"streams": [{"codec_type": "video"}]})); sys.exit(0)
"""


@pytest.fixture
def export_dir(tmp_path: Path) -> Path:
    return tmp_path / "exports"


@pytest.fixture
def fake_bins(tmp_path: Path) -> tuple[list[str], list[str]]:
    ff = tmp_path / "fake_ffmpeg.py"
    fp = tmp_path / "fake_ffprobe.py"
    ff.write_text(FAKE_FFMPEG, encoding="utf-8")
    fp.write_text(FAKE_FFPROBE, encoding="utf-8")
    return [sys.executable, str(ff)], [sys.executable, str(fp)]


def _settings(export_dir: Path, **overrides: str) -> DeviceSettings:
    return load_device_settings(
        NVR_PREFIX, nvr_env(EXPORT_DIR=str(export_dir), **RTSP, **overrides)
    )


@pytest.fixture
def runner(export_dir: Path, fake_bins: tuple[list[str], list[str]]) -> FfmpegRunner:
    ff, fp = fake_bins
    return FfmpegRunner(_settings(export_dir), ffmpeg_cmd=ff, ffprobe_cmd=fp)


def _ctx(make_ctx: Callable[..., ToolContext], export_dir: Path, **ov: str) -> ToolContext:
    return make_ctx(EXPORT_DIR=str(export_dir), **RTSP, **ov)


def _assert_envelope(result: dict[str, Any]) -> None:
    assert set(result) == {"success", "data", "error"}
    if not result["success"]:
        assert result["data"] is None
        assert set(result["error"]) == {"code", "message", "details"}


# --- fixtures: a fake NVR that answers playback / channels / events -------------


class InvHandler:
    """Answers the module calls list_motion_windows makes."""

    def __init__(self, playback: dict[str, Any]) -> None:
        self.playback = playback

    def __call__(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        if "playback" in body:
            return {"error_code": 0, **self.playback}
        if "chm" in body:
            return {
                "error_code": 0,
                "chm": {
                    "added_dev": [
                        {"id": "5", "name": "Main Door", "uuid": "u-5", "online": "1"},
                    ]
                },
            }
        if "unusual_detection" in body:
            return {
                "error_code": 0,
                "unusual_detection": {
                    "motion_detection": [{"time": "12:00:40", "channel": "5"}],
                },
            }
        return {"error_code": 0}


PLAYBACK_OK = {
    "playback": {
        "segments": [
            {"start_time": "12:00:00", "end_time": "12:00:20", "type": "motion"},
            {"start_time": "12:00:30", "end_time": "12:01:00", "type": "motion"},
            {"start_time": "08:00:00", "end_time": "09:00:00", "type": "continuous"},
        ]
    }
}


# --- list_recording_segments --------------------------------------------------


async def test_list_recording_segments_typed(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_recording_segments(ctx, 5, "2026-10-03", tz="Asia/Kolkata")
    _assert_envelope(result)
    data = result["data"]
    assert data["segment_count"] == 3
    assert {s["type"] for s in data["segments"]} == {"motion", "normal"}


async def test_list_recording_segments_garbage_is_protocol_error_with_raw(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = lambda _t, _b: {"error_code": 0}  # no recognisable segment list
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_recording_segments(ctx, 5, "2026-10-03")
    assert result["error"]["code"] == "PROTOCOL_ERROR"
    assert "raw" in result["error"]["details"]


async def test_list_recording_segments_bad_tz(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_recording_segments(ctx, 5, "2026-10-03", tz="Mars/Phobos")
    assert result["error"]["code"] == "INVALID_INPUT"


async def test_list_recording_segments_bad_date_no_io(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_recording_segments(ctx, 5, "03-10-2026")
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.requests == []


# --- list_motion_windows ------------------------------------------------------


async def test_motion_windows_merges_segments_and_events(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_motion_windows(ctx, channel=5, date="2026-10-03", tz="utc")
    _assert_envelope(result)
    data = result["data"]
    # The two motion segments (gap 10s <= 30) merge; continuous is filtered out.
    assert len(data["windows"]) == 1
    window = data["windows"][0]
    assert window["channel"] == 5 and window["name"] == "Main Door"
    assert window["kinds"] == ["motion"]
    # The motion event at 12:00:40 (inside the window) adds the events source.
    assert set(window["sources"]) == {"recording", "events"}
    assert data["summary"]["window_count"] == 1


async def test_motion_windows_all_channels(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_motion_windows(ctx, channel="all", date="2026-10-03", tz="utc")
    assert result["success"] is True
    assert result["data"]["channels_searched"] == [5]


async def test_motion_windows_kinds_filter(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_motion_windows(
        ctx, channel=5, date="2026-10-03", kinds=["normal"], tz="utc"
    )
    # Only the continuous (normal) segment qualifies now.
    assert len(result["data"]["windows"]) == 1
    assert result["data"]["windows"][0]["kinds"] == ["normal"]


async def test_motion_windows_bad_kind(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_motion_windows(ctx, channel=5, date="2026-10-03", kinds=["banana"])
    assert result["error"]["code"] == "INVALID_INPUT"


async def test_motion_windows_requires_date_or_since(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_motion_windows(ctx, channel=5)
    assert result["error"]["code"] == "INVALID_INPUT"


async def test_motion_windows_since_until_narrows(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    ctx = _ctx(make_ctx, export_dir)
    # Narrow to a window after all motion activity -> nothing.
    result = await inv.list_motion_windows(
        ctx, channel=5, date="2026-10-03", since="2026-10-03T13:00:00Z", tz="utc"
    )
    assert result["data"]["windows"] == []


async def test_motion_windows_bad_channel_reply_recorded_as_issue(
    make_ctx: Callable[..., ToolContext], export_dir: Path, fake: FakeNvr
) -> None:
    fake.api_handler = lambda _t, b: (
        {"error_code": 0, "chm": {"added_dev": [{"id": "5", "name": "Door", "uuid": "u"}]}}
        if "chm" in b
        else {"error_code": 0}  # playback & events: unrecognisable
    )
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.list_motion_windows(ctx, channel=5, date="2026-10-03", tz="utc")
    assert result["success"] is True
    assert result["data"]["windows"] == []
    assert result["data"]["issues"][0]["channel"] == 5


# --- contact sheet ------------------------------------------------------------


async def test_contact_sheet(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "ok")
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.contact_sheet(ctx, runner, 5, START, END, cols=4, rows=3)
    _assert_envelope(result)
    data = result["data"]
    assert len(data["tiles"]) == 12
    assert data["cols"] == 4 and data["rows"] == 3
    assert Path(data["path"]).exists()
    assert data["name"].endswith("_s1.jpg")
    assert PW not in data["url"] and "<redacted>" in data["url"]


async def test_contact_sheet_rejects_bad_geometry(
    make_ctx: Callable[..., ToolContext], export_dir: Path, runner: FfmpegRunner
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.contact_sheet(ctx, runner, 5, START, END, cols=99, rows=3)
    assert result["error"]["code"] == "INVALID_INPUT"


async def test_contact_sheet_ffmpeg_failure(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "fail")
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.contact_sheet(ctx, runner, 5, START, END)
    assert result["error"]["code"] == "EXPORT_FAILED"


# --- sampled frames -----------------------------------------------------------


async def test_sample_frames(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "ok")
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.sample_frames(ctx, runner, 5, START, END, every_s=2, max_frames=60)
    _assert_envelope(result)
    data = result["data"]
    assert data["frame_count"] == 6  # 0,2,4,6,8,10s
    for frame in data["frames"]:
        assert frame["name"].startswith("ch5_") and frame["name"].endswith("_s1.jpg")
        assert Path(frame["path"]).exists()
    # Temp pattern files were renamed away.
    assert list(export_dir.glob("_frames_*")) == []


async def test_sample_frames_rejects_bad_params(
    make_ctx: Callable[..., ToolContext], export_dir: Path, runner: FfmpegRunner
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.sample_frames(ctx, runner, 5, START, END, max_frames=0)
    assert result["error"]["code"] == "INVALID_INPUT"


async def test_sample_frames_nofootage(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "nofootage")
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.sample_frames(ctx, runner, 5, START, END)
    assert result["error"]["code"] == "NO_FOOTAGE_IN_WINDOW"


# --- export_clip re-encode extension ------------------------------------------


async def test_export_reencode_shrinks_to_target(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "ok")
    monkeypatch.setenv("FAKE_SIZE", "5000")  # lossless copy exceeds the target
    monkeypatch.setenv("FAKE_REENC_SIZE", "100")  # re-encode fits
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, START, END, confirm_write=True, target_max_mb=0.001
    )
    assert result["success"] is True, result
    data = result["data"]
    assert data["re_encoded"] is True
    assert data["fits_target"] is True
    assert data["original_bytes"] == 5000
    assert data["encoded_bytes"] == 100


async def test_export_reencode_still_too_large(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "ok")
    monkeypatch.setenv("FAKE_SIZE", "5000")
    monkeypatch.setenv("FAKE_REENC_SIZE", "9000")
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, START, END, confirm_write=True, target_max_mb=0.001
    )
    assert result["data"]["re_encoded"] is True
    assert result["data"]["fits_target"] is False


async def test_export_copy_already_fits_skips_reencode(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "ok")
    monkeypatch.setenv("FAKE_SIZE", "500")  # already under a 1 MB target
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, START, END, confirm_write=True, target_max_mb=1
    )
    assert result["data"]["re_encoded"] is False
    assert result["data"]["fits_target"] is True


async def test_export_max_width_forces_reencode(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_MODE", "ok")
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, START, END, confirm_write=True, max_width=640
    )
    assert result["data"]["re_encoded"] is True
    assert result["data"]["fits_target"] is True  # no size target -> always fits


async def test_export_dry_run_reports_reencode_plan(
    make_ctx: Callable[..., ToolContext], export_dir: Path, runner: FfmpegRunner
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true", DRY_RUN="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, START, END, confirm_write=True, target_max_mb=20, max_width=1280
    )
    # Dry-run is centralised in the guarded writer: the re-encode plan rides on the
    # echoed request.
    assert result["data"]["dry_run"] is True
    assert result["data"]["request"]["reencode"]["crf"] >= 18
    assert result["data"]["request"]["reencode"]["scale"] == "scale='min(iw,1280)':-2"


async def test_export_bad_target(
    make_ctx: Callable[..., ToolContext], export_dir: Path, runner: FfmpegRunner
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, START, END, confirm_write=True, target_max_mb=-1
    )
    assert result["error"]["code"] == "INVALID_INPUT"


# --- get_export (base64) ------------------------------------------------------


def _write_export(export_dir: Path, name: str, data: bytes) -> Path:
    export_dir.mkdir(parents=True, exist_ok=True)
    path = export_dir / name
    path.write_bytes(data)
    return path


async def test_get_export_returns_base64(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    name = "ch5_20261003t120000z_20261003t120010z_s1.mp4"
    _write_export(export_dir, name, b"VIDEODATA")
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.get_export(ctx, name, max_mb=20)
    data = result["data"]
    assert base64.b64decode(data["base64"]) == b"VIDEODATA"
    assert data["bytes"] == 9 and data["mime"] == "video/mp4"
    assert len(data["sha256"]) == 64


async def test_get_export_too_large(make_ctx: Callable[..., ToolContext], export_dir: Path) -> None:
    name = "ch5_20261003t120000z_20261003t120010z_s1.mp4"
    _write_export(export_dir, name, b"x" * 2048)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.get_export(ctx, name, max_mb=0.001)  # ~1048 bytes
    assert result["error"]["code"] == "TOO_LARGE"
    assert result["error"]["details"]["size_bytes"] == 2048


async def test_get_export_rejects_traversal(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.get_export(ctx, "../secret.mp4")
    assert result["error"]["code"] == "INVALID_INPUT"


async def test_get_export_missing(make_ctx: Callable[..., ToolContext], export_dir: Path) -> None:
    export_dir.mkdir(parents=True)
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.get_export(ctx, "ch5_20261003t120000z_s1.jpg")
    assert result["error"]["code"] == "NOT_FOUND"


# --- retention listing & purge ------------------------------------------------


def _age(path: Path, seconds: float) -> None:
    old = time.time() - seconds
    os.utime(path, (old, old))


async def test_list_exports_reports_retention(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    fresh = _write_export(export_dir, "ch5_20261003t120000z_s1.jpg", b"new")
    old = _write_export(export_dir, "ch6_20260101t000000z_s1.jpg", b"old")
    _age(old, 10 * 86400)  # older than the 7-day default
    _ = fresh
    ctx = _ctx(make_ctx, export_dir)
    result = await export_tool.list_exports(ctx)
    data = result["data"]
    assert data["retention_days"] == 7
    assert data["expired_count"] == 1
    expired = {e["name"]: e["expired"] for e in data["exports"]}
    assert expired["ch6_20260101t000000z_s1.jpg"] is True
    assert expired["ch5_20261003t120000z_s1.jpg"] is False


async def test_purge_refused_without_writes(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    result = await inv.purge_exports(ctx, confirm_write=True)
    assert result["error"]["code"] == "WRITE_REFUSED"


async def test_purge_dry_run_lists_without_deleting(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    old = _write_export(export_dir, "ch6_20260101t000000z_s1.jpg", b"old")
    _age(old, 10 * 86400)
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true", DRY_RUN="true")
    result = await inv.purge_exports(ctx, confirm_write=True)
    # Dry-run is centralised in the guarded writer: it echoes the purge request and
    # deletes nothing.
    assert result["data"]["dry_run"] is True
    assert result["data"]["request"] == {"action": "purge_exports", "retention_days": 7}
    assert old.exists()  # nothing deleted


async def test_purge_real_deletes_expired_only(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    fresh = _write_export(export_dir, "ch5_20261003t120000z_s1.jpg", b"new")
    old = _write_export(export_dir, "ch6_20260101t000000z_s1.jpg", b"old")
    _age(old, 10 * 86400)
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await inv.purge_exports(ctx, confirm_write=True)
    assert result["data"]["deleted"] == ["ch6_20260101t000000z_s1.jpg"]
    assert not old.exists() and fresh.exists()


# --- resource blob reader -----------------------------------------------------


def test_read_export_blob_ok(make_ctx: Callable[..., ToolContext], export_dir: Path) -> None:
    name = "ch5_20261003t120000z_s2.jpg"
    _write_export(export_dir, name, b"IMG")
    ctx = _ctx(make_ctx, export_dir)
    assert inv.read_export_blob(ctx, name) == b"IMG"


def test_read_export_blob_rejects_traversal(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    with pytest.raises(ValueError, match=r"generated export filename|escapes"):
        inv.read_export_blob(ctx, "../etc/passwd")


def test_read_export_blob_missing(make_ctx: Callable[..., ToolContext], export_dir: Path) -> None:
    export_dir.mkdir(parents=True)
    ctx = _ctx(make_ctx, export_dir)
    with pytest.raises(NotFound):
        inv.read_export_blob(ctx, "ch5_20261003t120000z_s1.jpg")


# --- helper-level coverage ----------------------------------------------------

from datetime import UTC, datetime, timedelta  # noqa: E402

BASE = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)


def test_channel_rows_fallbacks_and_bad_ids() -> None:
    rows = [
        {"id": "5", "name": "Door"},
        {"channel": "6", "alias": "Yard"},
        {"_row_key": "7"},  # no name -> "channel 7"
        {"id": "notanint"},  # skipped
    ]
    assert inv._channel_rows(rows) == {5: "Door", 6: "Yard", 7: "channel 7"}


def test_segment_inputs_skips_unparseable_and_handles_missing_end() -> None:
    from types import SimpleNamespace

    tz = UTC
    segs = [
        SimpleNamespace(type=SimpleNamespace(value="motion"), start="nope", end="12:00:10"),
        SimpleNamespace(type=SimpleNamespace(value="motion"), start="12:00:00", end=None),
        SimpleNamespace(type=SimpleNamespace(value="normal"), start="12:00:00", end="12:00:10"),
    ]
    out = inv._segment_inputs(5, "Door", segs, "2026-10-03", tz, {"motion"})
    assert len(out) == 1  # first skipped (bad start), third filtered by kind
    assert out[0].start == out[0].end  # missing end -> zero length


def test_event_inputs_filters() -> None:
    from types import SimpleNamespace

    tz = UTC
    events = [
        SimpleNamespace(source="hd_error", channel="5", time="12:00:00"),  # kind not requested
        SimpleNamespace(source="motion_detection", channel="nope", time="12:00:00"),  # bad channel
        SimpleNamespace(source="motion_detection", channel="9", time="12:00:00"),  # not a target
        SimpleNamespace(source="motion_detection", channel="5", time="bad"),  # bad time
        SimpleNamespace(source="motion_detection", channel="5", time="12:00:00"),  # good
    ]
    out = inv._event_inputs(events, {5: "Door"}, {5}, "2026-10-03", tz, {"motion"})
    assert len(out) == 1 and out[0].channel == 5


def test_in_range_bounds() -> None:
    w = Window(5, "d", BASE, BASE + timedelta(seconds=10), ("motion",), ("rec",))
    assert inv._in_range(w, None, None) is True
    assert inv._in_range(w, BASE + timedelta(seconds=20), None) is False  # window ends before lo
    assert inv._in_range(w, None, BASE - timedelta(seconds=5)) is False  # window starts after hi


def test_parse_bound_errors_and_none() -> None:
    assert inv._parse_bound("since", None, UTC) is None
    with pytest.raises(ValueError, match="ISO-8601"):
        inv._parse_bound("since", "not-a-date", UTC)


def test_rename_frames_cleans_up_extra_produced(tmp_path: Path) -> None:
    produced = [tmp_path / f"_f_{i}.jpg" for i in range(3)]
    for p in produced:
        p.write_bytes(b"x")
    targets = [tmp_path / "ch5_a_s1.jpg", tmp_path / "ch5_b_s1.jpg"]  # fewer than produced
    stamps = [{"timestamp": "t0"}, {"timestamp": "t1"}]
    frames = inv._rename_frames(produced, targets, stamps)
    assert len(frames) == 2
    assert not produced[2].exists()  # leftover removed


# --- end-to-end wrappers via MCP (covers the register() tool functions) --------


def _mcp(fake: FakeNvr, export_dir: Path, **ov: str):
    env = nvr_env(EXPORT_DIR=str(export_dir), **RTSP, **ov)
    backend = NvrBackend.from_env(env, http_transport=fake.transport())
    return build_server(load_global_settings(MCP_ENV_PREFIX, {}), backend)[0]


async def _call(mcp, name: str, args: dict[str, Any]) -> dict[str, Any]:
    import json

    result = await mcp.call_tool(name, args)
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if isinstance(structured, dict) and "success" in structured:
        return structured
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


async def test_wrappers_end_to_end(fake: FakeNvr, export_dir: Path) -> None:
    fake.api_handler = InvHandler(PLAYBACK_OK)
    mcp = _mcp(fake, export_dir)
    seg = await _call(mcp, "nvr_list_recording_segments", {"channel": 5, "date": "2026-10-03"})
    assert seg["data"]["segment_count"] == 3
    alias = await _call(mcp, "nvr_search_recordings", {"channel": 5, "date": "2026-10-03"})
    assert alias["success"] is True
    win = await _call(
        mcp, "nvr_list_motion_windows", {"channel": 5, "date": "2026-10-03", "tz": "utc"}
    )
    assert win["data"]["summary"]["window_count"] == 1
    # These two need ffmpeg; either it runs or returns MEDIA_UNAVAILABLE - both are envelopes.
    sheet = await _call(mcp, "nvr_contact_sheet", {"channel": 5, "start": START, "end": END})
    _assert_envelope(sheet)
    frames = await _call(mcp, "nvr_sample_frames", {"channel": 5, "start": START, "end": END})
    _assert_envelope(frames)


async def test_wrappers_get_and_purge_via_mcp(fake: FakeNvr, export_dir: Path) -> None:
    mcp = _mcp(fake, export_dir)
    missing = await _call(mcp, "nvr_get_export", {"name": "ch5_20261003t120000z_s1.jpg"})
    assert missing["error"]["code"] == "NOT_FOUND"
    refused = await _call(mcp, "nvr_purge_exports", {"confirm_write": True})
    assert refused["error"]["code"] == "WRITE_REFUSED"


async def test_export_resource_reads_blob(fake: FakeNvr, export_dir: Path) -> None:
    name = "ch5_20261003t120000z_s2.jpg"
    _write_export(export_dir, name, b"BLOB")
    mcp = _mcp(fake, export_dir)
    contents = await mcp.read_resource(f"exports://{name}")
    first = contents[0] if isinstance(contents, list) else next(iter(contents))
    assert first.content == b"BLOB"
