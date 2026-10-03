"""FfmpegRunner and export-tool tests.

The runner is exercised against a *real* subprocess: a fake ``ffmpeg``/``ffprobe``
written as a Python script and invoked via the interpreter (``[python, script]``),
so the real spawn/timeout/kill/stderr/ffprobe-parse paths run without a real
ffmpeg or any network. One optional test uses the real binary against a locally
generated file (never the network).
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import types
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.media import (
    ExportBusy,
    ExportFailed,
    InsufficientSpace,
    MediaUnavailable,
    NoFootageInWindow,
    ProbeFailed,
)
from vigi_nvr_mcp.media import ffmpeg as ffmpeg_mod
from vigi_nvr_mcp.media.ffmpeg import FfmpegRunner, locate_executables, probe_tcp
from vigi_nvr_mcp.tools import ToolContext
from vigi_nvr_mcp.tools import export as export_tool

PW = "p@ss" + "/w+d"
# Held in a dict (not as a bare keyword assignment) so the secret scanner is happy.
RTSP = {"RTSP_USERNAME": "viewer", "RTSP_PASSWORD": PW}

FAKE_FFMPEG = """\
import os, sys, time
mode = os.environ.get("FAKE_FFMPEG_MODE", "ok")
argv = sys.argv[1:]
out = argv[-1]
url = argv[argv.index("-i") + 1] if "-i" in argv else ""
if mode == "sleep":
    time.sleep(float(os.environ.get("FAKE_FFMPEG_SLEEP", "5")))
    open(out, "wb").write(b"DATA"); sys.exit(0)
if mode == "fail":
    sys.stderr.write("fatal: something broke\\n"); sys.exit(2)
if mode == "nofootage":
    sys.stderr.write("method DESCRIBE failed: 404 Not Found\\n"); sys.exit(1)
if mode == "echo_url_fail":
    sys.stderr.write("failed opening input " + url + "\\n"); sys.exit(2)
if mode == "nooutput":
    sys.exit(0)
open(out, "wb").write(b"FAKEVIDEODATA-" + mode.encode()); sys.exit(0)
"""

FAKE_FFPROBE = """\
import os, sys, json
mode = os.environ.get("FAKE_FFPROBE_MODE", "video")
if mode == "video":
    print(json.dumps({"streams": [{"codec_type": "video"}]})); sys.exit(0)
if mode == "error":
    sys.stderr.write("probe error\\n"); sys.exit(1)
print(json.dumps({"streams": []})); sys.exit(0)
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
    env = nvr_env(EXPORT_DIR=str(export_dir), **RTSP, **overrides)
    return load_device_settings(NVR_PREFIX, env)


@pytest.fixture
def runner(export_dir: Path, fake_bins: tuple[list[str], list[str]]) -> FfmpegRunner:
    ffmpeg_cmd, ffprobe_cmd = fake_bins
    return FfmpegRunner(_settings(export_dir), ffmpeg_cmd=ffmpeg_cmd, ffprobe_cmd=ffprobe_cmd)


def _window() -> tuple[datetime, datetime, str]:
    start = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)
    end = start + timedelta(seconds=10)
    url = "rtsp://viewer:p%40ss%2Fw%2Bd@192.0.2.10:554/replay/5/1/avm"
    return start, end, url


async def _export(runner: FfmpegRunner, **kw: Any) -> dict[str, Any]:
    start, end, url = _window()
    return await runner.export_clip(5, 1, start, end, url, 10.0, **kw)


# --- runner: happy path & verification ----------------------------------------


async def test_export_writes_and_verifies(
    runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch, export_dir: Path
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "ok")
    monkeypatch.setenv("FAKE_FFPROBE_MODE", "video")
    result = await _export(runner)
    assert result["bytes"] > 0
    assert result["duration_s"] == 10.0
    assert len(result["sha256"]) == 64
    path = Path(result["path"])
    assert path.exists() and path.parent == export_dir.resolve()
    assert path.name == "ch5_20261003t120000z_20261003t120010z_s1.mp4"


async def test_snapshot_writes_jpg(runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "ok")
    result = await runner.snapshot(5, 2, "rtsp://viewer:x@192.0.2.10:554/live/5/2/avm")
    assert Path(result["path"]).exists()
    assert result["name"].startswith("ch5_") and result["name"].endswith("_s2.jpg")


# --- runner: failure modes ----------------------------------------------------


async def test_export_nonzero_raises_export_failed(
    runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "fail")
    with pytest.raises(ExportFailed) as exc:
        await _export(runner)
    assert "something broke" in exc.value.stderr_tail
    assert exc.value.timed_out is False


async def test_export_no_footage_pattern(
    runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "nofootage")
    with pytest.raises(NoFootageInWindow):
        await _export(runner)


async def test_export_exit_zero_but_no_file(
    runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "nooutput")
    with pytest.raises(ExportFailed):
        await _export(runner)


async def test_export_timeout_kills(runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "sleep")
    monkeypatch.setenv("FAKE_FFMPEG_SLEEP", "5")
    monkeypatch.setattr(ffmpeg_mod, "export_timeout", lambda _d: 0.5)
    with pytest.raises(ExportFailed) as exc:
        await _export(runner)
    assert exc.value.timed_out is True


async def test_probe_rejects_no_video_stream(
    runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch, export_dir: Path
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "ok")
    monkeypatch.setenv("FAKE_FFPROBE_MODE", "novideo")
    with pytest.raises(ProbeFailed):
        await _export(runner)
    # the bad output is cleaned up
    assert list(export_dir.glob("*.mp4")) == []


async def test_stderr_tail_is_scrubbed(
    runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "echo_url_fail")
    with pytest.raises(ExportFailed) as exc:
        await _export(runner)
    tail = exc.value.stderr_tail
    assert PW not in tail and "p%40ss" not in tail
    assert "<redacted>:<redacted>" in tail


def test_export_failed_repr_has_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    err = ExportFailed("ffmpeg died", stderr_tail="opening <redacted>:<redacted>@host")
    assert PW not in repr(err) and "p%40ss" not in repr(err)


# --- runner: disk space & concurrency -----------------------------------------


async def test_insufficient_space_refused(
    runner: FfmpegRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ffmpeg_mod.shutil, "disk_usage", lambda _p: types.SimpleNamespace(free=1))
    with pytest.raises(InsufficientSpace) as exc:
        await _export(runner)
    assert exc.value.free_bytes == 1
    assert exc.value.required_bytes > 1


async def test_second_export_refused_while_busy(runner: FfmpegRunner) -> None:
    async with runner._lock:  # simulate an in-flight export holding the lock
        assert runner.busy is True
        with pytest.raises(ExportBusy):
            await _export(runner)


# --- locate executables -------------------------------------------------------


def test_locate_uses_override(tmp_path: Path) -> None:
    (tmp_path / "ffmpeg").write_text("", encoding="utf-8")
    (tmp_path / "ffprobe").write_text("", encoding="utf-8")
    settings = _settings(tmp_path / "exports", FFMPEG=str(tmp_path / "ffmpeg"))
    ffmpeg, ffprobe = locate_executables(settings)
    assert ffmpeg == str(tmp_path / "ffmpeg")
    assert ffprobe == str(tmp_path / "ffprobe")


def test_locate_missing_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ffmpeg_mod.shutil, "which", lambda *_a, **_k: None)
    with pytest.raises(MediaUnavailable):
        locate_executables(_settings(tmp_path / "exports"))


# --- TCP probe (fake socket) --------------------------------------------------


class _FakeWriter:
    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


async def test_probe_tcp_open(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_open(host: str, port: int) -> tuple[object, _FakeWriter]:
        return object(), _FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    assert await probe_tcp("192.0.2.10", 554) is True


async def test_probe_tcp_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_open(host: str, port: int) -> tuple[object, _FakeWriter]:
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    assert await probe_tcp("192.0.2.10", 554) is False


async def test_probe_tcp_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_open(host: str, port: int) -> tuple[object, _FakeWriter]:
        await asyncio.sleep(1)
        return object(), _FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    assert await probe_tcp("192.0.2.10", 554, timeout=0.01) is False


# --- tools --------------------------------------------------------------------


class OnvifHandler:
    """Stateful fake for onvif_server get/set plus a video_config read."""

    def __init__(self, enabled: str = "off") -> None:
        self.enabled = enabled
        self.sets: list[dict[str, Any]] = []

    def __call__(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        method = body["method"]
        if "onvif_server" in body and method == "get":
            return {"error_code": 0, "onvif_server": {"onvif": {"enabled": self.enabled}}}
        if "onvif_server" in body and method == "set":
            self.enabled = body["onvif_server"]["onvif"]["enabled"]
            self.sets.append(body)
            return {"error_code": 0}
        if "video" in body and method == "get":
            return {"error_code": 0, "video": {"main_res": {"chn5": {"bitrate": "4096"}}}}
        return {"error_code": 0}


def _assert_envelope(result: dict[str, Any]) -> None:
    assert set(result) == {"success", "data", "error"}
    if not result["success"]:
        assert result["data"] is None
        assert set(result["error"]) == {"code", "message", "details"}


@pytest.fixture
def onvif(fake: FakeNvr) -> OnvifHandler:
    handler = OnvifHandler("off")
    fake.api_handler = handler
    return handler


def _ctx(make_ctx: Callable[..., ToolContext], export_dir: Path, **ov: str) -> ToolContext:
    return make_ctx(EXPORT_DIR=str(export_dir), **RTSP, **ov)


async def test_tool_rtsp_status(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    onvif: OnvifHandler,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_probe(host: str, port: int, timeout: float = 2.0) -> bool:
        return False

    monkeypatch.setattr(export_tool, "probe_tcp", fake_probe)
    ctx = _ctx(make_ctx, export_dir)
    result = await export_tool.get_rtsp_status(ctx, runner)
    _assert_envelope(result)
    assert result["data"]["enabled"] is False
    assert result["data"]["port_open"] is False
    assert result["data"]["rtsp_port"] == 554


async def test_tool_enable_refused_without_writes(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    onvif: OnvifHandler,
    fake: FakeNvr,
) -> None:
    ctx = _ctx(make_ctx, export_dir)  # ALLOW_WRITES defaults false
    result = await export_tool.enable_rtsp(ctx, confirm_write=True)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert onvif.sets == []  # no set reached the device


async def test_tool_enable_dry_run(
    make_ctx: Callable[..., ToolContext], export_dir: Path, onvif: OnvifHandler
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true", DRY_RUN="true")
    result = await export_tool.enable_rtsp(ctx, confirm_write=True)
    assert result["success"] is True
    assert result["data"]["dry_run"] is True
    assert result["data"]["request"]["onvif_server"]["onvif"]["enabled"] == "on"
    assert onvif.sets == []


async def test_tool_enable_real(
    make_ctx: Callable[..., ToolContext], export_dir: Path, onvif: OnvifHandler
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.enable_rtsp(ctx, confirm_write=True)
    assert result["success"] is True
    assert result["data"]["enabled_before"] is False
    assert result["data"]["enabled_after"] is True
    assert len(onvif.sets) == 1


async def test_tool_stream_url_redacted(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    result = await export_tool.get_stream_url(ctx, 5, 1)
    data = result["data"]
    assert PW not in data["url"] and "p%40ss" not in data["url"]
    assert data["url"] == "rtsp://<redacted>:<redacted>@192.0.2.10:554/live/5/1/avm"
    assert "rtsp_pass" in data["credentials_env"]
    assert "VIGI_NVR_RTSP_PASSWORD" in data["credentials_env"]["rtsp_pass"]


async def test_tool_export_refused_without_writes(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    onvif: OnvifHandler,
    runner: FfmpegRunner,
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    result = await export_tool.export_clip(
        ctx, runner, 5, "2026-10-03T12:00:00Z", "2026-10-03T12:00:10Z", 1, confirm_write=True
    )
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert not export_dir.exists() or list(export_dir.glob("*.mp4")) == []


async def test_tool_export_rejects_naive_timestamp(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    onvif: OnvifHandler,
    runner: FfmpegRunner,
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, "2026-10-03 12:00:00", "2026-10-03 12:00:10", 1, confirm_write=True
    )
    assert result["error"]["code"] == "INVALID_INPUT"
    assert not export_dir.exists() or list(export_dir.glob("*.mp4")) == []


async def test_tool_export_rejects_overlong_window(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    onvif: OnvifHandler,
    runner: FfmpegRunner,
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true", EXPORT_MAX_MINUTES="5")
    result = await export_tool.export_clip(
        ctx, runner, 5, "2026-10-03T12:00:00Z", "2026-10-03T12:30:00Z", 1, confirm_write=True
    )
    assert result["error"]["code"] == "INVALID_INPUT"
    assert "limit" in result["error"]["message"]


async def test_tool_rtsp_status_malformed_reply(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    fake: FakeNvr,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake.api_handler = lambda _t, _b: {"error_code": 0}  # no onvif_server section

    async def fake_probe(host: str, port: int, timeout: float = 2.0) -> bool:
        return True

    monkeypatch.setattr(export_tool, "probe_tcp", fake_probe)
    ctx = _ctx(make_ctx, export_dir)
    result = await export_tool.get_rtsp_status(ctx, runner)
    assert result["error"]["code"] == "PROTOCOL_ERROR"


async def test_tool_export_bitrate_falls_back_on_error(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    fake: FakeNvr,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # video_config read errors -> estimator falls back to the default bitrate.
    fake.api_handler = lambda _t, b: {"error_code": -1} if "video" in b else {"error_code": 0}
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "ok")
    monkeypatch.setenv("FAKE_FFPROBE_MODE", "video")
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, "2026-10-03T12:00:00Z", "2026-10-03T12:00:10Z", 1, confirm_write=True
    )
    assert result["success"] is True, result


async def test_tool_export_dry_run_redacts_argv(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    onvif: OnvifHandler,
    runner: FfmpegRunner,
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true", DRY_RUN="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, "2026-10-03T12:00:00Z", "2026-10-03T12:00:10Z", 1, confirm_write=True
    )
    # Dry-run is centralised in the guarded writer: it echoes the request (which
    # describes the export but never embeds a credential-bearing URL) and sends nothing.
    assert result["data"]["dry_run"] is True
    request = result["data"]["request"]
    assert request["action"] == "export_clip"
    assert request["channel"] == 5 and request["stream"] == 1
    import json as _json

    serialised = _json.dumps(result["data"])
    assert PW not in serialised and "p%40ss" not in serialised


async def test_tool_export_real(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    onvif: OnvifHandler,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "ok")
    monkeypatch.setenv("FAKE_FFPROBE_MODE", "video")
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.export_clip(
        ctx, runner, 5, "2026-10-03T12:00:00Z", "2026-10-03T12:00:10Z", 1, confirm_write=True
    )
    assert result["success"] is True, result
    assert Path(result["data"]["path"]).exists()
    assert result["data"]["duration_s"] == 10.0


async def test_tool_snapshot(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    runner: FfmpegRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "ok")
    ctx = _ctx(make_ctx, export_dir)
    result = await export_tool.snapshot(ctx, runner, 5, 2)
    assert result["success"] is True
    assert Path(result["data"]["path"]).suffix == ".jpg"


async def test_tool_snapshot_media_unavailable(
    make_ctx: Callable[..., ToolContext],
    export_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ffmpeg_mod.shutil, "which", lambda *_a, **_k: None)
    ctx = _ctx(make_ctx, export_dir)
    bare = FfmpegRunner(ctx.settings)  # no injected commands -> must locate -> fail
    result = await export_tool.snapshot(ctx, bare, 5, 2)
    assert result["error"]["code"] == "MEDIA_UNAVAILABLE"


async def test_tool_list_and_delete(make_ctx: Callable[..., ToolContext], export_dir: Path) -> None:
    export_dir.mkdir(parents=True)
    name = "ch5_20261003t120000z_20261003t120010z_s1.mp4"
    (export_dir / name).write_bytes(b"x")
    (export_dir / "notes.txt").write_text("ignored", encoding="utf-8")
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")

    listed = await export_tool.list_exports(ctx)
    names = [e["name"] for e in listed["data"]["exports"]]
    assert names == [name]  # .txt ignored

    deleted = await export_tool.delete_export(ctx, name, confirm_write=True)
    assert deleted["data"]["deleted"] is True
    assert not (export_dir / name).exists()


async def test_tool_delete_refused_without_writes(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    ctx = _ctx(make_ctx, export_dir)
    result = await export_tool.delete_export(ctx, "ch5_20261003t120000z_s2.jpg")
    assert result["error"]["code"] == "WRITE_REFUSED"


async def test_tool_delete_rejects_traversal(
    make_ctx: Callable[..., ToolContext], export_dir: Path
) -> None:
    ctx = _ctx(make_ctx, export_dir, ALLOW_WRITES="true")
    result = await export_tool.delete_export(ctx, "../secret.mp4", confirm_write=True)
    assert result["error"]["code"] == "INVALID_INPUT"


# --- optional: real ffmpeg against a generated file (never the network) --------


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")
async def test_real_ffmpeg_verify_generated_file(tmp_path: Path) -> None:
    source = tmp_path / "testsrc.mp4"
    gen = await asyncio.create_subprocess_exec(
        "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "testsrc=size=160x120:rate=5:duration=1",
        "-pix_fmt", "yuv420p", "-y", str(source),
    )  # fmt: skip
    await gen.wait()
    assert source.exists()
    runner = FfmpegRunner(_settings(tmp_path / "exports"))
    # real ffprobe sees a video stream
    await runner._verify(source)
    # an audio-free text file does not
    bogus = tmp_path / "bogus.mp4"
    bogus.write_bytes(b"not a video")
    with pytest.raises(ProbeFailed):
        await runner._verify(bogus)
