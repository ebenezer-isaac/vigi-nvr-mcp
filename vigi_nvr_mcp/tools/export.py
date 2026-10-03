"""RTSP export, snapshot and stream-URL tools (Phase N7).

Six tools plus the RTSP enable switch:

* ``nvr_get_rtsp_status``  - read ONVIF/RTSP enablement and TCP-probe the port.
* ``nvr_enable_rtsp``      - the one-time ONVIF ``set`` (double write-gated, dry-run).
* ``nvr_get_stream_url``   - a redacted live RTSP URL plus a credentials-env hint.
* ``nvr_export_clip``      - export a replay window to mp4 (local write: gated).
* ``nvr_snapshot``         - a single JPEG into the export dir (read-only).
* ``nvr_list_exports`` / ``nvr_delete_export`` - manage the export dir (confined).

RTSP credentials live in the RTSP URL's userinfo and are visible to a local ``ps``
on the NVR host (a single-admin box by design). Every URL that leaves a tool is
redacted; the plaintext URL is only ever handed to ffmpeg as one argv element.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..core.errors import DeviceError, ProtocolError
from ..core.write_gate import check_write_gate
from ..media import DEFAULT_BITRATE_BPS
from ..media.ffmpeg import (
    EXPORT_SUFFIXES,
    FfmpegRunner,
    confine,
    export_argv,
    export_timeout,
    probe_tcp,
)
from ..media.urls import (
    live_url,
    redacted_url,
    replay_url,
    validate_channel,
    validate_stream,
    validate_window,
)
from . import ToolContext, run_tool

ONVIF_MODULE = "onvif_server"
ONVIF_SECTION = "onvif"
ENABLED_ON = "on"
ENABLED_OFF = "off"


def _parse_dt(name: str, value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{name} must be an ISO-8601 timestamp with a UTC offset (e.g. 2026-10-03T12:00:00Z)"
        ) from exc


def _enabled_flag(reply: Any) -> tuple[bool, Any]:
    if not isinstance(reply, dict):
        raise ProtocolError("onvif_server reply is not an object")
    section = reply.get(ONVIF_MODULE, reply)
    onvif = section.get(ONVIF_SECTION) if isinstance(section, dict) else None
    if not isinstance(onvif, dict) or "enabled" not in onvif:
        raise ProtocolError("onvif_server reply has no usable onvif.enabled field")
    raw = onvif["enabled"]
    return str(raw).strip().lower() in {ENABLED_ON, "1", "true", "enabled"}, raw


async def get_rtsp_status(ctx: ToolContext, runner: FfmpegRunner) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        reply = await ctx.client.call("get", ONVIF_MODULE, {"name": ONVIF_SECTION})
        enabled, raw = _enabled_flag(reply)
        port = ctx.settings.rtsp_port
        port_open = await probe_tcp(ctx.settings.host, port)
        return {
            "enabled": enabled,
            "enabled_raw": raw,
            "rtsp_port": port,
            "port_open": port_open,
            "hint": (
                "If enabled is false, call nvr_enable_rtsp once (write-gated). If enabled "
                "but port_open is false, the port may be firewalled on the NVR."
            ),
        }

    return await run_tool("nvr_get_rtsp_status", action)


async def enable_rtsp(ctx: ToolContext, confirm_write: bool = False) -> dict[str, Any]:
    refusal = check_write_gate(ctx.settings, "set", confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        params = {ONVIF_SECTION: {"enabled": ENABLED_ON}}
        request = {"method": "set", ONVIF_MODULE: params}
        if ctx.settings.dry_run:
            return {"dry_run": True, "request": request}
        before_reply = await ctx.client.call("get", ONVIF_MODULE, {"name": ONVIF_SECTION})
        before, _ = _enabled_flag(before_reply)
        response = await ctx.client.call("set", ONVIF_MODULE, params)
        after_reply = await ctx.client.call("get", ONVIF_MODULE, {"name": ONVIF_SECTION})
        after, _ = _enabled_flag(after_reply)
        return {
            "dry_run": False,
            "request": request,
            "response": response,
            "enabled_before": before,
            "enabled_after": after,
        }

    return await run_tool("nvr_enable_rtsp", lambda: ctx.writes.run(action))


async def get_stream_url(ctx: ToolContext, channel: int, stream: int = 1) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        url = live_url(ctx.settings, channel, stream)
        return {
            "channel": validate_channel(channel),
            "stream": validate_stream(stream),
            "url": redacted_url(url),
            # Keys deliberately avoid the names redact() strips (password*, pwd, …);
            # these are env-var hints, not secrets.
            "credentials_env": {
                "rtsp_user": "VIGI_NVR_RTSP_USERNAME (defaults to VIGI_NVR_USERNAME)",
                "rtsp_pass": "VIGI_NVR_RTSP_PASSWORD (defaults to VIGI_NVR_PASSWORD)",
            },
            "note": (
                "The real URL embeds credentials in its userinfo and is passed to your "
                "RTSP client directly; it is never returned here. Enable RTSP first "
                "(nvr_get_rtsp_status)."
            ),
        }

    return await run_tool("nvr_get_stream_url", action)


def _channel_bitrate_bps(reply: Any, channel: int) -> int:
    """Best-effort per-channel bitrate (bps) from a video_config reply; else default."""
    try:
        section = reply.get("video") if isinstance(reply, dict) else None
        main = section.get("main_res") if isinstance(section, dict) else None
        chn = main.get(f"chn{channel}") if isinstance(main, dict) else None
        raw = chn.get("bitrate") if isinstance(chn, dict) else None
        kbps = int(str(raw))
    except (AttributeError, TypeError, ValueError):
        return DEFAULT_BITRATE_BPS
    return max(kbps * 1000, DEFAULT_BITRATE_BPS) if kbps > 0 else DEFAULT_BITRATE_BPS


async def _estimate_bitrate(ctx: ToolContext, channel: int) -> int:
    try:
        reply = await ctx.client.query("video_config")
    except DeviceError:
        return DEFAULT_BITRATE_BPS
    return _channel_bitrate_bps(reply, channel)


async def export_clip(
    ctx: ToolContext,
    runner: FfmpegRunner,
    channel: int,
    start: str,
    end: str,
    stream: int = 1,
    confirm_write: bool = False,
) -> dict[str, Any]:
    refusal = check_write_gate(ctx.settings, "export", confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        ch, st = validate_channel(channel), validate_stream(stream)
        start_utc, end_utc, duration_s = validate_window(
            ctx.settings, _parse_dt("start", start), _parse_dt("end", end)
        )
        if ctx.settings.dry_run:
            url = replay_url(ctx.settings, ch, st, start_utc, end_utc)
            ffmpeg = ctx.settings.ffmpeg_path or "ffmpeg"
            name = "ch<N>_<start>_<end>_s<stream>.mp4"
            argv = export_argv(ffmpeg, redacted_url(url), name, export_timeout(duration_s))
            return {"dry_run": True, "argv": argv, "duration_s": duration_s}
        url = replay_url(ctx.settings, ch, st, start_utc, end_utc)
        bitrate = await _estimate_bitrate(ctx, ch)
        return await runner.export_clip(
            ch, st, start_utc, end_utc, url, duration_s, bitrate_bps=bitrate
        )

    return await run_tool("nvr_export_clip", action)


async def snapshot(
    ctx: ToolContext, runner: FfmpegRunner, channel: int, stream: int = 2
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        ch, st = validate_channel(channel), validate_stream(stream)
        url = live_url(ctx.settings, ch, st)
        return await runner.snapshot(ch, st, url)

    return await run_tool("nvr_snapshot", action)


async def list_exports(ctx: ToolContext) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        directory: Path = ctx.settings.export_path
        if not directory.exists():
            return {"export_dir": str(directory), "count": 0, "exports": []}
        entries = []
        for item in sorted(directory.iterdir()):
            if item.is_file() and item.suffix.lower() in EXPORT_SUFFIXES:
                stat = item.stat()
                entries.append(
                    {
                        "name": item.name,
                        "bytes": stat.st_size,
                        "modified_epoch": int(stat.st_mtime),
                    }
                )
        return {"export_dir": str(directory), "count": len(entries), "exports": entries}

    return await run_tool("nvr_list_exports", action)


async def delete_export(ctx: ToolContext, name: str, confirm_write: bool = False) -> dict[str, Any]:
    refusal = check_write_gate(ctx.settings, "delete", confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        target = confine(ctx.settings.export_path, name)
        if not target.exists():
            return {"deleted": False, "name": name, "reason": "no such export"}
        target.unlink()
        return {"deleted": True, "name": name}

    return await run_tool("nvr_delete_export", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    runner = FfmpegRunner(ctx.settings)

    @mcp.tool(name="nvr_get_rtsp_status")
    async def _status() -> dict[str, Any]:
        """Report whether ONVIF/RTSP is enabled (onvif_server.onvif.enabled) and
        whether the RTSP port (default 554, VIGI_NVR_RTSP_PORT) accepts TCP
        connections. Read-only."""
        return await get_rtsp_status(ctx, runner)

    @mcp.tool(name="nvr_enable_rtsp")
    async def _enable(confirm_write: bool = False) -> dict[str, Any]:
        """Enable ONVIF/RTSP on the NVR (onvif_server set). One-time setup. WRITE:
        needs VIGI_NVR_ALLOW_WRITES=true and confirm_write=true. Honours
        VIGI_NVR_DRY_RUN. Re-reads and returns enabled_before/after."""
        return await enable_rtsp(ctx, confirm_write)

    @mcp.tool(name="nvr_get_stream_url")
    async def _url(channel: int, stream: int = 1) -> dict[str, Any]:
        """Redacted live RTSP URL for a channel (1-16), stream 1=main/2=sub, plus a
        hint naming the env vars that hold the credentials. The password is never
        returned. Read-only."""
        return await get_stream_url(ctx, channel, stream)

    @mcp.tool(name="nvr_export_clip")
    async def _export(
        channel: int, start: str, end: str, stream: int = 1, confirm_write: bool = False
    ) -> dict[str, Any]:
        """Export a replay window (ISO-8601 start/end, UTC offset required) to an mp4
        in the export dir using ffmpeg -c copy (lossless). Writes to local disk, so
        it is gated like a write: VIGI_NVR_ALLOW_WRITES=true AND confirm_write=true.
        VIGI_NVR_DRY_RUN returns the argv with the URL redacted. Window <=
        VIGI_NVR_EXPORT_MAX_MINUTES. Returns path, bytes, duration_s, sha256 and a
        redacted ffmpeg stderr tail. An empty window surfaces as NO_FOOTAGE_IN_WINDOW."""
        return await export_clip(ctx, runner, channel, start, end, stream, confirm_write)

    @mcp.tool(name="nvr_snapshot")
    async def _snapshot(channel: int, stream: int = 2) -> dict[str, Any]:
        """Capture one JPEG frame from a channel's live stream into the export dir
        (read-only; stream defaults to 2=sub). Needs RTSP enabled and ffmpeg
        available. Returns path, bytes and sha256."""
        return await snapshot(ctx, runner, channel, stream)

    @mcp.tool(name="nvr_list_exports")
    async def _list() -> dict[str, Any]:
        """List mp4/jpg files in the export directory (name, bytes, mtime).
        Read-only."""
        return await list_exports(ctx)

    @mcp.tool(name="nvr_delete_export")
    async def _delete(name: str, confirm_write: bool = False) -> dict[str, Any]:
        """Delete one file from the export directory by name (path-confined; the name
        must be a generated export filename). WRITE: needs VIGI_NVR_ALLOW_WRITES=true
        and confirm_write=true."""
        return await delete_export(ctx, name, confirm_write)

    return [
        "nvr_get_rtsp_status",
        "nvr_enable_rtsp",
        "nvr_get_stream_url",
        "nvr_export_clip",
        "nvr_snapshot",
        "nvr_list_exports",
        "nvr_delete_export",
    ]
