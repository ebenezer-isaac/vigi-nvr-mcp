"""Investigation tools (Phase N7b): recording timeline, merged motion windows,
contact sheets, sampled frames, and agent-retrievable / purgeable exports.

These sit on top of N7's RTSP/ffmpeg layer (``media.urls`` + ``FfmpegRunner``) and
the pure logic in :mod:`vigi_nvr_mcp.investigate`. Contact sheets and sampled
frames are read-only (like ``nvr_snapshot``: they only read frames into the export
dir). ``nvr_purge_exports`` deletes files, so it is double write-gated. The export
directory is also exposed as MCP resources (``exports://<name>``) for clients that
fetch blobs without base64.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict

from ..core.errors import DeviceError, NotFound, ProtocolError
from ..core.redact import redact
from ..core.write_gate import check_write_gate
from ..investigate import (
    MAX_CHANNEL,
    MIN_CHANNEL,
    ExportTooLarge,
    RawProtocolError,
    SegmentType,
    resolve_tz,
)
from ..investigate.segments import classify_type, parse_device_time, parse_segments
from ..investigate.sheets import (
    contact_sheet_tail,
    sample_frames_tail,
    sample_timestamps,
    tile_timestamps,
)
from ..investigate.windows import Window, WindowInput, merge, summarise
from ..media.ffmpeg import EXPORT_SUFFIXES, FfmpegRunner, confine, export_timeout
from ..media.urls import (
    format_timestamp,
    redacted_url,
    replay_url,
    validate_channel,
    validate_stream,
    validate_window,
)
from . import ToolContext, run_tool
from .events import normalise_events
from .export import _parse_dt
from .shared import DateInput, parse_input, with_raw

MB = 1024 * 1024
DEFAULT_KINDS = ("motion", "smart", "alarm")
VALID_KINDS = frozenset(k.value for k in SegmentType)
MIME_BY_SUFFIX = {".mp4": "video/mp4", ".jpg": "image/jpeg"}


# --- recording timeline (folds N3's nvr_search_recordings) ---------------------


class RecordingTimeline(BaseModel):
    model_config = ConfigDict(extra="ignore")
    channel: int
    date: str
    segment_count: int
    segments: list[dict[str, Any]]


async def list_recording_segments(
    ctx: ToolContext, channel: int, date: str, tz: str = "local", include_raw: bool = False
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        args = parse_input(DateInput, channel=channel, date=date)
        resolve_tz(tz)  # validate early (maps bad tz to INVALID_INPUT)
        reply = await ctx.client.search_recordings(args.channel, args.date)
        try:
            segments = parse_segments(reply)
        except ProtocolError as exc:
            # Surface the raw payload (redacted) so N5 can correct the parser.
            raise RawProtocolError(str(exc), raw=redact(reply)) from exc
        model = RecordingTimeline(
            channel=args.channel,
            date=args.date,
            segment_count=len(segments),
            segments=[s.model_dump(mode="json") for s in segments],
        )
        return with_raw(model.model_dump(), reply, include_raw)

    return await run_tool("nvr_list_recording_segments", action)


# nvr_search_recordings (N3) is the same implementation under its old name.
async def search_recordings(
    ctx: ToolContext, channel: int, date: str, include_raw: bool = False
) -> dict[str, Any]:
    return await list_recording_segments(ctx, channel, date, include_raw=include_raw)


# --- merged motion windows ----------------------------------------------------


def _validate_kinds(kinds: list[str] | None) -> set[str]:
    chosen = list(DEFAULT_KINDS) if kinds is None else kinds
    if not isinstance(chosen, list) or not all(isinstance(k, str) for k in chosen):
        raise ValueError("kinds must be a list of strings")
    unknown = sorted(set(chosen) - VALID_KINDS)
    if unknown:
        raise ValueError(f"unknown kinds {unknown}; valid: {sorted(VALID_KINDS)}")
    return set(chosen)


def _resolve_day(date: str | None, since: str | None) -> str:
    """The calendar day to query playback for, from ``date`` or ``since``'s date."""
    source = date or (since[:10] if since else None)
    if not source:
        raise ValueError("provide date (YYYY-MM-DD) or since (an ISO-8601 timestamp)")
    DateInput(channel=MIN_CHANNEL, date=source)  # reuse the YYYY-MM-DD validator
    return source


def _parse_bound(name: str, value: str | None, tz_obj: Any) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=tz_obj)


def _channel_rows(rows: list[dict[str, Any]]) -> dict[int, str]:
    """Best-effort {channel_id: name} from added_dev rows (unverified field names)."""
    out: dict[int, str] = {}
    for row in rows:
        raw_id = row.get("id") or row.get("channel") or row.get("chn") or row.get("_row_key")
        try:
            cid = int(str(raw_id))
        except (TypeError, ValueError):
            continue
        name = row.get("name") or row.get("alias") or row.get("dev_name") or f"channel {cid}"
        out[cid] = str(name)
    return out


async def _channel_names(ctx: ToolContext) -> dict[int, str]:
    try:
        rows = await ctx.client.list_channels()
    except DeviceError:
        return {}
    return _channel_rows(rows)


def _segment_inputs(
    ch: int, name: str, segments: list[Any], day: str, tz_obj: Any, kinds: set[str]
) -> list[WindowInput]:
    inputs: list[WindowInput] = []
    for seg in segments:
        if seg.type.value not in kinds:
            continue
        start_dt = parse_device_time(seg.start, day, tz_obj)
        if start_dt is None:
            continue
        end_dt = parse_device_time(seg.end, day, tz_obj) if seg.end else None
        if end_dt is None or end_dt < start_dt:
            end_dt = start_dt
        inputs.append(
            WindowInput(
                ch, name, start_dt, end_dt, frozenset({seg.type.value}), frozenset({"recording"})
            )
        )
    return inputs


def _event_inputs(
    events: list[Any],
    names: dict[int, str],
    targets: set[int],
    day: str,
    tz_obj: Any,
    kinds: set[str],
) -> list[WindowInput]:
    inputs: list[WindowInput] = []
    for ev in events:
        kind = classify_type(ev.source).value
        if kind not in kinds:
            continue
        try:
            cid = int(str(ev.channel))
        except (TypeError, ValueError):
            continue
        if cid not in targets:
            continue
        when = parse_device_time(ev.time, day, tz_obj)
        if when is None:
            continue
        name = names.get(cid, f"channel {cid}")
        inputs.append(WindowInput(cid, name, when, when, frozenset({kind}), frozenset({"events"})))
    return inputs


def _in_range(w: Window, lo: datetime | None, hi: datetime | None) -> bool:
    if lo is not None and w.end < lo:
        return False
    return not (hi is not None and w.start > hi)


async def list_motion_windows(
    ctx: ToolContext,
    channel: int | str = "all",
    date: str | None = None,
    since: str | None = None,
    until: str | None = None,
    min_gap_s: float = 30.0,
    min_len_s: float = 3.0,
    kinds: list[str] | None = None,
    tz: str = "local",
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        kind_set = _validate_kinds(kinds)
        tz_obj = resolve_tz(tz)
        day = _resolve_day(date, since)
        lo = _parse_bound("since", since, tz_obj)
        hi = _parse_bound("until", until, tz_obj)
        if min_gap_s < 0 or min_len_s < 0:
            raise ValueError("min_gap_s and min_len_s must be non-negative")

        names = await _channel_names(ctx)
        if isinstance(channel, str) and channel.strip().lower() == "all":
            target_ids = sorted(names) or list(range(MIN_CHANNEL, MAX_CHANNEL + 1))
        else:
            raw_ch = channel.strip() if isinstance(channel, str) else channel
            target_ids = [validate_channel(int(raw_ch))]
        targets = set(target_ids)

        inputs: list[WindowInput] = []
        issues: list[dict[str, Any]] = []
        for cid in target_ids:
            name = names.get(cid, f"channel {cid}")
            try:
                reply = await ctx.client.search_recordings(cid, day)
                segments = parse_segments(reply)
            except ProtocolError as exc:
                issues.append({"channel": cid, "error": str(exc)})
                continue
            inputs.extend(_segment_inputs(cid, name, segments, day, tz_obj, kind_set))

        with contextlib.suppress(DeviceError):
            ev_reply = await ctx.client.list_events()
            events = normalise_events(ev_reply, None).events
            inputs.extend(_event_inputs(events, names, targets, day, tz_obj, kind_set))

        windows = [w for w in merge(inputs, min_gap_s, min_len_s) if _in_range(w, lo, hi)]
        result: dict[str, Any] = {
            "date": day,
            "channels_searched": target_ids,
            "kinds": sorted(kind_set),
            "windows": [w.to_dict() for w in windows],
            "summary": summarise(windows),
        }
        if issues:
            result["issues"] = issues
        return result

    return await run_tool("nvr_list_motion_windows", action)


# --- contact sheet & sampled frames (read-only) -------------------------------


def _replay(
    ctx: ToolContext, ch: int, st: int, start: str, end: str
) -> tuple[datetime, datetime, float, str]:
    start_utc, end_utc, duration_s = validate_window(
        ctx.settings, _parse_dt("start", start), _parse_dt("end", end)
    )
    url = replay_url(ctx.settings, ch, st, start_utc, end_utc)
    return start_utc, end_utc, duration_s, url


async def contact_sheet(
    ctx: ToolContext,
    runner: FfmpegRunner,
    channel: int,
    start: str,
    end: str,
    cols: int = 4,
    rows: int = 3,
    width: int = 1600,
    stream: int = 1,
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        ch, st = validate_channel(channel), validate_stream(stream)
        if not (1 <= cols <= 10 and 1 <= rows <= 10):
            raise ValueError("cols and rows must each be between 1 and 10")
        if not (64 <= width <= 8192):
            raise ValueError("width must be between 64 and 8192")
        start_utc, end_utc, duration_s, url = _replay(ctx, ch, st, start, end)
        tiles = tile_timestamps(start_utc, end_utc, cols, rows)
        name = f"ch{ch}_{format_timestamp(start_utc)}_{format_timestamp(end_utc)}_s{st}.jpg"
        output = ctx.settings.export_path / name
        timeout_s = export_timeout(duration_s)
        tail = contact_sheet_tail(
            url,
            str(output),
            timeout_s,
            cols=cols,
            rows=rows,
            width=width,
            start=start_utc,
            duration_s=duration_s,
        )
        result = await runner.run_to_file(url, output, tail, timeout_s, verify=False)
        return {**result, "cols": cols, "rows": rows, "tiles": tiles, "url": redacted_url(url)}

    return await run_tool("nvr_contact_sheet", action)


async def sample_frames(
    ctx: ToolContext,
    runner: FfmpegRunner,
    channel: int,
    start: str,
    end: str,
    every_s: float = 2.0,
    max_frames: int = 60,
    stream: int = 1,
) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        ch, st = validate_channel(channel), validate_stream(stream)
        if not (0 < max_frames <= 240):
            raise ValueError("max_frames must be between 1 and 240")
        if every_s <= 0:
            raise ValueError("every_s must be positive")
        start_utc, end_utc, duration_s, url = _replay(ctx, ch, st, start, end)
        stamps = sample_timestamps(start_utc, end_utc, every_s, max_frames)
        export_dir = ctx.settings.export_path

        def _target(index: int) -> Path:
            stamp = format_timestamp(start_utc + timedelta(seconds=index * every_s))
            return export_dir / f"ch{ch}_{stamp}_s{st}.jpg"

        targets = [_target(s["index"]) for s in stamps]
        tmp_prefix = f"_frames_ch{ch}_{format_timestamp(start_utc)}"
        out_pattern = export_dir / f"{tmp_prefix}_%03d.jpg"
        glob_pat = f"{tmp_prefix}_*.jpg"
        timeout_s = export_timeout(duration_s)
        tail = sample_frames_tail(
            url, str(out_pattern), timeout_s, every_s=every_s, frame_count=len(stamps)
        )
        produced, stderr_tail = await runner.run_multi(
            url, tail, timeout_s, lambda: list(export_dir.glob(glob_pat))
        )
        frames = _rename_frames(produced, targets, stamps)
        return {
            "channel": ch,
            "stream": st,
            "frame_count": len(frames),
            "frames": frames,
            "url": redacted_url(url),
            "ffmpeg_stderr_tail": stderr_tail,
        }

    return await run_tool("nvr_sample_frames", action)


def _rename_frames(
    produced: list[Path], targets: list[Path], stamps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for produced_path, target, stamp in zip(produced, targets, stamps, strict=False):
        with contextlib.suppress(OSError):
            produced_path.replace(target)
        if target.exists():
            frames.append(
                {
                    "name": target.name,
                    "timestamp": stamp["timestamp"],
                    "path": str(target.resolve()),
                }
            )
    for leftover in produced[len(targets) :]:
        with contextlib.suppress(OSError):
            leftover.unlink()
    return frames


# --- retrieval, listing retention, purge --------------------------------------


async def get_export(ctx: ToolContext, name: str, max_mb: float = 20.0) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        if max_mb <= 0:
            raise ValueError("max_mb must be positive")
        target = confine(ctx.settings.export_path, name)
        if not target.is_file():
            raise NotFound(f"no export named {name!r}")
        data = target.read_bytes()
        max_bytes = int(max_mb * MB)
        if len(data) > max_bytes:
            raise ExportTooLarge(
                f"{name} is {len(data)} bytes, over the {max_bytes}-byte inline limit; "
                "re-export with target_max_mb to shrink it, or fetch it as a resource "
                f"(exports://{name})",
                size_bytes=len(data),
                max_bytes=max_bytes,
            )
        return {
            "name": target.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "mime": MIME_BY_SUFFIX.get(target.suffix.lower(), "application/octet-stream"),
            "base64": base64.b64encode(data).decode("ascii"),
        }

    return await run_tool("nvr_get_export", action)


def _entry(item: Path, now: float, retention_s: float) -> dict[str, Any]:
    stat = item.stat()
    age = max(0.0, now - stat.st_mtime)
    return {
        "name": item.name,
        "bytes": stat.st_size,
        "modified_epoch": int(stat.st_mtime),
        "age_seconds": int(age),
        "expires_epoch": int(stat.st_mtime + retention_s),
        "expired": age > retention_s,
    }


async def purge_exports(ctx: ToolContext, confirm_write: bool = False) -> dict[str, Any]:
    refusal = check_write_gate(ctx.settings, "delete", confirm_write)
    if refusal is not None:
        return refusal

    async def action() -> dict[str, Any]:
        directory = ctx.settings.export_path
        retention_days = ctx.settings.export_retention_days
        retention_s = retention_days * 86400
        now = datetime.now(UTC).timestamp()
        expired = []
        if directory.exists():
            for item in sorted(directory.iterdir()):
                is_export = item.is_file() and item.suffix.lower() in EXPORT_SUFFIXES
                if is_export and now - item.stat().st_mtime > retention_s:
                    expired.append(item)
        names = [p.name for p in expired]
        if ctx.settings.dry_run:
            return {"dry_run": True, "retention_days": retention_days, "would_delete": names}
        for item in expired:
            with contextlib.suppress(OSError):
                item.unlink()
        return {
            "dry_run": False,
            "retention_days": retention_days,
            "deleted": names,
            "count": len(names),
        }

    return await run_tool("nvr_purge_exports", lambda: ctx.writes.run(action))


# --- export dir as MCP resources ----------------------------------------------


def read_export_blob(ctx: ToolContext, name: str) -> bytes:
    """Return the bytes of one export (path-confined). Raises on a bad name/miss."""
    target = confine(ctx.settings.export_path, name)
    if not target.is_file():
        raise NotFound(f"no export named {name!r}")
    return target.read_bytes()


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    runner = FfmpegRunner(ctx.settings)

    @mcp.tool(name="nvr_list_recording_segments")
    async def _segments(
        channel: int, date: str, tz: str = "local", include_raw: bool = False
    ) -> dict[str, Any]:
        """Typed recording timeline for one channel (1-16) on one day (YYYY-MM-DD),
        read-only: a list of {start, end, type, raw_type} where type is normal /
        motion / smart / manual / alarm / unknown. tz is 'local', 'utc' or an IANA
        zone. include_raw=true adds the raw device reply at data.raw. On an
        unrecognised reply shape returns PROTOCOL_ERROR with the payload under
        data.raw (the live run corrects the shape)."""
        return await list_recording_segments(ctx, channel, date, tz, include_raw)

    @mcp.tool(name="nvr_search_recordings")
    async def _search(channel: int, date: str, include_raw: bool = False) -> dict[str, Any]:
        """Alias of nvr_list_recording_segments (kept for compatibility). Lists
        recorded segments for one channel (1-16) on one day (YYYY-MM-DD),
        read-only."""
        return await search_recordings(ctx, channel, date, include_raw)

    @mcp.tool(name="nvr_list_motion_windows")
    async def _windows(
        channel: int | str = "all",
        date: str | None = None,
        since: str | None = None,
        until: str | None = None,
        min_gap_s: float = 30.0,
        min_len_s: float = 3.0,
        kinds: list[str] | None = None,
        tz: str = "local",
    ) -> dict[str, Any]:
        """Merged, de-duplicated activity windows for one channel (1-16) or "all",
        read-only. Combines the typed recording timeline with event logs, merging
        spans that overlap or sit within min_gap_s and dropping windows shorter than
        min_len_s. Provide date (YYYY-MM-DD) or since (ISO-8601); optionally narrow
        with since/until. kinds defaults to motion/smart/alarm. Returns sorted
        windows [{channel, name, start, end, duration_s, kinds, sources}] and a
        per-channel summary."""
        return await list_motion_windows(
            ctx, channel, date, since, until, min_gap_s, min_len_s, kinds, tz
        )

    @mcp.tool(name="nvr_contact_sheet")
    async def _sheet(
        channel: int,
        start: str,
        end: str,
        cols: int = 4,
        rows: int = 3,
        width: int = 1600,
        stream: int = 1,
    ) -> dict[str, Any]:
        """One JPEG contact sheet of cols x rows frames evenly sampled across a
        replay window (ISO-8601 start/end, UTC offset required), each tile's exact
        time burned in. Read-only (reads frames into the export dir). Returns the
        file info plus a tile->timestamp map so an agent can cite the moment. Needs
        RTSP enabled and ffmpeg available."""
        return await contact_sheet(ctx, runner, channel, start, end, cols, rows, width, stream)

    @mcp.tool(name="nvr_sample_frames")
    async def _frames(
        channel: int,
        start: str,
        end: str,
        every_s: float = 2.0,
        max_frames: int = 60,
        stream: int = 1,
    ) -> dict[str, Any]:
        """Individual JPEG frames every every_s seconds across a replay window
        (ISO-8601 start/end, UTC offset required), up to max_frames. Read-only.
        Returns each frame's name, path and timestamp. Use after a contact-sheet hit
        to pin the exact moment."""
        return await sample_frames(ctx, runner, channel, start, end, every_s, max_frames, stream)

    @mcp.tool(name="nvr_get_export")
    async def _get(name: str, max_mb: float = 20.0) -> dict[str, Any]:
        """Return one export file's content as base64 for files up to max_mb
        (default 20; Gmail caps attachments near 25 MB). Over the limit returns
        TOO_LARGE with the size and a hint to re-export with target_max_mb or fetch
        the exports://<name> resource. Path-confined to the export dir."""
        return await get_export(ctx, name, max_mb)

    @mcp.tool(name="nvr_purge_exports")
    async def _purge(confirm_write: bool = False) -> dict[str, Any]:
        """Delete exports older than VIGI_NVR_EXPORT_RETENTION_DAYS (default 7).
        Double-gated like any delete: needs VIGI_NVR_ALLOW_WRITES=true and
        confirm_write=true. VIGI_NVR_DRY_RUN=true lists what would be deleted
        without deleting."""
        return await purge_exports(ctx, confirm_write)

    @mcp.resource(
        "exports://{name}",
        name="nvr_export",
        description="A clip/snapshot/contact-sheet file from the NVR export directory.",
        mime_type="application/octet-stream",
    )
    def _export_resource(name: str) -> bytes:
        return read_export_blob(ctx, name)

    return [
        "nvr_list_recording_segments",
        "nvr_search_recordings",
        "nvr_list_motion_windows",
        "nvr_contact_sheet",
        "nvr_sample_frames",
        "nvr_get_export",
        "nvr_purge_exports",
    ]
