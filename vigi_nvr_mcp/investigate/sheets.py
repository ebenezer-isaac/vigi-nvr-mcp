"""Pure ffmpeg argv builders for contact sheets, sampled frames and re-encodes.

No subprocess, no shell: every function returns an argv *tail* (the arguments
after the ffmpeg binary) as a list of strings, plus the tile/frame -> timestamp
map the caller returns to the agent so it can cite an exact moment. The RTSP URL
(which carries credentials) is always a single list element and never interpolated
into a filter string. :func:`reencode_params` picks an x264 CRF and scale from the
clip duration and a target size; the actual fit is checked after encoding.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

MB = 1024 * 1024
# Re-encode: budget (bits/s) -> CRF. Lower CRF = better quality / bigger file.
_CRF_BY_BUDGET: tuple[tuple[float, int], ...] = (
    (6_000_000, 20),
    (3_000_000, 22),
    (1_500_000, 25),
    (750_000, 28),
    (350_000, 30),
    (0, 32),
)
_CRF_MIN, _CRF_MAX = 18, 34
_DEFAULT_CRF = 23
_SIZE_MARGIN = 0.90  # leave headroom for container/audio overhead under the target


def _epoch(dt: datetime) -> int:
    return int(dt.timestamp())


def tile_timestamps(start: datetime, end: datetime, cols: int, rows: int) -> list[dict[str, Any]]:
    """Even tile sampling times across ``[start, end)``: tile ``i`` -> ``start + i*step``."""
    if cols < 1 or rows < 1:
        raise ValueError("cols and rows must be >= 1")
    n = cols * rows
    duration = (end - start).total_seconds()
    if duration <= 0:
        raise ValueError("end must be after start")
    step = duration / n
    return [
        {"tile": i, "timestamp": (start + timedelta(seconds=i * step)).isoformat()}
        for i in range(n)
    ]


def _drawtext(start_epoch: int, fontsize: int) -> str:
    """drawtext that burns each frame's real wall-clock time (UTC) from its PTS.

    ``%{pts:gmtime:<epoch>:<fmt>}`` prints the frame time offset by the window
    start epoch, so every tile is labelled with the moment it was captured.
    """
    stamp = "%{pts\\:gmtime\\:" + str(start_epoch) + "\\:%Y-%m-%d %H\\\\:%M\\\\:%S}"
    return (
        f"drawtext=text='{stamp}':x=6:y=6:fontsize={fontsize}:"
        "fontcolor=white:box=1:boxcolor=black@0.5"
    )


def contact_sheet_vf(cols: int, rows: int, width: int, start: datetime, duration_s: float) -> str:
    """Build the ``-vf`` filtergraph for a ``cols x rows`` contact sheet."""
    if cols < 1 or rows < 1:
        raise ValueError("cols and rows must be >= 1")
    if width < cols:
        raise ValueError("width must be at least cols pixels")
    if duration_s <= 0:
        raise ValueError("duration must be positive")
    n = cols * rows
    fps = n / duration_s
    tile_w = max(2, width // cols)
    fontsize = max(12, tile_w // 20)
    return (
        f"fps={fps:.6f},scale={tile_w}:-2,{_drawtext(_epoch(start), fontsize)},tile={cols}x{rows}"
    )


def contact_sheet_tail(
    url: str,
    output: str,
    timeout_s: float,
    *,
    cols: int,
    rows: int,
    width: int,
    start: datetime,
    duration_s: float,
) -> list[str]:
    """Full ffmpeg argv tail for a single contact-sheet JPEG."""
    stimeout_us = str(int(timeout_s * 1_000_000))
    vf = contact_sheet_vf(cols, rows, width, start, duration_s)
    return [
        "-nostdin", "-hide_banner", "-loglevel", "error",
        "-rtsp_transport", "tcp", "-stimeout", stimeout_us, "-i", url,
        "-vf", vf, "-frames:v", "1", "-q:v", "2", "-y", output,
    ]  # fmt: skip


def sample_timestamps(
    start: datetime, end: datetime, every_s: float, max_frames: int
) -> list[dict[str, Any]]:
    """Frame times at ``every_s`` intervals from ``start``, capped at ``max_frames``."""
    if every_s <= 0:
        raise ValueError("every_s must be positive")
    if max_frames < 1:
        raise ValueError("max_frames must be >= 1")
    duration = (end - start).total_seconds()
    if duration <= 0:
        raise ValueError("end must be after start")
    out: list[dict[str, Any]] = []
    k = 0
    while k < max_frames:
        offset = k * every_s
        if offset > duration:
            break
        out.append({"index": k, "timestamp": (start + timedelta(seconds=offset)).isoformat()})
        k += 1
    return out


def sample_frames_tail(
    url: str,
    out_pattern: str,
    timeout_s: float,
    *,
    every_s: float,
    frame_count: int,
    width: int | None = None,
) -> list[str]:
    """Full ffmpeg argv tail writing ``frame_count`` JPEGs to a ``%0Nd`` pattern."""
    if frame_count < 1:
        raise ValueError("frame_count must be >= 1")
    stimeout_us = str(int(timeout_s * 1_000_000))
    vf = f"fps=1/{every_s:g}"
    if width is not None:
        vf = f"{vf},scale='min(iw,{width})':-2"
    return [
        "-nostdin", "-hide_banner", "-loglevel", "error",
        "-rtsp_transport", "tcp", "-stimeout", stimeout_us, "-i", url,
        "-vf", vf, "-frames:v", str(frame_count), "-q:v", "2", "-y", out_pattern,
    ]  # fmt: skip


def reencode_params(
    duration_s: float, target_max_mb: float | None, max_width: int | None
) -> dict[str, Any]:
    """Choose an x264 CRF (and optional scale) from the duration and target size."""
    if duration_s <= 0:
        raise ValueError("duration must be positive")
    if target_max_mb is not None:
        if target_max_mb <= 0:
            raise ValueError("target_max_mb must be positive")
        target_bytes = int(target_max_mb * MB)
        budget_bps = target_bytes * 8 * _SIZE_MARGIN / duration_s
        crf = next(crf for threshold, crf in _CRF_BY_BUDGET if budget_bps >= threshold)
    else:
        target_bytes = None
        crf = _DEFAULT_CRF
    crf = max(_CRF_MIN, min(_CRF_MAX, crf))
    scale = None if max_width is None else f"scale='min(iw,{int(max_width)})':-2"
    return {"crf": crf, "scale": scale, "target_bytes": target_bytes}


def reencode_tail(input_path: str, output_path: str, *, crf: int, scale: str | None) -> list[str]:
    """Full ffmpeg argv tail to re-encode a *local* file with libx264.

    The input is a local path (never RTSP), so no credentials appear here.
    """
    args = [
        "-nostdin", "-hide_banner", "-loglevel", "error",
        "-i", input_path, "-c:v", "libx264", "-preset", "veryfast", "-crf", str(crf),
        "-pix_fmt", "yuv420p",
    ]  # fmt: skip
    if scale is not None:
        args += ["-vf", scale]
    args += ["-c:a", "copy", "-movflags", "+faststart", "-y", output_path]
    return args
