"""``FfmpegRunner``: locate ffmpeg/ffprobe, build argv lists (never shell strings),
confine output to the export directory, refuse on low disk, run one job at a time,
enforce an overall timeout, verify the result with ffprobe, and scrub credentials.

The runner never interpolates into a shell. Every invocation is an argv list given
to ``asyncio.create_subprocess_exec``. The RTSP URL (which carries credentials in
its userinfo) is passed as a single argv element and scrubbed from every string
that is returned or logged.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import re
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from ..core.config import DeviceSettings
from . import (
    DEFAULT_BITRATE_BPS,
    FREE_SPACE_FACTOR,
    SNAPSHOT_TIMEOUT_S,
    TIMEOUT_FACTOR,
    TIMEOUT_MARGIN_S,
    ExportBusy,
    ExportFailed,
    InsufficientSpace,
    MediaUnavailable,
    NoFootageInWindow,
    ProbeFailed,
)
from .urls import format_timestamp, scrub

log = logging.getLogger(__name__)

STDERR_TAIL_CHARS = 2000
# ffmpeg messages that mean "the replay window had nothing", not a real failure.
NO_FOOTAGE_PATTERNS = re.compile(
    r"(404 not found|not found|no such|could not find|no stream|"
    r"immediate exit requested|invalid data found|end of file)",
    re.IGNORECASE,
)
# A generated export/snapshot filename: no separators, no traversal.
SAFE_NAME = re.compile(r"^ch\d{1,2}_[0-9tz]+(?:_[0-9tz]+)?_s[12]\.(?:mp4|jpg)$")
EXPORT_SUFFIXES = (".mp4", ".jpg")


def locate_executables(settings: DeviceSettings) -> tuple[str, str]:
    """Return ``(ffmpeg, ffprobe)`` paths or raise :class:`MediaUnavailable`.

    ``VIGI_NVR_FFMPEG`` overrides ffmpeg; ffprobe is looked for next to it, then on
    PATH. With no override, both are resolved from PATH.
    """
    override = settings.ffmpeg_path
    if override:
        ffmpeg = override if Path(override).is_file() else shutil.which(override)
        probe_sibling = Path(override).with_name(Path(override).name.replace("ffmpeg", "ffprobe"))
        ffprobe = str(probe_sibling) if probe_sibling.is_file() else shutil.which("ffprobe")
    else:
        ffmpeg = shutil.which("ffmpeg")
        ffprobe = shutil.which("ffprobe")
    if not ffmpeg or not ffprobe:
        raise MediaUnavailable(
            "ffmpeg/ffprobe not found. Install ffmpeg or set VIGI_NVR_FFMPEG to its path. "
            "RTSP export and snapshots are unavailable until then."
        )
    return ffmpeg, ffprobe


def _common_input(timeout_s: float, url: str) -> list[str]:
    stimeout_us = str(int(timeout_s * 1_000_000))
    return [
        "-nostdin", "-hide_banner", "-loglevel", "error",
        "-rtsp_transport", "tcp", "-stimeout", stimeout_us, "-i", url,
    ]  # fmt: skip


def export_tail(url: str, output: str, timeout_s: float) -> list[str]:
    """ffmpeg args (without the binary) for a lossless clip export (``-c copy``)."""
    return [*_common_input(timeout_s, url), "-c", "copy", "-movflags", "+faststart", "-y", output]


def snapshot_tail(url: str, output: str, timeout_s: float) -> list[str]:
    """ffmpeg args (without the binary) for a single-frame JPEG snapshot."""
    return [*_common_input(timeout_s, url), "-frames:v", "1", "-q:v", "2", "-y", output]


def export_argv(ffmpeg: str, url: str, output: str, timeout_s: float) -> list[str]:
    """Full export argv including the ffmpeg binary (used for dry-run display)."""
    return [ffmpeg, *export_tail(url, output, timeout_s)]


def snapshot_argv(ffmpeg: str, url: str, output: str, timeout_s: float) -> list[str]:
    """Full snapshot argv including the ffmpeg binary (used for dry-run display)."""
    return [ffmpeg, *snapshot_tail(url, output, timeout_s)]


def probe_tail(path: str) -> list[str]:
    return [
        "-v", "error", "-select_streams", "v",
        "-show_entries", "stream=codec_type", "-of", "json", path,
    ]  # fmt: skip


def export_timeout(duration_s: float) -> float:
    return duration_s * TIMEOUT_FACTOR + TIMEOUT_MARGIN_S


def estimate_bytes(duration_s: float, bitrate_bps: int) -> int:
    return int(duration_s * bitrate_bps / 8)


def _tail(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace").strip()
    return text[-STDERR_TAIL_CHARS:]


def _has_video_stream(probe_stdout: bytes) -> bool:
    """True if ffprobe's JSON lists at least one stream with codec_type 'video'."""
    try:
        parsed = json.loads(probe_stdout.decode("utf-8", errors="replace") or "{}")
    except (ValueError, UnicodeDecodeError):
        return False
    streams = parsed.get("streams") if isinstance(parsed, dict) else None
    if not isinstance(streams, list):
        return False
    return any(isinstance(s, dict) and s.get("codec_type") == "video" for s in streams)


def confine(export_dir: Path, name: str) -> Path:
    """Validate a user-supplied export name and resolve it inside ``export_dir``.

    Rejects separators, ``..`` traversal, absolute paths and anything that resolves
    (following symlinks) outside the export directory.
    """
    if not SAFE_NAME.fullmatch(name):
        raise ValueError(
            "name must be a generated export filename "
            "(e.g. ch5_20261003t120000z_20261003t120200z_s1.mp4)"
        )
    base = export_dir.resolve()
    target = (base / name).resolve()
    if target.parent != base:
        raise ValueError("name escapes the export directory")
    return target


async def probe_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if a TCP connection to ``host:port`` opens within ``timeout``."""
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return False
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True


class FfmpegRunner:
    """Serial ffmpeg/ffprobe driver confined to the export directory.

    Tests may inject ``ffmpeg_cmd``/``ffprobe_cmd`` (argv prefixes, e.g.
    ``[sys.executable, fake_script]``) to exercise the real subprocess path with a
    fake binary; production resolves single-element commands lazily at call time.
    """

    def __init__(
        self,
        settings: DeviceSettings,
        *,
        ffmpeg_cmd: list[str] | None = None,
        ffprobe_cmd: list[str] | None = None,
    ) -> None:
        self.settings = settings
        self._ffmpeg_cmd = ffmpeg_cmd
        self._ffprobe_cmd = ffprobe_cmd
        self._lock = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    def _commands(self) -> tuple[list[str], list[str]]:
        if self._ffmpeg_cmd is not None and self._ffprobe_cmd is not None:
            return self._ffmpeg_cmd, self._ffprobe_cmd
        ffmpeg, ffprobe = locate_executables(self.settings)
        return [ffmpeg], [ffprobe]

    def _export_dir(self) -> Path:
        path = self.settings.export_path
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    def _check_space(self, directory: Path, duration_s: float, bitrate_bps: int) -> None:
        estimate = estimate_bytes(duration_s, bitrate_bps)
        required = estimate * FREE_SPACE_FACTOR
        free = shutil.disk_usage(directory).free
        if free < required:
            raise InsufficientSpace(
                f"need about {required} bytes free (2x an estimated {estimate}); "
                f"only {free} available in the export directory",
                required_bytes=required,
                free_bytes=free,
            )

    async def _spawn(self, cmd: list[str], timeout_s: float, url: str) -> tuple[int, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout_s)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise ExportFailed(
                f"ffmpeg exceeded its {timeout_s:.0f}s timeout and was killed",
                timed_out=True,
            ) from None
        return proc.returncode or 0, scrub(_tail(stderr or b""), url)

    async def _verify(self, path: Path) -> None:
        _, ffprobe_cmd = self._commands()
        cmd = [*ffprobe_cmd, *probe_tail(str(path))]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), SNAPSHOT_TIMEOUT_S)
        if proc.returncode == 0 and _has_video_stream(out or b""):
            return
        raise ProbeFailed(
            "ffprobe found no video stream in the output file",
            stderr_tail=_tail(err or b""),
        )

    def _finish(self, path: Path, stderr_tail: str) -> dict[str, object]:
        data = path.read_bytes()
        return {
            "path": str(path.resolve()),
            "name": path.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "ffmpeg_stderr_tail": stderr_tail,
        }

    @staticmethod
    def _cleanup(path: Path) -> None:
        with contextlib.suppress(OSError):
            path.unlink()

    async def _run_job(
        self, url: str, output: Path, cmd: list[str], timeout_s: float, *, verify: bool
    ) -> dict[str, object]:
        if self.busy:
            raise ExportBusy("another export or snapshot is already running; try again shortly")
        async with self._lock:
            returncode, stderr_tail = await self._spawn(cmd, timeout_s, url)
            if returncode != 0 or not output.exists():
                self._cleanup(output)
                if NO_FOOTAGE_PATTERNS.search(stderr_tail):
                    raise NoFootageInWindow(
                        "ffmpeg reported no footage for this window; check nvr_search_recordings "
                        "for a window that actually contains recordings",
                        stderr_tail=stderr_tail,
                    )
                raise ExportFailed(f"ffmpeg exited with code {returncode}", stderr_tail=stderr_tail)
            if verify:
                try:
                    await self._verify(output)
                except ProbeFailed:
                    self._cleanup(output)
                    raise
            return self._finish(output, stderr_tail)

    async def export_clip(
        self,
        channel: int,
        stream: int,
        start_utc: datetime,
        end_utc: datetime,
        url: str,
        duration_s: float,
        *,
        bitrate_bps: int = DEFAULT_BITRATE_BPS,
    ) -> dict[str, object]:
        """Export a replay window to an mp4 (lossless copy) and ffprobe-verify it."""
        ffmpeg, _ = self._commands()
        directory = self._export_dir()
        self._check_space(directory, duration_s, bitrate_bps)
        name = (
            f"ch{channel}_{format_timestamp(start_utc)}_{format_timestamp(end_utc)}_s{stream}.mp4"
        )
        output = directory / name
        timeout_s = export_timeout(duration_s)
        cmd = [*ffmpeg, *export_tail(url, str(output), timeout_s)]
        result = await self._run_job(url, output, cmd, timeout_s, verify=True)
        return {**result, "duration_s": duration_s}

    async def snapshot(self, channel: int, stream: int, url: str) -> dict[str, object]:
        """Capture a single JPEG frame into the export directory."""
        ffmpeg, _ = self._commands()
        directory = self._export_dir()
        stamp = format_timestamp(datetime.now(UTC))
        name = f"ch{channel}_{stamp}_s{stream}.jpg"
        output = directory / name
        cmd = [*ffmpeg, *snapshot_tail(url, str(output), SNAPSHOT_TIMEOUT_S)]
        return await self._run_job(url, output, cmd, SNAPSHOT_TIMEOUT_S, verify=False)

    async def run_to_file(
        self,
        url: str,
        output: Path,
        tail: list[str],
        timeout_s: float,
        *,
        verify: bool = False,
    ) -> dict[str, object]:
        """Run one ffmpeg job (argv ``tail`` after the binary) producing ``output``.

        Reuses all the export guards (serial lock, timeout/kill, no-footage
        detection, optional ffprobe verify, credential scrubbing). ``url`` is only
        used to scrub credentials from the stderr tail; pass ``""`` for a local
        transcode whose argv carries no credentials.
        """
        ffmpeg, _ = self._commands()
        self._export_dir()
        cmd = [*ffmpeg, *tail]
        return await self._run_job(url, output, cmd, timeout_s, verify=verify)

    async def run_multi(
        self,
        url: str,
        tail: list[str],
        timeout_s: float,
        collect: Callable[[], list[Path]],
    ) -> tuple[list[Path], str]:
        """Run one ffmpeg job that writes several files; ``collect`` returns them.

        Used for sampled frames (a numbered output pattern). Applies the same
        serial lock, timeout/kill, no-footage detection and scrubbing as a single
        export, and cleans up partial output on failure.
        """
        ffmpeg, _ = self._commands()
        self._export_dir()
        cmd = [*ffmpeg, *tail]
        if self.busy:
            raise ExportBusy("another export or snapshot is already running; try again shortly")
        async with self._lock:
            returncode, stderr_tail = await self._spawn(cmd, timeout_s, url)
            produced = sorted(collect())
            if returncode != 0 or not produced:
                for path in produced:
                    self._cleanup(path)
                if NO_FOOTAGE_PATTERNS.search(stderr_tail):
                    raise NoFootageInWindow(
                        "ffmpeg reported no footage for this window; check "
                        "nvr_list_recording_segments for a window that has recordings",
                        stderr_tail=stderr_tail,
                    )
                raise ExportFailed(f"ffmpeg exited with code {returncode}", stderr_tail=stderr_tail)
            return produced, stderr_tail
