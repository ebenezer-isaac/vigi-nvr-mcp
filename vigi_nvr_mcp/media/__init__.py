"""RTSP media: pure URL builders and an ffmpeg export/snapshot runner.

Nothing in this package contacts the NVR's JSON API; it only builds RTSP URLs
and drives a local ``ffmpeg``/``ffprobe`` process. Credentials appear only in the
argv passed to ffmpeg (documented: visible to a local ``ps`` on the host) and are
scrubbed from every returned value, log line and error via
:func:`~vigi_nvr_mcp.media.urls.redacted_url`.

The media error types below subclass the device-agnostic ``DeviceError`` so the
shared ``run_tool`` wrapper turns them into ``{success, data, error}`` envelopes
with a stable ``code`` instead of letting an exception escape a tool.
"""

from __future__ import annotations

from typing import Any

from ..core.errors import DeviceError

# Channel / stream bounds (the NVR1016H has 16 channels; stream 1 = main, 2 = sub).
MIN_CHANNEL = 1
MAX_CHANNEL = 16
STREAMS = frozenset({1, 2})

# Bitrate assumed when the real per-channel bitrate is unknown (8 Mbit/s).
DEFAULT_BITRATE_BPS = 8_000_000
# Free space must exceed this multiple of the estimated clip size before export.
FREE_SPACE_FACTOR = 2
# Overall ffmpeg timeout = duration * factor + margin (seconds).
TIMEOUT_FACTOR = 1.5
TIMEOUT_MARGIN_S = 30.0
# Snapshot has no duration window; give it a fixed ceiling.
SNAPSHOT_TIMEOUT_S = 30.0


class MediaUnavailable(DeviceError):
    """ffmpeg or ffprobe could not be located. Not a crash: a clean refusal."""

    kind = "MEDIA_UNAVAILABLE"


class ExportBusy(DeviceError):
    """An export/snapshot is already running; only one runs at a time."""

    kind = "EXPORT_IN_PROGRESS"


class InsufficientSpace(DeviceError):
    """The export directory does not have enough free space for the clip."""

    kind = "INSUFFICIENT_SPACE"

    def __init__(self, message: str, *, required_bytes: int, free_bytes: int) -> None:
        self.required_bytes = required_bytes
        self.free_bytes = free_bytes
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"required_bytes": self.required_bytes, "free_bytes": self.free_bytes}


class ExportFailed(DeviceError):
    """ffmpeg exited non-zero or timed out. Carries a scrubbed stderr tail."""

    kind = "EXPORT_FAILED"

    def __init__(self, message: str, *, stderr_tail: str = "", timed_out: bool = False) -> None:
        self.stderr_tail = stderr_tail
        self.timed_out = timed_out
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"stderr_tail": self.stderr_tail, "timed_out": self.timed_out}


class NoFootageInWindow(ExportFailed):
    """ffmpeg failed with a pattern that means the replay window held no footage."""

    kind = "NO_FOOTAGE_IN_WINDOW"


class ProbeFailed(DeviceError):
    """ffprobe found no video stream in the produced file (a bad/empty export)."""

    kind = "PROBE_FAILED"

    def __init__(self, message: str, *, stderr_tail: str = "") -> None:
        self.stderr_tail = stderr_tail
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"stderr_tail": self.stderr_tail}


__all__ = [
    "DEFAULT_BITRATE_BPS",
    "FREE_SPACE_FACTOR",
    "MAX_CHANNEL",
    "MIN_CHANNEL",
    "SNAPSHOT_TIMEOUT_S",
    "STREAMS",
    "TIMEOUT_FACTOR",
    "TIMEOUT_MARGIN_S",
    "ExportBusy",
    "ExportFailed",
    "InsufficientSpace",
    "MediaUnavailable",
    "NoFootageInWindow",
    "ProbeFailed",
]
