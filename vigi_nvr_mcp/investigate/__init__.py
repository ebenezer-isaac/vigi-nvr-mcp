"""Investigation primitives (Phase N7b): a recording timeline, merged motion
windows, contact sheets and sampled frames, and agent-retrievable exports.

Nothing in this package contacts the NVR's JSON API or runs a subprocess. It is
pure data shaping: parsing the ``playback`` search reply into typed segments
(:mod:`.segments`), merging windows across sources (:mod:`.windows`), and
building ffmpeg argv lists for contact sheets / sampled frames / re-encodes
(:mod:`.sheets`). The tools in :mod:`vigi_nvr_mcp.tools.investigate` wire these
to the N7 ``FfmpegRunner`` and the NVR client.
"""

from __future__ import annotations

from datetime import tzinfo
from enum import StrEnum
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..core.errors import DeviceError, ProtocolError

# Channel / stream bounds mirror the media package (NVR1016H: 16 channels).
MIN_CHANNEL = 1
MAX_CHANNEL = 16


class SegmentType(StrEnum):
    """Normalised recording / event kind. ``raw_type`` always keeps the original."""

    normal = "normal"
    motion = "motion"
    smart = "smart"
    manual = "manual"
    alarm = "alarm"
    unknown = "unknown"


class RawProtocolError(ProtocolError):
    """A ``PROTOCOL_ERROR`` that carries the raw (already-redacted) device payload.

    The envelope sets ``data`` to ``None`` on failure, so the raw playback reply the
    live run (N5) needs to correct the parser is surfaced under
    ``error.details.raw`` instead of ``data.raw``.
    """

    def __init__(self, message: str, *, raw: Any) -> None:
        self._raw = raw
        super().__init__(message)

    def details(self) -> dict[str, Any]:
        return {"raw": self._raw}


class ExportTooLarge(DeviceError):
    """A requested export exceeds the inline (base64) retrieval limit."""

    kind = "TOO_LARGE"

    def __init__(self, message: str, *, size_bytes: int, max_bytes: int) -> None:
        self.size_bytes = size_bytes
        self.max_bytes = max_bytes
        super().__init__(message)

    def details(self) -> dict[str, int]:
        return {"size_bytes": self.size_bytes, "max_bytes": self.max_bytes}


def resolve_tz(tz: str) -> tzinfo:
    """Resolve ``"local"``/``"utc"``/an IANA name to a ``tzinfo``.

    ``"local"`` uses the host's local zone. An unknown name raises ``ValueError``
    (which ``run_tool`` maps to ``INVALID_INPUT``) rather than guessing.
    """
    key = (tz or "local").strip()
    lowered = key.lower()
    if lowered == "local":
        from datetime import datetime

        local = datetime.now().astimezone().tzinfo
        if local is None:  # pragma: no cover - astimezone always yields a tz
            return ZoneInfo("UTC")
        return local
    if lowered in {"utc", "z"}:
        return ZoneInfo("UTC")
    try:
        return ZoneInfo(key)
    except (ZoneInfoNotFoundError, ValueError, ModuleNotFoundError) as exc:
        raise ValueError(f"tz must be 'local', 'utc' or an IANA zone name; got {key!r}") from exc


__all__ = [
    "MAX_CHANNEL",
    "MIN_CHANNEL",
    "ExportTooLarge",
    "RawProtocolError",
    "SegmentType",
    "resolve_tz",
]
