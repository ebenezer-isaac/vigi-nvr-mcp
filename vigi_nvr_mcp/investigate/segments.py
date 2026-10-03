"""Parse the NVR ``playback`` search reply into a typed recording timeline.

The live shape is only partially known from static extraction of the 1.1.3 web
client (``playback.search_video_utility`` returning rows the UI reads as
``Object.values(row)[0]``), and the browser also wraps playback traffic in a
``web_playback_cmd`` envelope. Rather than bet on one shape, :func:`parse_segments`
walks the reply for the first list of segment-like rows under either arrangement,
normalises each to :class:`Segment`, and raises :class:`ProtocolError` (never
crashes) when nothing recognisable is present. Phase N5 confirms the real shape
against a live device; the raw payload is surfaced so that correction is cheap.
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta, tzinfo
from typing import Any

from pydantic import BaseModel, ConfigDict

from ..core.errors import ProtocolError
from . import SegmentType

# Candidate field names for each column. The device's exact names are unverified,
# so we accept the common spellings and keep the raw value regardless.
START_KEYS = ("start_time", "start", "begin_time", "begin", "starttime", "start_timestamp", "from")
END_KEYS = ("end_time", "end", "stop_time", "stop", "endtime", "end_timestamp", "to")
TYPE_KEYS = ("type", "record_type", "rec_type", "video_type", "videoType", "event_type", "recType")
# Keys whose value is the list of results in the two candidate envelope shapes.
RESULT_KEYS = frozenset(
    {
        "segments",
        "search_video_utility",
        "search_results",
        "searchresults",
        "results",
        "records",
        "record_list",
        "file_list",
        "playback_search",
    }
)
_MAX_DEPTH = 24

# Substring -> normalised kind. Checked in order; first hit wins. ``raw_type`` is
# always preserved on the Segment so a wrong guess here is never lossy.
_SMART_WORDS = (
    "smart", "intelligent", "human", "people", "person", "vehicle", "car",
    "line", "intrusion", "region", "loiter", "face", "ai",
)  # fmt: skip
_NORMAL_WORDS = ("normal", "continuous", "constant", "timing", "schedule", "plan", "all", "record")
_TYPE_RULES: tuple[tuple[tuple[str, ...], SegmentType], ...] = (
    (("alarm", "io_", "sensor", "alert"), SegmentType.alarm),
    (("manual", "hand"), SegmentType.manual),
    (_SMART_WORDS, SegmentType.smart),
    (("motion", "md", "move"), SegmentType.motion),
    (_NORMAL_WORDS, SegmentType.normal),
)
# Best-effort numeric record-type codes (unverified; N5 corrects). Unmapped -> unknown.
_NUMERIC_TYPES = {"0": SegmentType.normal, "1": SegmentType.normal, "2": SegmentType.motion}


class Segment(BaseModel):
    """One recorded span. ``start``/``end`` are the device's raw strings; ``type``
    is the normalised kind and ``raw_type`` the original value."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    start: str
    end: str | None = None
    type: SegmentType
    raw_type: Any = None


def classify_type(raw: Any) -> SegmentType:
    """Map a raw record-type value to a :class:`SegmentType`."""
    if raw is None:
        return SegmentType.unknown
    text = str(raw).strip().lower()
    if not text:
        return SegmentType.unknown
    if text in _NUMERIC_TYPES:
        return _NUMERIC_TYPES[text]
    for needles, kind in _TYPE_RULES:
        if any(n in text for n in needles):
            return kind
    return SegmentType.unknown


def _first_value(row: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _unwrap(item: Any) -> dict[str, Any] | None:
    """A row may be a dict, or a single-key wrapper ``{"<k>": {...}}`` (the shape
    the web UI reads via ``Object.values(row)[0]``)."""
    if not isinstance(item, dict):
        return None
    if len(item) == 1:
        (inner,) = item.values()
        if isinstance(inner, dict):
            return inner
    return item


def _rows_look_like_segments(rows: list[dict[str, Any]]) -> bool:
    return any(_first_value(r, START_KEYS) is not None for r in rows)


def _find_rows(node: Any, depth: int = 0) -> list[dict[str, Any]] | None:
    """Return the first list of segment-like rows anywhere in ``node``."""
    if depth > _MAX_DEPTH:
        return None
    if isinstance(node, list):
        unwrapped = [r for r in (_unwrap(i) for i in node) if r is not None]
        if unwrapped and _rows_look_like_segments(unwrapped):
            return unwrapped
        for item in node:
            found = _find_rows(item, depth + 1)
            if found is not None:
                return found
        return None
    if isinstance(node, dict):
        for value in node.values():
            found = _find_rows(value, depth + 1)
            if found is not None:
                return found
    return None


def _has_result_container(node: Any, depth: int = 0) -> bool:
    """True if a recognised results key is present (an empty-but-valid reply)."""
    if depth > _MAX_DEPTH or not isinstance(node, dict):
        return False
    for key, value in node.items():
        if key in RESULT_KEYS:
            return True
        if _has_result_container(value, depth + 1):
            return True
    return False


def _to_segment(row: dict[str, Any]) -> Segment | None:
    start = _first_value(row, START_KEYS)
    if start is None:
        return None
    end = _first_value(row, END_KEYS)
    raw_type = _first_value(row, TYPE_KEYS)
    return Segment(
        start=str(start),
        end=None if end is None else str(end),
        type=classify_type(raw_type),
        raw_type=raw_type,
    )


def parse_segments(reply: Any) -> list[Segment]:
    """Normalise a ``playback`` reply to typed segments.

    Accepts both candidate device shapes; returns ``[]`` for a recognised but
    empty result; raises :class:`ProtocolError` on an unrecognisable payload.
    """
    if not isinstance(reply, dict):
        raise ProtocolError("playback reply is not an object")
    rows = _find_rows(reply)
    if rows is None:
        if _has_result_container(reply):
            return []
        raise ProtocolError("playback reply has no recognisable recording-segment list")
    return [seg for seg in (_to_segment(r) for r in rows) if seg is not None]


def parse_device_time(value: Any, date: str, tz: tzinfo) -> datetime | None:
    """Best-effort parse of a device timestamp into an aware datetime.

    Handles ISO-8601 instants, epoch seconds (int or digit string), and
    time-of-day (``HH:MM:SS`` / ``HHMMSS``) combined with ``date`` (``YYYY-MM-DD``)
    in zone ``tz``. Returns ``None`` when nothing parses.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(value)
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit() and len(text) >= 10:
        return _from_epoch(int(text))
    iso = _try_iso(text, tz)
    if iso is not None:
        return iso
    return _try_time_of_day(text, date, tz)


def _from_epoch(value: float) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _try_iso(text: str, tz: tzinfo) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace("t", "T"))
    except ValueError:
        return None
    # Reject a bare date (no time component) so it falls through to time-of-day.
    if len(text) <= 10:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=tz)


def _try_time_of_day(text: str, date: str, tz: tzinfo) -> datetime | None:
    digits = text.replace(":", "")
    if not (digits.isdigit() and len(digits) in (4, 6)):
        return None
    try:
        day = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError:
        return None
    hour = int(digits[0:2])
    minute = int(digits[2:4])
    second = int(digits[4:6]) if len(digits) == 6 else 0
    if hour > 23 or minute > 59 or second > 59:
        # 24:00:00 is sometimes used for an end-of-day marker.
        if (hour, minute, second) == (24, 0, 0):
            return datetime.combine(day, time(0), tz) + timedelta(days=1)
        return None
    return datetime.combine(day, time(hour, minute, second), tz)
