"""Pure window-merge logic for :func:`nvr_list_motion_windows`.

Motion windows arrive from several sources - typed recording segments and event
logs - as many small, overlapping or adjacent spans per channel. :func:`merge`
collapses them into a clean, de-duplicated, sorted timeline: spans that overlap
or sit within ``min_gap_s`` of each other become one window, their kinds and
sources are unioned, and windows shorter than ``min_len_s`` are dropped.

Everything here is pure and works on timezone-aware datetimes, so DST shifts and
windows crossing midnight are handled by absolute-instant arithmetic with no
special cases. No I/O, no device, no clock.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class WindowInput:
    """One raw span from a single source, before merging."""

    channel: int
    name: str
    start: datetime
    end: datetime
    kinds: frozenset[str] = field(default_factory=frozenset)
    sources: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("window start/end must be timezone-aware")
        if self.end < self.start:
            raise ValueError("window end must not precede start")


@dataclass(frozen=True)
class Window:
    """A merged window across sources."""

    channel: int
    name: str
    start: datetime
    end: datetime
    kinds: tuple[str, ...]
    sources: tuple[str, ...]

    @property
    def duration_s(self) -> float:
        return (self.end - self.start).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "name": self.name,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "duration_s": self.duration_s,
            "kinds": list(self.kinds),
            "sources": list(self.sources),
        }


def merge(
    items: list[WindowInput], min_gap_s: float = 30.0, min_len_s: float = 3.0
) -> list[Window]:
    """Merge raw spans into sorted, non-overlapping windows per channel.

    Two spans on the same channel join when the later one starts within
    ``min_gap_s`` of the running end (overlap counts as a zero gap). Merged
    windows shorter than ``min_len_s`` are dropped. Returned sorted by
    ``(start, channel)``.
    """
    if min_gap_s < 0 or min_len_s < 0:
        raise ValueError("min_gap_s and min_len_s must be non-negative")
    by_channel: dict[int, list[WindowInput]] = {}
    for item in items:
        by_channel.setdefault(item.channel, []).append(item)

    merged: list[Window] = []
    for channel, spans in by_channel.items():
        merged.extend(_merge_channel(channel, spans, min_gap_s, min_len_s))
    merged.sort(key=lambda w: (w.start, w.channel))
    return merged


def _merge_channel(
    channel: int, spans: list[WindowInput], min_gap_s: float, min_len_s: float
) -> list[Window]:
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    out: list[Window] = []
    name = ""
    cur_start = cur_end = None
    kinds: set[str] = set()
    sources: set[str] = set()

    def flush() -> None:
        if cur_start is None or cur_end is None:
            return
        if (cur_end - cur_start).total_seconds() < min_len_s:
            return
        out.append(
            Window(
                channel=channel,
                name=name,
                start=cur_start,
                end=cur_end,
                kinds=tuple(sorted(kinds)),
                sources=tuple(sorted(sources)),
            )
        )

    for span in ordered:
        if cur_start is None:
            cur_start, cur_end = span.start, span.end
            name = span.name
            kinds, sources = set(span.kinds), set(span.sources)
            continue
        gap = (span.start - cur_end).total_seconds()
        if gap <= min_gap_s:
            cur_end = max(cur_end, span.end)
            kinds |= set(span.kinds)
            sources |= set(span.sources)
            name = name or span.name
        else:
            flush()
            cur_start, cur_end = span.start, span.end
            name = span.name
            kinds, sources = set(span.kinds), set(span.sources)
    flush()
    return out


def summarise(windows: list[Window]) -> dict[str, Any]:
    """Per-channel counts and totals for a merged window list."""
    per_channel: dict[str, dict[str, Any]] = {}
    for w in windows:
        key = str(w.channel)
        bucket = per_channel.setdefault(key, {"count": 0, "total_duration_s": 0.0, "kinds": set()})
        bucket["count"] += 1
        bucket["total_duration_s"] += w.duration_s
        bucket["kinds"].update(w.kinds)
    for bucket in per_channel.values():
        bucket["kinds"] = sorted(bucket["kinds"])
    return {"window_count": len(windows), "channels": per_channel}
