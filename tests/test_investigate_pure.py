"""Pure-logic tests for the N7b investigation package: window merge properties,
segment parsing on both candidate shapes, time parsing, tz resolution, and the
ffmpeg argv builders. No device, no subprocess, no clock.
"""

from __future__ import annotations

import itertools
import random
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from vigi_nvr_mcp.core.errors import ProtocolError
from vigi_nvr_mcp.investigate import SegmentType, resolve_tz
from vigi_nvr_mcp.investigate import sheets as S
from vigi_nvr_mcp.investigate.segments import (
    classify_type,
    parse_device_time,
    parse_segments,
)
from vigi_nvr_mcp.investigate.windows import Window, WindowInput, merge, summarise

PW = "p@ss" + "/w+d"  # for credential-leak checks in argv builders
BASE = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)


def _span(
    ch: int, start_s: float, end_s: float, kind: str = "motion", source: str = "rec"
) -> WindowInput:
    return WindowInput(
        channel=ch,
        name=f"ch{ch}",
        start=BASE + timedelta(seconds=start_s),
        end=BASE + timedelta(seconds=end_s),
        kinds=frozenset({kind}),
        sources=frozenset({source}),
    )


# --- window merge: explicit cases ---------------------------------------------


def test_merge_empty_is_empty() -> None:
    assert merge([], 30, 3) == []


def test_merge_combines_within_gap_and_unions_kinds_sources() -> None:
    spans = [
        _span(5, 0, 20, "motion", "rec"),
        _span(5, 30, 60, "smart", "events"),  # 10s gap -> merge
    ]
    (w,) = merge(spans, min_gap_s=30, min_len_s=3)
    assert (w.start, w.end) == (BASE, BASE + timedelta(seconds=60))
    assert w.kinds == ("motion", "smart")
    assert w.sources == ("events", "rec")
    assert w.duration_s == 60.0


def test_merge_splits_when_gap_exceeds_threshold() -> None:
    spans = [_span(5, 0, 20), _span(5, 60, 90)]  # 40s gap > 30
    result = merge(spans, min_gap_s=30, min_len_s=3)
    assert len(result) == 2


def test_merge_drops_windows_shorter_than_min_len() -> None:
    # Two isolated 1s spans, far apart: both dropped (duration < min_len).
    spans = [_span(5, 0, 1), _span(5, 1000, 1001)]
    assert merge(spans, min_gap_s=30, min_len_s=3) == []


def test_merge_overlapping_spans() -> None:
    spans = [_span(7, 0, 50), _span(7, 10, 30), _span(7, 40, 80)]
    (w,) = merge(spans, min_gap_s=0, min_len_s=3)
    assert (w.start, w.end) == (BASE, BASE + timedelta(seconds=80))


def test_merge_separates_channels() -> None:
    spans = [_span(1, 0, 20), _span(2, 5, 25)]
    result = merge(spans, min_gap_s=30, min_len_s=3)
    assert {w.channel for w in result} == {1, 2}


def test_merge_sorted_by_start_then_channel() -> None:
    spans = [_span(3, 100, 120), _span(1, 0, 20), _span(2, 0, 20)]
    result = merge(spans, min_gap_s=5, min_len_s=3)
    assert [(w.start, w.channel) for w in result] == [
        (BASE, 1),
        (BASE, 2),
        (BASE + timedelta(seconds=100), 3),
    ]


def test_merge_window_crossing_midnight() -> None:
    tz = ZoneInfo("Asia/Kolkata")
    near_midnight = datetime(2026, 10, 3, 23, 59, 0, tzinfo=tz)
    spans = [
        WindowInput(
            5, "d", near_midnight, near_midnight + timedelta(seconds=30), frozenset(), frozenset()
        ),
        WindowInput(
            5,
            "d",
            near_midnight + timedelta(seconds=40),
            near_midnight + timedelta(minutes=5),
            frozenset(),
            frozenset(),
        ),
    ]
    (w,) = merge(spans, min_gap_s=30, min_len_s=3)
    assert w.start.day == 3 and w.end.day == 4


def test_merge_across_dst_uses_absolute_instants() -> None:
    # US spring-forward: 2026-03-08 02:00 -> 03:00 local. A span straddling the
    # jump has a real (absolute) duration of 60s even though wall clock shows +1h.
    tz = ZoneInfo("America/New_York")
    start = datetime(2026, 3, 8, 1, 59, 30, tzinfo=tz)
    end = start + timedelta(seconds=60)
    (w,) = merge([WindowInput(5, "d", start, end, frozenset(), frozenset())], 30, 3)
    assert w.duration_s == 60.0


def test_window_input_rejects_naive_and_reversed() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        WindowInput(
            5, "d", datetime(2026, 10, 3, 12), datetime(2026, 10, 3, 13), frozenset(), frozenset()
        )
    with pytest.raises(ValueError, match="precede"):
        WindowInput(5, "d", BASE, BASE - timedelta(seconds=1), frozenset(), frozenset())


def test_merge_rejects_negative_params() -> None:
    with pytest.raises(ValueError):
        merge([_span(5, 0, 20)], min_gap_s=-1, min_len_s=3)


# --- window merge: property invariants over random inputs ---------------------


def _random_spans(rng: random.Random, n: int) -> list[WindowInput]:
    spans = []
    for _ in range(n):
        ch = rng.choice([1, 2, 3])
        s = rng.uniform(0, 600)
        length = rng.uniform(0, 40)
        spans.append(_span(ch, s, s + length, rng.choice(["motion", "smart", "alarm"])))
    return spans


@pytest.mark.parametrize("seed", range(25))
def test_merge_invariants(seed: int) -> None:
    rng = random.Random(seed)  # noqa: S311 - test data generation, not cryptographic
    gap = rng.choice([0, 5, 30, 60])
    min_len = rng.choice([0, 3, 10])
    spans = _random_spans(rng, rng.randint(0, 20))
    result = merge(spans, min_gap_s=gap, min_len_s=min_len)

    # 1. Every window meets the minimum length.
    assert all(w.duration_s >= min_len for w in result)
    # 2. Per channel, consecutive windows are strictly more than gap apart.
    for ch in {w.channel for w in result}:
        chan = [w for w in result if w.channel == ch]
        for prev, nxt in itertools.pairwise(chan):
            assert (nxt.start - prev.end).total_seconds() > gap
    # 3. Globally sorted by (start, channel).
    keys = [(w.start, w.channel) for w in result]
    assert keys == sorted(keys)
    # 4. Idempotence: merging the outputs again changes nothing.
    again = merge(
        [
            WindowInput(w.channel, w.name, w.start, w.end, frozenset(w.kinds), frozenset(w.sources))
            for w in result
        ],
        min_gap_s=gap,
        min_len_s=min_len,
    )
    assert [w.to_dict() for w in again] == [w.to_dict() for w in result]


def test_summarise_counts_per_channel() -> None:
    windows = [
        Window(1, "a", BASE, BASE + timedelta(seconds=10), ("motion",), ("rec",)),
        Window(
            1,
            "a",
            BASE + timedelta(seconds=100),
            BASE + timedelta(seconds=120),
            ("smart",),
            ("rec",),
        ),
    ]
    s = summarise(windows)
    assert s["window_count"] == 2
    assert s["channels"]["1"]["count"] == 2
    assert s["channels"]["1"]["total_duration_s"] == 30.0
    assert s["channels"]["1"]["kinds"] == ["motion", "smart"]


# --- segment parsing ----------------------------------------------------------


def test_parse_shape_a_segments_list() -> None:
    reply = {
        "playback": {
            "segments": [{"start_time": "12:00:00", "end_time": "12:00:20", "type": "motion"}]
        }
    }
    (seg,) = parse_segments(reply)
    assert seg.start == "12:00:00" and seg.end == "12:00:20"
    assert seg.type is SegmentType.motion and seg.raw_type == "motion"


def test_parse_shape_b_web_playback_cmd_wrapped_rows() -> None:
    reply = {
        "playback": {
            "web_playback_cmd": {
                "command": {
                    "content": {
                        "params": {
                            "search_results": [
                                {
                                    "0": {
                                        "start": "1760000000",
                                        "end": "1760000020",
                                        "record_type": "2",
                                    }
                                },
                                {
                                    "1": {
                                        "start": "1760000100",
                                        "end": "1760000130",
                                        "record_type": "manual",
                                    }
                                },
                            ]
                        }
                    }
                }
            }
        }
    }
    segs = parse_segments(reply)
    assert [s.type for s in segs] == [SegmentType.motion, SegmentType.manual]
    assert segs[0].raw_type == "2"


def test_parse_empty_results_is_empty_not_error() -> None:
    assert parse_segments({"playback": {"segments": []}}) == []
    assert parse_segments({"playback": {"search_video_utility": {"results": []}}}) == []


def test_parse_garbage_raises_protocol_error() -> None:
    with pytest.raises(ProtocolError):
        parse_segments({"error_code": 0})
    with pytest.raises(ProtocolError):
        parse_segments("not an object")
    with pytest.raises(ProtocolError):
        parse_segments([1, 2, 3])


def test_parse_skips_rows_without_a_start() -> None:
    reply = {"playback": {"segments": [{"foo": "bar"}, {"start": "12:00:00"}]}}
    segs = parse_segments(reply)
    assert len(segs) == 1 and segs[0].start == "12:00:00"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("continuous", SegmentType.normal),
        ("timing", SegmentType.normal),
        ("motion", SegmentType.motion),
        ("MD", SegmentType.motion),
        ("peopleDetection", SegmentType.smart),
        ("vehicle", SegmentType.smart),
        ("manual", SegmentType.manual),
        ("io_alarm", SegmentType.alarm),
        ("2", SegmentType.motion),
        ("1", SegmentType.normal),
        ("99", SegmentType.unknown),
        ("weirdthing", SegmentType.unknown),
        (None, SegmentType.unknown),
        ("", SegmentType.unknown),
    ],
)
def test_classify_type(raw: object, expected: SegmentType) -> None:
    assert classify_type(raw) is expected


# --- device time parsing ------------------------------------------------------


def test_parse_device_time_iso_with_zone() -> None:
    tz = ZoneInfo("Asia/Kolkata")
    dt = parse_device_time("2026-10-03T12:00:00+05:30", "2026-10-03", tz)
    assert dt == datetime(2026, 10, 3, 12, 0, tzinfo=tz)


def test_parse_device_time_iso_naive_uses_tz() -> None:
    tz = ZoneInfo("Asia/Kolkata")
    dt = parse_device_time("2026-10-03T12:00:00", "2026-10-03", tz)
    assert dt.utcoffset() == timedelta(hours=5, minutes=30)


def test_parse_device_time_epoch_and_time_of_day() -> None:
    tz = ZoneInfo("UTC")
    assert parse_device_time(1760000000, "2026-10-03", tz) is not None
    assert parse_device_time("1760000000", "2026-10-03", tz) is not None
    hhmmss = parse_device_time("120000", "2026-10-03", tz)
    assert hhmmss == datetime(2026, 10, 3, 12, 0, tzinfo=tz)
    colon = parse_device_time("12:00:00", "2026-10-03", tz)
    assert colon == datetime(2026, 10, 3, 12, 0, tzinfo=tz)


def test_parse_device_time_end_of_day_marker() -> None:
    tz = ZoneInfo("UTC")
    assert parse_device_time("24:00:00", "2026-10-03", tz) == datetime(2026, 10, 4, tzinfo=tz)


@pytest.mark.parametrize("bad", [None, True, "", "not-a-time", "99:99:99", "nope"])
def test_parse_device_time_unparseable_returns_none(bad: object) -> None:
    assert parse_device_time(bad, "2026-10-03", ZoneInfo("UTC")) is None


# --- tz resolution ------------------------------------------------------------


def test_resolve_tz_variants() -> None:
    assert resolve_tz("utc") == ZoneInfo("UTC")
    assert resolve_tz("UTC") == ZoneInfo("UTC")
    assert resolve_tz("Asia/Kolkata") == ZoneInfo("Asia/Kolkata")
    assert resolve_tz("local") is not None


def test_resolve_tz_bad_raises_value_error() -> None:
    with pytest.raises(ValueError, match="IANA"):
        resolve_tz("Mars/Phobos")


# --- sheets argv builders -----------------------------------------------------


def test_tile_timestamps_count_and_monotonic() -> None:
    tiles = S.tile_timestamps(BASE, BASE + timedelta(seconds=120), 4, 3)
    assert len(tiles) == 12
    assert [t["tile"] for t in tiles] == list(range(12))
    stamps = [datetime.fromisoformat(t["timestamp"]) for t in tiles]
    assert stamps == sorted(stamps)
    assert stamps[0] >= BASE and stamps[-1] < BASE + timedelta(seconds=120)


def test_contact_sheet_vf_has_fps_scale_drawtext_tile() -> None:
    vf = S.contact_sheet_vf(4, 3, 1600, BASE, 120)
    assert "fps=" in vf
    assert "scale=400:-2" in vf  # 1600 / 4
    assert "drawtext=" in vf and "gmtime" in vf
    assert "tile=4x3" in vf


def test_contact_sheet_tail_single_url_element_no_creds_in_filter() -> None:
    url = f"rtsp://viewer:{PW}@192.0.2.10:554/replay/5/1/avm"
    tail = S.contact_sheet_tail(
        url, "/out.jpg", 99.0, cols=4, rows=3, width=1600, start=BASE, duration_s=120
    )
    # The URL is exactly one argv element (so it can be redacted whole).
    assert tail.count(url) == 1
    assert url in tail
    # The credential never leaks into any other element (e.g. the filtergraph).
    others = [a for a in tail if a != url]
    assert all(PW not in a and "p%40ss" not in a for a in others)
    assert "-vf" in tail and "tile=4x3" in " ".join(others)


def test_contact_sheet_vf_rejects_bad_geometry() -> None:
    with pytest.raises(ValueError):
        S.contact_sheet_vf(0, 3, 1600, BASE, 120)
    with pytest.raises(ValueError):
        S.contact_sheet_vf(4, 3, 2, BASE, 120)  # width < cols
    with pytest.raises(ValueError):
        S.contact_sheet_vf(4, 3, 1600, BASE, 0)


def test_sample_timestamps_cap_by_count_and_duration() -> None:
    # 10s window, every 2s -> indices 0,2,4,6,8,10 = 6 frames.
    assert len(S.sample_timestamps(BASE, BASE + timedelta(seconds=10), 2, 60)) == 6
    # max_frames caps it.
    assert len(S.sample_timestamps(BASE, BASE + timedelta(seconds=100), 2, 5)) == 5


def test_sample_frames_tail_has_fps_frames_and_width_scale() -> None:
    tail = S.sample_frames_tail(
        "rtsp://u:p@h/replay", "/d/_f_%03d.jpg", 99.0, every_s=2, frame_count=6, width=640
    )
    joined = " ".join(tail)
    assert "fps=1/2" in joined and "scale='min(iw,640)'" in joined
    assert "-frames:v" in tail and "6" in tail


@pytest.mark.parametrize(
    "target,expect_lower_crf_than",
    [(50, 23), (1, 40)],
)
def test_reencode_params_crf_tracks_budget(target: float, expect_lower_crf_than: int) -> None:
    params = S.reencode_params(120, target, None)
    assert 18 <= params["crf"] <= 34
    assert params["crf"] < expect_lower_crf_than


def test_reencode_params_larger_target_gives_better_quality() -> None:
    big = S.reencode_params(120, 100, None)["crf"]
    small = S.reencode_params(120, 2, None)["crf"]
    assert big <= small


def test_reencode_params_scale_only_when_width_given() -> None:
    assert S.reencode_params(120, None, None)["scale"] is None
    assert S.reencode_params(120, None, 1280)["scale"] == "scale='min(iw,1280)':-2"


def test_reencode_params_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError):
        S.reencode_params(0, 20, None)
    with pytest.raises(ValueError):
        S.reencode_params(120, -1, None)


def test_reencode_tail_is_local_libx264_no_rtsp_no_creds() -> None:
    tail = S.reencode_tail("/in.mp4", "/out.mp4", crf=25, scale="scale='min(iw,1280)':-2")
    assert "libx264" in tail and "-crf" in tail and "25" in tail
    assert "-rtsp_transport" not in tail  # local file, not a stream
    assert tail[-1] == "/out.mp4"
    assert PW not in " ".join(tail)
