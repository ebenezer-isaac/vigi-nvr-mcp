"""Pure RTSP URL builders with strict validation.

TP-Link documents RTSP for VIGI NVRs (FAQ 5223):

* live:   ``rtsp://<host>:<port>/live/<channel>/<stream>/avm``
* replay: ``rtsp://<host>:<port>/replay/<channel>/<stream>/avm``
          ``?starttime=YYYYMMDDtHHMMSSz&endtime=YYYYMMDDtHHMMSSz`` (``z`` = UTC)

``<stream>`` is 1 (main) or 2 (sub). Every function is pure: it reads settings,
validates its arguments, and returns a string. Credentials are URL-encoded into
the userinfo; :func:`redacted_url` strips them for any value that leaves the host.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote, urlsplit, urlunsplit

from ..core.config import DeviceSettings
from . import MAX_CHANNEL, MIN_CHANNEL, STREAMS

REDACTED_USERINFO = "<redacted>:<redacted>"


def validate_channel(channel: object) -> int:
    if isinstance(channel, bool) or not isinstance(channel, int):
        raise ValueError(f"channel must be an integer {MIN_CHANNEL}-{MAX_CHANNEL}")
    if not MIN_CHANNEL <= channel <= MAX_CHANNEL:
        raise ValueError(f"channel must be between {MIN_CHANNEL} and {MAX_CHANNEL}")
    return channel


def validate_stream(stream: object) -> int:
    if isinstance(stream, bool) or not isinstance(stream, int) or stream not in STREAMS:
        raise ValueError("stream must be 1 (main) or 2 (sub)")
    return stream


def _require_aware(name: str, value: object) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware (include a UTC offset)")
    return value


def format_timestamp(value: datetime) -> str:
    """Render an aware datetime as the firmware's ``YYYYMMDDtHHMMSSz`` UTC form."""
    u = _require_aware("timestamp", value).astimezone(UTC)
    return f"{u.year:04d}{u.month:02d}{u.day:02d}t{u.hour:02d}{u.minute:02d}{u.second:02d}z"


def validate_window(
    settings: DeviceSettings, start: object, end: object
) -> tuple[datetime, datetime, float]:
    """Validate a replay window; return ``(start_utc, end_utc, duration_seconds)``."""
    start_dt = _require_aware("start", start).astimezone(UTC)
    end_dt = _require_aware("end", end).astimezone(UTC)
    if end_dt <= start_dt:
        raise ValueError("end must be strictly after start")
    duration_s = (end_dt - start_dt).total_seconds()
    max_s = settings.export_max_minutes * 60
    if duration_s > max_s:
        raise ValueError(
            f"window is {duration_s / 60:.1f} min; the limit is "
            f"{settings.export_max_minutes} min (VIGI_NVR_EXPORT_MAX_MINUTES)"
        )
    return start_dt, end_dt, duration_s


def _userinfo(settings: DeviceSettings) -> str:
    user = quote(settings.effective_rtsp_username, safe="")
    password = quote(settings.effective_rtsp_password, safe="")
    return f"{user}:{password}"


def _authority(settings: DeviceSettings, *, with_credentials: bool) -> str:
    host = f"{settings.host_for_url}:{settings.rtsp_port}"
    return f"{_userinfo(settings)}@{host}" if with_credentials else host


def live_url(
    settings: DeviceSettings, channel: int, stream: int = 1, *, with_credentials: bool = True
) -> str:
    """``rtsp://user:pass@host:port/live/<channel>/<stream>/avm``."""
    ch = validate_channel(channel)
    st = validate_stream(stream)
    authority = _authority(settings, with_credentials=with_credentials)
    return f"rtsp://{authority}/live/{ch}/{st}/avm"


def replay_url(
    settings: DeviceSettings,
    channel: int,
    stream: int,
    start_utc: datetime,
    end_utc: datetime,
    *,
    with_credentials: bool = True,
) -> str:
    """Replay URL for a validated time window (``end > start``, within the limit)."""
    ch = validate_channel(channel)
    st = validate_stream(stream)
    start_dt, end_dt, _ = validate_window(settings, start_utc, end_utc)
    authority = _authority(settings, with_credentials=with_credentials)
    query = f"starttime={format_timestamp(start_dt)}&endtime={format_timestamp(end_dt)}"
    return f"rtsp://{authority}/replay/{ch}/{st}/avm?{query}"


def redacted_url(url: str) -> str:
    """Replace any ``user:pass@`` userinfo in an RTSP URL with a placeholder."""
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit(parts._replace(netloc=f"{REDACTED_USERINFO}@{host}"))


def scrub(text: str, *urls: str) -> str:
    """Remove credentials from free text by replacing each URL with its redacted form.

    Replaces the full URL and the bare ``user:pass@`` userinfo so credentials never
    survive in an ffmpeg stderr tail even if ffmpeg reformats the URL it echoes.
    """
    if not text:
        return text
    out = text
    for url in urls:
        if not url:
            continue
        out = out.replace(url, redacted_url(url))
        parts = urlsplit(url)
        if "@" in parts.netloc:
            userinfo = parts.netloc.rsplit("@", 1)[0]
            out = out.replace(userinfo, REDACTED_USERINFO)
    return out
