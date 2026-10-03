"""Shared input models, the detection-kind enum and normalisation helpers for the
typed read tools (Phase N3).

Every typed tool validates its arguments through a pydantic model (so bad input is
rejected before any network call) and normalises the device reply through a small
pydantic model. When a reply is well-formed but missing the section a tool needs,
helpers here raise :class:`ProtocolError`, which ``run_tool`` turns into a
``PROTOCOL_ERROR`` envelope rather than letting an exception escape.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..core.errors import InvalidInput, ProtocolError

MIN_CHANNEL = 1
MAX_CHANNEL = 16
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# A pragmatic ISO-8601 instant: date, optional time, optional zone. Full RFC 3339
# parsing is datetime.fromisoformat's job; this only screens obviously bad input.
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$")


class DetectionKind(StrEnum):
    """The twelve detection modules, as LLM-friendly short names."""

    motion = "motion"
    people = "people"
    vehicle = "vehicle"
    linecross = "linecross"
    intrusion = "intrusion"
    region_entrance = "region_entrance"
    region_exiting = "region_exiting"
    loitering = "loitering"
    abandon_and_taken = "abandon_and_taken"
    scene_change = "scene_change"
    audio_exception = "audio_exception"
    tamper = "tamper"

    @property
    def module(self) -> str:
        """The firmware module name, e.g. ``motion`` -> ``motion_detection``."""
        stem = self.value.replace("_", "")
        return f"{stem}_detection"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ChannelInput(_StrictModel):
    channel: int = Field(ge=MIN_CHANNEL, le=MAX_CHANNEL)


class DetectionInput(_StrictModel):
    channel: int = Field(ge=MIN_CHANNEL, le=MAX_CHANNEL)
    kind: DetectionKind


class DateInput(_StrictModel):
    channel: int = Field(ge=MIN_CHANNEL, le=MAX_CHANNEL)
    date: str

    @field_validator("date")
    @classmethod
    def _check_date(cls, value: str) -> str:
        if not DATE_RE.fullmatch(value):
            raise ValueError("date must be YYYY-MM-DD")
        return value


class SinceInput(_StrictModel):
    since: str | None = None

    @field_validator("since")
    @classmethod
    def _check_since(cls, value: str | None) -> str | None:
        if value is not None and not ISO_RE.fullmatch(value):
            raise ValueError("since must be an ISO-8601 timestamp (e.g. 2026-10-03T12:00:00Z)")
        return value


def parse_input(model: type[BaseModel], **kwargs: Any) -> BaseModel:
    """Validate tool arguments, re-raising pydantic errors as a plain ``ValueError``
    (which ``run_tool`` maps to the ``INVALID_INPUT`` envelope). Raised before any
    network I/O happens, so a rejected call never touches the device."""
    try:
        return model(**kwargs)
    except ValidationError as exc:
        reasons = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'input'}: {e['msg']}" for e in exc.errors()
        )
        raise InvalidInput(reasons) from None


def require_section(reply: Any, module: str) -> dict[str, Any]:
    """Return ``reply[module]`` as a dict or raise :class:`ProtocolError`.

    The NVR echoes the requested module as a top-level key; a reply that answered
    ``error_code == 0`` but omitted it (or gave a non-object) is a protocol
    mismatch, not a device error."""
    if not isinstance(reply, dict):
        raise ProtocolError(f"NVR reply is not an object; expected a '{module}' section")
    section = reply.get(module)
    if not isinstance(section, dict):
        raise ProtocolError(f"NVR reply has no usable '{module}' section")
    return section


def decode_name(value: Any) -> Any:
    """Defensively ``decodeURIComponent`` a name field. The transport already
    decodes response strings once; this only runs if a ``%20``-style escape
    survived (e.g. a double-encoded name), and leaves plain strings untouched."""
    if isinstance(value, str) and "%" in value:
        return unquote(value, encoding="utf-8", errors="replace")
    return value


def with_raw(data: dict[str, Any], reply: Any, include_raw: bool) -> dict[str, Any]:
    """Attach the raw reply under ``raw`` when requested (``run_tool`` redacts it)."""
    return {**data, "raw": reply} if include_raw else data
