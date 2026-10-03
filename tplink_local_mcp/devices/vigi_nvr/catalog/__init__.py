"""Firmware error-code catalog vendored from the VIGI NVR web UI (``error.js``,
NVR1016H fw 1.1.3): symbol -> numeric code, 555 entries."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from types import MappingProxyType


@lru_cache(maxsize=1)
def code_to_symbol() -> MappingProxyType[int, str]:
    raw = json.loads(resources.files(__package__).joinpath("errcodes.json").read_text("utf-8"))
    return MappingProxyType({code: symbol for symbol, code in raw.items()})


def symbol_for(code: int) -> str | None:
    return code_to_symbol().get(code)
