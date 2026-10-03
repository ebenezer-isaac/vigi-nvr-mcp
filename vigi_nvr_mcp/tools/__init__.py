"""VIGI NVR tools. Each module exposes plain async functions taking a
``ToolContext`` (easy to test) and ``register(mcp, ctx) -> list[str]`` that
binds them to FastMCP under the ``nvr_`` prefix.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..client import NvrClient
from ..core.config import DeviceSettings
from ..core.serial import SerialLock
from ..core.tooling import run_tool

__all__ = ["ToolContext", "run_tool"]


@dataclass(frozen=True)
class ToolContext:
    settings: DeviceSettings
    client: NvrClient
    writes: SerialLock = field(default_factory=SerialLock)
