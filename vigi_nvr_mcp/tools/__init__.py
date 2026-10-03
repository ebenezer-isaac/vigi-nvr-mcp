"""VIGI NVR tools. Each module exposes plain async functions taking a
``ToolContext`` (easy to test) and ``register(mcp, ctx) -> list[str]`` that
binds them to FastMCP under the ``nvr_`` prefix.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..client import NvrClient
from ..core.config import DeviceSettings
from ..core.serial import GuardedWriter
from ..core.tooling import run_tool
from ..media.ffmpeg import FfmpegRunner

__all__ = ["ToolContext", "run_tool"]


@dataclass(frozen=True)
class ToolContext:
    settings: DeviceSettings
    client: NvrClient
    writes: GuardedWriter | None = None
    # One ffmpeg driver per server: a single serial lock and one export dir shared
    # by every media/investigation tool (built lazily so reads need no ffmpeg).
    runner: FfmpegRunner | None = None

    def __post_init__(self) -> None:
        if self.writes is None:
            object.__setattr__(self, "writes", GuardedWriter(self.settings))
        if self.runner is None:
            object.__setattr__(self, "runner", FfmpegRunner(self.settings))
