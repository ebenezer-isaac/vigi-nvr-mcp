"""VIGI NVR tools. Each module exposes plain async functions taking a
``ToolContext`` (easy to test) and ``register(mcp, ctx) -> list[str]`` that
binds them to FastMCP under the ``nvr_`` prefix.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..client import NvrClient
from ..core.breaker import canonical_device_key, default_state_dir
from ..core.config import DeviceSettings
from ..core.serial import GuardedWriter
from ..core.tooling import run_tool
from ..export_lock import ExportSerial
from ..media.ffmpeg import FfmpegRunner

__all__ = ["ToolContext", "run_tool"]

APP_NAME = "vigi-nvr-mcp"


@dataclass(frozen=True)
class ToolContext:
    settings: DeviceSettings
    client: NvrClient
    writes: GuardedWriter | None = None
    # One ffmpeg driver per server: a single serial lock and one export dir shared
    # by every media/investigation tool (built lazily so reads need no ffmpeg).
    runner: FfmpegRunner | None = None
    # Cross-process "one export in flight" over the shared state store.
    export_serial: ExportSerial | None = None

    def __post_init__(self) -> None:
        if self.writes is None:
            object.__setattr__(self, "writes", GuardedWriter(self.settings))
        if self.runner is None:
            object.__setattr__(self, "runner", FfmpegRunner(self.settings))
        if self.export_serial is None:
            state_dir = (
                Path(self.settings.state_dir)
                if self.settings.state_dir
                else default_state_dir(APP_NAME)
            )
            object.__setattr__(
                self,
                "export_serial",
                ExportSerial(state_dir, canonical_device_key(self.settings.host)),
            )
