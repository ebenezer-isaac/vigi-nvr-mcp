"""One export in flight per device, crash-visible, over the shared state store.

An mp4 export can run for minutes and spends real disk and NVR bandwidth; two
overlapping exports would compete and can corrupt a half-written file. This is the
same single-fact shape as the login budget - "is an export already running?" read,
decided and written as one step - so it is a thin :class:`~vigi_nvr_mcp.core.slot.SingleSlot`
over the canonical :class:`~vigi_nvr_mcp.core.state.ReservationStore`, exactly as
``LoginBreaker`` is, rather than an in-process lock a second process would not see and
rather than the anonymous-count path whose release could zero a current holder's slot
(x1c round-2 F1).

``reserve()`` admits exactly one export: a second caller is refused with
:class:`~vigi_nvr_mcp.core.errors.PreconditionFailed` while one is in flight. A crash
leaves the named slot on disk (crash-visible); because an export cannot block the
device forever, a reservation older than ``stale_after_s`` is reclaimed by the next
``reserve`` and the dead holder's later release is a stale no-op.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .core.breaker import _safe
from .core.slot import SingleSlot, single_slot_store
from .core.state import Reservation

# An export reservation older than this (no release seen) is a crashed holder.
EXPORT_STALE_S = 3600.0


class ExportSerial:
    """Cross-process "one export at a time" over the canonical reservation store."""

    def __init__(
        self,
        state_dir: Path,
        device_key: str,
        *,
        clock: Callable[[], float] = time.time,
        stale_after_s: float = EXPORT_STALE_S,
        lock_timeout_s: float = 5.0,
    ) -> None:
        store = single_slot_store(Path(state_dir), clock=clock, lock_timeout_s=lock_timeout_s)
        self._slot = SingleSlot(
            store,
            f"export-{_safe(device_key)}",
            stale_after_s=stale_after_s,
            clock=clock,
            reason="EXPORT_IN_PROGRESS",
            message="an export is already in progress on this device; only one runs at a time.",
        )

    @property
    def path(self) -> Path:
        return self._slot.path

    def reserve(self) -> Reservation:
        """Reserve the single export slot. Raises ``PreconditionFailed`` if one is in
        flight, or when the store cannot be used (fail closed)."""
        return self._slot.reserve(meta={"pid": os.getpid()})

    def status(self) -> dict[str, Any]:
        return self._slot.status()
