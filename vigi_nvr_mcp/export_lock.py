"""One export in flight per device, crash-visible, over the shared state store.

An mp4 export can run for minutes and spends real disk and NVR bandwidth; two
overlapping exports would compete and can corrupt a half-written file. This is the
same single-fact shape as the login budget - "is an export already running?" read,
decided and written as one step - so it uses the same :class:`ReservationStore`
primitive rather than an in-process lock that a second process would not see.

``reserve()`` admits exactly one export: a second caller is refused with
``PreconditionFailed`` while one is in flight. A crash leaves the reservation on disk
(crash-visible); because an export cannot block the device forever, a reservation
older than ``stale_after_s`` is treated as a dead holder and reclaimed.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .core.breaker import _safe
from .core.errors import PreconditionFailed
from .core.state import Reservation, ReservationStore

# An export reservation older than this (no release seen) is a crashed holder.
EXPORT_STALE_S = 3600.0


class ExportLedger(BaseModel):
    """The strictly-typed fact: is an export in flight, and since when."""

    model_config = ConfigDict(strict=True, extra="forbid")

    version: Literal[1] = 1
    reserved: int = Field(ge=0)
    holder_pid: int | None
    started_at: float | None = Field(allow_inf_nan=False)
    last_update: float = Field(allow_inf_nan=False)


class ExportSerial:
    """Cross-process "one export at a time" over :class:`ReservationStore`."""

    def __init__(
        self,
        state_dir: Path,
        device_key: str,
        *,
        clock: Callable[[], float] = time.time,
        stale_after_s: float = EXPORT_STALE_S,
        lock_timeout_s: float = 5.0,
    ) -> None:
        self._clock = clock
        self._stale = stale_after_s
        self._store: ReservationStore = ReservationStore(
            Path(state_dir),
            f"export-{_safe(device_key)}",
            ExportLedger,
            make_default=self._fresh,
            lock_timeout_s=lock_timeout_s,
        )

    @property
    def path(self) -> Path:
        return self._store.path

    def _fresh(self) -> ExportLedger:
        return ExportLedger(
            reserved=0, holder_pid=None, started_at=None, last_update=float(self._clock())
        )

    def _admit(self, current: ExportLedger | None) -> ExportLedger:
        now = float(self._clock())
        ledger = current or self._fresh()
        if ledger.reserved > 0:
            started = ledger.started_at or 0.0
            if now - started < self._stale:
                raise PreconditionFailed(
                    "an export is already in progress on this device; only one runs at a time.",
                    reason="EXPORT_IN_PROGRESS",
                    context={"since_epoch": int(started)},
                )
            # Older than the staleness window: the holder crashed; reclaim the slot.
        return ledger.model_copy(
            update={
                "reserved": 1,
                "holder_pid": os.getpid(),
                "started_at": now,
                "last_update": now,
            }
        )

    def _resolve(
        self, current: ExportLedger | None, outcome: object, kwargs: dict[str, Any]
    ) -> ExportLedger:
        ledger = current or self._fresh()
        return ledger.model_copy(
            update={
                "reserved": 0,
                "holder_pid": None,
                "started_at": None,
                "last_update": float(self._clock()),
            }
        )

    def reserve(self) -> Reservation:
        """Reserve the single export slot. Raises ``PreconditionFailed`` if one is in
        flight, or ``StateUnavailable`` if the store cannot be used (fail closed)."""
        return self._store.reserve(self._admit, self._resolve)

    def status(self) -> dict[str, Any]:
        from .core.errors import StateUnavailable

        try:
            ledger = self._store.load()
        except StateUnavailable as exc:
            return {"in_flight": None, "reason": str(exc), "path": str(self.path)}
        reserved = bool(ledger and ledger.reserved > 0)
        return {
            "in_flight": reserved,
            "since_epoch": int(ledger.started_at) if reserved and ledger.started_at else None,
            "path": str(self.path),
        }
