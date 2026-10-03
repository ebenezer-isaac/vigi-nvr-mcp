"""Serialisation of guarded operations.

A guarded write is "read live state, check preconditions, write, read again".
Two such operations interleaving could each pass their checks and then clobber
one another, so every guarded write runs under one per-device ``SerialLock``.
The lock is not re-entrant: acquire it at the tool level only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from .config import DeviceSettings

T = TypeVar("T")


class SerialLock:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    async def run(self, action: Callable[[], Awaitable[T]]) -> T:
        """Run ``action`` with exclusive access; waits for any operation in flight."""
        async with self._lock:
            return await action()


class GuardedWriter:
    """The single guarded-write executor: central dry-run plus serialisation.

    Every mutating tool hands its write to ``run(request, action)``. When
    ``settings.dry_run`` is set this returns ``{"dry_run": True, "request": request}``
    and performs no I/O at all; otherwise it runs ``action`` under the per-device
    serial lock. Dry-run lives here and ONLY here — tools must not re-implement it,
    so a new mutating path cannot forget to honour it.
    """

    def __init__(self, settings: DeviceSettings, lock: SerialLock | None = None) -> None:
        self._settings = settings
        self._lock = lock or SerialLock()

    @property
    def busy(self) -> bool:
        return self._lock.busy

    async def run(
        self, request: dict[str, Any], action: Callable[[], Awaitable[T]]
    ) -> T | dict[str, Any]:
        if self._settings.dry_run:
            return {"dry_run": True, "request": request}
        return await self._lock.run(action)
