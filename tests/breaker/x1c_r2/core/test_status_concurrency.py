"""x1c round 2 - F4: status() is NOT accurate under concurrency.

The claim: "status() is accurate under concurrency and never crashes." It never
crashes (it catches StateUnavailable). But ``status()`` reads the ledger through
``ReservationStore.load``, which takes the per-key cross-process lock for a PURE
READ. A single atomic file (os.replace) does not need the lock to be read
consistently, so taking it has only downsides under concurrency:

* while any other process holds the lock (an ordinary reserve/release, or a stuck
  holder), ``status()`` BLOCKS for up to the full lock timeout (default 5s), then
* reports ``state="open"`` with a ``reason`` string - i.e. it misreports a perfectly
  healthy, closed breaker as open, purely because it could not grab the lock.

A ``breaker --show`` or a monitoring healthcheck that polls status during a
concurrent login therefore both hangs and lies.

The test holds the advisory lock the way a concurrent reserve would, then asserts
status() stays accurate and prompt. It FAILS on shipped code.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from vigi_nvr_mcp.core.breaker import LoginBreaker
from vigi_nvr_mcp.core.state import Outcome


def _acquire(lock_path: Path) -> int:
    fd = os.open(lock_path, os.O_RDWR)
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _release(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def test_status_is_accurate_while_another_holder_has_the_lock(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, "dev", max_failures=5, lock_timeout_s=0.3)
    # Establish a healthy, CLOSED breaker and materialise the lock file.
    b.reserve_attempt().release(Outcome.SUCCESS)
    assert b.status()["state"] == "closed"

    lock_path = b.path.with_name(b.path.stem + ".lock")
    fd = _acquire(lock_path)  # simulate a concurrent reserve/release holding the lock
    try:
        start = time.monotonic()
        snap = b.status()
        elapsed = time.monotonic() - start
        assert snap["state"] == "closed", (
            f"status() misreported a healthy breaker as {snap['state']!r} merely "
            "because another process held the lock during a read"
        )
        assert elapsed < 0.2, (
            f"status() blocked {elapsed:.2f}s on a pure read waiting for an unrelated "
            "lock holder (a --show/healthcheck hangs during any concurrent login)"
        )
    finally:
        _release(fd)
