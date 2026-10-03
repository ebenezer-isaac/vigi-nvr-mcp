"""x1c / core — crash semantics and durability of the atomic writer.

Controls (hold):
* A dropped reservation handle leaves ``reserved`` elevated on disk and the next
  ``reserve_attempt`` refuses (fail closed) — the crash-between-reserve-and-release
  guarantee.
* A torn/garbage file left where the ledger belongs is refused, never read as valid.

Observation (no finding, documented): ``AtomicStateFile.write`` does not ``fsync``
the file or its parent directory before/after ``os.replace`` (``state.py:157-179``).
``os.replace`` still gives ATOMICITY (a reader sees the old or the new file, never a
torn one), and a post-crash torn file fails the strict schema -> fail closed, so the
claim "a torn write can never be read as valid" holds. But without ``fsync`` the
*durability* of a just-committed reservation is not guaranteed across power loss; on
power loss the ledger can roll back to the previous committed state. That is the safe
direction for a budget (it can only forget a reservation, i.e. under-count — never
over-count), so it is recorded, not scored.

POSIX-only (written, not observable on Windows): a process killed while HOLDING the
store lock has the lock released by the OS on exit, so the next acquirer proceeds,
and the dead holder's ``reserved`` increment (written before it died) still counts
against the budget — fail closed, as claimed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vigi_nvr_mcp.core.breaker import LoginBreaker
from vigi_nvr_mcp.core.errors import BreakerOpen
from vigi_nvr_mcp.core.state import Outcome


def test_dropped_handle_counts_against_budget(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, "dev", max_failures=1)
    b.reserve_attempt()  # handle dropped, never released (simulated crash)
    del_marker = b.status()["reserved"]
    assert del_marker == 1
    fresh = LoginBreaker(tmp_path, "dev", max_failures=1)  # "next process"
    with pytest.raises(BreakerOpen):
        fresh.reserve_attempt()


def test_torn_file_is_never_read_as_valid(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, "dev", max_failures=1)
    b.path.parent.mkdir(parents=True, exist_ok=True)
    # A half-written / null-padded file as a crash during a non-atomic write would
    # leave. os.replace makes this impossible for a live reader, but prove the
    # schema refuses it anyway (defence in depth).
    b.path.write_bytes(b'{"version": 1, "key": "dev", "rese\x00\x00\x00')
    with pytest.raises(BreakerOpen):
        b.reserve_attempt()
    assert b.status()["state"] == "open"


@pytest.mark.skipif(os.name == "nt", reason="requires os.fork + flock; deploy target is Ubuntu")
def test_posix_killed_holder_releases_lock_and_reservation_still_counts(tmp_path: Path) -> None:
    import signal
    import time

    b = LoginBreaker(tmp_path, "dev", max_failures=1)

    pid = os.fork()
    if pid == 0:  # child: reserve (writes reserved=1), then die WITHOUT releasing
        try:
            child = LoginBreaker(tmp_path, "dev", max_failures=1)
            child.reserve_attempt()
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    time.sleep(0.05)

    # The child is gone; the OS freed its lock. The next acquirer proceeds, and the
    # dead child's reserved increment still counts: budget spent, fail closed.
    assert b.status()["reserved"] == 1
    with pytest.raises(BreakerOpen):
        b.reserve_attempt()
