"""x1c / core — the central cross-process claim, and the POSIX lock-inode race.

Control (holds): 16 real processes hammering ``reserve_attempt`` on one key with
``max_failures=3`` admit EXACTLY 3. The increment under the cross-process advisory
lock serialises the read-modify-write; no over- or under-admission. Verified on the
Windows dev host (``msvcrt.locking``) and expected identical on Ubuntu (``flock``).

POSIX-only (written, NOT observable on Windows): if the dedicated ``.lock`` file is
unlinked by another process between two acquirers, the second acquirer ``open``s a
NEW inode at the same path and ``flock`` on that new inode succeeds immediately —
two processes then believe they hold the per-key lock and both run the
read-modify-write, defeating the serialisation. ``ReservationStore`` never unlinks
its own lock file (``clear()`` keeps it, ``state.py:331-334``), so this needs an
external deleter (a tmp-reaper, ``rm`` on the state dir, a stale-file sweeper); on
Windows the delete-while-locked simply fails, so the race cannot be reproduced here.
"""

from __future__ import annotations

import multiprocessing as mp
import os
from pathlib import Path

import pytest

from vigi_nvr_mcp.core.breaker import LoginBreaker
from vigi_nvr_mcp.core.errors import BreakerOpen, Cooldown


def _reserve_and_hold(args: tuple[str, str, int]) -> str:
    state_dir, key, max_failures = args
    b = LoginBreaker(Path(state_dir), key, max_failures=max_failures)
    try:
        b.reserve_attempt()  # held (never released): occupies a budget slot
        return "admitted"
    except (BreakerOpen, Cooldown):
        return "refused"


def test_sixteen_processes_max_three_admit_exactly_three(tmp_path: Path) -> None:
    ctx = mp.get_context("spawn")
    jobs = [(str(tmp_path), "dev", 3)] * 16
    with ctx.Pool(16) as pool:
        results = pool.map(_reserve_and_hold, jobs)
    assert results.count("admitted") == 3, results
    assert results.count("refused") == 13, results


@pytest.mark.xfail(
    reason="POSIX flock cannot survive the lock file being unlinked (a new open() is a new "
    "inode). Documented LIMITATION, not a store bug: the store never unlinks its own lock and "
    "the state dir is 0700, so an external deleter is outside the threat model.",
    strict=False,
)
@pytest.mark.skipif(os.name == "nt", reason="POSIX flock inode semantics; deploy target is Ubuntu")
def test_posix_lockfile_deletion_breaks_mutual_exclusion(tmp_path: Path) -> None:
    """DELETING the lock file mid-hold lets a second acquirer lock a new inode.

    This is the documented POSIX hazard: it proves the store relies on the lock
    file's inode being stable. It fails (two holders) on Linux if anything deletes
    the ``.lock`` file while it is held.
    """
    import fcntl

    b = LoginBreaker(tmp_path, "dev", max_failures=1)
    # Materialise the store + lock file via one reservation cycle.
    b.reserve_attempt().release(Outcome_SUCCESS())
    lock_path = tmp_path / "breaker-dev.lock"
    assert lock_path.exists()

    fd_a = os.open(lock_path, os.O_RDWR)
    fcntl.flock(fd_a, fcntl.LOCK_EX | fcntl.LOCK_NB)  # holder A
    try:
        os.unlink(lock_path)  # external deleter removes the name; A keeps the inode
        fd_b = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)  # NEW inode
        try:
            took_second = True
            try:
                fcntl.flock(fd_b, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                took_second = False
            assert not took_second, (
                "a second acquirer locked a NEW inode while holder A still holds the "
                "old one: deleting the .lock file defeats cross-process mutual "
                "exclusion (two concurrent read-modify-writes on the ledger)."
            )
        finally:
            os.close(fd_b)
    finally:
        os.close(fd_a)


def Outcome_SUCCESS():  # tiny indirection so the import stays POSIX-local
    from vigi_nvr_mcp.core.state import Outcome

    return Outcome.SUCCESS
