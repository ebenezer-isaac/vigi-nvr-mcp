"""x1c round 2 - F2: clear() is not atomic; it can race a concurrent reserve.

The round-1 F1 fix made ``clear()`` bump the epoch so a reservation taken before the
clear is recognised as stale afterwards. But ``clear()`` does this as TWO separate
locked operations:

    previous_epoch = self._store.load()      # lock #1: read the epoch
    ...
    self._store.set(fresh @ previous_epoch+1) # lock #2: write the fresh ledger

The lock is released between them. A ``reserve_attempt()`` by another process that
lands in that window commits a reservation at the OLD epoch; ``set(fresh)`` then
silently discards it (reservations wiped, epoch bumped). This is exactly the
decide-then-record split the root-cause spec (05 §1.1a) says the refactor had to
remove - reintroduced by the fix itself.

Two concrete harms, each disproving the claim "clear() ... cannot race a concurrent
reserve into an inconsistent state":

1. Over-admit: the raced holder B is live (its login POST is in flight) but has no
   ledger record, so a post-clear reserve C is admitted -> two live login attempts
   across processes under a budget of one.
2. Lost failure: B's eventual release(FAILURE) is stale (epoch bumped), so the real
   device-side failure B caused is never counted - the device lockout counter
   advances while the breaker's stays at zero (a budget leak).

The race window is realised deterministically by injecting the concurrent reserve at
the exact seam the lock leaves open (between clear's load and set). The injection
proves the window EXISTS and is exploitable; it is not a contrived code change.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vigi_nvr_mcp.core.breaker import LoginBreaker
from vigi_nvr_mcp.core.errors import BreakerOpen
from vigi_nvr_mcp.core.state import Outcome


def _race_clear(victim: LoginBreaker, racer: LoginBreaker) -> object:
    """Run ``victim.clear()`` while ``racer`` reserves in the load->set window."""
    captured: dict[str, object] = {}
    original_set = victim._store.set

    def racing_set(model: object) -> None:
        # This fires AFTER clear() read the epoch but BEFORE it writes the fresh
        # ledger - i.e. while no lock is held by clear().
        captured["res"] = racer.reserve_attempt()
        return original_set(model)  # type: ignore[arg-type]

    victim._store.set = racing_set  # type: ignore[assignment]
    victim.clear()
    return captured["res"]


def test_clear_racing_reserve_does_not_overadmit(tmp_path: Path) -> None:
    server = LoginBreaker(tmp_path, "dev", max_failures=1)
    operator = LoginBreaker(tmp_path, "dev", max_failures=1)

    res_b = _race_clear(operator, server)  # B reserved inside clear's window
    # B's login POST is now in flight across processes. A second attempt MUST refuse
    # while B is live; on the shipped code the ledger forgot B, so C is admitted.
    with pytest.raises(BreakerOpen):
        server.reserve_attempt()
    assert res_b is not None


def test_raced_reservation_failure_is_not_lost(tmp_path: Path) -> None:
    server = LoginBreaker(tmp_path, "dev", max_failures=1)
    operator = LoginBreaker(tmp_path, "dev", max_failures=1)

    res_b = _race_clear(operator, server)
    # B's login reached the device and FAILED (wrong credentials). Recording that
    # failure must advance the breaker's count so the device lockout is tracked.
    res_b.release(Outcome.FAILURE, failure={"device_error_code": -40401})
    assert server.status()["failures"] == 1, (
        "the raced reservation's real device failure was silently dropped (stale "
        "release after an epoch bump) - the breaker now under-counts the device lockout"
    )


def test_two_clears_racing_bump_the_epoch_twice(tmp_path: Path) -> None:
    """Concurrent clears collapse to a single epoch bump (lost update on epoch).

    Two independent operators each running `breaker --clear` must leave the epoch
    advanced by two (each clear is a distinct invalidation point); the non-atomic
    load->set lets both read the same epoch and write the same +1.
    """
    a = LoginBreaker(tmp_path, "dev", max_failures=1)
    b = LoginBreaker(tmp_path, "dev", max_failures=1)
    a.clear()  # epoch -> 1
    start = LoginBreaker(tmp_path, "dev").status()["epoch"]
    assert start == 1

    original_set = a._store.set

    def racing_set(model: object) -> None:
        b.clear()  # b reads epoch 1, writes epoch 2
        return original_set(model)  # a also read epoch 1, writes epoch 2 (clobbers)

    a._store.set = racing_set  # type: ignore[assignment]
    a.clear()

    final = LoginBreaker(tmp_path, "dev").status()["epoch"]
    assert final == start + 2, (
        f"two concurrent clears advanced the epoch by {final - start}, not 2 - the "
        "epoch (the staleness token) can repeat across distinct clears"
    )
