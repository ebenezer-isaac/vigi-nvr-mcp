"""x1c / core — F1: ``clear()`` does not invalidate outstanding reservations, so a
deferred ``release`` admits OVER the budget (the central claim is disproved).

Central claim under attack: "``ReservationStore.reserve(key)`` admits at most
``max`` concurrent reservations per key across processes ... an unresolved
``Reservation`` (crash, exception, dropped handle) counts against the budget until
``clear()``."

Root of the defect: ``reserved`` is an anonymous COUNT, and ``release`` is an
anonymous ``reserved = max(0, reserved - 1)`` decrement (``breaker.py:179``). A
``Reservation`` does not record WHICH increment it owns, and ``clear()``
(``state.py:331``) merely unlinks the ledger without invalidating the live
``Reservation`` handles that were taken before it. So a reservation taken *before* a
clear, when it is released *after* the clear, decrements the count of a DIFFERENT,
current holder that was admitted after the clear — freeing a budget slot that is
still in flight. A third reservation is then admitted while two are already live,
so with ``max_failures=1`` there are two concurrent admissions: the invariant the
whole module exists to hold is broken.

This is single-process and fully deterministic (no sleeps, no clock), but it models
the ordinary cross-process recovery flow: the server process holds an in-flight
reservation across a login POST while the operator runs ``breaker --clear`` in a
separate CLI process to recover a stuck breaker.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vigi_nvr_mcp.core.breaker import LoginBreaker
from vigi_nvr_mcp.core.errors import BreakerOpen, Cooldown
from vigi_nvr_mcp.core.state import Outcome


def _try_reserve(b: LoginBreaker):
    try:
        return b.reserve_attempt()
    except (BreakerOpen, Cooldown):
        return None


def test_clear_then_stale_release_admits_over_budget(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, "dev", max_failures=1)

    res_a = _try_reserve(b)  # in-flight login in the server process
    assert res_a is not None
    assert b.status()["reserved"] == 1

    # Operator recovers a stuck breaker (a separate `breaker --clear` process).
    b.clear()
    assert b.status()["reserved"] == 0

    # A new login is admitted after the clear — this is the single legitimate
    # holder the budget of 1 permits.
    res_b = _try_reserve(b)
    assert res_b is not None
    assert b.status()["reserved"] == 1

    # The pre-clear login now finishes. Its release performs an anonymous
    # decrement on the POST-clear ledger, wiping res_b's slot although res_b is
    # still in flight.
    res_a.release(Outcome.SUCCESS)

    # res_c must be REFUSED: res_b already holds the single slot. Instead it is
    # admitted, so two reservations (res_b, res_c) are live under max_failures=1.
    res_c = _try_reserve(b)
    live = [r for r in (res_b, res_c) if r is not None]
    assert len(live) <= 1, (
        "central invariant broken: a stale release after clear() freed a slot that "
        f"was still in flight, so {len(live)} reservations are concurrently admitted "
        "under max_failures=1 (budget over-spent -> extra wrong-credential POSTs can "
        "reach the device the breaker exists to protect)."
    )
