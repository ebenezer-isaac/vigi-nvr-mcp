"""x1c round 2 - F1: the export lock does NOT have the breaker's guarantees.

The round-1 over-admit (F1: an anonymous `reserved` count decremented by an
anonymous release lets an old/stale release free a *current* holder's slot) was
fixed for ``LoginBreaker`` only, by giving each reservation a named slot + epoch
and routing reserve/release through ``ReservationStore.mutate``.

``ExportSerial`` was NOT fixed. It still rides the original
``ReservationStore.reserve(admit, resolve)`` path, whose ``_resolver`` is hardcoded
to ``return False`` (never stale) and whose ``_resolve`` blindly writes
``reserved=0`` regardless of *who* is releasing. So an export holder that was
reclaimed as "stale" and a brand-new legitimate holder share one anonymous count,
and the old holder's release zeroes the new holder's slot -> two real, non-stale
exports run concurrently under a "one export at a time" guarantee, which the module
itself says "can corrupt a half-written file".

These tests assert the CORRECT invariant and therefore FAIL on the shipped code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vigi_nvr_mcp.core.errors import PreconditionFailed
from vigi_nvr_mcp.core.state import Outcome
from vigi_nvr_mcp.export_lock import ExportSerial


def test_old_holder_release_cannot_free_the_current_holder(tmp_path: Path) -> None:
    """A (reclaimed-away) old holder's release must NOT drop the new holder's slot."""
    now = [1000.0]
    s = ExportSerial(tmp_path, "dev", clock=lambda: now[0], stale_after_s=60.0)

    res_a = s.reserve()  # holder A, started_at=1000
    assert s.status()["in_flight"] is True

    now[0] = 2000.0  # A now looks stale (older than 60s)
    res_b = s.reserve()  # B reclaims the slot; B is the CURRENT, fresh, legitimate holder
    assert s.status()["in_flight"] is True
    assert s.status()["since_epoch"] == 2000  # it is B's reservation now

    # A (the old, reclaimed-away holder) finishes its slow export and releases. Its
    # release owns nothing current, so it MUST be a stale no-op.
    assert res_a.release(Outcome.SUCCESS) is True, (
        "release of a reclaimed-away holder reports stale=False and zeroes the count"
    )
    # B is still holding a fresh (age 0) reservation; the slot must still be in flight.
    assert s.status()["in_flight"] is True, (
        "old holder's release wiped the current holder's slot (anonymous decrement)"
    )
    assert res_b is not None


def test_no_two_live_exports_after_old_release(tmp_path: Path) -> None:
    """The end-to-end over-admit: B (fresh) + C both run while 'one at a time' holds."""
    now = [1000.0]
    s = ExportSerial(tmp_path, "dev", clock=lambda: now[0], stale_after_s=60.0)

    res_a = s.reserve()
    now[0] = 2000.0
    res_b = s.reserve()  # current legitimate holder, started_at=2000, age 0

    res_a.release(Outcome.SUCCESS)  # old holder's release zeroes the anonymous count

    # B is still a live, NON-stale export (age 0). A third reserve MUST be refused.
    with pytest.raises(PreconditionFailed):
        s.reserve()  # <- admits C on the shipped code: B and C run concurrently
    assert res_b is not None


def test_reservationstore_reserve_stale_detection_is_not_implemented(tmp_path: Path) -> None:
    """The store primitive's documented stale detection is dead code.

    ``Reservation``'s docstring promises ``release``/``stale`` report a slot that no
    longer exists, but ``ReservationStore.reserve`` builds the resolver to ``return
    False`` unconditionally, so every direct user of the store (ExportSerial, and any
    future single-fact safety built on it) inherits round-1 F1.
    """
    now = [1000.0]
    s = ExportSerial(tmp_path, "dev", clock=lambda: now[0], stale_after_s=60.0)
    res_a = s.reserve()
    now[0] = 2000.0
    s.reserve()  # reclaims A's slot; A's handle now owns nothing
    # A releasing a slot that was reclaimed away must be reported stale.
    assert res_a.release(Outcome.SUCCESS) is True
    assert res_a.stale is True
