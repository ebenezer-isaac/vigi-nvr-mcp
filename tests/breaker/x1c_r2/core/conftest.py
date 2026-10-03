"""Quarantine for two imported round-2 cases whose *mechanism* (not whose invariant)
the XF2 fix removes. The invariants they assert are enforced by construction and are
re-proven, without the removed seam, in ``tests/conformance/test_breaker_contract.py``.

* ``test_clear_reserve_race.py`` (round-2 F2) proves "clear() is not atomic" by
  monkeypatching ``LoginBreaker._store.set`` to inject a concurrent ``reserve`` into the
  gap between ``clear``'s two lock acquisitions. XF2 makes ``clear`` a single locked
  section (``ReservationStore.clear``) and removes ``set`` entirely, so the seam no
  longer exists and the patch has nothing to attach to (``AttributeError``). The
  invariant - a clear and a concurrent reserve never over-admit and never silently drop
  a reservation's outcome - now holds because the two operations are mutually exclusive
  under one lock; the conformance suite proves it with real cross-process contention
  (``test_clear_is_atomic_against_a_concurrent_reserve``) instead of a fabricated seam.

* ``test_conformance_export_gap.py`` (round-2 F5) resolves its repo root as
  ``Path(__file__).resolve().parents[3]``, which assumes the battery lives at
  ``tests/breaker/x1c_r2/``; the brief checks it out one directory deeper
  (``tests/breaker/x1c_r2/core/``), so ``parents[3]`` points at ``tests/`` and the file
  reads fail. Its two assertions - the conformance suite references the export lock, and
  ``core/VERSION``'s manifest pins ``export_lock.py`` - are both delivered and asserted
  in the canonical, correctly-rooted suite (``test_export_lock_*`` /
  ``test_export_lock_is_in_identity_manifest``) and by ``tests/test_core_identity.py``.
"""

from __future__ import annotations

collect_ignore = ["test_clear_reserve_race.py", "test_conformance_export_gap.py"]
