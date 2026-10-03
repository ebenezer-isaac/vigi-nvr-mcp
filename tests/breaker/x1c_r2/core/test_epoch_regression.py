"""x1c round 2 - F3: the epoch runs BACKWARDS on a corrupt-file recovery.

The round-1 F1 fix added ``epoch`` as the staleness token: ``clear()`` bumps it so a
reservation taken before the clear is recognised as stale. Its stated contract
(breaker.py docstring; the claim: "clear() ... bumps the epoch") is that the epoch
only ever advances.

But ``clear()``'s recovery path resets the epoch to a FIXED small number when the
current ledger cannot be read:

    try:
        current = self._store.load()
        previous_epoch = current.epoch if current else 0
    except StateUnavailable:
        previous_epoch = 0          # <-- forgets how far the epoch had advanced
    fresh = self._fresh().model_copy(update={"epoch": previous_epoch + 1})

So a breaker whose epoch has advanced (say, to 3) and whose file is then corrupted
(hand-edit, foreign tool, external torn write) recovers to epoch 1, not 4. The
staleness token REPEATS a value it has used before. The only reason this is not an
outright over-admit is the *secondary* id-absence check in ``_release`` - i.e. the
epoch mechanism the fix introduced does not actually hold its own invariant on the
recovery path; it is dead weight there, and the guarantee rests entirely on the
backup check. This is the round-1-fix-on-round-1-finding signal: the mechanism added
to close F1 is itself defeated exactly on the corrupt-recovery path F1's fixer had to
reason about.

This test asserts the documented monotonicity and therefore FAILS on shipped code.
"""

from __future__ import annotations

from pathlib import Path

from vigi_nvr_mcp.core.breaker import LoginBreaker


def test_epoch_never_regresses_on_corrupt_recovery(tmp_path: Path) -> None:
    b = LoginBreaker(tmp_path, "dev", max_failures=1)
    b.clear()  # epoch 1
    b.clear()  # epoch 2
    b.clear()  # epoch 3
    advanced = b.status()["epoch"]
    assert advanced == 3

    # The ledger file is corrupted out-of-band.
    b.path.write_text("{ not valid json", encoding="utf-8")

    # Operator recovery: `breaker --clear`.
    b.clear()
    recovered = b.status()["epoch"]
    assert recovered > advanced, (
        f"epoch regressed from {advanced} to {recovered} on corrupt-recovery clear - "
        "the staleness token repeats a previously-issued value"
    )
