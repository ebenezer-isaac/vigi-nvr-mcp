# Breaker round x1c-r2 — vector canonical-core — vigi-nvr-mcp @ 7eeb489

Model (ran on): claude-opus-4-8
Branch: breaker/x1c-r2-core (worktree breaker-x1c-r2-core), verified HEAD 7eeb489
(`7eeb489 Merge branch 'fix/xf1-core'`, on top of `8061514 fix(breaker): own
reservation slots + clear epoch, finite-only cooldowns (x1c F1, F2)`). core/VERSION = v1.2.0.

Claim attacked (abridged): at most `max` reservations per key are live across
processes; no reserve/release/clear/crash/restart interleaving over-admits; a release
from a previous epoch or unknown id is a logged no-op; clear() recovers from
corruption AND bumps the epoch AND cannot race a concurrent reserve into an
inconsistent state; legacy v1.1.0 ledgers migrate and are never dropped; status() is
accurate under concurrency and never crashes; non-finite cooldown_until self-heals
while every OTHER non-finite float refuses the load; clear() resets tripped; the export
lock has the same guarantees; the conformance suite proves all of this identically and
its core_pkg fixture cannot be satisfied by the wrong package.

## Round-1-on-round-1 signal (explicit)

Round 1 found F1 (clear() + deferred release over-admit, because `reserved` was an
anonymous COUNT decremented anonymously) and F2 (non-finite cooldown stuck). The fixer
(commit 8061514), for `LoginBreaker` ONLY: named slots (`reservations: id -> ts`,
`reserved = len`), per-reservation epoch, `clear()` bumps the epoch, `release` no-ops
when epoch/id is stale; plus finite-only floats + self-healing cooldown.

Round 2: the fix was partial and self-undermining.
* The round-1 F1 bug is STILL LIVE in `export_lock.py` (F1). The fix was applied to
  `LoginBreaker`, which bypasses `ReservationStore.reserve` for its own `mutate`.
  `ExportSerial` still calls `ReservationStore.reserve(admit, resolve)`, whose resolver
  is hardcoded `return False` (state.py:334 — the `Reservation.stale` detection the
  docstring promises is dead code) and whose `_resolve` writes `reserved=0` blindly. A
  reclaimed-away holder's release zeroes the CURRENT holder's slot — round-1 F1 verbatim.
* The epoch fix REINTRODUCED the decide-then-record split 05-ROOT-CAUSE §1.1(a) says
  the refactor removed: `clear()` reads the epoch under one lock then writes under a
  second (breaker.py:399, :407), so a racing reserve is silently discarded (F2); and
  the epoch token is non-monotonic on the corrupt-recovery path (resets to 1, F3) —
  defeated exactly on the corrupt path F1's fixer reasoned about; only the secondary
  id-absence check now carries the guarantee.

## Controls that PASS (fix holds here — no finding)

- Ordinary cross-process budget (LoginBreaker): conformance 8-process max=1 → exactly 1
  admitted; no-lost-update across 8 processes. The `mutate` reserve serialises the RMW.
- Round-1 F1 for LoginBreaker: reserve→clear→reserve→release(old) no longer over-admits
  (id-absence check); conformance test_clear_then_stale_release_cannot_overadmit PASS.
- Round-1 F2: non-finite cooldown_until self-heals; last_update + reservation timestamps
  use allow_inf_nan=False and REFUSE (NaN timestamp → BreakerOpen). Matches claim.
- Migration: legacy reserved=3 → 3 placeholder reservations that count; reserved=-1 / 1e9
  / true / 1.0(float) all refuse via extra="forbid" on the leftover `reserved`. No drop.
- Strict schema: corrupt/truncated/non-dict/wrong-types/unknown-version → BreakerOpen.
- clear() resets tripped AND failures (full _fresh()), so "reset tripped but keep
  failures → instant re-trip" does NOT apply; code matches documented semantics.
- --clear on an unwritable dir → BreakerOpen (fail closed), exit 3. --clear while this
  process holds a reservation → that handle's release is a stale no-op (fail-safe).
- Crash fail-closed, key normalisation, no secrets in ledger/status: conformance PASS.
- epoch overflow (1e30): no crash (Python big-int). future/duplicate reservation ids:
  counted, no crash. uuid4 ids: unpredictable, not reused.

## Axes that produced nothing

- cooldown arithmetic beyond F2 (self-heal total). reserve↔release on LoginBreaker other
  than via clear() (single mutate lock holds). secrets (none reach ledger/status).
- conformance "wrong core_pkg": a package missing breaker/errors/state ModuleNotFound-
  errors loudly (not vacuous); canonicity is enforced by a SEPARATE tests/
  test_core_identity.py, not the conformance suite — the gap F5 records for export_lock.py.

---

## F1  export lock over-admits — round-1 F1 still live in ExportSerial — Impact 3 (two exports run at once under a documented "one export at a time"; the module itself says overlapping exports "compete and can corrupt a half-written file" — a recording export silently corrupted, NVR bandwidth/disk double-spent) × Likelihood 2 (needs an export outliving the 1-hour staleness window then a second export, then the first releases — uncommon but real for large footage; adversary-reading: no; strict floor 1 → Minor; proposed 2 on reachability of the staleness path) = 6 Major (proposed)
Test: tests/breaker/x1c_r2/core/test_export_lock_overadmit.py::test_no_two_live_exports_after_old_release
Test: tests/breaker/x1c_r2/core/test_export_lock_overadmit.py::test_old_holder_release_cannot_free_the_current_holder
Test: tests/breaker/x1c_r2/core/test_export_lock_overadmit.py::test_reservationstore_reserve_stale_detection_is_not_implemented
What happens: with stale_after_s=60: export A reserves at t=1000; at t=2000 export B
reclaims A's slot (A older than the window) — B is now the fresh (age 0) legitimate
holder. A then finishes its slow export and release(SUCCESS); because the store's
resolver always returns False and ExportSerial._resolve sets reserved=0 unconditionally,
A's release zeroes B's live slot. A third reserve() is admitted while B is still a live,
non-stale export → two real exports concurrently under "one at a time" (measured:
in_flight goes False after A's release; C admitted). res_a.release() returns stale=False
where the contract requires True.
Why (root cause hypothesis): the named-slot+epoch fix was applied only to LoginBreaker;
ExportSerial still rides the un-fixed ReservationStore.reserve path (_resolver hardcoded
return False, state.py:330-334) with an anonymous reserved count any release zeroes — so
a reclaimed-away holder frees the current holder (round-1 F1 on a sibling surface). Do not fix.

## F2  clear() is not atomic — a reserve racing its load→set window is silently discarded (transient over-admit + lost failure) — Impact 3 (a login POST reaches the device for a reservation the ledger forgot, so a second attempt is admitted concurrently; and the forgotten reservation's real failure is dropped, so the breaker under-counts the device lockout — repeated, it walks the admin account toward the hard device lock) × Likelihood 1 (needs operator `breaker --clear` to land in the sub-ms gap between clear's two lock acquisitions while the server reserves; adversary-reading: no; only witness is this test) = 3 Minor
Test: tests/breaker/x1c_r2/core/test_clear_reserve_race.py::test_clear_racing_reserve_does_not_overadmit
Test: tests/breaker/x1c_r2/core/test_clear_reserve_race.py::test_raced_reservation_failure_is_not_lost
Test: tests/breaker/x1c_r2/core/test_clear_reserve_race.py::test_two_clears_racing_bump_the_epoch_twice
What happens: clear() does previous_epoch = load() (lock #1) then set(fresh @ epoch+1)
(lock #2); the lock is dropped between them. Injecting a reserve_attempt() at that exact
seam (deterministic proof the window is exploitable): B commits at the old epoch,
set(fresh) wipes it. Then (a) a post-clear reserve_attempt() is ADMITTED though B's login
is still in flight — pytest.raises(BreakerOpen) fails "DID NOT RAISE"; (b) B.release(
FAILURE) is stale, so status()["failures"] stays 0 — the device failure is lost. Two
concurrent clears collapse to a single epoch bump (+1 not +2). Disproves the explicit
"clear() ... cannot race a concurrent reserve into an inconsistent state."
Why (root cause hypothesis): clear() (breaker.py:398-409) does decide-then-record as two
separate locked ops instead of one locked section — the split 05-ROOT-CAUSE §1.1(a) says
was removed, reintroduced by the epoch fix. Do not fix.

## F3  epoch runs BACKWARDS on a corrupt-file recovery — the fix's own staleness token is non-monotonic exactly where round 1 lived — Impact 2 (the epoch mechanism added to close round-1 F1 is defeated on the corrupt-recovery path, so the "stale by epoch" guarantee rests entirely on the secondary id-absence check — a latent single-point weakening, not an independent over-admit) × Likelihood 1 (needs a corrupt/hand-edited ledger then `breaker --clear`; only witness is this test) = 2 Won't-fix/Minor
Test: tests/breaker/x1c_r2/core/test_epoch_regression.py::test_epoch_never_regresses_on_corrupt_recovery
What happens: three clears advance the epoch to 3; the ledger is corrupted; the recovery
clear() catches StateUnavailable and sets previous_epoch = 0 (breaker.py:401-404),
writing epoch 1 — a value already used. A reservation taken at epoch 1 before the
corruption is NOT recognised as stale by the epoch check afterwards (only the id-absence
check catches it, because clear also empties reservations). "clear() ... bumps the epoch"
is not a monotonic guarantee.
Why (root cause hypothesis): the corrupt-recovery branch resets the epoch to a fixed 0
rather than preserving a durable high-water mark, so the token the fix relies on repeats. Do not fix.

## F4  status() is inaccurate (and blocks) under concurrency — Impact 2 (a `breaker --show` or healthcheck polling during any concurrent login both hangs up to the full lock timeout — default 5s — and misreports a healthy CLOSED breaker as "open"; a visible wrong read he can get past by retrying) × Likelihood 2 (status() must be called during the brief window another process holds the lock for a reserve/release; a periodic healthcheck plus frequent logins makes it reachable; adversary-reading: no) = 4 Minor
Test: tests/breaker/x1c_r2/core/test_status_concurrency.py::test_status_is_accurate_while_another_holder_has_the_lock
What happens: with a healthy CLOSED breaker, holding the <key>.lock the way a concurrent
reserve would, status() blocks for the whole lock_timeout_s (measured ~the timeout) then
returns {"state":"open","reason":...}. "status() is accurate under concurrency" is false.
Why (root cause hypothesis): status() reads through ReservationStore.load, which takes the
cross-process lock for a PURE READ (state.py:309-312); the atomically-replaced ledger does
not need the lock to be read consistently, so taking it only adds contention and a
fail-closed "open" on timeout. Do not fix.

## F5  the conformance suite does not prove the export-lock claim, and export_lock.py is outside the identity manifest — Impact 2 (the claim "the export lock has the same guarantees; the conformance suite proves all of this identically" is false: zero export cases and export_lock.py unhashed, so F1 ships unconformed and the file can drift across repos uncaught) × Likelihood 2 (the gap is certain on every run; the realised consequence — an export bug slipping through — has already occurred as F1) = 4 Minor
Test: tests/breaker/x1c_r2/core/test_conformance_export_gap.py::test_conformance_suite_covers_the_export_lock
Test: tests/breaker/x1c_r2/core/test_conformance_export_gap.py::test_export_lock_is_pinned_by_the_identity_manifest
What happens: tests/conformance/test_breaker_contract.py never references ExportSerial or
the store's reserve() primitive (only LoginBreaker), and core/VERSION's manifest hashes
only core/* plus the conformance test — vigi_nvr_mcp/export_lock.py is absent. So neither
behavioural conformance nor the X1 verbatim-identity test covers the export lock, which is
exactly how F1 (a round-1 finding) survived the fix on that surface.
Why (root cause hypothesis): the conformance + identity machinery was scoped to core/ and
LoginBreaker, but the claim extends the guarantee to export_lock.py (outside core/, reusing
the un-fixed store path). Do not fix.

## Platform matrix

Deploy target Ubuntu; this host Windows 10 (Python 3.13.0, msvcrt.locking lock path). All
five findings are deterministic and platform-independent (injected clock, seam injection at
a documented two-lock gap, a manifest/text assertion, an advisory lock via msvcrt here /
fcntl on POSIX).

Observed ON THIS WINDOWS HOST:
- F1 export over-admit (3 tests) — FAIL (finding), deterministic.
- F2 clear/reserve race + two-clears epoch collapse (3 tests) — FAIL (finding), via seam
  injection at breaker.py:399/407.
- F3 epoch regression — FAIL (finding), deterministic.
- F4 status under contention — FAIL (finding); blocked ~lock_timeout_s then reported "open".
- F5 conformance/identity export gap (2 tests) — FAIL (finding), static.
- Controls (8-proc budget, round-1 F1 for LoginBreaker, F2 self-heal, migration, strict
  schema, clear resets tripped, secrets) — PASS.

Expected on Ubuntu CI (fcntl path): F1/F2/F3/F5 identical (no OS dependence); F4 identical
(fcntl LOCK_EX held). The two POSIX-only conformance hazards (lockfile-deletion inode race;
forked killed holder) remain skipped on Windows and MUST run on Ubuntu, unchanged from round 1.

Convergence: F1 is a proposed Major, so this round does NOT converge. Per 04-BREAKER-PROTOCOL
§1, round 2 not clean → STOP; a root-cause agent (not a third battery) is indicated. The
structural cause is already named in 05-ROOT-CAUSE §4 (the decide-then-record / anonymous-
count shape recurs in every single-fact safety on the store): the fix closed it for
LoginBreaker but left it open in ExportSerial and reintroduced it inside clear().
