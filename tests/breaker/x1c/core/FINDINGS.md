# Breaker round x1c - vector canonical-core - vigi-nvr-mcp @ a9958fd
Model: claude-opus-4-8
Branch: breaker/x1c-core (worktree breaker-x1c-core), verified HEAD a9958fd.

Claim attacked (verbatim, abridged): "core/ v1.1.0 @ a9958fd: ReservationStore.reserve(key) admits at
most max concurrent reservations per key across PROCESSES; an unresolved Reservation counts against the
budget until clear(); tripped is sticky; cooldown remaining is clamped >= 0 and survives restart; the
ledger is strict-schema and any load failure refuses with StateUnavailable/BreakerOpen; the TLS backend
compares the leaf cert SHA-256 on httpx's own connection at start_tls BEFORE the stream is returned;
ConfirmWrite collapses every non-true JSON value to False; redact() implements the documented union
without over-stripping; GuardedWriter.run(require_gate=False) still serialises and honours dry-run;
AtomicStateFile writes are atomic and a torn write can never be read as valid."

## Summary
The core is strong: cross-process budget, strict-schema fail-closed loads, ConfirmWrite, redaction, the
TLS start_tls pinning mechanism (the r2 side-channel/latch findings are genuinely fixed) and GuardedWriter
all hold under attack. Two breaks found, both in the reservation/cooldown state machine: F1 the central
"at most max concurrent reservations" invariant is broken by clear() interacting with an outstanding
Reservation (anonymous decrement after reset); F2 the "strict-schema" ledger admits non-finite floats, so
a hand-edited cooldown_until of Infinity/NaN never counts down.

Axes with NO finding (controls, pass on this host unless noted):
- Cross-process budget (central claim, ordinary path): 16 real spawn processes, max=3 -> EXACTLY 3
  admitted, 13 refused. Increment under the advisory lock serialises the RMW; conformance 8-worker
  lost-update case also holds.
- Strict-schema fail-closed loads: corrupt/truncated/non-dict, wrong types incl. false/"1"/[1], unknown
  version, torn null-padded file all raise BreakerOpen (conformance + test_crash_and_durability). Extra
  keys, string "1" for version, version 0/2 and a UTF-8 BOM also refuse (verified manually); the shipped
  conformance suite does NOT cover extra-keys / BOM / version==0 / string-"1" explicitly though the code
  handles them.
- tripped sticky across a raised budget; success keeps failures and clears cooldown; BUSY/ABORT budget
  (conformance, re-confirmed).
- Crash fail-closed: dropped/un-released handle leaves reserved elevated; next reserve refuses.
- canonical_device_key: fe80::1 == fe80:0:0:0:0:0:0:1, NVR.local == nvr.local (conformance).
- TLS pinning mechanism: _PinnedStream.start_tls reads httpx's own leaf cert and raises TlsPinMismatch
  BEFORE returning the stream, fails closed on an unreadable cert, leaks no fingerprint in the message. No
  latch; every new connection wrapped.
- ConfirmWrite: 1, 1.0, "true", "True", "1", "yes", 0, None, [], {} all -> False; only boolean True ->
  True; JSON schema stays {"type":"boolean"}. (No bool subclass exists in Python to pass is-True.)
- redact: documented union implemented exactly; auth_result/online/conn_status/uuid/row_id/key_present
  survive; secrets stripped at depth, in lists, without mutation.
- GuardedWriter: require_gate=False honours dry-run (no I/O), runs ungated export with writes off and
  serialises it, fails closed when gated without allow_writes, releases the lock on an action exception.
- AtomicStateFile atomicity: pid-suffixed tmp + os.replace -> no torn read; conformance no-lost-update
  across 8 processes holds.

Observations (documented, not scored):
- No fsync of file or parent dir in AtomicStateFile.write (state.py:157-179). os.replace still gives
  atomicity and a post-crash torn file fails the schema (fail closed), so "torn write never read as valid"
  holds; only durability across power loss is unguaranteed, and the failure direction is under-count (safe
  for a budget).
- Orphaned tmp litter: a crash between json.dump to <name>.json.<pid>.tmp and os.replace leaves the tmp;
  PIDs reused and tmp is O_TRUNC-reopened, so no corruption, just litter.
- Plain http:// + pin: post_json verifies AFTER the POST on the non-handshake path, so http:// + pin would
  send the request before refusing; but DeviceSettings.base_url always forces https://, so unreachable via
  config.
- redact device vocabulary: Archer data (RSA ciphertext), sign, hash are NOT in the documented union, so
  redact does not strip them - consistent with "implements the documented union" (spec-completeness, not a
  code-vs-claim deviation).
- SerialLock non-reentrant: nesting run deadlocks; documented in the module, no path nests it.

---

## F1 clear() + a deferred release admit OVER the budget - the central "at most max concurrent reservations" invariant is broken - Impact 3 (budget over-spends: a second login is admitted while the first is still in flight, so two wrong-credential POSTs reach the device the breaker protects; repeated, this can walk the admin account into the device-side hard lockout and leave the NVR unreachable until a human intervenes) x Likelihood 2 (needs breaker --clear, the operator recovery action, to land in the sub-second window while a reservation is held across a login POST in the server process - an uncommon but operationally real combination; adversary-reading: no, clear is a CLI action, not an injected tool argument; strict-rubric floor: only witness is this test, which caps likelihood at 1 -> Minor; proposed at 2 on reachability of the recovery path) = 6 Major (proposed)
Test: tests/breaker/x1c/core/test_reservation_clear_overadmit.py::test_clear_then_stale_release_admits_over_budget
What happens: with max_failures=1: reserve A (reserved=1); clear() unlinks the ledger (reserved=0) but
does NOT invalidate the live handle A; reserve B admitted as the one legitimate post-clear holder
(reserved=1); A.release(SUCCESS) runs reserved = max(0, reserved-1) on the post-clear ledger and wipes B's
slot (reserved=0); reserve C is then admitted. B and C are both live under a budget of 1 - measured: 2
reservations concurrently admitted, assert 2 <= 1 fails.
Why (root cause hypothesis): reserved is an anonymous COUNT and release is an anonymous decrement
(breaker.py:179) - a Reservation does not record which increment it owns - while clear() (state.py:331)
resets the count without invalidating outstanding handles, so a release issued after a clear decrements a
different, current holder's slot.

## F2 The "strict-schema" ledger admits non-finite floats; a hand-edited cooldown_until of Infinity/NaN never counts down (stuck breaker) - Impact 3 (the breaker refuses every login forever - reserve_attempt raises Cooldown on every call regardless of the clock - leaving the device unreachable until a human runs breaker --clear) x Likelihood 1 (the writer clamps cooldown_s to [0, 7200] and can never emit a non-finite value, so the file must come from a hand-edit or a foreign tool; only witness is this test) = 3 Minor
Test: tests/breaker/x1c/core/test_schema_nonfinite_cooldown.py::test_nonfinite_cooldown_never_expires[Infinity]
Test: tests/breaker/x1c/core/test_schema_nonfinite_cooldown.py::test_nonfinite_cooldown_never_expires[NaN]
What happens: BreakerLedger (breaker.py:79) sets strict=True, extra="forbid" but NOT allow_inf_nan=False
(unlike DeviceSettings.timeout_seconds, config.py:104). json.loads accepts the Infinity/NaN tokens and
strict float accepts the non-finite value, so the load SUCCEEDS (not a "load failure" that refuses).
_cooldown_remaining (breaker.py:142) then computes inf-clock()==inf / nan-clock()==nan, and
min(7200.0, inf|nan) clamps to 7200.0 on every call - so after advancing the clock ~1e9s the cooldown still
reports 7200.0s remaining (assert 7200.0 == 0 fails). -Infinity instead reads as 0 remaining and is
admitted (benign), showing non-finite handling is simply unprincipled.
Why (root cause hypothesis): the float fields lack allow_inf_nan=False, so the "strict schema refuses any
invalid shape" guarantee has a hole for non-finite floats, and the min(MAX_COOLDOWN_S, ...) clamp assumes a
finite operand.

## Platform matrix
Deploy target is Ubuntu; this host is Windows 10 (Python 3.13.0, msvcrt.locking lock path).

Ran and observed ON THIS WINDOWS HOST:
- F1 clear-overadmit - FAIL (finding), deterministic, platform-independent.
- F2 non-finite cooldown (Infinity, NaN) - FAIL (finding), platform-independent.
- 16-process max=3 budget - PASS (exactly 3 admitted). Cross-process mutual exclusion via msvcrt.locking
  confirmed here; fcntl.flock expected identical on Ubuntu.
- dropped-handle fail-closed, torn-file refused, TLS start_tls mechanism, ConfirmWrite, redact,
  GuardedWriter - all PASS.

Written but NOT observable on Windows (skipif; CI on Ubuntu MUST run these):
- test_central_claim_concurrency.py::test_posix_lockfile_deletion_breaks_mutual_exclusion - the POSIX inode
  race: deleting the .lock file mid-hold lets a second acquirer flock a new inode (two holders). The store
  never deletes its own lock file, so this needs an external deleter; on Windows a delete of a locked file
  simply fails, so the race cannot be reproduced here. Expected to EXPOSE the hazard on Linux.
- test_crash_and_durability.py::test_posix_killed_holder_releases_lock_and_reservation_still_counts -
  os.fork a child that reserves then dies without releasing; asserts the OS frees the lock AND the dead
  holder's reserved still counts (fail closed). Expected PASS on Linux (control for the claim).

Could NOT observe on ANY platform here (need a real TLS server / the real AsyncConnectionPool backend):
- The end-to-end "zero request bytes on a TLS mismatch" guarantee over httpx's real pinning backend
  (unit-level the start_tls mechanism is correct; injected http_transport in tests bypasses the backend and
  exercises only the post-response _verify_pin).
- Per-request re-verification of a REUSED pooled connection, and whether
  response.extensions["network_stream"] is populated by the custom AsyncConnectionPool (if not, _verify_pin
  would _peer_cert_der() -> TransportError on every request - fail closed, but a functional break). Flagged
  for an integration test on the deploy host.
