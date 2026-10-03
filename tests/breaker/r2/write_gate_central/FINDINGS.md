# Breaker round 2 — vector write-gate-central — vigi-nvr-mcp @ 0295583
Model: claude-opus-4-8 (commit trailer uses the configured subagent id, Claude Fable 5.1)
Branch: breaker/r2-write-gate-central

Claim attacked:
> Every mutating path (`nvr_call`, `nvr_raw_call`, `nvr_remove_channel`,
> `nvr_move_channel`, `nvr_backup_config`'s writes if any) goes through exactly one
> `GuardedWriter.run(request, action)` which enforces `ALLOW_WRITES` + `confirm_write`,
> serialises writes, and under `VIGI_NVR_DRY_RUN` returns `{dry_run: true, request}`
> performing zero I/O — there is no other place dry-run is decided; `nvr_remove_channel`
> refuses `online=="1"` rows unless `force=True`, checked on a fresh re-read immediately
> before the write; `nvr_move_channel` refuses an occupied target on the fresh re-read;
> `nvr_backup_config` rejects HTML / JSON-error / <1 KB responses and reports
> `content_type/size/sha256`; `InvalidInput` is the only error mapped to `INVALID_INPUT`;
> a depth bomb in params returns an envelope.

## Verdict

The round-1 Criticals are genuinely fixed: the depth bomb now returns an envelope
(no `RecursionError`), the online/`force` remove guard exists and is checked on the
fresh re-read, the raw gateway honours dry-run, and backup rejects HTML/<1 KB/JSON-error
bodies. The GuardedWriter centralisation holds for `nvr_call`/`nvr_raw_call`/
`nvr_remove_channel`/`nvr_move_channel` — all serialise and all honour dry-run with zero
I/O. Concurrency holds (ten concurrent removes serialise and each re-reads after the
prior delete committed).

Two clauses of the claim are nonetheless **false**, both Minor: `nvr_backup_config`
is a mutating (`do`) path that never touches `GuardedWriter` and ignores dry-run (F1),
and `InvalidInput` is **not** the only error mapped to `INVALID_INPUT` — a plain
`UnicodeEncodeError` is, and its internal message leaks (F2). Neither is a device-
destructive or secret-exfiltrating hazard, so **no Critical and no Major: round 2 has
converged.**

Axes with no finding (attacked, held — see `test_axes_that_hold.py`):
- **Central bypass (grep + runtime):** the only non-`get` `client.call` outside a
  GuardedWriter action is `request_config_backup` (F1). The typed read tools all issue
  `get`; `nvr_call` routes a catalog-`mutates` **or** non-`get` call through
  `ctx.writes.run`; `nvr_raw_call` routes everything but `get` through it. No
  `nvr_enable_rtsp`/`do`-using read tool other than backup. No tool passes dry-run state
  of its own.
- **Dry-run source:** `GuardedWriter.run` reads `self._settings.dry_run` live on every
  call (not cached); `settings` is a frozen pydantic model (env read once at startup).
  grep for dry_run finds the decision only in `core/serial.py`; `tools/channels.py` and
  `backend/nvr.py` only *report* it.
- **State machine:** `force=True` with a uuid mismatch still refuses (UUID is checked
  before the online/force guard); `force` + dry-run performs no write; move with the
  source row moved -> `UUID_MISMATCH`; move onto an occupied slot -> `TARGET_OCCUPIED` on
  the fresh re-read; two queued guarded writes — the second's whole action (incl. its
  re-read) runs only after the first's action (incl. its write) under the shared lock.
- **Concurrency:** 10 concurrent `nvr_remove_channel` on one `ToolContext` -> all 10
  serialise, all succeed, and exactly 20 list reads occur (before+after per remove), so
  each re-read sees the prior delete.
- **confirm_write at the real FastMCP boundary:** round-1's "coerces only genuine bools"
  was **inaccurate** at the time — pydantic coerced truthy strings ("true", "yes", "on",
  "y", "t", "1", 1) to True and negatives to False, and unparseable values raised a
  `ToolError` before the tool body ran. No value a caller meant as "no" coerced to True,
  so it was never a dangerous fail-open, but a truthy *string* did reach the gate as True.
  **Closed in X1b (2026-10-03):** `confirm_write` is now typed `core.types.ConfirmWrite`,
  whose `BeforeValidator` collapses every value except the JSON boolean `true` to `False`.
  So "true"/"1"/1/"yes"/"sure"/"2"/null all reach the gate as `False` and are refused with
  a single `WRITE_REFUSED` envelope and **zero I/O** (no schema error, no `ToolError`); only
  the genuine boolean `true` authorises the write. See
  `test_axes_that_hold.py::test_confirm_write_boundary_only_true_confirms`.
- **ALLOW_WRITES:** read per call from `settings.allow_writes` in `check_write_gate`;
  unparseable env fails fast at startup (`ConfigError`), never fail-open (round-1 held).
- **Backup content & reported fields:** HTML/XML (leading `<`), JSON error envelopes, and
  <1 KB bodies are rejected; `content_type` is **sniffed** from the first byte (not
  trusted from a device header); `sha256`/`size` are of the in-memory bytes, identical to
  what `write_private_file` writes. (1024 bytes of zeros / a PNG are accepted as
  octet-stream, but the claim only promises to reject HTML/JSON-error/<1 KB, so this is
  within the claim.)
- **ids / uuid encoding:** `validate_channel_id` strips and matches [A-Za-z0-9_-]{1,64}
  so " 1"->"1" and 1->"1", while "01" stays distinct (-> NotFound, no false match); uuid
  compare is strict inequality on the unmodified live value, so upper/lower-case or
  padded live uuids cannot falsely match (fail-closed). At the FastMCP boundary the
  id/uuid params are typed `str`.
- **Depth bomb:** `validate_params` checks depth *before* recursing, so a 4000-deep dict
  returns `INVALID_INPUT` with 0 device requests — round-1 F1 fixed.

## F1 `nvr_backup_config` is a mutating (`do`) path that bypasses GuardedWriter and ignores `VIGI_NVR_DRY_RUN` — Impact 2 (a config-export `do` is sent to the device and a credential-bearing file is written to disk in a mode the operator uses to preview with no side effects; non-destructive and recoverable) x Likelihood 2 (adversary-reading? no — needs `DRY_RUN=true` set *and* a backup call, the master-plan §5 pre-LIVE preview ritual, but no incident on record) = 4 Minor
Test: tests/breaker/r2/write_gate_central/test_backup_bypasses_guarded_writer.py::test_backup_performs_no_device_io_under_dry_run
Test: tests/breaker/r2/write_gate_central/test_backup_bypasses_guarded_writer.py::test_backup_writes_no_file_under_dry_run
What happens: `backup_config` calls `ctx.client.request_config_backup()`, which issues
{"method":"do","system":{"download_conf":null}} — a non-`get` request — straight through
`client.call`, never through `ctx.writes` (the GuardedWriter). With `VIGI_NVR_DRY_RUN=true`
and a fake that serves a 2 KB blob, the `do` reaches the device (api_requests contains
{'method':'do','system':{'download_conf':None}}) and `nvr-config-*.bin` is written to
disk; the tool returns success:true with real path/size/sha256 and no data.dry_run. The
claim states every mutating path — "incl. `nvr_backup_config`'s writes if any" — goes
through "exactly one `GuardedWriter.run`" and under dry-run "performs zero I/O"; backup
does neither. (Note: backup's own docstring and Master-Plan §5 classify it read-only /
not-a-write-tool, so the *code* is arguably spec-consistent; it is the *claim* that
overreaches. Scored against the claim.)
Why (root cause hypothesis): the backup `do` predates the GuardedWriter centralisation
and was never routed through it, so the one place that decides dry-run never sees it.

## F2 A lone surrogate in `params` is mapped to `INVALID_INPUT` carrying the raw Python codec error — `InvalidInput` is **not** the only error so mapped, and an internal message leaks — Impact 2 (a mislabeled error whose message leaks an internal codec detail incl. the character position; visible to the client, no I/O, recoverable) x Likelihood 2 (adversary-reading? **yes** — `params` is an LLM-supplied argument and a lone surrogate survives the JSON boundary (json.loads decodes a surrogate escape into it); reachable by anyone who wants it, but of no benefit to them) = 4 Minor
Test: tests/breaker/r2/write_gate_central/test_invalid_input_label_and_leak.py::test_surrogate_param_not_mislabeled_and_no_leak_inner
Test: tests/breaker/r2/write_gate_central/test_invalid_input_label_and_leak.py::test_surrogate_param_via_real_mcp_boundary
What happens: `catalog.validate_params` sizes strings with obj.encode("utf-8"). A lone
UTF-16 surrogate (chr(0xD800)) makes .encode raise `UnicodeEncodeError` — a `ValueError`
that is **not** an `InvalidInput`. The per-tool `except ValueError` in `tools/raw.py`
(`nvr_raw_call` and, via `build_body`, `nvr_call`) catches it and returns
{code:"INVALID_INPUT", message:"'utf-8' codec can't encode character ... in position 0:
surrogates not allowed"}. The fixer hardened the shared `run_tool` (`DeviceError` by kind,
else `INTERNAL_ERROR` with no internals) to make this guarantee true, but the older
tool-level `except ValueError` sites were left in place and defeat it: a non-`InvalidInput`
error reaches `INVALID_INPUT` and the internal codec message (contradicting Master-Plan
§1.8 / security "error messages don't leak internals") reaches the client. Confirmed both
via the inner function and through the registered `nvr_raw_call` tool (`mcp.call_tool`);
0 device requests either way.
Why (root cause hypothesis): dry-run/validation centralisation was partial — `run_tool`
now distinguishes `InvalidInput` from other `ValueError`s, but `tools/raw.py` still has
its own except-ValueError -> INVALID_INPUT that cannot tell client input from an internal
`UnicodeEncodeError`.

## Round-1-on-round-1 signal
F2 sits directly on the fixer's seam: `run_tool` was hardened to make "`InvalidInput`
is the only error mapped to `INVALID_INPUT`" true, but the pre-existing per-tool
except-ValueError blocks in `tools/raw.py` were not brought into that scheme, so the
guarantee leaks around them. F1 sits on code the fixer did **not** touch (backup's `do`
predates the GuardedWriter) and shows the centralisation is not yet total. Both are Minor;
the round-1 Criticals/Majors are fixed, so round 2 converges.
