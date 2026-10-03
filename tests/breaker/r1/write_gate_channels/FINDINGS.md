# Breaker round 1 — vector write-gate-channels — vigi-nvr-mcp @ db9f7866d6fa2a9e04b031d3baca17e5bd2d7582
Model: claude-opus-4-8
Claim attacked: In `vigi-nvr-mcp`, no mutating request (any `method` other than
`get`, or any catalog call marked `mutates`) can leave the process unless BOTH
`VIGI_NVR_ALLOW_WRITES=true` AND `confirm_write=True`; with `VIGI_NVR_DRY_RUN=true`
nothing is sent and the exact body is returned; `nvr_remove_channel` and
`nvr_move_channel` cannot act on a row whose live `uuid` differs from
`expected_uuid`, cannot remove an `online=="1"` row without `force`, cannot move
onto an occupied `new_id`, always re-read `added_dev` immediately before writing,
and return before/after rows; guarded writes serialise so a read-check-write
cannot interleave with another; `nvr_call`/`nvr_raw_call` refuse the `login` and
`user_management` modules; `nvr_backup_config` writes only inside
`VIGI_NVR_BACKUP_DIR` with mode 0600.

Axes with no finding (verified to hold, or not reachable):
- confirm_write fail-open ("false"/"0"/1/None/"yes"): the gate tests
  `confirm_write is not True`; strings/ints/None are refused (fail-closed) at the
  function level, and pydantic at the FastMCP boundary coerces only genuine bools.
- ALLOW_WRITES env coercion (True/yes/"1 "): a pydantic bool; unparseable values
  fail fast at startup (ConfigError), never fail open.
- method case (GET/Get/" get"): validate_call rejects anything outside
  {get,set,do,add,delete} -> INVALID_INPUT before the gate.
- module refusal bypass (Login/LOGIN/"login "): module.lower() handles case;
  MODULE_RE rejects trailing space -> INVALID_INPUT. Refused either way.
- uuid compare (case/whitespace, empty/None): strict !=; expected is stripped,
  live uuid is not, so a padded live value cannot falsely match (fail-closed);
  empty/None expected_uuid rejected by validate_uuid.
- move onto occupied slot (occupant online=="0"): any occupant -> refused
  (TARGET_OCCUPIED), independent of its status. Holds.
- move old_id == new_id: rejected INVALID_INPUT.
- re-read before write: both tools re-list added_dev inside the action,
  immediately before the write. Holds.
- serialise / TOCTOU: the backend builds exactly one ToolContext, so one
  SerialLock is shared across remove/move/raw; the whole read-check-write runs
  under it, so two guarded writes cannot interleave. Holds.
- partial multi-id apply: nvr_remove_channel only ever deletes a single id; no
  multi-id path is exposed. N/A.
- before/after redaction: _public applies redact, and the occupant in the
  TARGET_OCCUPIED error context is redacted too. Holds.
- token expiry mid-write replay: client.call re-logs in once and resends on
  TokenExpired; that code is raised only on -40401/-40403 (call NOT processed),
  so the single resend is safe — no evidence of double-apply.
- backup path traversal / symlink: backup_dir is operator config, the filename is
  generated, and the download URL's ".." / "//" / "\\" are rejected in
  get_session_file. No bypass.
- catalog `mutates` clause: this build ships no catalog gateway (catalog.py is
  only the error-code table); nvr_call gates on method alone. The claim's
  "catalog call marked mutates" sub-clause is not implemented here — noted, but
  not independently exploitable without a catalog.
- nvr_call method `get` with a write-shaped body: passes the gate and is sent
  ungated, but by the claim's own definition (method != get) this is not
  "mutating", and there is no device evidence the NVR acts on a get-bodied write.
  Likelihood 1; documented, not scored against the claim.
- backup mode on Windows: 0o600 is not meaningfully enforced on Windows, but the
  deploy target is Ubuntu systemd. Likelihood 1 (Won't-fix).

## F1 Live (online=="1") channel is removable with no `force` guard — Impact 4 (test: the live camera row is deleted and the tool returns success:True, removed:True) x Likelihood 3 (adversary-reading? yes — the channel id and uuid are LLM-supplied during the exact cleanup workflow this phase exists for, and in the owner's real topology live cams share uuids with the ghosts being deleted) = 12 Critical
Test: tests/breaker/r1/write_gate_channels/test_remove_online_guard.py::test_remove_online_row_refused_without_force
Also: tests/breaker/r1/write_gate_channels/test_remove_online_guard.py::test_remove_channel_exposes_a_force_override
What happens: nvr_remove_channel has no `force` parameter and performs no check on
the row's `online` field. With VIGI_NVR_ALLOW_WRITES=true and confirm_write=True,
calling remove_channel(ctx, "9", "uuid-live", confirm_write=True) on a row with
online=="1", conn_status=="0" succeeds: it sends
{"method":"do","chm":{"chm_del_dev":{"ids":["9"]}}}, unbinds the live camera, and
returns {removed: True}. The spec (N4) and the claim both state an online row must
be refused unless force=True; that guard is entirely absent. The only protection
left for a live row is the two write gates plus the uuid match — and the uuid of
the live row matches by definition, so nothing stops it.
Why (root cause hypothesis): the online/force guard specified in N4 was never
implemented in remove_channel; the tool signature omits force and action() goes
straight from the uuid check to delete_channels.

## F2 nvr_call ignores VIGI_NVR_DRY_RUN; a mutating raw request (incl. a channel delete) is transmitted under dry-run — Impact 4 (test: a set/do body reaches the device despite DRY_RUN=true) x Likelihood 3 (adversary-reading? yes for confirm_write; the per-master-plan §5 pre-LIVE ritual previews raw bodies with DRY_RUN=true while the deployed server already has ALLOW_WRITES=true) = 12 Critical
Test: tests/breaker/r1/write_gate_channels/test_raw_call_dry_run.py::test_nvr_call_write_honours_dry_run
Also: tests/breaker/r1/write_gate_channels/test_raw_call_dry_run.py::test_nvr_call_destructive_do_honours_dry_run
What happens: tools/raw.py::nvr_call has no dry-run branch. With both write gates
open it runs ctx.writes.run(lambda: ctx.client.call(method, module, params))
unconditionally. Under make_ctx(ALLOW_WRITES="true", DRY_RUN="true"),
nvr_call(ctx, "set", "system", {"x":1}, confirm_write=True) is sent to the device
(fake.writes is non-empty) and the result carries no data.dry_run. Routing a
channel delete through the same gateway (do chm {"chm_del_dev":{"ids":["9"]}})
also fires for real. The typed channel tools honour dry-run; the escape hatch that
can send any module/method does not, so the claim "with VIGI_NVR_DRY_RUN=true
nothing is sent" is false for the raw gateway. Master-plan §5 and N2 both require
every write tool to support dry-run.
Why (root cause hypothesis): dry-run is implemented per-tool inside the channel
functions rather than centrally in the write gate / client.call, and nvr_call was
never given the branch.

## F3 nvr_backup_config saves non-config content (e.g. an HTML login page) as "the backup" — Impact 4 (test: an HTML login page is written to disk and reported as a successful backup, making the pre-cleanup safety net hollow) x Likelihood 1 (adversary-reading? no — reproducible only with this mock; no device evidence a valid session file GET returns HTML) = 4 Minor
Test: tests/breaker/r1/write_gate_channels/test_backup_content.py::test_backup_rejects_html_login_page
What happens: backup_config saves any non-empty bytes from download_session_file
under nvr-config-*.bin and returns success:True; the only check is `if not data`.
If the session file GET returns an HTML login/redirect page (200), that page is
persisted and reported as a valid backup. The operator is told "run
nvr_backup_config first" before destructive cleanup, so a bogus backup gives false
confidence. Outside the claim's strict backup text (location + mode, which both
hold) but inside the "backup" attack axis.
Why (root cause hypothesis): no content/magic-byte validation on the downloaded
bytes before writing them as a config backup.
