# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-03

First public release: a complete, read-first, lockout-aware MCP server for a
single TP-Link VIGI NVR, verified against VIGI NVR1016H(UN) firmware 1.1.3 Build
260727. Built and hardened over several phases, each reviewed by an adversarial
"breaker" pass before merge.

### Added

- **Auth and transport.** Browser-free login against the NVR's local JSON API:
  RSA-PKCS1v15(MD5) for `encrypt_type` 2 with a bare-MD5 fallback for
  `encrypt_type` 1, verified byte-for-byte against the vendor web UI's own
  vectors. Self-signed TLS by default, with optional SHA-256 certificate pinning
  (trust-on-first-use, enforced on the server's own connection, fail-closed).
- **Lockout breaker.** A persistent, per-host login breaker that never
  auto-retries, trips after a configurable failure budget (default 1), and
  survives restarts so a crash-loop cannot drain the device's login budget.
  `--check-auth [--login]` verifies the scheme without risking the counter;
  `breaker --show|--clear` inspects and resets it.
- **Catalog gateway.** `nvr_call` / `nvr_raw_call` reach all 586 documented
  calls across 61 modules through one validated, write-gated, redacting entry
  point, with `nvr_list_modules` / `nvr_list_calls` / `nvr_describe_call` for
  discovery.
- **Typed read tools** for device, system, network, users, storage, disks,
  recording status, video/image/detection config, firewall, cloud status and
  time.
- **Channel management.** List and inspect bound cameras, group duplicates by
  device UUID, flag stale "ghost" channels, and remove/move bindings behind
  double write-gates with per-write UUID checks; `nvr_plan_channel_cleanup`
  produces an ordered, resumable plan.
- **Media / RTSP export.** Enable ONVIF/RTSP, build redacted stream URLs, export
  replay windows to mp4 (lossless `-c copy` or re-encode to a size target),
  capture snapshots, and manage a retention-aware export directory (also exposed
  as `exports://` MCP resources).
- **Investigation primitives.** Merged motion/activity windows, time-stamped
  contact sheets, frame sampling, and a documented end-to-end "find the footage
  and send it" recipe for a vision-capable agent.
- **Safety by construction.** Uniform `{success, data, error}` envelopes;
  rule-based recursive redaction of all credential-bearing fields; writes gated
  by both an env switch and a typed `confirm_write` boolean; a shared dry-run
  executor; distinct CLI exit codes (0–4); systemd deploy example and install
  guide; a release gate (`scripts/gate.py`) and a secret scanner
  (`scripts/check_no_secrets.py`).

### Hardened (breaker rounds and the core refactor)

- Adversarial review rounds tightened the catalog (shape-aware wire bodies, an
  integrity hash over the vendored catalog, Unicode screening, a single error
  mapper), the write path (all writes routed through one guarded writer so
  dry-run and serialisation cannot be bypassed), and config loading (unknown
  env keys for either prefix now fail loudly).
- Two breaker rounds on the login breaker did not converge at the reported
  level, so the breaker was rebuilt from its root cause into a single
  **locked, schema-validated, atomically-written** ledger: admit-and-reserve is
  one step under a cross-process lock, the identity is a canonicalised device
  key, the ledger is strict-pydantic (so `false` can never coerce to `0`), and
  every store failure fails closed. A `core/VERSION` manifest plus an identity
  test keep the device-agnostic `core/` template byte-identical across the
  sibling projects that copy it. See
  [docs/specs/05-ROOT-CAUSE-breaker.md](docs/specs/05-ROOT-CAUSE-breaker.md).

### Not yet verified

- Several response shapes (`nvr_list_recording_segments`,
  `nvr_search_recordings`, `nvr_list_events`, and the `nvr_list_motion_windows`
  merge inputs) are `INFERRED` from the 1.1.3 web client and await a first live
  run; they degrade to a `PROTOCOL_ERROR` envelope rather than crashing.

[0.1.0]: https://github.com/ebenezer-isaac/vigi-nvr-mcp/releases/tag/v0.1.0
