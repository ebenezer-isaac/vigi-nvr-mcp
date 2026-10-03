# Master Plan — three standalone, browser-free MCP servers for the owner's TP-Link devices

**Decision (owner, 2026-10-03): three standalone repos, not one consolidated server.** Each is a complete MCP server; the device-agnostic `core/` directory is written once in `vigi-nvr-mcp` and **copied verbatim** into the other two (a shared package is extracted later only if it stays identical). Rationale: the three protocols share nothing, standalone repos let agents work with zero collisions, and public users install only the device they own.

| Repo / package / script | Hardware (owner's) | Protocol | Env prefix | Tool prefix | Spec |
|---|---|---|---|---|---|
| `vigi-nvr-mcp` / `vigi_nvr_mcp` / `vigi-nvr-mcp` | VIGI NVR1016H(UN), fw 1.1.3 Build 260727 | JSON-RPC `POST /stok=<t>/ds`, RSA-PKCS1v15(md5) login | `VIGI_NVR_*` | `nvr_` | `01-NVR-SPEC.md` |
| `tplink-easysmart-mcp` / `tplink_easysmart_mcp` / `tplink-easysmart-mcp` | TL-SG1016PE Easy Smart PoE | HTML pages + `*.cgi` form posts, cleartext login | `EASYSMART_*` | `switch_` | `02-SWITCH-SPEC.md` |
| `archer-router-mcp` / `archer_router_mcp` / `archer-router-mcp` | Archer AX53 v1 (AX3000), UI 1.11.0 | `/cgi-bin/luci/;stok=<t>/admin/<mod>?form=<f>`, SG hardened profile | `ARCHER_ROUTER_*` | `router_` | `03-ROUTER-SPEC.md` |

Optional fourth backend, **parked**: a bridge-mode gateway/ONT (out of scope). Low value while it only relays; revisit after the three above. Hygiene item for the owner now: [redacted] — disable telnet in its admin UI if the firmware allows.

The three protocols share **nothing** below the MCP layer. The copied `core/` is scaffolding only: config, envelope, redaction, write-gating, lockout breaker, serialised request queue, transport base, CLI helpers, test harness. **Never** build a "shared stok protocol" abstraction — it is false.

Repos live under `E:/projects-working-dir/`, each MIT, **public**, each with its own `scripts/gate.py`, `scripts/check_no_secrets.py`, `.env.example`, `deploy/<name>.service.example`. Python 3.11+, `mcp` (FastMCP), `httpx`, `cryptography`, `pydantic` v2, `python-dotenv`; dev: `pytest`, `pytest-cov`, `respx`, `ruff`.

## 1. Non-negotiables (apply to every phase of every spec)

1. **Public repo = zero secrets, zero real network data.** No private IPs except RFC 5737 `192.0.2.x` placeholders, no MACs, serials, hostnames, site/camera/person names, no captured responses. `scripts/check_no_secrets.py` is a test and a pre-commit gate.
2. **No browser at runtime.** `tools/capture-login/` (headless Chrome one-shot) is an isolated dev utility with its own `package.json`; never imported, never required.
3. **Lockout safety.** Every backend: never auto-retry a failed login; one explicit login per call path; a persistent **breaker** (file under `<PREFIX>_STATE_DIR`, default `~/.local/state/<repo-name>/`) that blocks further logins after a failure until a human clears it (`<script> breaker --clear`); surface the device's attempt counters in the error; env `<PREFIX>_LOGIN_DISABLED=true` freezes auth.
4. **Writes are gated twice.** `<PREFIX>_ALLOW_WRITES=true` in env **and** `confirm_write=True` on the tool call. Otherwise a mutating tool returns `{success:false, error:{code:"WRITE_NOT_ALLOWED"}}` and performs **no network call**.
5. **Envelope.** Every tool returns `{"success": bool, "data": ..., "error": {"code","message","details"} | null}`. Never raise out of a tool.
6. **Redaction.** Any field named like `ciphertext`, `password*`, `passwd*`, `key`, `stok`, `token`, `nonce`, `cookie` is stripped from tool output recursively (pure function, returns new objects).
7. **Serialised I/O per device.** One in-flight request per backend (asyncio lock). Required for the router's rolling hash, and harmless elsewhere.
8. **Style.** Files 200–400 lines (hard max 800). Immutability (new objects, never mutate inputs). Explicit errors, never swallowed. Pydantic at every boundary (tool inputs, device responses we rely on). Logging never includes request bodies of login calls.
9. **Tests are fault-finding.** Per module: happy path (minimal), edge cases (primary), adversarial (bad/oversized input, injection in strings, unexpected device responses, login page returned instead of data), state machine (expired token mid-batch, breaker tripped, writes disabled), and no `any`-style escapes. Coverage ≥ 80% per backend, ≥ 90% for `core/`.

## 2. The leash — phase contract for agents

Every phase in the three specs is sized to fit one agent context. An agent assigned a phase MUST:

- **Build everything listed under "Deliverables". Nothing may be deferred.** The following are forbidden anywhere under the package directory at the end of a phase: `NotImplementedError`, `TODO`, `FIXME`, `XXX`, `pass  # stub`, bare `...` function bodies, `return None  # later`, tools registered without an implementation, tests marked `skip`/`xfail` without a spec citation. `scripts/gate.py` greps for these and fails.
- **Stop and report instead of stubbing** if the phase cannot be finished (context, missing input, blocked question). The report must say exactly what is missing. A truncated-but-honest phase is acceptable; a "complete" phase with stubs is a failed phase and will be re-run.
- **Touch ≤ 14 files and add ≤ 1,500 LOC per phase.** If the work is bigger, stop and propose the split.
- **Run the gate before every commit**: `python scripts/gate.py` = ruff + pytest (with coverage thresholds) + `check_no_secrets` + stub-grep + `<script> --list-tools` (must succeed and list every tool the spec names for the phases completed so far). Commit only on PASS. Conventional commits (`feat:`/`fix:`/`test:`/`docs:`/`refactor:`/`chore:`), each ending with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- **Never push, never create a remote.** The orchestrator reviews and publishes.
- **Never contact a real device** unless the phase explicitly says "LIVE" and gives the exact command; live phases are run by the orchestrator with the owner present.
- **End with the Phase Report** (verbatim headings): `## Deliverables built` (file list), `## Tools registered` (paste `--list-tools` output), `## Gate output` (tail of `gate.py`), `## Tests` (count, coverage %), `## Deviations` (with reasons), `## Open questions`, `## Commits`.

The orchestrator re-runs `scripts/gate.py` independently after every phase and spot-reads 2–3 files. A phase that fails the gate or has stubs is sent back with the gate output.

## 3. Template core (`<package>/core/`) — built once in NVR phase N1, copied verbatim by S1 and R1

| File | Contents |
|---|---|
| `config.py` | `GlobalSettings` (transport/host/port/state_dir/log level) and `DeviceSettings` base (host, port, username, password, verify_tls, tls_fingerprint_sha256, allow_writes, login_disabled, timeout_s). Loaded from env with prefix. Validation: host non-empty & no whitespace, 1 ≤ port ≤ 65535, timeout finite & > 0. Fails fast at startup with a clear message. |
| `envelope.py` | `ok(data)`, `fail(code, message, details=None)`; `Envelope` pydantic model. |
| `errors.py` | `DeviceError` hierarchy: `AuthFailed(attempts, max_attempts)`, `TokenExpired`, `LockedOut`, `WriteNotAllowed`, `BreakerOpen`, `ProtocolError`, `TransportError`, `ConfigError`. `to_envelope(exc)`. |
| `redact.py` | `redact(obj) -> obj'` recursive; configurable key patterns; tested for nesting, lists, no-mutation. |
| `write_gate.py` | `require_write(settings, confirm_write: bool, action: str)` → raises `WriteNotAllowed` with which gate failed. |
| `breaker.py` | `LoginBreaker(state_dir, device)`: `check()`, `record_failure(details)`, `clear()`; JSON state file; tested for persistence across instances. |
| `serial.py` | `SerialExecutor`: per-device asyncio lock + optional min-interval; `async with executor:`. |
| `transport.py` | `HttpTransport` wrapper over `httpx.AsyncClient`: timeouts, `verify_tls` or SHA-256 fingerprint pinning (custom SSL context), retries **only** for connection errors on idempotent reads (max 2), never for auth. |
| `server.py` (per repo, not in core) | FastMCP app factory; registers `<prefix>status`; stdio or streamable-HTTP bound to `<PREFIX>_MCP_HOST` (default `127.0.0.1`). |
| `cli.py` (per repo) | `serve`, `--list-tools`, `--check-auth [--login]`, `breaker --show|--clear`. |

Tool naming: `nvr_*`, `switch_*`, `router_*`; each server exposes `<prefix>status` as its healthcheck. Every tool: pydantic input model, docstring that an LLM can act on (what it does, whether it mutates, what it refuses), returns `Envelope`.

## 4. Sequencing and dependency graph

```
N1 core+auth ─► N2 catalog gateway ─► N3 typed read tools ─► N4 channels (needs channel-management.md) ─► N5 LIVE verify + ghost cleanup + re-home ─► N6 docs/deploy
                                   └──────────────────────────────────────────────┐
S0 LIVE fixture capture (owner creds) ─► S1 parsers ─► S2 client ─► S3 tools ─► S4 LIVE poe_cycle test
R0 LIVE envelope capture (owner creds) ─► R1 crypto ─► R2 auth+session ─► R3 read tools ─► R4 write tools ─► R5 LIVE reservation test
```
- N1 is done (core exists). S1 and R1 may start immediately by copying `vigi-nvr-mcp/vigi_nvr_mcp/core/`; N2/N3/N4 run in parallel on `vigi-nvr-mcp` in separate git worktrees. Different repos never collide.
- `S0` and `R0` are orchestrator-run live captures that need the owner's switch and router passwords and a window when the owner is logged out of those web UIs. Until then S1/R1 can proceed from the already-downloaded JS/pages only where the spec says so.
- Each phase = one agent run. Maximise parallelism: one agent per phase wherever the graph allows; same-repo phases use `git worktree` branches that the orchestrator merges.

## 5. Verification the orchestrator runs

- After each phase: `python scripts/gate.py`; spot-read; diff review for secrets and for "defensive" `except Exception: pass`.
- Before any LIVE phase: read the exact request bodies the tool will send (dry-run mode `<PREFIX>_DRY_RUN=true` logs the body and does not send — every write tool must support it).
- Before publishing: `git log -p | python scripts/check_no_secrets.py --stdin` over full history; if anything leaks, the repo is re-initialised, not force-pushed.

## 6. Deployment target (private, not in repo)

Three non-root systemd services on the owner's Ubuntu server, each with its own `EnvironmentFile=/etc/<repo-name>.env` (0600), streamable-HTTP on `127.0.0.1` on three ports, reachable only via Tailscale/SSH; three entries in the MCP client config. The switch backend must run there (cleartext login, wired LAN only). Real hostnames/IPs/ports live only in that env file and the owner's private notes.

## 7. Task tracker (owner 2026-10-03: "track each of them as a task in the master spec and see it through to completion")

Status legend: `todo` · `running` · `built` (agent reported) · `verified` (orchestrator re-ran the gate) · `merged` · `converged` (breaker round clean under the rubric) · `live-ok` · `done`. Explicitly **out of scope** (owner): ntfy/notification tooling; ONT backend.

### vigi-nvr-mcp
| ID | Task | Status | Evidence |
|---|---|---|---|
| N1 | core + auth + channel writes | merged | `db9f786`, 370 tests, gate PASS (orchestrator) |
| N2 | catalog gateway (586 calls) | merged | `20cfd27` → main `eb2bdeb`, 519 tests on main |
| N3 | typed read tools | merged | `0fc37c8` |
| N4 | cleanup planner + specs in repo | merged | `eb562e3` |
| NB1 | breaker round 1 (5 vectors) | triaged | 4 Crit / 3 Major → `triage/vigi-nvr-mcp-r1.md` |
| NF1 | fixer round 1 (7 causes) | merged | `8869e68` → main `0295583`, 604 tests, 82 breaker tests green |
| NB2 | breaker round 2 (4 vectors) | triaged | write-gate CONVERGED (2 Minor); catalog 1 Major (wire wrapper); TLS 1 Crit + 1 Major (→ X1 design); breaker 1 Major (→ root-cause) |
| NF2 | fixer round 2: catalog wire shapes, content hash, unicode separators, global strict keys, backup via writer, single error mapper | merged | `75c8da5` → main `ecae627`, 860 tests, 117 breaker tests green |
| NRC | root-cause agent: lockout breaker across all three repos → refactor spec | running | `triage/ROOT-CAUSE-breaker.md` |
| N7 | RTSP media export + snapshots + enable switch | verified | `ea10a81`, 600 tests, 39 tools (dry-run to migrate at merge) |
| N7b | investigation primitives | merged | `51ebd48`; integrated onto fixed main at `5f16a7d` (812 tests, 45 tools, one dry-run impl, one runner) |
| NB3 | breaker round on N7/N7b | todo | |
| N5 | LIVE: one login, read checks, ghost cleanup (1,2,7,8,13,14), re-home 9→1,10→2,11→7,12→8, enable RTSP, snapshot, 2-min export, probe for a local-display module | todo | owner present |
| N6 | docs/deploy polish (README, .env.example, CHANGELOG, SECURITY.md, systemd, install.md) | todo | |
| NP | full-history secret scan → `gh repo create --public` → push | todo | after N6 |
| ND | deploy on the deployment server (systemd, loopback, Tailscale) | todo | |

### archer-router-mcp
| ID | Task | Status | Evidence |
|---|---|---|---|
| R1 | scaffold + clean-room crypto (byte-exact vectors) | verified | `eb83311`, 235 tests |
| RB1 | breaker round 1 (crypto; fresh vendor vectors) | converged | 2 Minor folded into R2 |
| R2 | auth + session + persistent breaker + TLS pin + feature flags | verified | `7c1d54c`, 352 tests; core hardened (persistent breaker, rule redaction, strict env, TLS pin) — source for X1 |
| R3 | reads: status, clients (typed), DHCP leases/reservations, Wi-Fi, port forwards, mesh, WAN, access-control/speed-limit/schedule/IoT reads, presence log + history | merged | `f84175a` → main `c99b9a7`, 421 tests, 18 tools (field shapes INFERRED → R5 confirms) |
| R4 | writes (11 tools), `PROTECTED_MACS` startup enforcement, reboot rate limit, `force_takeover` double gate, INFERRED bodies behind `R0_UNCONFIRMED` | merged | `0d178aa` → main `9c06445`, 517 tests, 29 tools |
| RB2 | breaker round on R2 | triaged | 1 Major (unwritable state dir fails open) → fixed once in X1; round not converged |
| RB3 | breaker round on R4 writes | triaged | 1 Crit (R0 gate on one tool only), 2 Major (replay double-write; limiter decide-then-record → X1b), 1 Minor, 2 Won't-fix |
| RF3 | fixer: structural R0 gate for all INFERRED writes, no-replay + read-back for writes, uniform protected guard, subnet fail-closed | merged | `a9d07d0` → main `3de4a1a`, 535 tests + 2 strict-xfail (limiter → X1b) |
| R0 | LIVE envelope capture (HTTPS skip-encrypt? Wi-Fi write body; `hostname` vs `comment`) | todo | owner: router password, logged out |
| R5 | LIVE: add the EZVIZ wired-MAC reservation, verify, remove | todo | |
| RD/RP | docs polish, publish, deploy | todo | |

### tplink-easysmart-mcp
| ID | Task | Status | Evidence |
|---|---|---|---|
| S1 | scaffold + parsers + forms + login classifier | verified | `e4e8004`, 327 tests (LOC overage accepted: tests) |
| SB1 | breaker round 1 (parsers/forms vs MIT reference) | triaged | 2 Major (substring classifier; unbounded `portNum`), 2 Minor, 1 Won't-fix → fixer SF1 after S2 |
| S2 | client: session, breaker, cooldown, confirm-after-login, logout | merged | `ac0ebbd` → main `82c2c7e`, 414 tests |
| S3 | tools: system/ports/stats/PoE/VLAN reads; `switch_set_poe`, `switch_set_port`, `switch_poe_cycle` (protected ports, port map, one in flight) | merged | `798f841` → main `99103cd`, 469 tests, 13 tools |
| SF1 | fixer: SB1 Majors (structural page classification; cap every declared length) | merged | `0cb8157` → main `07ecf42`, 422 tests, breaker tests green |
| SB2 | breaker round on S2 | triaged | cooldown clock Major → X1 breaker; classifier hazard resolved by SF1 (verified); `RequestPlan` repr Minor → S3 merge pass |
| SB3 | breaker round on S3 (tools + PoE cycle) | triaged | 4 Major (restore guard scope ×2, numeric name shadowing, string confirm) + 2 Minor (marker lock/clock → X1b) |
| SF2 | fixer: cycle restore in `finally` incl. BaseException, type-stable port resolution, strict confirm_write (`core/types.py`) | merged | `0ad16f2` → main `e9a93f7`, 480 tests + 3 strict-xfail (marker → X1b) |
| S0 | LIVE fixture capture (hw/fw, session model, variable names, auto-limit field, VLAN/cable-test pages) | todo | owner: switch creds, camera→port map, uplink port |
| S4 | LIVE: cycle one camera port, confirm it returns | todo | |
| SD/SP | docs polish, publish, deploy (LAN host only) | todo | |

### Cross-cutting
| ID | Task | Status |
|---|---|---|
| X1 | core sync: ONE canonical core (persistent breaker with writability proof, union redaction, strict env, TLS pin, ProtocolError/InvalidInput, GuardedWriter central dry-run, exit codes) copied verbatim into all three repos + identity test | todo (after NB2 + NVR r2 auth-persist report; requirements in triage file) |
| X2 | polish pass per repo: README (purpose, install, env table, tools table, write gating, lockout callout, security notes, prior-art credits), `.env.example`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, repo description + topics, license headers | todo |
| X3 | publish ×3: history scan clean → `gh repo create ebenezer-isaac/<name> --public` → push → verify CI green | todo |
| X4 | deploy ×3 on the deployment server; env files 0600; three MCP entries for the MCP client | todo |
| X5 | **CLIENT-HANDOVER.md** (private): endpoints, tool catalog + semantics, safety rules, recipes (channel cleanup, footage investigation, new-device alert, PoE cycle), estate map (channels, camera→port, addresses), limitations, where credentials live | todo (last) |

### X1 — canonical core refactor (spec = `triage/ROOT-CAUSE-breaker.md` §2–§4 + the "X1 consolidated requirements" in `triage/vigi-nvr-mcp-r1.md`)
Preconditions: NF2 + N7 integration merged on `vigi-nvr-mcp` main; S3 merged on `tplink-easysmart-mcp` main; R4 merged on `archer-router-mcp` main.
| ID | Task | Status |
|---|---|---|
| X1a (**merged** `3cde7b5` → NVR main `1c727b1`; core v1.0.0, 945 tests, conformance 26 pass incl. 8-process lock) | **Canonical core in `vigi-nvr-mcp`** (one agent): `core/state.py` (`AtomicStateFile` + `ReservationStore`: cross-process flock/msvcrt lock on a `.lock` file, writability proven at acquire, strict pydantic schema, atomic replace, 0700/0600); `core/breaker.py` as a thin policy over it (`reserve_attempt()`/`Reservation.release()`, sticky `tripped`, cooldown as ledger state, `canonical_device_key`); `core/transport.py` TLS pin enforced on httpx's OWN connection at `start_tls` via a custom httpcore network backend (no latch; every connection; observed fingerprint from the real connection); `core/redact.py` union rule set; `core/config.py` one strict-env rule for both prefixes; `core/errors.py` with `ProtocolError`/`InvalidInput`/`PreconditionFailed`/`BreakerOpen`/`Cooldown`/`TlsPinMismatch`; `core/serial.py` `GuardedWriter.run(..., require_gate)`; `core/cli.py` exit map 0–4 + `breaker --show|--clear`; `core/VERSION` manifest + `tests/test_core_identity.py`; `tests/conformance/test_breaker_contract.py` (11 cases incl. real multi-process); migrate NVR `auth.py`/`cli.py` call sites per ROOT-CAUSE §3; N7 export serial → `ReservationStore`. | todo |
| X1b (step 1 **merged**: core v1.1.0 → NVR main `a9958fd`, 1029 tests; step 2: switch **merged** `c1af9fd` → main `050d797` (536 tests, core byte-identical, conformance 28 pass, xfails retired); router sync running) | **Sync + call-site migration in router and switch**: copy `core/` + conformance + identity test verbatim; migrate `archer_router_mcp/auth.py`/`server.py`/`cli.py` (reserve around `_post_login` incl. the authorised takeover; `EXCEEDED_MAX_ATTEMPTS` → cooldown), R4 reboot rate-limit → `ReservationStore`; migrate `tplink_easysmart_mcp/switch/auth.py` (delete `LoginCooldown`; errType 3/4/5 → cooldown not failure; 1/2/6 → failure; confirmed 0 → success), S3 `cycle_in_progress` → `Reservation` (one per port), `RequestPlan` repr fix (SC-F3); gates green in both. | todo |
| X1c | Breaker round on the canonical core (conformance + TLS pin + state primitive), ≤ 2 rounds; findings fixed in the canonical copy and re-synced. | todo |
