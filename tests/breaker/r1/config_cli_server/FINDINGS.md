# Breaker round 1 — vector config-cli-server — vigi-nvr-mcp @ db9f786
Model: claude-opus-4-8
Claim attacked: "In `vigi-nvr-mcp`, settings fail fast and loudly on any invalid
value (host with whitespace/scheme/path, port 0/65536/`'443 '`, non-finite or
non-positive timeout, unknown transport, `MAX_LOGIN_FAILURES` outside 1-5); the
MCP server binds `127.0.0.1` unless explicitly configured and streamable-HTTP
never defaults to `0.0.0.0`; every registered tool returns a `{success,data,error}`
envelope and never raises into the MCP framework, including on unexpected device
responses and transport errors and cancelled tasks; `nvr_status` and
`--list-tools` perform zero device I/O; `--check-auth` without `--login` never
sends a login; CLI exit codes distinguish config error / auth failure / lockout /
success; the stdio server survives a tool raising and keeps serving."

Axes with no finding (verified, produced nothing):
- empty-string vs unset: an empty `VIGI_NVR_*` value is passed to pydantic and
  rejected (port/host/bool all fail loudly); unset falls back to default. Correct.
- hex/octal ports (`0x1BB`, `0o777`), `1e3`, internal-space ints (`4 43`):
  all rejected. Correct.
- IPv6 host (bare `2001:db8::1` accepted and bracketed in base_url; bracketed
  input rejected), `localhost` (accepted - intended): correct.
- `VERIFY_TLS` `False`/`false`/`0`: parse to False; whitespace-padded bools
  (`"FALSE "`, `" true"`) are correctly rejected (bool coercion, unlike int,
  does not strip) - so booleans honour "fail loudly", numerics do not (see F1).
- unknown transport (`sse`), port 0/65536/-1, MAX_LOGIN_FAILURES 0/6,
  non-finite/non-positive timeout (`nan`/`inf`/`-inf`/`0`): all rejected.
- `.env` precedence: `load_dotenv(..., override=False)` - real env wins. Correct.
- bind default: `mcp_host` defaults `127.0.0.1`; `_validate_bind` requires an IP
  literal; streamable-http with `VIGI_MCP_HOST` unset binds loopback, never
  `0.0.0.0` (0.0.0.0 only on explicit config, and is warned). Claim holds.
- `--list-tools` device I/O: builds the backend with placeholder host
  `192.0.2.1`, makes no network call and no DNS lookup (httpx resolves lazily).
  Holds. (Minor: the throwaway `httpx.AsyncClient` it builds is never `aclose`d -
  a ResourceWarning in a process that exits immediately; impact ~0, not scored.)
- tool robustness to crafted device responses (HTML, `{}`, `[]`, `"string"`,
  `error_code` as `"0"`, 200-non-object, >8 MB, deep nesting, `ReadTimeout`): every
  path funnels through the transport into `TransportError`/`ApiError` (both
  `DeviceError`) and `run_tool` returns an envelope; `error.details` carries only
  generic messages, never the raw body. Claim holds for all run_tool-wrapped tools.
  (The one tool NOT wrapped is `nvr_status` - see F4.)
- `--check-auth` without `--login`: only the pre-auth challenge is fetched;
  `fake.login_attempts == 0`. Holds.
- `--login` via env / server built twice / call after close: no env path sets
  `--login`; `build_server` is a pure factory (independent instances); a call after
  `aclose()` surfaces as an `INTERNAL_ERROR` envelope via `run_tool`. No finding.

Out-of-scope observations (belong to other vectors; recorded, not scored here):
- The login breaker is an in-memory per-process ledger (`core/breaker.py
  LoginLedger`); master-plan sec 1.3/3 require a persistent breaker file under
  `<PREFIX>_STATE_DIR` plus a `breaker --show|--clear` CLI. Neither exists, and
  there is no `state_dir` setting. (auth-lockout vector.)
- `backup_dir` accepts relative paths and does not expand `~` (stored literally).
  (backup vector.)

---

## F1 Numeric settings silently accept whitespace/underscore/float strings (incl. the claim's own `PORT='443 '`) - Impact 1 (coerced to the intended value; owner is not misled and connects to the right port) x Likelihood 4 (a trailing space in a systemd EnvironmentFile/.env line is a trivially common edit; adversary-reading: no) = 4 Minor
Test: tests/breaker/r1/config_cli_server/test_config_numeric_whitespace.py::test_port_rejects_malformed_but_coercible_strings (and the mcp_port/timeout/max_login_failures variants)
What happens: `VIGI_NVR_PORT='443 '` (the exact value the claim says must fail)
loads as `port=443`. So do `' 443'`, `'+443'`, `'4_4_3'` (PEP-515 underscores ->
443) and `'443.0'` (integral float -> 443). The same whitespace laxness applies to
`TIMEOUT_SECONDS` and `MAX_LOGIN_FAILURES`. Pydantic's lax int/float coercion
strips/normalises these; the "fail fast and loudly on any invalid value" guarantee
does not hold for numeric fields (it does for booleans - see axes above). Harmless
in effect, but it disproves the claim as written.
Why (root cause hypothesis): numeric fields rely on pydantic's default lax string
coercion with no pre-strip/`strict` guard, so whitespace- and underscore-padded
and float-form strings normalise instead of raising.

## F2 CLI exit code cannot distinguish auth failure from lockout (both exit 1) - Impact 2 (a visible failure he can read in the JSON envelope, but a shell script branching on `$?` cannot tell "wrong password -> stop" from "login frozen/breaker -> clear it") x Likelihood 2 (only when `--check-auth --login` is scripted and branches on the exit code; adversary-reading: no) = 4 Minor
Test: tests/breaker/r1/config_cli_server/test_cli_exit_codes.py::test_auth_failure_and_lockout_have_distinct_exit_codes
What happens: `cli.main` runs `--check-auth` as
`emit_envelope(asyncio.run(run_check_auth(...)))`, and `emit_envelope` returns
`0` on success else `1`. A device auth rejection yields `AUTH_FAILED` and a local
lockout refusal (`VIGI_NVR_LOGIN_DISABLED=true`, or the device reporting 0
attempts remaining) yields `LOGIN_REFUSED` - both map to exit code `1`. The
claim says exit codes distinguish config error / auth failure / lockout / success;
config error (`2`) and success (`0`) are distinct, but auth failure and lockout are
not.
Why (root cause hypothesis): `emit_envelope` collapses every `success=False`
envelope to the single exit code 1, so the four claimed outcomes map onto only
three codes.

## F3 `nvr_status` performs device I/O on every call - Impact 1 (by design: the healthcheck's job is reachability, so nothing is lost or misreported) x Likelihood 4 (every `nvr_status` call; adversary-reading: no) = 4 Minor (recommend rewording the claim)
Test: tests/breaker/r1/config_cli_server/test_status_io_and_envelope.py::test_status_performs_zero_device_io
What happens: `nvr_status` -> `backend.healthcheck()` -> `_challenge_report()` ->
`auth.get_challenge()` sends a pre-auth `POST /` to the device. After one
`nvr_status` call, `fake.requests` contains that POST, so the claim "`nvr_status`
... perform[s] zero device I/O" is false. (It does correctly avoid a login:
`fake.login_attempts == 0`.) This is intended behaviour per master-plan sec 3
("status = reachability, offered auth scheme, lockout counters"); the finding is a
claim-accuracy one, not a code defect.
Why (root cause hypothesis): the claim conflates "no login" with "no I/O";
`nvr_status` is a reachability healthcheck and must reach the device.

## F4 `nvr_status` is the only tool not wrapped by `run_tool`; a non-`DeviceError` raises into the MCP framework instead of an envelope - Impact 2 (the `nvr_status` call errors out as a FastMCP `ToolError` the client sees; the stdio server itself keeps serving) x Likelihood 1 (reproduced only with a non-`DeviceError` below `healthcheck`; in production httpx wraps transport faults into `TransportError`=`DeviceError`, which healthcheck catches - a test-reachable state; adversary-reading: no) = 2 Won't-fix (but a cheap one-line wrap would honour the claim)
Test: tests/breaker/r1/config_cli_server/test_status_io_and_envelope.py::test_status_returns_envelope_on_non_device_error (contrast: ::test_other_tools_return_envelope_on_non_device_error passes)
What happens: `server._status` calls `backend.healthcheck()` directly;
`healthcheck` only catches `DeviceError`. With a transport that raises
`RuntimeError`, `nvr_status` raises `ToolError` into the framework, while the same
fault through any `run_tool`-wrapped tool (e.g. `nvr_get_device_info`) returns a
clean `{"success": false, "error": {"code": "INTERNAL_ERROR"}}` envelope. The
claim "every registered tool ... never raises into the MCP framework" has exactly
one hole, and it is the healthcheck tool.
Why (root cause hypothesis): `_status` bypasses the shared `run_tool`
`except Exception` safety net that every other tool uses.

## F5 `run_tool` re-raises `asyncio.CancelledError` (and other `BaseException`) - Impact 1 x Likelihood 1 = 1 Won't-fix (the test documents the correct expectation)
Test: tests/breaker/r1/config_cli_server/test_cancelled_task_envelope.py::test_run_tool_returns_envelope_on_cancelled_task
What happens: `run_tool` catches `Exception`; `CancelledError`/`KeyboardInterrupt`
are `BaseException`, so a cancelled tool task propagates rather than becoming an
envelope - disproving the claim's "...including on ... cancelled tasks". This is the
Won't-fix case where the test is kept as documentation: re-raising
`CancelledError` is the correct cooperative-cancellation behaviour; the claim is
over-broad, not the code. Scores: Impact 1, Likelihood 1.
Why (root cause hypothesis): the claim lists cancellation as something to swallow;
swallowing `CancelledError` would itself be a bug.

## F6 Unknown/misspelled `VIGI_NVR_*` variables are silently ignored (not "failed loudly") - Impact 2 (a typo'd `VIGI_NVR_VERIFY_TLS` leaves verification off with no warning; most typos fail toward the safe default) x Likelihood 2 (env-var typos happen; adversary-reading: no) = 4 Minor
Test: tests/breaker/r1/config_cli_server/test_tls_authentication_gap.py::test_unknown_prefixed_var_is_rejected
What happens: `load_device_settings` pre-filters the environment to the known
suffix set before handing it to pydantic, so the model's `extra="forbid"` never
sees an unknown key. `VIGI_NVR_VERIFYTLS=true` / `VIGI_NVR_ALLOW_WRITE=true`
(misspellings) load without error and take the defaults. "Fail fast and loudly on
any invalid value" does not cover unsupported/misspelled variable names.
Why (root cause hypothesis): the known-suffix filter in `load_device_settings`
defeats `extra="forbid"`, which can only reject unknown keys it is shown.

## F7 No supported configuration authenticates the NVR's TLS certificate (verify_tls defaults off, `TLS_FINGERPRINT_SHA256` silently ignored) - Impact 4 (the login carries the admin password, encrypted only with a public key fetched over the same unauthenticated TLS channel, so a LAN on-path attacker can substitute the key and capture the credential) x Likelihood 2 (requires an active on-path attacker on the MCP<->NVR LAN segment; no evidence one is present, but ARP-spoofing from a compromised LAN/IoT host is an attacker goal and thus reachable - adversary-reading: yes) = 8 Major (proposed; see note)
Test: tests/breaker/r1/config_cli_server/test_tls_authentication_gap.py::test_device_certificate_can_be_authenticated and ::test_bogus_tls_fingerprint_is_rejected
What happens: `DeviceSettings` has no `tls_fingerprint_sha256` field and the
transport does no pinning; `verify_tls` defaults to `False`, and with a self-signed
device cert `verify_tls=True` fails the handshake. So there is no configuration in
which the NVR's certificate is authenticated. An owner who sets
`VIGI_NVR_TLS_FINGERPRINT_SHA256` (even a syntactically bogus one) gets no error
and no pinning - the variable is dropped (see F6). This contradicts both the "fail
loudly on any invalid value" clause (a garbage fingerprint is silently accepted)
and master-plan sec 3 ("verify_tls or SHA-256 fingerprint pinning").
Why (root cause hypothesis): the fingerprint-pinning half of the master-plan sec 3
transport/config contract was not built; `verify_tls=False` is the only reachable
state, leaving the channel unauthenticated.
Note for the orchestrator: F7 straddles the transport/crypto vector; ownership and
final severity are the orchestrator's call. The witnessing tests here prove the
config gap (silent accept + no pinning field); the credential-interception impact
is standard TLS/MITM reasoning, not demonstrated against a live socket.

Convergence: no Critical. One Major proposed (F7, cross-vector); the rest are
Minor/Won't-fix. The central envelope/bind/check-auth guarantees largely hold; the
claim is disproven on specifics (F1 port `'443 '`, F2 exit codes, F3 nvr_status
I/O, F4 nvr_status raising, F5 cancellation) and on the TLS gap (F7).
