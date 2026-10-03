# core/ — reusable template

This directory is **self-contained and device-agnostic**. It imports nothing
from the rest of `vigi_nvr_mcp` (a test enforces this), so sibling projects,
such as MCP servers for other local devices, copy it **verbatim** as their
starting point. Keep it that way: device-specific code (protocols, error
tables, tool names, env prefixes) belongs outside `core/`.

| Module | Purpose |
|---|---|
| `config.py` | `DeviceSettings` / `GlobalSettings` from `<PREFIX>*` env vars; fail-fast validation that never echoes values |
| `envelope.py` | `{success, data, error}` response envelope |
| `errors.py` | Exception hierarchy with stable `kind` codes and `details()` |
| `redact.py` | Pure recursive redaction of credential-bearing fields |
| `write_gate.py` | Two-key write gate: `<PREFIX>ALLOW_WRITES=true` + per-call `confirm_write=true` |
| `state.py` | `AtomicStateFile` (strict-schema, 0600, tmp+replace) and `ReservationStore` (cross-process lock, admit-and-reserve, fail-closed) — the one-fact primitive |
| `breaker.py` | Login circuit breaker: a thin policy over `ReservationStore` (atomic admit, sticky trip, cooldown, canonical device key) |
| `serial.py` | `SerialLock` / `GuardedWriter` serialising read-check-write operations and central dry-run |
| `transport.py` | httpx JSON transport: TLS pinning on httpx's own connection (custom httpcore backend), timeouts, size caps, token masking in logs |
| `tooling.py` | `run_tool`: wraps a tool body in an envelope, redacts, never leaks internals |
| `cli.py` | Logging setup (stderr) and envelope printing |

Dependencies: `httpx`, `pydantic` v2. Python 3.11+.

When copying: keep the tests that cover these modules, and change nothing here
that would require knowing which device is on the other end.
