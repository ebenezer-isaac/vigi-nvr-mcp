# vigi-nvr-mcp

An [MCP](https://modelcontextprotocol.io) server for one TP-Link VIGI NVR on
your own network. It uses the NVR's local JSON API directly: no cloud and no
browser. Reads come first. Writes need two separate opt-ins, and login is
built to avoid tripping the NVR's account lockout.

**Tested on:** VIGI NVR1016H(UN), firmware 1.1.3. Other models and firmware
may differ, especially in auth. Verify yours first (see below).

> [!WARNING]
> **Account lockout.** VIGI NVRs lock the `admin` account after about 10 failed
> logins. While locked you cannot reach the NVR, including its recordings. The
> login circuit breaker is built around that risk:
> - A failed login is **never retried automatically**.
> - By default, **one** failed login per process stops all further logins until
>   restart (`VIGI_NVR_MAX_LOGIN_FAILURES`, 1-5).
> - Every failure reports the NVR's own counters: `attempts_left`,
>   `max_attempts`, and `lock_seconds_left` while locked.
> - If the NVR reports 0 attempts left, no login is sent. Automatic logins also
>   stop when fewer than 3 are left.
> - `VIGI_NVR_LOGIN_DISABLED=true` freezes authentication before any network I/O.
>
> Confirm the password with `--check-auth` before pointing an agent at the server.

## Auth scheme

The scheme below is verified against firmware 1.1.3 by running the vendor web
UI's own JavaScript on test vectors (`tests/fixtures/auth_vectors.json`):

- challenge: `POST /` `{"method":"do","user_management":{"get_encrypt_info":null}}`
- password: `MD5("TPCQ75NF2Y:" + password)` in upper-case hex, then `":" + nonce`,
  RSA PKCS#1 v1.5 under the challenge key, then base64 (`encrypt_type` 2). If
  the NVR offers only `encrypt_type` 1, the bare MD5 is sent instead.
- every JSON string value is URL-encoded on the wire (both directions).

Auth schemes vary between firmware versions; some TP-Link firmware uses
SHA-256-based schemes instead.

## Verifying the auth flow on your firmware

```sh
vigi-nvr-mcp --check-auth           # challenge only: NO login
vigi-nvr-mcp --check-auth --login   # plus exactly ONE login attempt
```

The first form prints the offered `encrypt_type`s, the challenge `code`, and
any lockout counters. The second makes one attempt and reports either success
or the error code with the counters. The session token is never printed.

`tools/capture-login/` is an optional, isolated, one-time dev utility. It uses
Node and puppeteer-core to record the envelopes the vendor web UI itself
sends, with one login, on a device you own. It is not part of the server. See
its README.

## Install

```sh
python -m venv .venv && . .venv/bin/activate
pip install .            # or: pip install -e '.[dev]'
```

Python 3.11+. Runtime dependencies: `mcp` (1.x, FastMCP), `httpx`,
`cryptography`, `pydantic`, `python-dotenv`.

## Configuration

Configuration comes only from environment variables (a `.env` in the working
directory is loaded if present). Start from `.env.example`. Never commit `.env`.

| Variable | Default | Notes |
|---|---|---|
| `VIGI_NVR_HOST` | (required) | Hostname or IP |
| `VIGI_NVR_PORT` | `443` | |
| `VIGI_NVR_USERNAME` | `admin` | |
| `VIGI_NVR_PASSWORD` | (required) | |
| `VIGI_NVR_VERIFY_TLS` | `false` | NVRs use self-signed certificates |
| `VIGI_NVR_TIMEOUT_SECONDS` | `10` | 1-120 |
| `VIGI_NVR_ALLOW_WRITES` | `false` | First write key |
| `VIGI_NVR_DRY_RUN` | `false` | Writes return the exact request without sending it |
| `VIGI_NVR_LOGIN_DISABLED` | `false` | Freeze authentication |
| `VIGI_NVR_MAX_LOGIN_FAILURES` | `1` | Per-process failure budget, 1-5 |
| `VIGI_NVR_BACKUP_DIR` | `backups` | Where `nvr_backup_config` writes (mode 0600) |
| `VIGI_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `VIGI_MCP_HOST` | `127.0.0.1` | IP literal to bind for HTTP |
| `VIGI_MCP_PORT` | `8765` | |
| `VIGI_MCP_LOG_LEVEL` | `INFO` | Logs go to stderr |

Everything is validated at startup. A bad host, an out-of-range or NaN port,
and similar errors stop the server with a message that names the variable but
never its value.

## Running

**stdio** (Claude Desktop / Claude Code):

```json
{
  "mcpServers": {
    "vigi-nvr": {
      "command": "/path/to/.venv/bin/vigi-nvr-mcp",
      "env": { "VIGI_NVR_HOST": "<nvr-host>", "VIGI_NVR_PASSWORD": "<password>" }
    }
  }
}
```

**streamable-http**:

```sh
VIGI_MCP_TRANSPORT=streamable-http vigi-nvr-mcp   # http://127.0.0.1:8765/mcp
```

The server has **no authentication of its own**. Keep it on loopback and reach
it over Tailscale or an SSH tunnel; never bind it to the LAN. A hardened
systemd example is in `deploy/vigi-nvr-mcp.service.example`.

`vigi-nvr-mcp --list-tools` prints the tool names without touching any device.

## Tools

Every tool returns `{"success": bool, "data": ..., "error": {code, message, details} | null}`.
Fields named `ciphertext`, `key`, `stok`, `passwd`, `pwd`, `token`, `secret` or
`password*` are always redacted. No tool can return camera credentials.

| Tool | Kind | Description |
|---|---|---|
| `nvr_status` | read | Healthcheck: reachability, auth scheme, lockout counters, session state, safety policy. Never logs in |
| `nvr_auth_status` | local | Session state and last failure counters. No I/O |
| `nvr_login` | auth | Explicit single login attempt |
| `nvr_get_device_info`, `nvr_get_module_spec`, `nvr_get_system_info`, `nvr_get_network_info`, `nvr_get_video_resolutions` | read | Device information |
| `nvr_list_disks`, `nvr_get_recording_status` | read | Storage (raw reply) |
| `nvr_list_channels`, `nvr_get_channel` | read | Bound cameras (`chm` `added_dev`) |
| `nvr_find_duplicate_channels` | read | Groups channels by device `uuid`; flags offline/disconnected rows as stale |
| `nvr_backup_config` | read | Downloads the config backup (`system` `download_conf`). Not write-gated, so run it before any cleanup |
| `nvr_remove_channel` | **write** | Unbinds a channel (`chm_del_dev`) |
| `nvr_move_channel` | **write** | Moves a binding to an **empty** slot (`chm_mod_dev_chn`), keeping its settings |
| `nvr_call` | read/**write** | Raw `{"method", module: params}`; `login` and `user_management` always refused |

### Write gating

Any non-`get` method requires **both** `VIGI_NVR_ALLOW_WRITES=true` on the
server and `confirm_write: true` on the call (the literal boolean). Channel
writes add three more checks:

- `expected_uuid` must match the live row, which is re-read just before writing.
- Move refuses an occupied target, because the firmware would silently replace it.
- Guarded writes are serialised, so two of them cannot interleave.

`VIGI_NVR_DRY_RUN=true` returns the exact request instead of sending it.
Results include redacted before/after rows.

## Security notes

- The release gate (`scripts/gate.py`) runs `scripts/check_no_secrets.py`.
  It fails on private IPv4 ranges, MAC addresses, 32-hex tokens, `stok`
  values, `ciphertext` values and `password=` assignments, and on any
  committed `.env`, `captures/` or `backups/` path.
- Bodies are never logged. Session tokens are masked in every log line,
  including httpx's own.
- Config backups and capture outputs can hold credentials or live tokens. Both
  directories are git-ignored and written with mode 0600.
- Read-helper sections come from static extraction of the 1.1.3 web client.
  The channel and backup primitives are verified. `nvr_call` covers anything
  else.

## Development

```sh
pip install -e '.[dev]'
python scripts/gate.py   # ruff, pytest + coverage (core >= 90%, package >= 80%),
                         # secret scan, stub scan, --list-tools; prints PASS/FAIL
```

All tests run against mocks; nothing touches a device. `vigi_nvr_mcp/core/` is
a self-contained, device-agnostic template that sibling projects copy
verbatim (see `vigi_nvr_mcp/core/README.md`).

## Prior art

- [gunwookim0221/tp-link-vigi-sdk](https://github.com/gunwookim0221/tp-link-vigi-sdk) (MIT)
- [sgrajaragul/TP-Link-VIGI-Camera-Automation](https://github.com/sgrajaragul/TP-Link-VIGI-Camera-Automation) (MIT)

Not affiliated with or endorsed by TP-Link. "TP-Link" and "VIGI" are
trademarks of their owner.

## License

MIT. See `LICENSE`.
