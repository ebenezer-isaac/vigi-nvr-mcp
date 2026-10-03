# tplink-local-mcp — local, browser-free MCP server for TP-Link VIGI NVRs, Archer routers and Easy Smart switches

An [MCP](https://modelcontextprotocol.io) server that talks to TP-Link devices
on your own network over their local JSON APIs. It does not use the cloud or a
browser. Reads come first. Writes need two separate opt-ins, and login is
built to avoid tripping the devices' account lockout.

| Backend | Tools | Status |
|---|---|---|
| VIGI NVR | `nvr_*` | Working. Tested on **VIGI NVR1016H(UN), firmware 1.1.3** |
| Archer router | `router_*` | Scaffold, pending protocol discovery. No tools yet |
| Easy Smart switch | `switch_*` | Scaffold, pending protocol discovery. No tools yet |

A backend is enabled only when its `<PREFIX>HOST` variable is set. Nothing else
is registered.

> [!WARNING]
> **Account lockout.** VIGI NVRs lock the `admin` account after about 10 failed
> logins. While locked you cannot reach the NVR, including its recordings. This
> server is built around that risk:
> - A failed login is **never retried automatically**.
> - By default, **one** failed login per process stops all further logins until
>   restart (`TPLINK_NVR_MAX_LOGIN_FAILURES`, 1-5).
> - Every failure reports the device's own counters: `attempts_left`,
>   `max_attempts`, and `lock_seconds_left` while locked.
> - If the device reports 0 attempts left, no login is sent. Automatic logins
>   also stop when fewer than 3 are left.
> - `TPLINK_NVR_LOGIN_DISABLED=true` freezes authentication before any network I/O.
>
> Confirm the password with `--check-auth` (below) before pointing an agent at
> the server.

## Auth scheme and firmware

The login flow is verified against NVR1016H firmware 1.1.3 by running the
vendor web UI's own JavaScript on test vectors (see
`tests/fixtures/vigi_nvr_auth_vectors.json`):

- challenge: `POST /` `{"method":"do","user_management":{"get_encrypt_info":null}}`
- password: `MD5("TPCQ75NF2Y:" + password)` in upper-case hex, then `":" + nonce`,
  RSA PKCS#1 v1.5 under the challenge key, then base64 (`encrypt_type` 2). If
  the device offers only `encrypt_type` 1, the bare MD5 is sent instead.
- every JSON string value is URL-encoded on the wire (both directions).

**Auth schemes vary between firmware versions.** Some TP-Link firmware uses
SHA-256-based schemes instead. Do not assume yours matches. Verify it first, as
described next.

## Verifying the auth flow on your firmware

```sh
tplink-local-mcp --check-auth --device nvr           # challenge only: NO login
tplink-local-mcp --check-auth --login --device nvr   # plus exactly ONE login attempt
```

The first form prints the offered `encrypt_type`s, the challenge `code`, and
any `time`/`max_time` counters, without logging in. Adding `--login` makes one
attempt and reports either success or the error code with the lockout
counters. The session token is never printed.

`tools/capture-login/` is an optional one-time dev utility. It records the
envelopes the vendor web UI itself sends (Node + puppeteer-core, one login, a
device you own). It is not part of the server. See its README.

## Install

```sh
python -m venv .venv && . .venv/bin/activate
pip install .            # or: pip install -e '.[dev]' for development
```

Python 3.11+. Runtime dependencies: `mcp` (1.x, FastMCP), `httpx`,
`cryptography`, `pydantic`, `python-dotenv`.

## Configuration

All configuration comes from environment variables. A `.env` file in the
working directory is loaded if present. Copy `.env.example` to start. Never
commit `.env`.

| Variable | Default | Notes |
|---|---|---|
| `TPLINK_NVR_HOST` | (unset) | Hostname or IP. Enables the NVR backend |
| `TPLINK_NVR_PORT` | `443` | |
| `TPLINK_NVR_USERNAME` | `admin` | |
| `TPLINK_NVR_PASSWORD` | (required) | |
| `TPLINK_NVR_VERIFY_TLS` | `false` | NVRs use self-signed certificates |
| `TPLINK_NVR_TIMEOUT_SECONDS` | `10` | 1-120 |
| `TPLINK_NVR_ALLOW_WRITES` | `false` | First write key (see below) |
| `TPLINK_NVR_DRY_RUN` | `false` | Writes return the exact request without sending it |
| `TPLINK_NVR_LOGIN_DISABLED` | `false` | Freeze authentication |
| `TPLINK_NVR_MAX_LOGIN_FAILURES` | `1` | Per-process failure budget, 1-5 |
| `TPLINK_NVR_BACKUP_DIR` | `backups` | Where `nvr_backup_config` writes (mode 0600) |
| `TPLINK_ROUTER_*`, `TPLINK_SWITCH_*` | | Same suffixes, for the scaffold backends |
| `TPLINK_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `TPLINK_MCP_HOST` | `127.0.0.1` | IP literal to bind for HTTP |
| `TPLINK_MCP_PORT` | `8765` | |

Settings are validated at startup. Invalid hosts, out-of-range or NaN ports,
and similar errors stop the server with a message that names the variable but
never echoes its value.

## Running

**stdio** (Claude Desktop / Claude Code), for example:

```json
{
  "mcpServers": {
    "tplink": {
      "command": "/path/to/.venv/bin/tplink-local-mcp",
      "env": { "TPLINK_NVR_HOST": "<nvr-host>", "TPLINK_NVR_PASSWORD": "<password>" }
    }
  }
}
```

**streamable-http** (hosted on a small always-on box):

```sh
TPLINK_MCP_TRANSPORT=streamable-http tplink-local-mcp   # serves http://127.0.0.1:8765/mcp
```

The server has **no authentication of its own**. Keep it on loopback and reach
it over Tailscale or an SSH tunnel. Do not bind it to the LAN. A systemd example
is in `deploy/tplink-local-mcp.service.example`.

## Tools

Every tool returns `{"success": bool, "data": ..., "error": {code, message, details} | null}`.
Fields named `ciphertext`, `key`, `stok`, `passwd`, `pwd`, `token`, `secret` or
`password*` are always redacted. No tool can return camera credentials.

| Tool | Kind | Description |
|---|---|---|
| `tplink_status` | read | Configured backends, their tools, and a healthcheck (NVR: pre-auth challenge only, never logs in) |
| `nvr_auth_status` | local | Session state and last failure counters. No I/O |
| `nvr_login` | auth | Explicit single login attempt |
| `nvr_get_device_info`, `nvr_get_module_spec`, `nvr_get_system_info`, `nvr_get_network_info`, `nvr_get_video_resolutions` | read | Device information |
| `nvr_list_disks`, `nvr_get_recording_status` | read | Storage (raw reply) |
| `nvr_list_channels`, `nvr_get_channel` | read | Bound cameras (`chm` `added_dev`) |
| `nvr_find_duplicate_channels` | read | Groups channels by device `uuid`. Within a group, offline/disconnected rows are flagged as stale |
| `nvr_backup_config` | read | Downloads the config backup (`system` `download_conf`) to `TPLINK_NVR_BACKUP_DIR`. Not write-gated, so run it before any cleanup |
| `nvr_remove_channel` | **write** | Unbinds a channel (`chm_del_dev`) |
| `nvr_move_channel` | **write** | Moves a binding to an **empty** slot (`chm_mod_dev_chn`), keeping its settings |
| `nvr_call` | read/**write** | Raw `{"method", module: params}`. `login` and `user_management` are always refused |

### Write gating

Any non-`get` method requires **both**:

1. `TPLINK_NVR_ALLOW_WRITES=true` on the server (the operator's switch), and
2. `confirm_write: true` on the individual call (the literal boolean; `"yes"` is refused).

The channel tools add more checks. `expected_uuid` must match the live row,
which is re-read immediately before the write. `nvr_move_channel` refuses an
occupied target, because the firmware would silently replace it.
`TPLINK_NVR_DRY_RUN=true` returns the exact request instead of sending it. Both
tools return redacted before/after rows.

## Security notes

- No secrets live in the repository. `scripts/check_no_secrets.py` runs as a
  test. It fails on private IPv4 ranges, MAC addresses, 32-hex tokens, `stok`
  values, `ciphertext` values and `password=` assignments, and on any committed
  `.env`, `captures/` or `backups/` path.
- Request and response bodies are never logged. Session tokens are masked in
  all log lines, including httpx's own.
- Config backups and capture outputs can contain credentials or live tokens.
  Both directories are git-ignored and written with mode 0600.
- Module/section names for the read helpers come from static extraction of the
  firmware 1.1.3 web client. The channel and backup primitives are verified;
  some read parameters are not yet verified live. `nvr_call` is the escape hatch.

## Development

```sh
pip install -e '.[dev]'
pytest -q --cov                # all tests run against mocks; nothing touches a device
ruff check . && ruff format --check .
python scripts/check_no_secrets.py
```

## Prior art

- [gunwookim0221/tp-link-vigi-sdk](https://github.com/gunwookim0221/tp-link-vigi-sdk) (MIT)
- [sgrajaragul/TP-Link-VIGI-Camera-Automation](https://github.com/sgrajaragul/TP-Link-VIGI-Camera-Automation) (MIT)

Not affiliated with or endorsed by TP-Link. "TP-Link", "VIGI", "Archer" and
"Easy Smart" are trademarks of their owner.

## License

MIT. See `LICENSE`.
