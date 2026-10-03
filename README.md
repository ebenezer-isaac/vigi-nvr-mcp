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
| `VIGI_NVR_RTSP_PORT` | `554` | RTSP/ONVIF port probed by `nvr_get_rtsp_status` |
| `VIGI_NVR_RTSP_USERNAME` | (NVR username) | RTSP account; defaults to `VIGI_NVR_USERNAME` |
| `VIGI_NVR_RTSP_PASSWORD` | (NVR password) | RTSP password; defaults to `VIGI_NVR_PASSWORD` |
| `VIGI_NVR_EXPORT_DIR` | `~/.local/share/vigi-nvr-mcp/exports` | Clip/snapshot output (dir 0700) |
| `VIGI_NVR_EXPORT_MAX_MINUTES` | `60` | Longest export window, 1-1440 |
| `VIGI_NVR_EXPORT_RETENTION_DAYS` | `7` | Age after which `nvr_purge_exports` deletes a clip, 1-3650 |
| `VIGI_NVR_FFMPEG` | (PATH) | Path to `ffmpeg` if not on `PATH` |
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
| `nvr_get_rtsp_status` | read | ONVIF/RTSP enablement plus a TCP probe of the RTSP port |
| `nvr_enable_rtsp` | **write** | One-time ONVIF/RTSP enable (`onvif_server` set) |
| `nvr_get_stream_url` | read | Redacted live RTSP URL + which env vars hold the credentials |
| `nvr_export_clip` | **write** (local) | Exports a replay window to mp4 (`ffmpeg -c copy`; `target_max_mb`/`max_width` re-encode to fit) |
| `nvr_snapshot` | read | One JPEG frame from a live stream into the export dir |
| `nvr_list_exports`, `nvr_delete_export` | read / **write** | Manage the export directory (path-confined); listing reports age and retention |
| `nvr_list_recording_segments` | read | Typed recording timeline for a channel/day (`nvr_search_recordings` is an alias) |
| `nvr_list_motion_windows` | read | Merged, de-duplicated activity windows across the timeline and event logs |
| `nvr_contact_sheet` | read | One JPEG grid of time-stamped frames across a window, with a tile→time map |
| `nvr_sample_frames` | read | Individual JPEG frames at an interval across a window |
| `nvr_get_export` | read | Returns a file's content as base64 (≤ `max_mb`, else `TOO_LARGE`) |
| `nvr_purge_exports` | **write** | Deletes exports older than the retention window (double-gated, dry-run) |
| `nvr_call` | read/**write** | Raw `{"method", module: params}`; `login` and `user_management` always refused |

The export directory is also exposed as MCP **resources** (`exports://<name>`,
blob content, path-confined) so clients that support resources can fetch a file
without base64 in a tool result.

### Write gating

Any non-`get` method requires **both** `VIGI_NVR_ALLOW_WRITES=true` on the
server and `confirm_write: true` on the call (the literal boolean). Channel
writes add three more checks:

- `expected_uuid` must match the live row, which is re-read just before writing.
- Move refuses an occupied target, because the firmware would silently replace it.
- Guarded writes are serialised, so two of them cannot interleave.

`VIGI_NVR_DRY_RUN=true` returns the exact request instead of sending it.
Results include redacted before/after rows.

## Exporting footage over RTSP

TP-Link VIGI NVRs expose live and recorded video over RTSP, so footage can be
exported losslessly with `ffmpeg` and no proprietary player. These tools need
`ffmpeg` and `ffprobe` on `PATH` (or `VIGI_NVR_FFMPEG` pointing at `ffmpeg`); if
neither is found, the media tools return a `MEDIA_UNAVAILABLE` envelope instead
of failing.

**One-time: turn RTSP on.** Many NVRs ship with ONVIF/RTSP off (port 554
closed). Check and enable it:

```text
nvr_get_rtsp_status                       # enabled? is 554 open?
nvr_enable_rtsp(confirm_write=true)       # needs VIGI_NVR_ALLOW_WRITES=true
```

`nvr_enable_rtsp` is write-gated like any mutation and supports
`VIGI_NVR_DRY_RUN=true` (it returns the exact `onvif_server` request without
sending it). It re-reads the setting afterwards and reports
`enabled_before`/`enabled_after`.

**Export a clip.** `nvr_export_clip` takes ISO-8601 `start`/`end` (a UTC offset
is required) and writes an mp4 into `VIGI_NVR_EXPORT_DIR`:

```text
nvr_export_clip(channel=5,
                start="2026-10-03T14:00:00Z",
                end="2026-10-03T14:02:00Z",
                stream=1, confirm_write=true)
```

Writing to local disk counts as a write, so it needs both
`VIGI_NVR_ALLOW_WRITES=true` and `confirm_write=true`. The window must be no
longer than `VIGI_NVR_EXPORT_MAX_MINUTES`. The result includes the file path,
size, duration, SHA-256 and a redacted `ffmpeg` stderr tail; the clip is
`ffprobe`-verified to contain a video stream. `nvr_snapshot` grabs a single JPEG
and is read-only. `nvr_list_exports` and `nvr_delete_export` manage the
directory (names are path-confined). Use `nvr_search_recordings` to find a
window that actually has footage; an empty window surfaces as
`NO_FOOTAGE_IN_WINDOW`.

> [!WARNING]
> **RTSP credentials are visible on the NVR host.** `ffmpeg` receives the RTSP
> URL with the username and password in its userinfo, so the credentials appear
> in that process's command line (`ps`) on the machine running this server. The
> intended deploy target is a single-admin box. Prefer a dedicated viewer
> account via `VIGI_NVR_RTSP_USERNAME`/`VIGI_NVR_RTSP_PASSWORD` rather than the
> `admin` login. Every URL this server returns or logs is redacted; only
> `ffmpeg` ever sees the plaintext.

Exports can be large. Keep `VIGI_NVR_EXPORT_DIR` on a disk with room. Old clips
are pruned by `nvr_purge_exports` (deletes files older than
`VIGI_NVR_EXPORT_RETENTION_DAYS`, double write-gated, with a dry run), and
`nvr_list_exports` reports each file's age and the next purge. The directory is
created with mode 0700; exported footage is not encrypted.

## Investigation recipe

The MCP is the data plane; your agent (with vision and a mail tool) does the
looking, deciding and sending. To answer something like *"find footage of when a
car came to the front door yesterday and email it to me"*, an agent can follow
this verbatim (names and dates are placeholders):

1. **Find the activity windows.** Ask the NVR's own timeline, not the raw video:

   ```text
   nvr_list_motion_windows(channel="Main Door", date="2026-10-02",
                           kinds=["motion","smart","alarm"])
   ```

   This returns merged `[{channel, name, start, end, duration_s, kinds, sources}]`
   windows. (`channel` may be a number, or `"all"` to sweep every channel.)

2. **Look at each window cheaply.** For every window, build one contact sheet and
   inspect it with vision. Each tile has its exact time burned in, so a hit can be
   cited to the second:

   ```text
   nvr_contact_sheet(channel=5, start="2026-10-02T14:03:00Z",
                     end="2026-10-02T14:05:00Z", cols=4, rows=3)
   ```

   The result includes a `tiles` list mapping each tile to its timestamp. One
   contact sheet is one image for the agent to read, so a day of windows is a
   handful of images, not hours of video.

3. **Pin the moment.** On a hit, pull individual frames around it to find the
   exact second:

   ```text
   nvr_sample_frames(channel=5, start="2026-10-02T14:03:40Z",
                     end="2026-10-02T14:04:10Z", every_s=1)
   ```

4. **Export a mail-sized clip.** Re-encode to fit the agent's mail attachment cap
   (Gmail is ~25 MB; 20 is a safe target):

   ```text
   nvr_export_clip(channel=5, start="2026-10-02T14:03:50Z",
                   end="2026-10-02T14:04:05Z", target_max_mb=20,
                   confirm_write=true)        # needs VIGI_NVR_ALLOW_WRITES=true
   ```

   The result reports `original_bytes`, `encoded_bytes` and `fits_target`.

5. **Retrieve and send.** Fetch the bytes and hand them to the mail tool:

   ```text
   nvr_get_export(name="ch5_...mp4", max_mb=20)   # base64 content
   ```

   Or, if your client supports MCP resources, read `exports://ch5_...mp4`
   directly. Then send it with the agent's own Gmail/mail tool.

Exports live on the server host (`VIGI_NVR_EXPORT_DIR`), not on the agent's
machine; `nvr_get_export` and the `exports://` resources are how a remote agent
pulls them. Housekeeping runs through `nvr_purge_exports`.

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
