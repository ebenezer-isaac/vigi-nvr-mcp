# vigi-nvr-mcp

An [MCP](https://modelcontextprotocol.io) server for a single TP-Link VIGI NVR
on your own network. It speaks the NVR's local JSON API directly — no cloud, no
browser, no vendor app — and exposes it to an AI agent or any MCP client as a
set of safe, typed tools: read the device and its cameras, manage channels,
and export recorded footage over RTSP. Reads are free; every write needs two
separate opt-ins; and login is engineered around the NVR's account-lockout so an
agent cannot lock you out of your own recordings.

> [!WARNING]
> **Account lockout is the main risk.** VIGI NVRs lock the `admin` account after
> ~10 failed logins, and while locked you cannot reach the NVR at all, including
> its recordings. This server never auto-retries a login and, by default, stops
> all logins after a **single** failure until a human clears the breaker.
> Confirm your password with `vigi-nvr-mcp --check-auth --login` before pointing
> an agent at it. See [Safety model](#safety-model).

## Supported hardware

| | |
|---|---|
| **Tested model** | VIGI NVR1016H(UN) |
| **Tested firmware** | 1.1.3 Build 260727 |
| **Auth scheme (this firmware)** | MD5 + RSA-PKCS1v15 (`encrypt_type` 2), falling back to bare MD5 (`encrypt_type` 1) |

Other VIGI models and firmware very likely work, but **the login scheme varies
by firmware** — this unit uses MD5+RSA, and newer firmware is known to use
SHA-256-based schemes. The server auto-detects `encrypt_type` 1 vs 2, but if
your firmware uses something else, login will fail. Verify first, without
risking the lockout counter:

```sh
vigi-nvr-mcp --check-auth           # fetch the challenge only: offered schemes, counters; NO login
vigi-nvr-mcp --check-auth --login   # plus exactly ONE login attempt
```

The full wire protocol is documented in
[docs/protocol/vigi-nvr.md](docs/protocol/vigi-nvr.md).

## Features

- **45 tools** over one NVR, all returning a uniform `{success, data, error}`
  envelope with credentials redacted.
- **Catalog gateway** — `nvr_call` reaches every one of the **586 documented
  calls** across 61 API modules through one validated, write-gated entry point,
  so coverage is the whole inventory rather than 586 hand-written tools.
- **Typed reads** for the high-value calls: device/system/network info, users,
  storage and disks, recording status, video/image/detection config, firewall,
  cloud status, time.
- **Channel management** — list bound cameras, group duplicates by device UUID,
  flag stale "ghost" channels, and plan/execute cleanup (remove, move) with
  per-write UUID checks.
- **Footage over RTSP** — enable ONVIF/RTSP, build redacted stream URLs, export
  replay windows to mp4 (lossless `-c copy`, or re-encode to a size target),
  grab snapshots, build time-stamped contact sheets, sample frames, and run a
  full "find the footage and send it" investigation recipe.
- **MCP resources** — the export directory is also exposed as `exports://<name>`
  blobs for clients that support resources.

## Install

```sh
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install .                                    # or: pip install -e '.[dev]'
```

- **Python 3.11+**. Runtime deps: `mcp` (1.x, FastMCP), `httpx`, `cryptography`,
  `pydantic`, `python-dotenv`, `tzdata`.
- **`ffmpeg`/`ffprobe`** are optional and only needed for the media/export
  tools. If they are not found, those tools return a `MEDIA_UNAVAILABLE`
  envelope instead of failing; everything else works without them. Point
  `VIGI_NVR_FFMPEG` at the binary if it is not on `PATH`.

## Configuration

Configuration comes **only** from environment variables (a `.env` in the working
directory is loaded if present). Copy [`.env.example`](.env.example) and never
commit your `.env`. Everything is validated once at startup; a bad value stops
the server with a message that names the variable but never prints its value.

### NVR connection

| Variable | Default | Meaning |
|---|---|---|
| `VIGI_NVR_HOST` | *(required)* | NVR hostname or IP (no scheme/port/path) |
| `VIGI_NVR_PORT` | `443` | HTTPS API port |
| `VIGI_NVR_USERNAME` | `admin` | Login username |
| `VIGI_NVR_PASSWORD` | *(required)* | Login password (1–128 chars) |
| `VIGI_NVR_VERIFY_TLS` | `false` | NVRs ship self-signed certs, so off by default |
| `VIGI_NVR_TLS_FINGERPRINT_SHA256` | *(unset)* | Pin the cert by SHA-256 (64 hex, colons optional); fails closed on mismatch. Observe the value via `nvr_status` / `--check-auth` (`tls_fingerprint_observed`) |
| `VIGI_NVR_TIMEOUT_SECONDS` | `10` | Per-request timeout, 1–120 |

### Safety switches

| Variable | Default | Meaning |
|---|---|---|
| `VIGI_NVR_ALLOW_WRITES` | `false` | First write gate (env). Writes also need `confirm_write: true` per call |
| `VIGI_NVR_DRY_RUN` | `false` | Writes return the exact request without sending it |
| `VIGI_NVR_LOGIN_DISABLED` | `false` | Freeze authentication before any network I/O |
| `VIGI_NVR_MAX_LOGIN_FAILURES` | `1` | Per-host failure budget before the breaker trips, 1–5 |
| `VIGI_NVR_BACKUP_DIR` | `backups` | Where `nvr_backup_config` writes (dir/files 0600) |
| `VIGI_NVR_STATE_DIR` | `~/.local/state/vigi-nvr-mcp/` | Persistent login-breaker state (per host, 0600) |

### RTSP / media export

| Variable | Default | Meaning |
|---|---|---|
| `VIGI_NVR_RTSP_PORT` | `554` | RTSP/ONVIF port probed by `nvr_get_rtsp_status` |
| `VIGI_NVR_RTSP_USERNAME` | *(NVR username)* | RTSP account; defaults to `VIGI_NVR_USERNAME` |
| `VIGI_NVR_RTSP_PASSWORD` | *(NVR password)* | RTSP password; defaults to `VIGI_NVR_PASSWORD` |
| `VIGI_NVR_EXPORT_DIR` | `~/.local/share/vigi-nvr-mcp/exports` | Clip/snapshot output (dir 0700) |
| `VIGI_NVR_EXPORT_MAX_MINUTES` | `60` | Longest export window, 1–1440 |
| `VIGI_NVR_EXPORT_RETENTION_DAYS` | `7` | Age after which `nvr_purge_exports` deletes a clip, 1–3650 |
| `VIGI_NVR_FFMPEG` | *(PATH)* | Path to `ffmpeg` if not on `PATH` (`ffprobe` is found beside it) |

### MCP server

| Variable | Default | Meaning |
|---|---|---|
| `VIGI_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `VIGI_MCP_HOST` | `127.0.0.1` | IP literal to bind for HTTP (keep it loopback) |
| `VIGI_MCP_PORT` | `8765` | HTTP port |
| `VIGI_MCP_LOG_LEVEL` | `INFO` | Log level; logs go to stderr |

Any unknown `VIGI_NVR_*` / `VIGI_MCP_*` variable is rejected at startup (a typo
must not silently leave a write gate or TLS verification in an unintended state).

## Running

### stdio (Claude Desktop / Claude Code)

```json
{
  "mcpServers": {
    "vigi-nvr": {
      "command": "/path/to/.venv/bin/vigi-nvr-mcp",
      "env": { "VIGI_NVR_HOST": "192.0.2.1", "VIGI_NVR_PASSWORD": "<password>" }
    }
  }
}
```

### streamable-HTTP (hosting)

```sh
VIGI_MCP_TRANSPORT=streamable-http vigi-nvr-mcp   # http://127.0.0.1:8765/mcp
```

> [!IMPORTANT]
> The server has **no authentication of its own.** Keep it bound to loopback and
> reach it over **Tailscale or an SSH tunnel** — never bind it to the LAN. A
> hardened systemd example and install guide are in
> [`deploy/`](deploy/vigi-nvr-mcp.service.example).

`vigi-nvr-mcp --list-tools` prints the tool names without touching any device.

## Safety model

The whole point of this server is to be safe to hand to an autonomous agent.

- **Reads are free.** Any `get` call runs without extra gates.
- **Writes are double-gated.** Every mutating call needs **both**
  `VIGI_NVR_ALLOW_WRITES=true` on the server **and** `confirm_write: true` (the
  literal JSON boolean) on the call. The `confirm_write` parameter is typed, so
  a truthy string or number (`"true"`, `"1"`, `1`, `"yes"`) is collapsed to
  `false` at the MCP boundary and refused with a `WRITE_REFUSED` envelope and
  **no network call** — it is never coerced through the gate. Channel writes add
  three more checks: `expected_uuid` must match the live row (re-read just before
  writing); remove refuses a live (`online=="1"`) row unless `force=true`; move
  refuses an occupied target. Guarded writes are serialised so two cannot
  interleave.
- **Dry-run.** `VIGI_NVR_DRY_RUN=true` makes every write return
  `{"dry_run": true, "request": <exact body>}` and send nothing. Dry-run lives
  in the one guarded-write executor every mutating tool shares, so no write path
  can forget it.
- **Lockout breaker.** A failed login is **never** retried. After
  `VIGI_NVR_MAX_LOGIN_FAILURES` failures (default 1) the breaker **trips**:
  every failure/success is reserved-then-recorded under a cross-process lock in
  a per-host JSON file under `VIGI_NVR_STATE_DIR` (mode 0600), so even a
  crash-loop with bad credentials cannot keep spending the device's login
  budget. "Tripped" means a sticky flag is set; once tripped, no login is sent
  until a human clears it — raising the budget afterwards does **not** silently
  un-trip it. Inspect or clear it:
  ```sh
  vigi-nvr-mcp breaker --show     # state, failures, whether it is tripped
  vigi-nvr-mcp breaker --clear    # reset after you have fixed the credentials
  ```
  A corrupt or unwritable state file fails **closed** (refuses logins).
  `VIGI_NVR_LOGIN_DISABLED=true` freezes authentication before any network I/O.
  The credential-free challenge/reachability probe stays allowed either way.
- **TLS pinning (TOFU).** Set `VIGI_NVR_TLS_FINGERPRINT_SHA256` to pin the NVR's
  self-signed certificate; the pin is enforced on this server's own connection
  and fails closed on mismatch. On an unpinned connection, `nvr_status` /
  `--check-auth` report the observed fingerprint (`tls_fingerprint_observed`) so
  you can trust-on-first-use and paste it back into your config.
- **Redaction.** Every tool result is recursively stripped of credential-bearing
  fields by a rule-based matcher (keys equal to `ciphertext, stok, token, nonce,
  cookie, secret, authorization, pubkey, key`, or *containing*
  `pass/pwd/secret/token/cipher`, or *ending* `_key`). No tool can return camera
  or session credentials. Request bodies are never logged; session tokens are
  masked in every log line, including httpx's own.
- **Exit codes** (so a shell script can branch): **0** success · **1** auth
  failed · **2** config error · **3** lockout / breaker open / login disabled ·
  **4** transport error.

## Tools

Every tool returns `{"success": bool, "data": ..., "error": {code, message,
details} | null}`. "Kind" marks whether a tool mutates; a **write** needs both
write gates.

### Status & auth

| Tool | Kind | Description |
|---|---|---|
| `nvr_status` | read | Healthcheck: reachability, offered auth scheme, lockout counters, session state, safety policy, observed TLS fingerprint. Never logs in |
| `nvr_auth_status` | local | Session state and last-failure counters. No I/O |
| `nvr_login` | auth | Explicit single login attempt (never retried) |

### Catalog gateway

| Tool | Kind | Description |
|---|---|---|
| `nvr_list_modules` | read | Every API module with its call/mutating counts |
| `nvr_list_calls` | read | Catalogued calls for one module |
| `nvr_describe_call` | read | One call's spec: example params, whether it mutates, response-shape hint |
| `nvr_call` | read/**write** | Catalogued gateway `(module, method, key, params)`; `login`/`user_management` always refused |
| `nvr_raw_call` | read/**write** | Off-catalog escape hatch `(method, module, params)`; write-gated unless `get` |

### Device & network

| Tool | Kind | Description |
|---|---|---|
| `nvr_get_device_info` | read | Model, firmware, identity |
| `nvr_get_module_spec` | read | Capability spec: max channels, codecs, feature flags |
| `nvr_get_system_info` | read | Device name, time zone, session timeout |
| `nvr_get_network_info` | read | IP/mask/gateway/DNS, service ports |
| `nvr_get_video_resolutions` | read | Main/minor stream resolution tables |
| `nvr_get_video_config` | read | Per-channel resolution, codec, bitrate |
| `nvr_get_image_config` | read | Image, OSD, privacy-mask, ROI config for one channel |
| `nvr_get_detection_config` | read | Detection config for a channel and detection kind |
| `nvr_get_users` | read | User account names and groups only (never credentials) |
| `nvr_get_firewall` | read | Allow/deny lists and service exposure |
| `nvr_get_cloud_status` | read | TP-Link ID binding/connection status |
| `nvr_get_time` | read | Device time, time zone, NTP, DST |

### Channels

| Tool | Kind | Description |
|---|---|---|
| `nvr_list_channels` | read | All bound cameras (`chm added_dev`); credentials redacted |
| `nvr_get_channel` | read | One channel by id |
| `nvr_find_duplicate_channels` | read | Group by device `uuid`; flag offline/disconnected rows as stale ghosts |
| `nvr_plan_channel_cleanup` | read | Ordered, resumable cleanup plan (back up, remove ghosts, re-home real cameras) |
| `nvr_backup_config` | read | Download the config backup (`download_conf`); not write-gated, so run it before any cleanup |
| `nvr_remove_channel` | **write** | Unbind a channel (`chm_del_dev`); refuses a live row unless `force=true` |
| `nvr_move_channel` | **write** | Move a binding to an empty slot (`chm_mod_dev_chn`), keeping its settings |
| `nvr_set_channel_credentials` | **write** | Re-authenticate a bound camera by pushing a username + RSA-encrypted password (`chm_edit_dev`); polls until it reconnects |
| `nvr_renumber_channel` | **write** | Re-point a bound channel to a new camera IP (delete + re-add + rename, since `chm_edit_dev` ignores `ip`); DESTRUCTIVE and the channel id changes. Camera must already be reachable at the new IP |

### Storage & recording

| Tool | Kind | Description |
|---|---|---|
| `nvr_list_disks` | read | Installed hard disks and state (raw reply) |
| `nvr_get_storage` | read | Disks (status/capacity/free/health) plus overwrite policy |
| `nvr_get_recording_status` | read | Recording/storage policy status |
| `nvr_list_recording_segments` | read | Typed recording timeline for a channel/day (`nvr_search_recordings` is an alias) |
| `nvr_search_recordings` | read | Alias of `nvr_list_recording_segments` |
| `nvr_list_events` | read | Best-effort recent events/alerts (disk, network, video-loss, smart) |

### Media / export

| Tool | Kind | Description |
|---|---|---|
| `nvr_get_rtsp_status` | read | Whether ONVIF/RTSP is enabled, plus a TCP probe of the RTSP port |
| `nvr_enable_rtsp` | **write** | One-time ONVIF/RTSP enable (`onvif_server` set) |
| `nvr_get_stream_url` | read | Redacted live RTSP URL + which env vars hold the credentials |
| `nvr_export_clip` | **write** (local) | Export a replay window to mp4 (`-c copy`; `target_max_mb`/`max_width` re-encode to fit) |
| `nvr_snapshot` | read | One JPEG frame from a live stream into the export dir |
| `nvr_list_exports` | read | List exports with age and next-purge time |
| `nvr_delete_export` | **write** (local) | Delete one export by name (path-confined) |
| `nvr_get_export` | read | Return a file's content as base64 (≤ `max_mb`, else `TOO_LARGE`) |
| `nvr_purge_exports` | **write** (local) | Delete exports older than the retention window (double-gated, dry-run) |

### Investigation

| Tool | Kind | Description |
|---|---|---|
| `nvr_list_motion_windows` | read | Merged, de-duplicated activity windows across the timeline and event logs |
| `nvr_contact_sheet` | read | One JPEG grid of time-stamped frames across a window, with a tile→time map |
| `nvr_sample_frames` | read | Individual JPEG frames at an interval across a window |

The export directory is also exposed as MCP **resources** (`exports://<name>`,
blob content, path-confined) for clients that support them.

## Recipes

Placeholder names (`Front Door`, dates, channel numbers) stand in for yours.

### Channel cleanup (remove ghosts, re-home cameras)

Over time a VIGI NVR accumulates **ghost** channels — stale, offline duplicates
of a camera that was re-added or moved. This cleans them up safely.

1. **Back up first** (not write-gated, so always safe):
   ```text
   nvr_backup_config
   ```
2. **See the duplicates.** Groups channels by device UUID and flags the ghosts:
   ```text
   nvr_find_duplicate_channels
   ```
3. **Get an ordered plan.** Read-only; produces a resumable step list (ghosts
   first, then moves, one at a time, re-read after each):
   ```text
   nvr_plan_channel_cleanup
   ```
4. **Dry-run the plan.** With `VIGI_NVR_DRY_RUN=true`, run each step's tool to
   see the exact request body without sending it.
5. **Execute one step at a time**, re-listing after each and stopping on any
   surprise (needs `VIGI_NVR_ALLOW_WRITES=true`):
   ```text
   nvr_remove_channel(channel_id=13, expected_uuid="<uuid>", confirm_write=true)
   nvr_move_channel(from_id=9, to_id=1, expected_uuid="<uuid>", confirm_write=true)
   ```
6. **Verify:** `nvr_list_channels` and `nvr_get_recording_status`.

### Footage investigation ("find when a car came to the front door yesterday")

The MCP is the data plane; your agent (with vision and a mail tool) does the
looking, deciding and sending.

1. **Find activity windows** from the NVR's own timeline, not raw video:
   ```text
   nvr_list_motion_windows(channel="Front Door", date="2026-10-02",
                           kinds=["motion","smart","alarm"])
   ```
   Returns merged `[{channel, name, start, end, duration_s, kinds, sources}]`.
2. **Look at each window cheaply.** One contact sheet per window; each tile has
   its exact time burned in, so a hit can be cited to the second:
   ```text
   nvr_contact_sheet(channel=5, start="2026-10-02T14:03:00Z",
                     end="2026-10-02T14:05:00Z", cols=4, rows=3)
   ```
3. **Pin the moment.** On a hit, pull individual frames:
   ```text
   nvr_sample_frames(channel=5, start="2026-10-02T14:03:40Z",
                     end="2026-10-02T14:04:10Z", every_s=1)
   ```
4. **Export a mail-sized clip** (re-encode to fit, e.g. 20 MB under Gmail's
   ~25 MB cap; needs `VIGI_NVR_ALLOW_WRITES=true`):
   ```text
   nvr_export_clip(channel=5, start="2026-10-02T14:03:50Z",
                   end="2026-10-02T14:04:05Z", target_max_mb=20, confirm_write=true)
   ```
5. **Retrieve and send.** Fetch the bytes (or read the `exports://` resource) and
   hand them to the agent's mail tool:
   ```text
   nvr_get_export(name="ch5_...mp4", max_mb=20)
   ```

Exports live on the server host (`VIGI_NVR_EXPORT_DIR`), not on the agent's
machine; `nvr_get_export` and the `exports://` resources are how a remote agent
pulls them. Housekeeping runs through `nvr_purge_exports`.

## Limitations

- **Local-monitor layout is not exposed.** The NVR's own HDMI/VGA display grid
  and view layout are not reachable through this server.
- **Video is delivered over RTSP, not JSON.** Clips and frames come from the
  RTSP endpoints via `ffmpeg`; there is no JSON "give me the video" call. The
  media tools therefore need `ffmpeg`/`ffprobe`.
- **RTSP credentials are visible to local `ps`.** `ffmpeg` receives the RTSP URL
  with credentials in its userinfo, so they appear in that process's command
  line on the host running this server. Every URL the server returns or logs is
  redacted, but the plaintext is unavoidable in the `ffmpeg` invocation — use a
  dedicated viewer account and a single-admin box.
- **Some response shapes are `INFERRED` until a first live run.** These were
  derived statically from the 1.1.3 web client and have not yet been confirmed
  against a live device; the parsers return a `PROTOCOL_ERROR` envelope (never a
  crash) on an unexpected shape:
  - `nvr_list_recording_segments` / `nvr_search_recordings` (the `playback`
    search timeline)
  - `nvr_list_events` (event/alarm lists)
  - the merge inputs for `nvr_list_motion_windows`
  The channel and backup primitives, auth, and the catalog counts are verified.

## Troubleshooting

- **`-40401` everywhere.** This one code means three things depending on the
  path: the credential-free *challenge* reply (normal), a *failed login* (with a
  rising attempt counter), or an *expired session token* on `/stok=.../ds`
  (the client re-logs in once automatically). If `--check-auth --login` returns
  `-40401` with `attempts_left` dropping, the password is wrong — stop before you
  hit the lockout.
- **Account locked (`-40404` / `-40408`).** Too many failed logins. Wait out the
  lock (or power-cycle per your firmware), fix the password, then
  `vigi-nvr-mcp breaker --clear`. `-40408` means locked until manual
  intervention.
- **Nonce invalid (`-40410`).** The challenge nonce went stale between fetch and
  login; fetch a fresh challenge and try once more.
- **Logins refused with no network call.** The breaker is tripped or login is
  disabled. Run `vigi-nvr-mcp breaker --show`; clear it with
  `breaker --clear` after fixing credentials, and check
  `VIGI_NVR_LOGIN_DISABLED`.
- **RTSP tools fail or return nothing.** Check `nvr_get_rtsp_status`: if RTSP is
  off or port 554 is closed, run `nvr_enable_rtsp(confirm_write=true)` once. If
  tools return `MEDIA_UNAVAILABLE`, `ffmpeg`/`ffprobe` are not found — install
  them or set `VIGI_NVR_FFMPEG`. An empty replay window surfaces as
  `NO_FOOTAGE_IN_WINDOW`.
- **Login scheme mismatch.** If `--check-auth` shows an `encrypt_type` this
  server does not implement, your firmware uses a different login scheme (e.g.
  SHA-256). See [docs/protocol/vigi-nvr.md](docs/protocol/vigi-nvr.md).

## Prior art

- [gunwookim0221/tp-link-vigi-sdk](https://github.com/gunwookim0221/tp-link-vigi-sdk) (MIT)
- [sgrajaragul/TP-Link-VIGI-Camera-Automation](https://github.com/sgrajaragul/TP-Link-VIGI-Camera-Automation) (MIT)

`tools/capture-login/` is an optional, isolated, one-time dev utility (Node +
puppeteer-core) that records the login envelopes the vendor web UI itself sends,
on a device you own. It is not part of the server — the server imports nothing
from it and runs no browser. See its [README](tools/capture-login/README.md).

## Development

```sh
pip install -e '.[dev]'
python scripts/gate.py   # ruff, pytest + coverage (core >= 90%, package >= 80%),
                         # secret scan, stub scan, --list-tools; prints PASS/FAIL
```

- All tests run against mocks; nothing touches a device. The gate must print
  **PASS** before every commit.
- `vigi_nvr_mcp/core/` is a self-contained, device-agnostic template that
  sibling projects copy **verbatim**; a `core/VERSION` manifest plus
  `tests/test_core_identity.py` fail the gate if a copy drifts. Edit `core/` only
  in this repo (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- Design docs: the [specs](docs/specs/) (master plan, NVR spec, breaker
  protocol, breaker root-cause) and the [wire protocol](docs/protocol/vigi-nvr.md).
- Security reporting and the threat model: [SECURITY.md](SECURITY.md). Release
  history: [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE). Not affiliated with or endorsed by TP-Link.
"TP-Link" and "VIGI" are trademarks of their owner.
