# 01 — vigi-nvr-mcp (standalone repo `E:/projects-working-dir/vigi-nvr-mcp`, package `vigi_nvr_mcp`)

Target: VIGI NVR1016H(UN), fw 1.1.3 Build 260727. Verified protocol facts live in `docs/protocol/vigi-nvr.md` (written in N1 from the discovery files). Read `00-MASTER-PLAN.md` §1–§2 first; every rule there applies.

Inputs available to agents (scratchpad `nvr/discovery/`, orchestrator copies the needed ones into the repo under `vigi_nvr_mcp/catalog/` and `tests/fixtures/vigi_nvr/`):
- `auth-vectors.json` — byte-exact login vectors (dummy password/nonce). **Authoritative.**
- `endpoints.json` — 61 modules, 586 calls, 217 mutating; `_about`/`_conventions` keys describe the format.
- `_errcodes.json` — firmware error-code table.
- `auth-flow.md`, `channel-management.md`, `SUMMARY.md` — when delivered.

## Protocol (do not re-derive)

- Pre-auth: `POST https://<host>:<port>/` ; authed: `POST https://<host>:<port>/stok=<token>/ds`. Body `{"method":"get|set|do|add|delete|…","<module>":{…}}`. Headers `Content-Type: application/json; charset=UTF-8`, `X-Requested-With: XMLHttpRequest`. Response always has `error_code` (0 = ok).
- Challenge: `POST / {"user_management":{"get_encrypt_info":null},"method":"do"}` → `{"error_code":-40401,"data":{"code":…,"encrypt_type":["1","2"],"key":"<URL-encoded base64 SPKI DER RSA-1024>","nonce":"<8 chars>", "time"?:int, "max_time"?:int}}`.
- Login: `{"method":"do","login":{"username":u,"password":ENC,"passwdType":"md5","encrypt_type":"2"}}` → `{"error_code":0,"stok":"<32 hex>","user_group":"root"}`.
  `md5_auth_pwd(p) = MD5("TPCQ75NF2Y:"+p).hexdigest().upper()`; plaintext = `md5_auth_pwd(p) + ":" + nonce`; `ENC = quote(b64(RSA_PKCS1v15(pub, plaintext)), safe="")`. If the server offers only `["1"]`: `encrypt_type:"1"` and `password = md5_auth_pwd(p)` (no RSA).
- Failed login → `error_code -40401` with `data.time`/`data.max_time` (attempt counter; lockout at max). Expired/invalid token on `/stok=…/ds` → `-40401` too; distinguish by **which URL** was called.
- `securityEncode`/`orgAuthPwd` are **not** login; they are the media-stream password (`pullStreamInfo.password`) — out of scope.

## Phase N1 — core + auth (one agent)

**Deliverables**
- Everything in Master Plan §3 `core/` (self-contained, NVR-agnostic, with `core/README.md` stating it is the template the other two repos copy verbatim), fully implemented and tested (≥ 90% coverage on `core/`).
- `vigi_nvr_mcp/crypto.py`: `md5_auth_pwd`, `build_login_plaintext(md5_hex, nonce)`, `load_public_key(url_encoded_b64_spki) -> RSAPublicKey`, `rsa_encrypt_pkcs1v15_urlsafe(pub, plaintext) -> str`. Pure.
- `vigi_nvr_mcp/auth.py`: `NvrAuthenticator(settings, transport, breaker)`: `get_challenge() -> Challenge` (pydantic: code, encrypt_types, key, nonce, time, max_time), `login() -> Token` (exactly one HTTP login; on failure raises `AuthFailed(time,max_time)` and `breaker.record_failure`), `token` cache, `invalidate()`. Honour `login_disabled` and the breaker **before any login POST**. **Clarification (round-1 decision AL-F4/CC-F3): `login_disabled` and an open breaker freeze *login attempts* only — the credential-free challenge probe (`get_challenge`, used by `nvr_status`/`--check-auth`) stays allowed; it spends no login attempt and is the lockout-safe reachability check.** On `-40410` (nonce stale/reused) the password was never evaluated: do NOT resend inside the same call — raise `NonceInvalid` (retryable, not counted as a credential failure), so there is exactly one login POST per explicit `login()`.
- `vigi_nvr_mcp/transport.py`: `NvrTransport(HttpTransport)`: `post_preauth(body)`, `post_api(token, body)`; maps non-zero `error_code` to `NvrApiError(code, meaning)` using the error table; raises `TokenExpired` on `-40401` from `/ds`.
- `vigi_nvr_mcp/client.py`: `NvrClient`: `call(method, module, params) -> dict` with: serialised execution, lazy login, **single** re-login on `TokenExpired` (then re-raise), never on `AuthFailed`.
- `vigi_nvr_mcp/errors.py`: `NVR_ERROR_CODES: dict[int, str]` imported from `_errcodes.json` (vendored as `vigi_nvr_mcp/catalog/errcodes.json`), `NvrApiError`.
- `vigi_nvr_mcp/backend.py`: `VigiNvrBackend(DeviceBackend)`; `healthcheck()` = challenge only (no login) returning encrypt types + counters.
- Tools: `nvr_check_auth` (challenge only; shows `time/max_time` if present), `nvr_login` (explicit; one attempt; returns `user_group` only — never the token), `nvr_get_device_info` (`device_info` / `basic_info`).
- `tests/fixtures/vigi_nvr/auth_vectors.json` (copied) + tests asserting every field of it; RSA round-trip with a generated key; URL-encoding of `+ / =`; key `%2b` decoding; encrypt_type 1 path; challenge parsing with/without `time`.
- Lockout tests: failed login → no retry, breaker written (a **persistent** file under `<PREFIX>_STATE_DIR`, so the budget survives a process restart; corrupt/unwritable state ⇒ breaker treated open, fail closed), `AuthFailed(time=9,max_time=10)` surfaced; `login_disabled` → **no login POST** (the credential-free challenge probe is still allowed — assert `login_attempts == 0`, not that the transport is untouched); breaker open → same; expired token mid-call → exactly one re-login then success; expired token twice → `TokenExpired` raised, no third login. `-40410` → `NonceInvalid`, exactly one login POST, not counted as a failure.
- `docs/protocol/vigi-nvr.md` — the protocol section above plus the error-code table.
- `scripts/gate.py`, `scripts/check_no_secrets.py`, `pyproject.toml`, `.env.example`, `.gitignore`, `LICENSE`, `README.md` skeleton, `deploy/vigi-nvr-mcp.service.example`.

**Done when** gate passes; `--list-tools` shows `nvr_status`, `nvr_check_auth`, `nvr_login`, `nvr_get_device_info`.

## Phase N2 — catalog gateway (comprehensive coverage, one agent)

The inventory is the coverage. Every one of the 586 calls becomes reachable, validated and write-gated through one gateway, without 586 registrations.

**Deliverables**
- `vigi_nvr_mcp/catalog/endpoints.json` vendored verbatim (first run `check_no_secrets` on it; if any real address slipped into an example, replace with `192.0.2.x` and note it in the commit).
- `vigi_nvr_mcp/catalog.py`: `Catalog.load()`, `modules()`, `calls(module)`, `find(module, method, key) -> CallSpec` (pydantic: module, method, key, params_example, mutates, ui_context, response_shape_hint), `build_body(spec, params)`; param validation: params must be JSON-serialisable, max depth 6, max 200 keys, strings ≤ 4 KB, no control chars, keys must be `[A-Za-z0-9_.-]{1,64}`; if `params_example` has a shape, unknown top-level keys are rejected unless `allow_extra=True`.
- Tools: `nvr_list_modules()` (name, description, call count, mutating count), `nvr_list_calls(module)` , `nvr_describe_call(module, method, key)` (returns the spec incl. example), `nvr_call(module, method, key, params, confirm_write=False, allow_extra=False)`: refuses unknown `(module, method, key)` with the three nearest matches; mutating (per catalog **or** method ∉ {`get`}) requires both write gates; supports `VIGI_NVR_DRY_RUN` (returns the exact body under `data.dry_run` and does not send).
- `nvr_raw_call(method, module, params, confirm_write)` for calls not in the catalog — **always** write-gated unless `method == "get"`, and logged at WARNING.
- Tests: catalog loads with `module_count == 61` and `len(all calls) == 586` and `mutating == 217` (read those numbers from the file's `_about`/computed, assert equality so a trimmed file fails); every mutating spec is refused without gates and sends nothing; a `get` spec sends the exact expected body; dry-run; fuzz 50 random specs → `build_body` output is valid JSON and contains `method`; adversarial params (depth bomb, 10k keys, 1 MB string, NUL bytes) rejected before any I/O.

**Done when** `nvr_call` can reach every catalogued call in tests via a fake transport and the count assertions pass.

**Wire shapes (CI-F1 fix, breaker r2).** A call is identified by `(module, method, key)`, but the firmware does not nest every call's params the same way — the `key` means different things per method/convention. `build_body` therefore derives one `CallSpec.shape ∈ {name_list, name, table, action, bare}` deterministically (from the inventory conventions in `endpoints.json._conventions` and the verified request captures in `discovery/_tools/raw-calls.json` + `channel-management.md`) and applies it. `params` passed to `nvr_call`/`build_body` is always the call's **inner** body (the fields `params_example` lists); the shape supplies the wrapper:

| shape | wire body | when |
|---|---|---|
| `table` | `{<module>: {"table": <key>}}` | `get` whose key is a verified table (returns rows), e.g. `chm/get/added_dev` → `{"chm":{"table":"added_dev"}}` |
| `name` | `{<module>: {"name": <key>}}` | `get` whose key is a verified scalar-name section, e.g. `function/get/module_spec` |
| `name_list` | `{<module>: {"name": [<key>]}}` | every other real-keyed `get` (the list form the web client uses throughout) — the default |
| `action` | `{<module>: {<key>: {...params}}}` | `do`/`set`/`add`/`delete` with a real sub-method key, e.g. `chm/do/chm_mod_dev_chn` → `{"chm":{"chm_mod_dev_chn":{"old_id":"9","new_id":"1"}}}` |
| `bare` | `{<module>: {...params}}` | the few calls whose key is `(dynamic)`/absent — params pass straight through; flagged as such in `nvr_describe_call` |

For an `action` call `build_body` also accepts an already-wrapped `{<key>: {...}}` body (it is not double-wrapped), and the unknown-top-level-key check validates the **inner** params against `params_example` — so the device-correct body is never rejected and a wrapper-less body is never emitted. `nvr_describe_call` returns a `wire_example`: the exact full body to put on the wire. The shape is verified against the `channel-management.md` envelopes and the `raw-calls.json` fixtures in `tests/test_catalog_wire_shapes.py`.

**Catalog integrity (CI-F2/CI-F3 fixes).** The vendored `endpoints.json`/`errcodes.json` each carry a sidecar `<stem>.sha256` (SHA-256 of the canonical UTF-8 JSON text, written by `scripts/sanitize_catalog.py`); `Catalog.load()`/`code_to_symbol()` recompute and compare it, so a **count-preserving** tamper (a flipped `mutates` flag, a rewritten `params_example`, a swapped `method`) raises `ConfigError` at startup, not inside a tool. Param string validation rejects any Unicode Cc/Cf/Zl/Zp character via `has_forbidden_chars` (so U+2028/U+2029 line separators and the U+FEFF BOM no longer pass the C0/C1-only screen) and lone UTF-16 surrogates as `InvalidInput` before any `.encode()`.

## Phase N3 — typed read tools (one agent; may split N3a/N3b if > 14 files)

Hand-written, LLM-friendly tools for the high-value reads. Each returns a normalised pydantic model under `data` plus `raw` when `include_raw=True`. All use `client.call`; none bypass the catalog validation.

| Tool | Module / key | Notes |
|---|---|---|
| `nvr_get_system_info` | `system`, `device_info`, `function.module_spec` | model, fw, uptime, max_channels, codecs |
| `nvr_get_network` | `network`, `port`, `uhttpd`, `media_server`, `onvif_server` (reads) | IP/mask/gw/DNS, service ports |
| `nvr_list_channels` | `chm.added_dev` | normalised rows: id, name, alias, ip, port, protocol, online, conn_status (+meaning), auth_result (+meaning), uuid, model; **ciphertext never returned**; `include_offline_only` filter |
| `nvr_find_duplicate_channels` | derived | group by `uuid`; a row is a **ghost** iff another row with the same uuid exists AND this row has `online=="0"` AND `conn_status != "0"` AND (`auth_result == "1"` OR name equals its generic model name); output `{uuid, keep: row, ghosts: [rows]}` with a human explanation. Unit-test on an anonymised fixture that reproduces the owner's pattern (14 rows, 6 ghosts across 3 uuids, 3 real-but-offline rows, 2 rows legitimately sharing a uuid that must NOT be flagged because both are online). |
| `nvr_get_video_config` | `video.main_res/minor_res`, `advance_settings` | per-channel resolution/codec/bitrate |
| `nvr_get_image_config(channel)` | `image`, `OSD`, `cover`, `ROI` | |
| `nvr_get_detection_config(channel, kind)` | `motion_detection`, `people_detection`, `vehicle_detection`, `linecross_detection`, `intrusion_detection`, `regionentrance_detection`, `regionexiting_detection`, `loitering_detection`, `abandonandtaken_detection`, `scenechange_detection`, `audioexception_detection`, `tamper_detection` | `kind` enum; read-only |
| `nvr_get_storage` | `harddisk_manage` reads, `plan_advance`, `record_plan` | disks: status/capacity/free/health; overwrite policy |
| `nvr_get_recording_status` | `record_control` reads + `harddisk_manage` + `chm` | per channel: recording on/off, schedule present, last error; **this is the "does footage exist" tool** |
| `nvr_search_recordings(channel, date)` | `playback` search | list segments (start, end, type) |
| `nvr_list_events(since)` | `unusual_detection`, `alarm_server`, chm `chm_get_msg_alarm_list_extend` | best-effort normalised |
| `nvr_get_users` | `user_management` reads | names/groups only |
| `nvr_get_firewall` | `firewall`, `protocol` reads | |
| `nvr_get_cloud_status` | `cloud_status`, `cloud_config` reads | |
| `nvr_get_time` | `system` time/NTP | |

Tests per tool: fixture response → normalised model; malformed/missing fields → `ProtocolError` envelope not exception; unexpected `error_code` → mapped meaning; URL-encoded `%20` names decoded.

## Phase N4 — channel management writes (one agent; **blocked on `channel-management.md`**)

Inputs: the discovery doc's verified delete/add/modify envelopes and `conn_status`/`auth_result` meanings.

**Deliverables**
- `nvr_remove_channel(channel_id, expected_uuid, confirm_write)`: refuses unless the live row's `uuid` equals `expected_uuid` (prevents removing the wrong slot after a renumber); refuses if the row is `online=="1"` unless `force=True`; dry-run supported; after the write re-reads `added_dev` and returns before/after rows.
- If the discovery doc verifies a renumber/move primitive: `nvr_move_channel(from_id, to_id, expected_uuid, confirm_write)` with the same guards. If not: `nvr_add_channel(ip, port, protocol, username, password, name, confirm_write)` + `nvr_set_channel_name(id, name)`; `password` is accepted only via a `VIGI_NVR_CAMERA_PASSWORDS` env map (`name=pw;…`) referenced by name, never as a tool argument that would appear in logs.
- `nvr_plan_channel_cleanup()` (read-only): from `nvr_find_duplicate_channels` and the free-slot rules the doc verifies, produce an ordered plan: `[{step, tool, args, rationale}]` to remove all ghosts and re-home real cameras into slots 1–8, with the lowest-risk order (ghosts first, then moves/re-adds, one at a time, verify after each).
- Tests: guards (uuid mismatch, online without force, writes disabled, dry-run body equality against the doc's envelope), plan generation on the anonymised fixture (expected exact step list), state machine (token expiry between steps, failure mid-plan leaves a resumable plan).

## Phase N5 — LIVE verification (orchestrator-run, owner present)

1. `vigi-nvr-mcp --check-auth` → challenge only.
2. `vigi-nvr-mcp --check-auth --login` → **one** login; expect `user_group: root`.
3. `nvr_get_device_info`, `nvr_list_channels`, `nvr_find_duplicate_channels` → compare against the known table.
4. `nvr_plan_channel_cleanup` → review every step's body in dry-run.
5. Execute the plan **one step at a time** with `confirm_write=True`, re-listing after each; stop on any surprise.
6. `nvr_get_recording_status` for all remaining channels.
Record results (sanitised) as `docs/protocol/vigi-nvr-verified.md`.

## Phase N6 — docs & deploy (one agent)

README sections for the NVR backend (tools table, write gating, lockout callout, catalog gateway usage, examples), `docs/protocol/vigi-nvr.md` finalised, `deploy/` unit + `install.md` (non-root user, env file perms, loopback bind, Tailscale access), CHANGELOG. No secrets.

## Phase N7 — media: RTSP playback export, snapshots, stream URLs (one agent)

**Why:** TP-Link documents RTSP playback for VIGI NVRs (FAQ 5223): live `rtsp://<nvr>:<port>/live/<ch>/<stream>/avm`, replay `rtsp://<nvr>:<port>/replay/<ch>/<stream>/avm?starttime=YYYYMMDDtHHMMSSz&endtime=YYYYMMDDtHHMMSSz` (`z` = UTC; `l` = local on newer fw). `<stream>` 1 main / 2 sub. Time-ranged replay + `ffmpeg -c copy` = lossless clip export with no proprietary player protocol. The owner's NVR currently has RTSP **off** (554 closed); the web UI's switch is `get {"onvif_server":{"name":"onvif"}}` → `onvif_server.onvif.enabled` and `set {"onvif_server":{"onvif":{"enabled":"on"}}}` (verified from the page script `ConfNetworkOnvif`). Credentials for RTSP = NVR user accounts.

**Deliverables**
- `vigi_nvr_mcp/media/` (new package, ≤ 400 lines/file): `urls.py` — pure builders `live_url(settings, channel, stream)`, `replay_url(settings, channel, stream, start_utc, end_utc)` with strict validation (channel 1–16, stream ∈ {1,2}, timezone-aware datetimes, `end > start`, duration ≤ `VIGI_NVR_EXPORT_MAX_MINUTES` default 60, format `YYYYMMDDtHHMMSSz` exactly); `redacted_url()` for any output. `ffmpeg.py` — `FfmpegRunner`: locate `ffmpeg`/`ffprobe` (`VIGI_NVR_FFMPEG` override; absent ⇒ `MediaUnavailable` envelope, never a crash), build argv lists (never a shell string), `-rtsp_transport tcp`, `-c copy -movflags +faststart` for export, `-frames:v 1 -q:v 2` for snapshots, `-stimeout`/overall timeout = duration × 1.5 + 30 s, output only inside `VIGI_NVR_EXPORT_DIR` (default `~/.local/share/vigi-nvr-mcp/exports/`, 0700) with generated names `ch<N>_<start>_<end>_<stream>.mp4` / `.jpg`, refuse if free space < 2× an estimated size (bitrate from `nvr_get_video_config` when available, else 8 Mbit/s), one export at a time (serial), kill on timeout, return `{path, bytes, duration_s, sha256, ffmpeg_stderr_tail}`; `ffprobe` the result and fail if no video stream. Credentials: pass the URL with userinfo via argv (documented: visible to local `ps` on the host — the deploy target is a single-admin box; `VIGI_NVR_RTSP_USERNAME/PASSWORD` default to the NVR admin creds but may be a dedicated viewer account) and scrub it from every log/error/envelope via `redacted_url`.
- Tools: `nvr_get_rtsp_status()` — reads `onvif_server.onvif.enabled` and TCP-probes `<host>:<rtsp_port>` (default 554; `VIGI_NVR_RTSP_PORT`), reports `enabled`, `port_open`; `nvr_enable_rtsp(confirm_write)` — the `onvif_server` set, double-gated + dry-run, re-reads after; `nvr_get_stream_url(channel, stream)` → redacted live URL + a `credentials_env` hint (never the password); `nvr_export_clip(channel, start, end, stream=1, confirm_write=False)` — export is a **local write** (disk), so it is gated like a write (`ALLOW_WRITES` + `confirm_write`) and dry-run returns the argv with the URL redacted; `nvr_snapshot(channel, stream=2)` (read-only: a JPEG into the export dir); `nvr_list_exports()` / `nvr_delete_export(name, confirm_write)` (path-confined, name regex). `nvr_search_recordings` (N3) stays the "where is footage" tool; its live shape is confirmed in N5 — until then `nvr_export_clip` documents that an empty window yields an ffmpeg error, surfaced as `NO_FOOTAGE_IN_WINDOW` when stderr matches the known patterns.
- Tests: URL builders (every validation rule; `+`/`/`/`@` in password URL-encoded; format exactness; UTC conversion from other zones); argv construction (no shell; no password in `repr`/logs/errors); runner with a fake `ffmpeg` executable (a Python script on PATH) that writes a file / sleeps past timeout / exits non-zero / prints "404"/"no such" patterns → correct envelopes; disk-space refusal; path confinement (`../`, absolute, symlink); concurrency (second export refused while one runs); RTSP status with a fake socket; enable write gating + dry-run.

**Done when** gate passes with ≥ 90% on `media/`; `--list-tools` shows the six new tools. LIVE (N5 addendum, orchestrator-run): `nvr_get_rtsp_status` → `nvr_enable_rtsp` (dry-run, then real) → re-probe 554 → `nvr_snapshot(5)` (an EZVIZ bridge channel) → `nvr_export_clip` of a 2-minute window from today → `ffprobe` the file.

## Phase N7b — investigation primitives: motion windows, contact sheets, agent-retrievable exports (one agent; after N7)

**Goal (owner's words):** "search for video footage of when a car came to the front door yesterday … sift through camera motion-detected frames … classify … download it and send it to my Gmail." The MCP is the data plane; the agent (openclaw, with vision + Gmail) does the looking, deciding and sending.

**Deliverables**
- `nvr_list_recording_segments(channel, date, tz="local")` — the NVR's typed recording timeline for a day: `[{start, end, type ∈ {normal, motion, smart, manual, alarm, unknown}, raw_type}]`. Built on the `playback` search the web UI uses (static shape from `endpoints.json`; `nvr_search_recordings` from N3 is folded into this — one implementation, keep the old name as an alias). Live-verified in N5; until then the parser accepts both the inferred and the capture shapes and returns `PROTOCOL_ERROR` with the raw payload under `data.raw` on anything else (never a crash).
- `nvr_list_motion_windows(channel | "all", date | since, until=None, min_gap_s=30, min_len_s=3, kinds=["motion","smart","alarm"])` — merged, de-duplicated windows across sources: typed segments (above) ∪ event logs (`unusual_detection` / `chm_get_msg_alarm_list_extend` / smart-detection modules where they expose per-channel event lists). Output `[{channel, name, start, end, duration_s, kinds, sources}]`, sorted; `summary` with counts per channel. Pure merge logic in `vigi_nvr_mcp/investigate/windows.py` with property tests (overlaps, adjacency within `min_gap_s`, DST boundaries, windows crossing midnight, empty inputs).
- `nvr_contact_sheet(channel, start, end, cols=4, rows=3, width=1600, stream=1)` — one JPEG: `rows×cols` frames at even intervals across the window via RTSP replay (`ffmpeg -vf "select=…,scale=…,tile=CxR"` or `fps=` + `tile`), timestamp burned into each tile (`drawtext` with the computed time) so the agent can cite the exact moment; returns path + the tile→timestamp map. Reuses N7's `FfmpegRunner` (argv only, confinement, serial, timeouts).
- `nvr_sample_frames(channel, start, end, every_s=2, max_frames=60, stream=1)` — individual JPEGs for the hit window; returns paths + timestamps.
- `nvr_export_clip(..., target_max_mb=None, max_width=None)` extension — when set, re-encode (`libx264 -crf` chosen from duration/target; `-preset veryfast`; scale to `max_width`) so the file fits the target (Gmail cap 25 MB documented; default suggestion 20); report `original_bytes`, `encoded_bytes`, `fits_target`. `-c copy` remains the default when no target is given.
- Retrieval for a remote agent: `nvr_get_export(name, max_mb=20)` returns base64 content for files ≤ `max_mb` (else `TOO_LARGE` with the size and the hint to use `target_max_mb`); expose the export directory as MCP **resources** (`exports://<name>`, `blob` content, name regex, path-confined) so clients that support resources can fetch without base64 in the tool result. README documents both paths and that exports live on the server host (`VIGI_NVR_EXPORT_DIR`).
- Retention: `VIGI_NVR_EXPORT_RETENTION_DAYS` (default 7) — `nvr_list_exports` reports age and the next purge; `nvr_purge_exports(confirm_write)` deletes older than retention (double-gated; dry-run lists what would go).
- README "Investigation recipe" an agent can follow verbatim: `nvr_list_motion_windows(channel="Main Door", date=<yesterday>)` → for each window `nvr_contact_sheet` → inspect → on a hit `nvr_sample_frames` to pin the moment → `nvr_export_clip(target_max_mb=20)` → `nvr_get_export` → send via the agent's mail tool. Include a worked example with placeholder names and a note on cost (one contact sheet ≈ one image per window).
- Optional, clearly separated and **not** required for done: `nvr_scan_motion(channel, start, end, every_s=1, threshold)` — server-side frame-difference fallback over RTSP replay (the old "route 3") for when the NVR's own timeline is unavailable; pure numpy-free implementation (ffmpeg `-vf "select='gt(scene,0.x)'"` scene-change detection + `showinfo` timestamps parsed from stderr) returning candidate windows. Build only if N7b's budget (≤14 files / ≤1,500 LOC) allows after everything above; otherwise list it in the report for N8.

**Tests:** window merge properties; contact-sheet argv (tile math, timestamp map, no shell, no creds in argv `repr`); re-encode parameter selection (CRF/scale from duration & target) with the fake ffmpeg; base64 size gate; resource name confinement; retention purge dry-run vs real; all tools return envelopes on ffmpeg failure/timeouts; segment parser on both candidate shapes + garbage. Gate ≥ 90% on `investigate/` and `media/`.

**Done when** gate passes and `--list-tools` shows `nvr_list_recording_segments`, `nvr_list_motion_windows`, `nvr_contact_sheet`, `nvr_sample_frames`, `nvr_get_export`, `nvr_purge_exports` and the extended `nvr_export_clip`. LIVE (N5 addendum): windows for yesterday on the Main Door channel; one contact sheet; one 20 MB-targeted export; `ffprobe` it.
