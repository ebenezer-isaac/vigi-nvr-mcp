# VIGI NVR wire protocol

Everything this server knows about talking to a TP-Link VIGI NVR, in one place.
All of it is verified against **VIGI NVR1016H(UN), firmware 1.1.3 Build 260727**
by reading the vendor web UI's own JavaScript and running it on test vectors
(`tests/fixtures/auth_vectors.json`). Other models and firmware may differ,
especially in the login scheme — see [Auth variations](#auth-variations).

No secrets or real network data appear here; `192.0.2.1` is an RFC 5737
documentation address.

## Transport

- **Pre-auth:** `POST https://<host>:<port>/`
- **Authenticated:** `POST https://<host>:<port>/stok=<token>/ds`
- Headers: `Content-Type: application/json; charset=UTF-8`,
  `X-Requested-With: XMLHttpRequest`.
- The NVR ships a **self-signed** certificate, so TLS verification is off by
  default (`VIGI_NVR_VERIFY_TLS=false`). You can instead pin the certificate by
  its SHA-256 fingerprint (`VIGI_NVR_TLS_FINGERPRINT_SHA256`); the pin is
  enforced on this server's own connection and fails closed on a mismatch.

Every request body is a single JSON object of the form:

```json
{ "method": "get|set|do|add|delete|...", "<module>": { ... } }
```

Every response body carries an `error_code` (`0` = success). On the
authenticated path a non-zero code is mapped to a named error (see
[Error codes](#error-codes)); `-40401` on the `/stok=.../ds` path specifically
means the token expired.

### Wire URL-encoding

Every JSON **string value** is URL-encoded on the wire, in **both**
directions — the client encodes the values it sends and decodes the values it
receives. So a channel named `Front Door` travels as `Front%20Door`, and the
RSA key in a challenge arrives URL-encoded (its `+` as `%2b`, etc.). This is a
value-level transform, not a form encoding of the whole body.

## Authentication

Login is a three-value computation over an RSA challenge. The server makes
**exactly one** login attempt per call path and never retries automatically
(see the lockout notes below).

### 1. Challenge

```json
POST /
{ "method": "do", "user_management": { "get_encrypt_info": null } }
```

Reply (note `error_code` is `-40401` even on success here — it signals
"not yet authenticated", not a failure):

```json
{
  "error_code": -40401,
  "data": {
    "code": 0,
    "encrypt_type": ["1", "2"],
    "key": "<URL-encoded base64 SPKI DER RSA-1024 public key>",
    "nonce": "<8 chars>",
    "time": 0,
    "max_time": 10
  }
}
```

- `encrypt_type` lists the schemes the firmware offers. `"2"` = RSA, `"1"` =
  bare MD5.
- `time` / `max_time` are the device's own failed-attempt counter and its
  lockout threshold, when present. These are surfaced to the caller on every
  failure as `attempts_left` / `max_attempts`.

### 2. Login composition (`encrypt_type` 2)

```
md5_hex   = MD5("TPCQ75NF2Y:" + password).hexdigest().upper()
plaintext = md5_hex + ":" + nonce
ENC       = urlencode( base64( RSA_PKCS1v15_encrypt(challenge_key, plaintext) ) )
```

```json
POST /
{
  "method": "do",
  "login": {
    "username": "<user>",
    "password": "<ENC>",
    "passwdType": "md5",
    "encrypt_type": "2"
  }
}
```

Success:

```json
{ "error_code": 0, "stok": "<32 hex>", "user_group": "root" }
```

The `stok` is the session token used in the authenticated URL. This server
caches it in memory only, never logs it, and never returns it from any tool.

### 3. Login composition (`encrypt_type` 1)

If the firmware offers only `["1"]`, there is no RSA step:

```
password = md5_hex   # MD5("TPCQ75NF2Y:" + password), upper-case hex
```

sent with `encrypt_type: "1"`. On that firmware the password field is a
password-equivalent hash — treat it as a secret.

### Auth variations

The constant salt (`TPCQ75NF2Y`), the MD5 digest and the RSA-PKCS1v15 wrapper
are specific to this firmware line. Other TP-Link firmware is known to use
SHA-256-based schemes. Confirm yours before pointing an agent at the server:

```sh
vigi-nvr-mcp --check-auth           # challenge only: prints offered encrypt_type, NO login
vigi-nvr-mcp --check-auth --login   # plus exactly ONE login attempt
```

`securityEncode` / `orgAuthPwd` in the web UI are **not** part of login; they
build the media-stream password (`pullStreamInfo.password`) and are out of
scope here.

## Session and token lifecycle

- The client logs in lazily (on the first authenticated call) and serialises
  all I/O to one in-flight request per device.
- An expired/invalid token on `/stok=.../ds` returns `-40401`. The client
  re-logs in **once** and retries the call; a second `-40401` is raised as
  `TokenExpired` — it never loops.
- A failed login (`-40401` on `POST /` with a rising `time` counter) is raised
  as `AuthFailed` and is **never** retried. The persistent login breaker records
  it (see the README's safety model).

## Error codes

The firmware's full error table is vendored at
`vigi_nvr_mcp/data/errcodes.json` and mapped by `vigi_nvr_mcp/errors.py`. The
codes that matter for auth and the common tool paths:

| Code | Name | Meaning |
|---|---|---|
| `0` | `ENONE` | Success |
| `-40401` | `EUNAUTH` | Not authenticated: returned by the challenge, by a failed login (with a rising attempt counter), and by an expired session token on `/ds` |
| `-40403` | `ESESSIONTIMEOUT` | Session timed out |
| `-40404` | `ESYSLOCKED` | Account temporarily locked (too many failed logins) |
| `-40408` | `ESYSLOCKEDFOREVER` | Account locked until manual intervention |
| `-40410` | `ESYSNONCEINVALID` | Challenge nonce stale/invalid — fetch a fresh challenge before the next attempt |
| `-40411` | `EUSRUNSUPPORTED` | User/scheme unsupported |
| `-40412` | `ETMPPWD_EXPIRED` | Temporary password expired |
| `-71501` | `ENVRCHMTPARAERR` | Channel-management parameter error |
| `-71520` | `ENVRCHMUUIDINVP` | Channel UUID invalid/mismatched |
| `-71521` | `ENVRCHMDELINVP` | Channel delete parameter invalid |
| `-71554` | `ENVRCHMAUTHFAIL` | Channel (camera) authentication failed |
| `-71558` | `ENVRCHMCHNNCONN` | Channel not connected |
| `-71559` | `ENVRCHMCHNDOWN` | Channel down/offline |

## Channel primitives

Bound cameras ("channels") live under the `chm` module:

| Operation | Method / key | Notes |
|---|---|---|
| List bindings | `get` `chm` `added_dev` | Rows carry `id`, `name`, `ip`, `port`, `protocol`, `online` (`"1"`/`"0"`), `conn_status`, `auth_result`, `uuid`, model; credential fields (`ciphertext`, etc.) are present on the wire but always redacted before a tool returns |
| Remove a binding | `do` `chm` `chm_del_dev` | Unbinds a channel. This server re-reads the row first and refuses unless `expected_uuid` matches; refuses an `online=="1"` row unless `force=true` |
| Move a binding | `set` `chm` `chm_mod_dev_chn` | Moves a binding to an empty slot, keeping its settings; refuses an occupied target |
| Re-auth a binding | `do` `chm` `chm_edit_dev` | Pushes the channel's full `added_dev` row back with `username` and an RSA-encrypted `ciphertext` overwritten, to re-authenticate a camera whose stored password went stale. The password is encrypted with the device's **fixed** `$.encryptPub` key (fetched from `/web-static/lib/jquery-1.10.1.js`), not the per-session login key. The reply's `auth_result == -71558` is a transient "authenticating" state; this server re-reads until `conn_status == auth_result == "0"` |
| Add a binding | `do` `chm` `chm_add_dev_list` | Binds a camera by IP: `{"device_list":[{"connect_prot","ip","port","username","ciphertext","passwd_strength":"low"}]}`. The new binding lands in the **first empty** channel slot (not a chosen id) and the name is **reset** to the model default (e.g. `C210`) |

**Re-pointing a channel to a new IP.** `chm_edit_dev` returns `error_code 0` but
**silently ignores the `ip` field** — `ip` is discovery-derived, not editable (only
`name`/`username`/`ciphertext` take). To move a channel to a new camera IP you must
**delete + re-add + rename**: `chm_del_dev` the old binding, `chm_add_dev_list` at the
new IP (reusing the original row's `connect_prot` and `port`), poll `added_dev` for the
row whose `uuid` matches to learn its new id, then `chm_edit_dev` to restore the
original `name`. `nvr_renumber_channel` performs exactly this sequence. This does **not**
change the camera's own IP/DHCP — the camera must already be reachable at the new IP.

A **ghost** channel is a stale duplicate: another row shares its `uuid`, it is
`online=="0"`, `conn_status != "0"`, and it either failed auth (`auth_result ==
"1"`) or still carries its generic model name. `nvr_find_duplicate_channels`
groups by `uuid` and flags ghosts; `nvr_plan_channel_cleanup` turns that into an
ordered, resumable remove/re-home plan.

## RTSP (video delivery)

Video is delivered over **RTSP**, not JSON. ONVIF/RTSP is a one-time enable on
many units (port 554 closed by default):

- Read: `get` `onvif_server` `{ "name": "onvif" }` → `onvif_server.onvif.enabled`
- Enable: `set` `onvif_server` `{ "onvif": { "enabled": "on" } }` (write-gated)

URL shapes (TP-Link FAQ 5223), with `<stream>` = 1 (main) or 2 (sub):

```
live:   rtsp://<user>:<pass>@<host>:<port>/live/<channel>/<stream>/avm
replay: rtsp://<user>:<pass>@<host>:<port>/replay/<channel>/<stream>/avm
        ?starttime=YYYYMMDDtHHMMSSz&endtime=YYYYMMDDtHHMMSSz
```

The timestamps are UTC (`z`); newer firmware may accept `l` for local time.
Username and password are URL-encoded into the userinfo. Every URL this server
returns or logs is redacted (`<redacted>:<redacted>@host`); only `ffmpeg` ever
receives the plaintext URL, which is why the deploy target is a single-admin
box and a dedicated viewer account is recommended
(`VIGI_NVR_RTSP_USERNAME` / `VIGI_NVR_RTSP_PASSWORD`).

## The catalog

Beyond the hand-written tools, the whole documented API surface is vendored as
a catalog at `vigi_nvr_mcp/data/endpoints.json`: **61 modules, 586 calls** (with
a `_about`/`_conventions` header and a checked-in `endpoints.sha256`). The
`nvr_call` gateway validates `(module, method, key, params)` against it and
routes any catalogued call through the same write-gating and redaction as the
typed tools, so coverage is the inventory rather than 586 separate
registrations. `nvr_raw_call` is the off-catalog escape hatch and is write-gated
unless the method is `get`.
