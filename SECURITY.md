# Security policy

`vigi-nvr-mcp` is designed to be safe to hand to an autonomous agent that can
reach a camera NVR on a home or small-office network. This document states the
threat model, what the safety mechanisms do and do not protect, and how to report
a problem.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue:

- Use GitHub's **private vulnerability reporting** on this repository
  (Security → Report a vulnerability), or
- open a regular issue that says only "security report, please provide a private
  channel" with no details.

Include the affected version/commit, the NVR model and firmware, reproduction
steps, and the impact. **Remove all secrets** (passwords, `stok`/session tokens,
`ciphertext` values, real IPs/MACs/serials) before sending anything — redact
`--check-auth` output the way the tool itself does. Please allow a reasonable
window for a fix before any public disclosure.

## Threat model

### 1. A LAN attacker

Someone on the same network as the NVR or the host running this server.

- The MCP server **has no authentication of its own** and must be bound to
  loopback (`127.0.0.1`) and reached over Tailscale or an SSH tunnel. Binding it
  to a LAN address hands full tool access to anyone on the LAN; the server logs a
  warning if you bind HTTP to a non-loopback address.
- NVR traffic is HTTPS, but VIGI NVRs ship **self-signed** certificates, so
  verification is off by default and a LAN attacker could MITM the NVR
  connection. Pin the certificate (`VIGI_NVR_TLS_FINGERPRINT_SHA256`) to close
  this; the pin is enforced on the server's own connection and fails closed on
  mismatch. `nvr_status` reports the observed fingerprint for trust-on-first-use.
- **RTSP credentials** are passed to `ffmpeg` in the URL userinfo and are
  therefore visible to local `ps` on the server host. Run on a single-admin box
  and use a dedicated viewer account (`VIGI_NVR_RTSP_USERNAME` /
  `VIGI_NVR_RTSP_PASSWORD`).

### 2. A compromised or careless MCP client

The agent/client connected to this server is assumed to be powerful but not
fully trusted — a prompt-injected agent should not be able to damage the NVR or
exfiltrate credentials.

- **Writes are double-gated:** both `VIGI_NVR_ALLOW_WRITES=true` (server env) and
  a typed `confirm_write: true` (per call) are required. Truthy strings/numbers
  do not satisfy the gate and are refused with no network call. Leave
  `VIGI_NVR_ALLOW_WRITES=false` for read-only agents.
- **Channel writes** re-read the live row and require a matching
  `expected_uuid`, refuse live rows without `force`, and refuse occupied move
  targets, so an agent cannot blindly remove or overwrite the wrong camera.
- **Credentials never leave the server.** Tool output is recursively stripped of
  credential-bearing fields; no tool returns the session token, camera
  ciphertext, or any password. Request bodies are never logged and tokens are
  masked in all logs.
- **`dry_run`** lets you review the exact request bodies an agent would send
  before enabling writes.

### 3. Device lockout (availability)

The signature risk of this class of device: too many failed logins lock the
`admin` account, taking the NVR and its recordings offline.

- A failed login is **never** auto-retried.
- The persistent, per-host **breaker** trips after a small failure budget
  (default 1) and refuses further logins until a human clears it; admit-and-
  record is one atomic step under a cross-process lock, so even concurrent
  processes or a crash-loop cannot overspend the budget. A corrupt or unwritable
  state file fails **closed**.
- `--check-auth` validates the login scheme using only the credential-free
  challenge, spending no attempt; `--check-auth --login` spends exactly one.
- `VIGI_NVR_LOGIN_DISABLED=true` freezes all authentication before any network
  I/O.

## What this does not protect against

- A fully trusted, authorised write agent with `VIGI_NVR_ALLOW_WRITES=true` can
  still make real changes — that is the point of the gate, not a bug.
- Exported footage on disk is **not encrypted**; protect `VIGI_NVR_EXPORT_DIR`
  and `VIGI_NVR_BACKUP_DIR` with filesystem permissions (created 0700/0600).
- Weak NVR passwords, compromised cameras, or the NVR's own firmware
  vulnerabilities are out of scope.

## Supported versions

Only the latest release receives security fixes.
