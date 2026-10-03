# Breaker round 1 — vector wire-redact-secrets — vigi-nvr-mcp @ db9f786

Model: claude-opus-4-8

Claim attacked: In `vigi-nvr-mcp`, no password, session token (stok), nonce,
camera `ciphertext`, or RSA key can ever appear in logs, exception
messages/tracebacks, tool result envelopes, files written by the package, or
`--list-tools`/`--check-auth` output. `encode_wire`/`decode_wire` are lossless
and applied exactly once in each direction for every request and response
(including the login password field and the server's URL-encoded RSA key).
`redact()` strips every secret-bearing key spelling the device uses and never
mutates its input.

Axes with no finding (executable controls in `test_controls_no_finding.py`, all
pass):

- **Wire encoding.** `decode_wire(encode_wire(x)) == x` holds over thousands of
  random strings containing `+ / % =`, spaces, NUL, unicode, already-encoded
  `%2b`/`%25`, and the empty string. Encoding is applied exactly once per
  direction: the login `password` field is plain base64 on the wire with no
  double-escape, and the server's URL-encoded RSA `key` is decoded exactly once
  (`load_challenge_public_key` deliberately does not unquote again). Numbers,
  bools, `None` and dict keys are untouched. A bare `%` and malformed escapes
  (`%2`, `%ZZ`, `abc%`) are left **literal** — neither raised nor corrupted
  (the `except ValueError` guarding `decode_wire` in `transport._post` is in
  practice dead, because `unquote(..., errors="replace")` never raises; harmless).
- **Secrets in logs.** A DEBUG capture across a successful login, an
  authenticated POST, and a failed login contains no plaintext password, no
  `md5_auth_pwd(password)`, and no raw stok. The stok in `/stok=<t>/ds` is masked
  (`stok=<redacted>`) in both the package's own log line and httpx's
  `HTTP Request:` line (via `_MaskTokenFilter`). `body_summary` logs only method
  + module key names, never values.
- **Secrets in exceptions / repr.** `password` is a pydantic `SecretStr`, so
  `repr(DeviceSettings)` prints `**********`. httpx transport/timeout/JSON-decode
  and pydantic `ValidationError`s are all re-raised with `from None` and a generic
  message carrying only the exception type — the original request body/URL and
  the offending value never surface. `config._format_validation_error` passes
  `include_input=False`.
- **Breaker file / backup name.** No breaker **file** is written at this SHA (the
  breaker is an in-process `LoginLedger`), so there is nothing to leak. The backup
  filename is `nvr-config-<UTC timestamp>.bin` (no secret); the backup *content*
  is the NVR's own config blob, documented as credential-bearing and out of the
  redactor's scope.
- **`--list-tools` / `--check-auth`.** `--list-tools` prints tool names only.
  `_challenge_report` returns `key_present`/`nonce_present` booleans and counters,
  never the key or nonce values; the success path returns `auth.status()` (no
  secret).
- **Redaction immutability / depth / cycles.** `redact()` rebuilds containers and
  does not mutate its input, terminates on cyclic/deep structures, and leaves
  scalars and non-string keys intact (existing `test_core_redact.py` + re-probed).

## F1 redact() omits spec-mandated and claim-protected key spellings — Impact 4 (integration test leaks a session `cookie` and a plaintext password `new_pwd` into a `success` tool envelope; rubric impact-4 = "a password [or] token ... written anywhere it should not be") x Likelihood 2 (evidence below; adversary-reading? yes) = 8 Major

Test:
- `tests/breaker/r1/wire_redact_secrets/test_redact_missing_secret_keys.py::test_secret_bearing_key_is_redacted` (params `nonce`, `cookie`, `pubkey`, `old_password`, `new_pwd`, `Authorization`)
- `tests/breaker/r1/wire_redact_secrets/test_redact_missing_secret_keys.py::test_nonce_and_cookie_from_spec_are_stripped`
- `tests/breaker/r1/wire_redact_secrets/test_redact_missing_secret_keys.py::test_rsa_pubkey_does_not_reach_output_in_clear`
- `tests/breaker/r1/wire_redact_secrets/test_envelope_leaks_via_raw_tool.py::test_nvr_call_envelope_contains_no_plaintext_secret`

What happens: `core/redact.py` strips only the exact keys
`{ciphertext, key, stok, passwd, pwd, token, secret}` plus the prefix
`password`. It therefore passes through, verbatim:

| Key | Status | Why it matters |
|---|---|---|
| `nonce` | LEAKED | named in MASTER-PLAN 1.6 **and** the claim's protected set |
| `cookie` | LEAKED | named in MASTER-PLAN 1.6; a session cookie == a session token |
| `pubkey` | LEAKED | the challenge RSA key when the field is not spelled exactly `key` |
| `old_password` | LEAKED | password-change flow: the current password in clear (prefix is `password`, not `old_password`) |
| `new_pwd` | LEAKED | password-change flow: the new password in clear (`pwd` is matched only exactly) |
| `Authorization` | LEAKED | a bearer/basic credential header value |

The integration test drives the registered `nvr_call` tool with a mocked device
reply
`{"error_code":0,"data":{"nonce":...,"cookie":...,"pubkey":...,"new_pwd":"hunter2",
"password":...,"stok":...}}`. The resulting envelope is
`{"success": true, "data": {... "nonce":"LIVE-NONCE-abc123",
"cookie":"SESSIONID=secret-session-token","pubkey":"RSA-PUBLIC-KEY-DER-BASE64",
"new_pwd":"hunter2", "password":"<redacted>", "stok":"<redacted>"}}` — `password`
and `stok` ARE redacted (the redactor ran), but the four missed spellings reach
the LLM/operator in clear. This directly disproves both "no ... nonce ... or RSA
key can ever appear in ... tool result envelopes" and "redact() strips every
secret-bearing key spelling the device uses".

Likelihood evidence: the witness for a *legitimate* NVR response using these
spellings is this breaker's own fake, so the base likelihood would be 1 — but
(a) MASTER-PLAN 1.6 authors enumerated `nonce` and `cookie` as must-strip,
documentary evidence that the device is expected to emit them, and (b)
`verify_tls` defaults to **False** (`core/config.py`), so any LAN host or MITM
authors the reply body verbatim and chooses the field spelling. Under the rubric's
adversary exception (a crafted device response from a compromised LAN host, which
the master plan's "assume breach" threat model assumes), reaching the state is the
adversary's to control, so likelihood is 2 (reachable, not yet seen on a
production device).

Why (root cause hypothesis): the redaction key set in `core/redact.py`
(`_EXACT_KEYS` + `_PREFIXES`) is a hand-maintained list that drifted from the
single source of truth in MASTER-PLAN 1.6 — `nonce` and `cookie` were dropped,
and `passwd`/`pwd` were encoded as exact matches rather than the `passwd*`/`pwd*`
prefixes the spec specifies, so compound spellings (`old_password`, `new_pwd`,
`pubkey`, `Authorization`) slip through. Do not fix here.
