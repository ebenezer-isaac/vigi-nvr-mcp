# Breaker round 2 — vector redact-tls-config — vigi-nvr-mcp @ 0295583
Model: claude-opus-4-8

Claim attacked: "In `vigi-nvr-mcp` @ `0295583`, `redact()` strips every key matching
the documented rules (exact {ciphertext, stok, token, nonce, cookie, secret,
authorization, pubkey, key} u contains {pass, pwd, secret, token, cipher} u endswith
`_key`) at any depth, in lists, without mutating input, and never strips
`auth_result`, `online`, `conn_status`, `uuid`; the rule set in `core/redact.py` and
in `docs/specs/00-MASTER-PLAN.md` S1.6 are identical; with a pin configured, the
transport compares the leaf certificate's SHA-256 (DER) and fails closed with
`TlsPinMismatch` before any request is sent, and the pin is normalised (case, colons)
and validated (64 hex) at config load; `nvr_status`/`--check-auth` report
`tls_fingerprint_observed`; any `VIGI_NVR_*`/`VIGI_MCP_*` key not in the schema fails
loudly naming it; CLI exit codes are 0 ok / 1 auth failed / 2 config error / 3
lockout-breaker-disabled / 4 transport and nothing else; no secret appears in any
log, repr, exception, envelope, `--show`, or `--check-auth` output."

The claim splits into two halves. **The redaction half holds** (round-1 F1 is
genuinely fixed; the rules are implemented and match S1.6). **The TLS-pinning half
does not**: pinning is done against a separate side-channel connection, not the one
that carries the request, and a single transient probe error latches it off for the
life of the transport. A third, smaller break: the r1 "strict env keys" fix was
applied to the device loader only, so `VIGI_MCP_*` typos are still swallowed.

Axes with no finding (controls in `test_controls_axes_that_hold.py`, all pass):

- **Redaction rules vs S1.6.** `_EXACT_KEYS`/`_CONTAINS`/`_ENDSWITH` in `core/redact.py`
  are character-for-character the S1.6 set. Every exact key, every `contains`
  fragment (incl. the r1-F1 misses `nonce`, `cookie`, `pubkey`, `old_password`,
  `new_pwd`, `Authorization`) and every `*_key` key is stripped at top level and
  nested inside lists; `auth_result`, `online`, `conn_status`, `uuid`, `key_present`
  survive. Tuples become lists; input is not mutated; depth/cycles terminate
  (existing `test_core_redact.py` + re-probed). **Round-1 F1 (Major) is fixed.**
- **Redaction out-of-scope edges (scored, not disproofs).** The rules are
  ASCII-substring tests on the lower-cased key, so a homoglyph key (Cyrillic 'a' in
  "Password"), a zero-width/NUL-split key, a secret used as a dict KEY, and a secret
  embedded in a JSON-encoded string VALUE (`{"data": a-json-string-containing-stok}`)
  are not matched -- by design, since the claim is scoped to "every key matching the
  documented rules" and the device emits ASCII field keys. These are
  adversary-authored states hiding adversary-authored values (no real secret gain) or
  reachable only if a real device nests JSON strings. **Impact 4 (potential) x
  Likelihood 1 (witness is this breaker's own fake; device never observed emitting
  them; adversary-reading: no -- the attacker who authors the reply gains nothing by
  hiding their own value) = 4 Minor / effectively Won't-fix.** Over-matching
  (`_row_key` -- a real channel-row id in `client.py` -- and `tokens_remaining`) is
  redacted; functionally harmless because channel tools recompute `channel_id`
  separately, and the task scores over-redaction Minor.
- **Pydantic models / generators / dataclasses.** `redact` passes non-dict/list
  values through unchanged, so a pydantic model or generator holding a secret is not
  descended -- but no tool returns such an object into `run_tool(redact(...))`; tool
  outputs are plain dicts (and `SecretStr` reprs as `**********` anyway). Not
  reachable; no finding.
- **Pin normalisation / validation.** Uppercase and colon forms normalise to 64
  lower-case hex; 63/65-char, `sha256:`-prefixed, non-hex and empty values are
  rejected at config load (`normalise_fingerprint` via a `field_validator`), surfaced
  as `ConfigError`. Base URL is always `https://` (the `DeviceSettings.base_url`
  property forces the scheme), so an HTTP URL with a pin is not reachable. Holds.
- **`verify_tls=True` AND pin set.** Both apply independently; no finding there
  beyond F2 (which is worse when `verify_tls` is left at its `False` default, as the
  data connection then has no validation of any kind).
- **`tls_fingerprint_observed` reporting.** `_challenge_report` includes it and the
  field/plumbing exist (holds) -- but see F2: the value reported is the probe
  connection's cert, not the request connection's.
- **Exit codes.** `_EXIT_BY_CODE` maps AUTH_FAILED->1, CONFIG_ERROR->2,
  LOGIN_REFUSED/BREAKER_OPEN->3, TRANSPORT_ERROR/TLS_PIN_MISMATCH->4, else 1; argparse
  errors exit 2; an uncaught exception exits 1 (all within {0,1,2,3,4}). `--list-tools`
  on a broken config returns 0 because it builds a placeholder device and reads
  `load_global_settings(prefix, {})` -- i.e. it ignores the environment by design, so
  a bad config does not map to exit 2 there; a claim-accuracy nit only (the offline
  lister reaches no error class), not scored.
- **Round-1-on-round-1.** r1 F1 (redaction misses) fixed; r1 F6 (unknown
  `VIGI_NVR_*`) fixed for the device loader -- but not the global loader (F3 below);
  r1 F7 (no cert pinning) is now built but is defeated by F1/F2.

---

## F1 TLS pinning fails OPEN: one transient probe error latches the pin check off for the transport's life -- Impact 4 (the admin password -- RSA-encrypted only with a key fetched over the same channel -- is then interceptable by a LAN on-path attacker; rubric impact-4 "a password ... written anywhere it should not be" / captured) x Likelihood 3 (a first-use TLS/connect blip is one common coincidence away; and disabling the one-shot probe is an attacker's goal -- adversary-reading: yes, so likelihood is its reachability) = 12 Critical (proposed)
Test: tests/breaker/r2/redact_tls_config/test_tls_pin_failopen.py::test_pin_is_reverified_after_a_transient_probe_failure
What happens: `JsonHttpTransport._ensure_pinned` sets `self._pin_checked = True`
*before* it awaits `_peer_cert_der()`. In the test, the first probe raises
`TransportError` (a transient blip) and the first `post_json` errors out -- but the
flag is already latched. The second `post_json` on the same transport finds
`_pin_checked` true, returns from `_ensure_pinned` immediately, and sends the request
through httpx with **no certificate check at all** (probe called 1x, second request
sent). Because the backend builds one transport per process, pinning is silently
disabled for the life of the server after a single early probe failure. With
`verify_tls` defaulting to `False`, that leaves the data connection wholly
unauthenticated -- exactly the state the pin was configured to prevent.
Why (root cause hypothesis): the "check at most once" flag is set before, not after,
a successful verification, so a failed probe is indistinguishable from a passed one
on every later call -- fail-open instead of fail-closed.

## F2 The pin guards a separate side-channel connection, not the one that carries the request (TOCTOU / wrong-connection pinning); the request connection's certificate is never compared to the pin -- Impact 4 (a forged cert on the data connection is accepted while the genuine cert is shown on the probe -> credential interception) x Likelihood 2 (requires a LAN on-path attacker who serves two certs or exploits the two independent connections; adversary-reading: yes -- it is the attacker's goal, reachable but not trivial) = 8 Major (proposed)
Test: tests/breaker/r2/redact_tls_config/test_tls_pin_wrong_connection.py::test_request_serving_certificate_is_the_one_pinned
What happens: `_ensure_pinned` opens its **own** one-shot TLS socket
(`_peer_cert_der` -> `asyncio.open_connection(host, port, ssl=CERT_NONE)`), pins that
certificate, and then lets httpx make a wholly independent connection for the real
POST. In the test the probe presents the genuine cert (matches the pin) while the
`httpx.MockTransport` data connection presents a forged cert (`IMPOSTOR_DER`, != pin)
on its `network_stream`/`ssl_object`. The request succeeds, no `TlsPinMismatch` is
raised, and the forged cert is never even read (`getpeercert` call count 0) because
`_capture_observed` early-returns once the probe has set `_observed`. The claim's
"compares the leaf certificate's SHA-256 (DER) ... before any request is sent" is
compared against the wrong leaf: the probe's, not the request's. As a corollary,
`tls_fingerprint_observed` (surfaced by `nvr_status`/`--check-auth`) reports the
probe cert, so an operator pinning from the observed value can pin a cert the data
path never used.
Why (root cause hypothesis): certificate acquisition for pinning is a second,
CERT_NONE connection decoupled from httpx's connection pool, so the byte stream that
carries credentials is authenticated by nothing that was pinned.

## F3 Unknown `VIGI_MCP_*` keys are silently ignored -- the r1 strict-env-key fix was applied only to the device loader -- Impact 2 (a typo'd global setting silently keeps its default; all three globals fail safe -- stdio / 127.0.0.1 / 8765 -- so the operator is misled about config state but not endangered) x Likelihood 2 (env-file typos happen; r1 F6 established this class on record; adversary-reading: no) = 4 Minor
Test: tests/breaker/r2/redact_tls_config/test_global_config_unknown_key.py::test_unknown_global_key_fails_loudly_and_names_it (and ::test_unknown_global_key_is_not_silently_dropped documents the swallow)
What happens: the r1 fix added an unknown-key scan to `load_device_settings`
(`VIGI_NVR_*`) but `load_global_settings` (`VIGI_MCP_*`) still pre-filters the
environment down to its three known suffixes before validation, so pydantic's
`extra="forbid"` never sees the stray key. `VIGI_MCP_TRANPORT=streamable-http`
(a typo of TRANSPORT) loads with no error and the server keeps `mcp_transport="stdio"`.
The claim's "any `VIGI_NVR_*`/`VIGI_MCP_*` key not in the schema fails loudly naming
it" is false for the entire `VIGI_MCP_*` half.
Why (root cause hypothesis): the fix is an asymmetric copy -- the unknown-key scan
lives in `load_device_settings` but was not mirrored into `load_global_settings`, so
the known-suffix pre-filter still defeats `extra="forbid"` for globals.

---

Convergence: NOT clean -- one Critical (F1) and one Major (F2) proposed (both TLS
pinning), plus one Minor (F3). Per the protocol a Critical/Major in round 2 means the
round did not converge; the two TLS findings share a single root cause (the pin is
enforced on a side-channel probe connection governed by a once-only latch, rather
than on httpx's own connection), which is a candidate for the root-cause/refactor
step rather than a third battery. The redaction half of the claim holds.
