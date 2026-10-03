# Breaker round 1 — vector catalog-gateway — vigi-nvr-mcp @ db9f786
Model: claude-opus-4-8 (commit trailer uses the configured subagent id, Claude Fable 5.1)
Branch: breaker/r1-catalog-gateway

Claim attacked:
> In `vigi-nvr-mcp`, `nvr_call` (the generic gateway) and `catalog.py` validate every call
> before any I/O: unknown `(module, method, key)` combinations are refused with no network
> call; params are rejected before I/O when they exceed depth 6, 200 keys, 4 KB strings,
> contain control characters, or have keys outside `[A-Za-z0-9_.-]{1,64}`; any call that is
> mutating by catalog flag OR by method != `get` is write-gated; the vendored error table
> maps every documented code to a meaning and unknown codes are reported as unknown, not
> swallowed; the catalog data files are public-safe and load fails loudly if a file is
> missing, truncated or tampered; a token expiry in the middle of a multi-call tool
> re-authenticates once and replays the failed call exactly once.

## Verdict

The claim is **largely false at this commit**, for two distinct reasons:

1. **Most of it is not built yet.** Commit `db9f786` ("refactor: standalone layout") is
   N1-era. There is **no catalog gateway**: `catalog.py` is a 20-line error-code map
   (`code_to_symbol` / `symbol_for`) with **no** `endpoints.json`, `Catalog`, `CallSpec`,
   `find`, `build_body`, or any `(module, method, key)` validation. The "generic gateway"
   `nvr_call` (in `tools/raw.py`) validates only through `client.validate_call`: method in a
   5-element set, module regex `^[A-Za-z][A-Za-z0-9_]{0,63}$`, params is dict/None, and
   `len(repr(params)) <= 64 KiB`. The depth-6 / 200-key / 4 KB-string / control-char /
   key-charset / unknown-call guards **do not exist**. These are catalogued under
   *Not yet implemented (spec N2)* below (per the brief: absent != broken).

2. **What *does* exist has real defects**, below as F1-F5.

Of the claim, only these clauses actually **hold** (evidenced, passing, in
`test_axes_that_hold.py`): write-gating by `method != get` with no I/O; `confirm_write` not
coerced from truthy strings; odd/absent `error_code`s (2^31, float, string, missing) reported
as `DEVICE_API_ERROR`/`TRANSPORT_ERROR` and never silently succeeding; **unknown non-zero
codes reported, not swallowed**; and **token-expiry mid multi-call re-authenticates once and
replays exactly once** (a second expiry propagates with no third login).

Axes that produced nothing: **secrets** - `scripts/check_no_secrets.py` is clean and a direct
grep of `vigi_nvr_mcp/data/*.json` for `192.168.`, `10.x`, `172.16-31.x`, MACs, 32-hex,
uuid/serial patterns found **no hits** (the only data file is `errcodes.json`; there is no
`endpoints.json` to leak). **Concurrency/serial-lock** and **device-destructive writes** -
nothing new beyond write-gating, which holds. **Token replay / state machine** - holds.

---

## F1 <nested params crash the gateway - RecursionError escapes the tool>  — Impact 2 (uncaught exception leaves the tool instead of an envelope; violates Master-Plan invariant #5 "never raise out of a tool"; test shows the raise) x Likelihood 3 (params is an LLM-client-supplied argument; a deep-but-tiny object bypasses the 64 KiB guard and is trivial to emit; adversary-reading? **yes**) = 6 Major
Test: tests/breaker/r1/catalog_gateway/test_param_recursion.py::test_nested_params_return_envelope_not_recursionerror
Test: tests/breaker/r1/catalog_gateway/test_param_recursion.py::test_validate_call_crashes_on_depth_bomb
What happens: `validate_call` (client.py:62) measures size with `len(repr(params))`. `repr`
recurses, so a dict nested ~3000 deep (approx 48 KiB of repr - under the 64 KiB cap) raises
`RecursionError` *before* the size comparison completes. In `tools/raw.py::nvr_call` the call
sits inside `try/except ValueError`, which does **not** catch `RecursionError`, so the
exception propagates out of the tool rather than returning `{success:false, error:...}`.
Confirmed: `raw.nvr_call(ctx,"get","system",<3000-deep>)` raises `RecursionError`, 0 device
requests made. Every typed read tool funnels through the same `validate_call`, so the crash is
not confined to the raw tool.
Why (root cause hypothesis): size is estimated with `repr()`, which is itself recursive and
unbounded; there is no depth check, so a cheap deep structure defeats the only params guard.

## F2 <error-code table silently collapses colliding symbols (incl. -1)>  — Impact 2 (the symbol shown for a code is ambiguous/possibly wrong - a diagnostic the owner reads) x Likelihood 2 (-1 is a generic firmware error he can plausibly hit; the other four are mail/WLAN codes; adversary-reading? no) = 4 Minor
Test: tests/breaker/r1/catalog_gateway/test_error_table.py::test_error_codes_invert_without_collision
Test: tests/breaker/r1/catalog_gateway/test_error_table.py::test_minus_one_is_not_silently_resolved
What happens: `errcodes.json` holds 555 `symbol -> code` entries but only **550 distinct
codes**. `catalog.code_to_symbol` inverts to `{code: symbol}` via a dict comprehension, so the
5 codes that carry two symbols keep whichever comes last and **silently drop** the other.
Measured collisions: -1 (ERR_PERCENT / EINVCLOUDERRORGENERIC -> kept EINVCLOUDERRORGENERIC),
-50201, -50202, -50203, -50933. "Maps every documented code" is therefore not lossless.
Why (root cause hypothesis): the table is keyed by symbol (not unique on code) and inverted
without detecting key collisions; the claim assumes a bijection that the data file is not.

## F3 <no integrity check on the catalog; a corrupt file is mislabeled as client input and leaks parser internals>  — Impact 2 (a server-side corruption is reported to the client as the client's own INVALID_INPUT, and the raw parser offset is leaked into the client-facing message - contradicts "fails loudly if truncated/tampered" and Master-Plan 1.8 "errors don't leak internals") x Likelihood 1 (requires write/partial-write to the installed package file; a state not produced outside a test; adversary-reading? no - an attacker with that access has larger powers) = 2 Won't-fix/Minor
Test: tests/breaker/r1/catalog_gateway/test_catalog_integrity.py::test_tampered_errcodes_loads_silently
Test: tests/breaker/r1/catalog_gateway/test_catalog_integrity.py::test_truncated_catalog_mislabeled_and_leaks_internals
What happens: `code_to_symbol` is a lazy `lru_cache`d `json.loads` with no count, checksum or
schema. A **tampered** file (valid JSON, altered entries) loads with no error and serves wrong
symbols. A **truncated** file is not noticed at startup; on the first lookup inside a tool it
raises `json.JSONDecodeError` - a `ValueError` subclass - which `run_tool`'s
`except ValueError -> INVALID_INPUT` catches, so the tool returns
`{"code":"INVALID_INPUT","message":"Expecting ',' delimiter: line 1 column 17 (char 16)"}`:
the owner is told *his* input was invalid, and an internal parser detail is leaked.
Why (root cause hypothesis): no load-time validation of the vendored data, plus a fail-open
`except ValueError` in the shared tool wrapper that cannot tell "client sent bad input" from
"server-side code raised a ValueError".

## F4 <"every documented code has a meaning" is false - ~530 of 555 codes have none>  — Impact 1 (the owner still gets the symbol and numeric code; only the human meaning is missing) x Likelihood 2 (non-curated codes do occur; adversary-reading? no) = 2 Won't-fix/Minor
Test: tests/breaker/r1/catalog_gateway/test_error_table.py::test_every_documented_code_has_a_meaning
What happens: `errors.ERROR_CODES` curates meanings for ~25 login/session codes; every other
documented code resolves via `describe_error_code` to "No curated meaning; see symbol". The
claim's "maps every documented code to a meaning" is literally untrue (e.g. -1). Recorded as
low-severity because the symbol fallback is arguably acceptable design - it is the *claim
wording* that overstates, not necessarily the code.
Why (root cause hypothesis): meanings are a hand-curated subset over a symbol-only data file.

## F5 <input validation lets medium bombs and control chars through to the device>  — Impact 1-2 (control chars / NUL / 300-key / 5 KB params are forwarded verbatim to the NVR) x Likelihood 1 (non-adversarial; adversary-reading? yes - reachable by a crafted tool arg) = 2 Won't-fix/Minor at this commit
Test: tests/breaker/r1/catalog_gateway/test_not_yet_implemented_n2.py::test_param_boundaries_rejected_before_io[*]
What happens: the only guard is `len(repr) <= 64 KiB`, which *does* catch the gross bombs
(100k keys / 50 MB string -> INVALID_INPUT, verified), but a 300-key dict, a 5 KB string, a
value containing NUL, and keys __proto__ / a-newline-b / Cyrillic-homoglyph all pass
validation and are sent on the wire (observed body {'method':'get','system':{'__proto__':'x',
'n':'a\x00b'}}). This is the N2 param-validation that is **not yet built**; listed here only
because the existing guard gives a false impression of validation. See *Not yet implemented*.
Why (root cause hypothesis): N2 param validation is unimplemented; the N1 size guard is the
only check.

---

## Not yet implemented (spec N2) - absent guarantees, scored as if relied upon

These are **not defects of existing code**; they are N2 deliverables missing at `db9f786`.
Each has an evidencing failing test and the band it *would* carry if the claim were relied on.

- **NI1 - No call catalog; unknown (module, method, key) is NOT refused and DOES hit the
  network.** `nvr_call` accepts any regex-valid module and sends it. Measured: `get` on
  `totally_bogus_module_zzz` -> success:true, 3 HTTP requests, body
  {'method':'get','totally_bogus_module_zzz':{'q':1}} delivered. No "three nearest matches",
  no `key` argument at all. *Would-be* Impact 2 x Likelihood 3 (adversary) = **6 Major**.
  Test: test_not_yet_implemented_n2.py::test_unknown_module_is_refused_without_io

- **NI2 - Param limits absent:** depth <= 6, <= 200 keys, strings <= 4 KB, control-char
  rejection, key charset [A-Za-z0-9_.-]{1,64} - none enforced (see F5 evidence).
  *Would-be* Impact 2 x Likelihood 3 (adversary) = **6 Major**.
  Test: test_not_yet_implemented_n2.py::test_param_boundaries_rejected_before_io[*]

- **NI3 - Gateway surface absent:** no Catalog / CallSpec / load / find / build_body /
  modules / calls; no nvr_list_modules / nvr_list_calls / nvr_describe_call; no separate
  nvr_raw_call; no VIGI_NVR_DRY_RUN body echo on nvr_call; no catalog `mutates` flag
  (write-gating works, but purely off method != get).
  *Would-be* Impact 2 x Likelihood 2 = **4 Minor** (functionality gap, not a hazard).
  Test: test_not_yet_implemented_n2.py::test_catalog_gateway_surface_exists

- **NI4 - No endpoints.json count assertions** (module=61 / calls=586 / mutating=217 that the
  spec requires so a trimmed file fails). File does not exist; integrity gap for the catalog
  is therefore wholly unbuilt. *Would-be* Impact 2 x Likelihood 1 = **2**.
  (No separate test; the file's absence is the evidence - vigi_nvr_mcp/data/ holds only
  errcodes.json.)

## Convergence note
F1 is Major (6). Per the rubric a round with any Major has **not converged**. The bulk of the
claim is additionally unmet because N2 is unbuilt (NI1/NI2 would each be Major if those
guarantees were treated as live). Everything the claim asserts about auth/token-replay,
write-gating by method, confirm_write strictness and unknown-code reporting **holds**.
