# Breaker round 2 — vector catalog-integrity — vigi-nvr-mcp @ 0295583
Model: claude-opus-4-8 (commit trailer uses the configured subagent id, Claude Fable 5.1)
Branch: breaker/r2-catalog-integrity

Claim attacked:
> `validate_catalogs()` runs at startup and refuses to serve if `data/endpoints.json`
> or `data/errcodes.json` is missing, truncated, tampered, or has counts != 61 modules /
> 586 calls / 217 mutating / 555 errcodes; `code_to_symbols` returns every symbol for a
> colliding code; `nvr_call(module, method, key, params)` refuses any combination not in
> the catalog with the three nearest matches and no I/O; params are validated structurally
> (depth <= 6 before any recursion, <= 200 keys, strings <= 4 KB, no control chars, key regex)
> in exactly one place used by both `nvr_call` and `nvr_raw_call` and every typed tool;
> `mutates` from the catalog OR method != get gates the write; `nvr_describe_call` output
> never contains real network data; `nvr_list_modules` counts match the file; the sanitiser
> `scripts/sanitize_catalog.py` is idempotent and `check_no_secrets` passes on its output.

## Verdict

Most of the claim **holds**. `validate_catalogs()` is called at startup
(`server.py:32`); the hard-coded 61/586/217/555 count gates catch a *trimmed* file;
`code_to_symbols(-1)` returns both `ERR_PERCENT` and `EINVCLOUDERRORGENERIC`; unknown
triples are refused with nearest matches and **no I/O**; the depth/key/string/key-charset
boundaries are exact (6/200/4096/64 accepted, one-over rejected); `validate_params` is the
single structural validator reached by `build_body` (-> `nvr_call`) and by `validate_call`
(-> `client.call` -> `nvr_raw_call` and every typed tool); write-gating is `spec.mutates OR
method != get`; `nvr_list_modules` counts are computed from the loaded file; and the
vendored `endpoints.json` is secret-clean (grep for private IPv4 / MAC / 32-hex / public
IPs -> 0 hits; `nvr_describe_call` echoes only `<value>` placeholders).

Three defects remain. **F1 is Major** -> the round has **not converged**.

Axes that produced nothing (and why): **nearest-match cost** — difflib on a 1,000-char
module name took 0.02 s, no DoS. **key as None / empty** — both miss the index -> clean
`CALL_NOT_FOUND`, no I/O. **method case** (`GET` vs `get`) — correctly refused
(case-sensitive index), no I/O. **mutating-get / get-mutating** — no catalogued call is
both `method==get` and `mutates`, and `method != get` is gated regardless of the flag, so
the gate holds both ways. **`_about` counts edited to match a trimmed file** — `_about` is
never read; the counts are module constants, so editing it is inert and trimming is still
caught. **zero-call module / intra-module duplicate (method,key)** — none exist in the
file. **4 KB of %-escapes** — validation is pre-encoding (4096 B -> 12 KB on the wire),
but 12 KB is not a DoS. **non-UTF-8 / 200 MB file** — `read_text("utf-8")` raises
`UnicodeDecodeError` (outside the `try`, so not re-wrapped as `ConfigError`) and a 200 MB
file fails the count gate; both still refuse to serve at startup, matching the claim intent.
**secrets** — clean (see above). **code_to_symbols**, **unknown-triple refusal**,
**sanitiser idempotence / check_no_secrets** — hold.

---

## F1 <generic gateway drops the catalogued action-key wrapper — catalogued mutating calls go on the wire malformed> — Impact 2 (a mutating call issued through the documented `nvr_call` path emits a body the firmware does not dispatch on; a retry cannot fix it, and if the device answers error_code:0 to the wrapperless body the operator is misled that the write happened — potential Impact 4) x Likelihood 3 (the generic gateway is the only route to the 251 catalogued do/set/add/delete calls that carry an example, plus 85 with none; an LLM following `nvr_describe_call` emits the wrong shape every time; adversary-reading? yes) = 6 Major
Test: tests/breaker/r2/catalog_integrity/test_wire_format_wrapper.py::test_catalogued_mutating_call_matches_verified_wire
Test: tests/breaker/r2/catalog_integrity/test_wire_format_wrapper.py::test_correct_wrapped_body_is_not_rejected
Test: tests/breaker/r2/catalog_integrity/test_wire_format_wrapper.py::test_every_example_round_trips_through_its_key
What happens: a call is identified by (module, method, key), and the firmware dispatches
a do/set/add/delete call by nesting its parameters **under the action key** —
VERIFIED capture (discovery/channel-management.md):
`{"method":"do","chm":{"chm_mod_dev_chn":{"old_id":"9","new_id":"1"}}}`. But
`build_body` builds `{"method": spec.method, spec.module: params}` and **never references
`spec.key`**, and all 363 non-null `params_example` values store the inner fields
(`{"old_id","new_id"}`), not the wrapper. Following the catalog example,
`nvr_call("chm","do","chm_mod_dev_chn",{"old_id":"9","new_id":"1"},confirm_write=True)`
puts `{"method":"do","chm":{"old_id":"9","new_id":"1"}}` on the wire (confirmed end-to-end
against the fake transport) — the chm_mod_dev_chn level is gone. And passing the
device-correct wrapped body instead is **rejected** by the unknown-top-level-key check
(unknown parameter chm_mod_dev_chn), because that check compares against the
(wrapperless) example. So the only accepted shape is the wrong one; the correct shape
needs `allow_extra=True` AND manual wrapping, which contradicts the catalog own
describe output. test_every_example_round_trips_through_its_key shows this for
**251/251** catalogued do/set/add/delete calls with a dict example. (Live run is the
final judge, per the brief; the evidence is the VERIFIED firmware capture plus the
deterministic body the gateway emits.)
Why (root cause hypothesis): the action name lives only in the catalog `key`; it is never
reflected into params_example nor injected by build_body, so the key-to-body-wrapper
relationship is lost and the fake-transport N2 tests — which do not assert the
device-accepted shape — stay green.

## F2 <catalog integrity is counts-only: a count-preserving tamper is served without error> — Impact 2 (a tampered catalog serves wrong metadata: nvr_describe_call would hand an LLM attacker-chosen example parameters, and mutates flags can be falsified; it does not by itself open the write gate, since no catalogued call is get+mutating) x Likelihood 1 (needs write access to the installed data/endpoints.json; a state not produced outside a test, and an attacker with that access already has larger powers; adversary-reading? the state is a tamper goal, but reachability requires package-write privilege, so 1) = 2 Won't-fix/Minor — but it **disproves the claim "refuses to serve if ... tampered" clause**
Test: tests/breaker/r2/catalog_integrity/test_tamper_undetected.py::test_paired_mutates_flip_is_refused
Test: tests/breaker/r2/catalog_integrity/test_tamper_undetected.py::test_params_example_tamper_is_refused
Test: tests/breaker/r2/catalog_integrity/test_tamper_undetected.py::test_method_swap_is_refused
What happens: Catalog.load only integrity check compares (module_count, call_count,
mutating_count) to the constants (61, 586, 217) — there is **no checksum and no
per-entry validation**. Driving the real Catalog.load() over tampered bytes (patched
resource reader) shows three count-preserving tampers load with no ConfigError: (a)
flipping one mutates true->false and another false->true (chm/do/chm_add_dev_list then
reads mutates=False while the totals still read 61/586/217); (b) replacing a
params_example with {"attacker_controlled":"<x>"} (never counted); (c) swapping a
mutating call method from do to get (changes the index key, no total). A single
true->false flip *is* caught (mutating_count drops to 216) — the compensating flip is what
defeats the gate. The brief "edit a single mutates flag" is therefore caught; a
paired or non-count edit is not.
Why (root cause hypothesis): the file authenticity is reconciled by three aggregate
counts rather than a content hash, so the large space of count-preserving edits is
invisible to the gate.

## F3 <validate_params control-char screen is C0/C1 only — Unicode line/paragraph separators and the BOM pass> — Impact 1 (U+2028/U+2029/U+FEFF travel verbatim into the request body and into any log line / echoed envelope; a viewer or JS-JSON parser treats U+2028/U+2029 as newlines -> log-line injection; no data loss or wrong device action) x Likelihood 2 (a crafted tool argument from an LLM client can carry them; adversary-reading? yes, but low value) = 2 Won't-fix/Minor — **disproves the claim "no control chars" wording**
Test: tests/breaker/r2/catalog_integrity/test_control_char_separators.py::test_unicode_separators_in_value_are_rejected[U+2028 LINE SEPARATOR]
Test: tests/breaker/r2/catalog_integrity/test_control_char_separators.py::test_unicode_separators_in_value_are_rejected[U+2029 PARAGRAPH SEPARATOR]
Test: tests/breaker/r2/catalog_integrity/test_control_char_separators.py::test_unicode_separators_in_value_are_rejected[U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM]
What happens: _CONTROL = [\x00-\x1f\x7f-\x9f] catches C0 and C1 only. validate_params
accepts a string value containing U+2028, U+2029 or U+FEFF; U+0085 (NEL, a C1) is correctly
rejected, so the gap is specifically the non-C0/C1 line/paragraph separators and the BOM.
Why (root cause hypothesis): "no control chars" was implemented as the C0/C1 code-point
range; Unicode Zl/Zp separators and Cf format characters fall outside it.

---

## Convergence note
F1 is Major (6). Per the rubric a round with any Major has **not converged**. F2 and F3
are Minor (2) but each disproves a specific clause of the claim ("refuses to serve if ...
tampered"; "no control chars") and are recorded as task lines. Everything else the claim
asserts — startup validation, trim detection, count gates, code_to_symbols, nearest-match
refusal with no I/O, the exact boundaries, the single validation path, write-gating,
describe/list metadata, and secret-cleanliness — holds (see test_axes_that_hold.py).
