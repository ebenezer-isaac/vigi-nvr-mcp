"""Breaker r1 / catalog-gateway — F2 & F4: the vendored error table.

Claim: "the vendored error table maps every documented code to a meaning and
unknown codes are reported as unknown, not swallowed."

Two breaks:
  F2 — ``catalog.code_to_symbol`` inverts ``{symbol: code}`` into ``{code: symbol}``.
       errcodes.json has 555 symbols but only 550 distinct codes: 5 codes carry
       two symbols each (``-1`` among them). The inversion silently keeps whichever
       symbol comes last, dropping the other with no error.
  F4 — only ~25 codes have a curated *meaning*; the other ~530 documented codes
       resolve to "No curated meaning; see symbol", so "maps every documented
       code to a meaning" is false. ``-1`` (a generic error the owner can hit) is
       one of them.

The "unknown codes reported as unknown, not swallowed" half of the claim holds
and is characterised in test_axes_that_hold.py.
"""

from __future__ import annotations

import json
from collections import Counter
from importlib import resources

from vigi_nvr_mcp import catalog
from vigi_nvr_mcp.errors import describe_error_code


def _raw_table() -> dict[str, int]:
    text = resources.files("vigi_nvr_mcp").joinpath("data/errcodes.json").read_text("utf-8")
    return json.loads(text)


def test_colliding_symbols_are_all_kept_not_dropped() -> None:
    # RECONCILED to orchestrator decision CG-F2 (fixer brief item 3): the five
    # colliding codes are real firmware data and are KEPT, not de-duplicated.
    # catalog.code_to_symbols(code) returns every symbol for a code (a tuple), so
    # no symbol is silently dropped on inversion. The original test demanded zero
    # collisions, which contradicts the data and the decision.
    table = _raw_table()
    codes = Counter(table.values())
    for code, n in codes.items():
        if n > 1:
            expected = tuple(sorted(s for s, c in table.items() if c == code))
            assert tuple(sorted(catalog.code_to_symbols(code))) == expected, (
                f"colliding code {code} lost a symbol: "
                f"{catalog.code_to_symbols(code)} != {expected}"
            )


def test_minus_one_keeps_both_symbols() -> None:
    # Decision CG-F2: -1 is documented under two symbols; both are retained.
    table = _raw_table()
    symbols_for_minus_one = sorted(s for s, c in table.items() if c == -1)
    assert sorted(catalog.code_to_symbols(-1)) == symbols_for_minus_one, (
        f"-1 must keep all symbols {symbols_for_minus_one}; "
        f"got {catalog.code_to_symbols(-1)!r}"
    )


def test_many_codes_fall_back_to_symbol_meaning() -> None:
    # WON'T-FIX per orchestrator decision CG-F4 (fixer brief): curating a human
    # meaning for all ~550 codes is not required; the symbol fallback is acceptable
    # design, and the "maps every documented code to a meaning" claim was
    # overstated. This documents that uncurated codes fall back to their symbol.
    table = _raw_table()
    without_meaning = [
        code
        for code in set(table.values())
        if describe_error_code(code) == "No curated meaning; see symbol"
    ]
    assert without_meaning, "expected most codes to use the symbol fallback"
    assert describe_error_code(-1) == "No curated meaning; see symbol"
