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


def test_error_codes_invert_without_collision() -> None:
    table = _raw_table()
    codes = Counter(table.values())
    collisions = {code: n for code, n in codes.items() if n > 1}
    # A lossless code->symbol map requires codes to be unique. They are not:
    # these symbols are silently dropped by catalog.code_to_symbol.
    assert collisions == {}, (
        f"{len(collisions)} error code(s) map to >1 symbol and are silently "
        f"collapsed on inversion: {collisions}"
    )


def test_minus_one_is_not_silently_resolved() -> None:
    table = _raw_table()
    symbols_for_minus_one = sorted(s for s, c in table.items() if c == -1)
    # -1 is documented under two symbols; the catalog returns exactly one of them
    # with no indication the other exists.
    assert len(symbols_for_minus_one) <= 1, (
        f"-1 is ambiguous across symbols {symbols_for_minus_one}; "
        f"catalog.symbol_for(-1) returns only {catalog.symbol_for(-1)!r}"
    )


def test_every_documented_code_has_a_meaning() -> None:
    table = _raw_table()
    without_meaning = [
        code for code in set(table.values())
        if describe_error_code(code) == "No curated meaning; see symbol"
    ]
    # Claim: "maps every documented code to a meaning." It does not.
    assert without_meaning == [], (
        f"{len(without_meaning)} of {len(set(table.values()))} documented codes "
        f"have no curated meaning (e.g. -1 -> {describe_error_code(-1)!r})"
    )
