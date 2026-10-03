"""Breaker r2 — vector catalog-integrity — F3: ``validate_params`` lets Unicode
line/paragraph separators and the BOM through.

The claim: params are validated with "no control chars". ``validate_params`` enforces
this with ``[\\x00-\\x1f\\x7f-\\x9f]`` — the C0/C1 range only. Characters that are
line terminators or formatting controls OUTSIDE that range pass:

* U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR — real line breaks that are
  treated as newlines by JSON-in-JS parsers and by log viewers (log-injection);
* U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM.

These travel verbatim into the request body (and into logs / any echoed envelope).
Each test asserts the claim's "no control chars" and fails against current code.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.catalog import validate_params
from vigi_nvr_mcp.core.errors import InvalidInput

SEPARATORS = [
    (" ", "U+2028 LINE SEPARATOR"),
    (" ", "U+2029 PARAGRAPH SEPARATOR"),
    ("﻿", "U+FEFF ZERO WIDTH NO-BREAK SPACE / BOM"),
]


@pytest.mark.parametrize("char,name", SEPARATORS, ids=[n for _, n in SEPARATORS])
def test_unicode_separators_in_value_are_rejected(char: str, name: str) -> None:
    with pytest.raises(InvalidInput):
        validate_params({"note": f"line-a{char}line-b"})
    # If no exception was raised, the character passed the control-char screen.
    pytest.fail(f"{name} passed validate_params' control-char check and would reach the wire")


def test_c0_c1_controls_are_still_rejected() -> None:
    """Sanity anchor (expected PASS): genuine C0/C1 controls ARE caught, so the gap
    above is specifically the non-C0/C1 separators, not a blanket failure."""
    for bad in ("\x00", "\x07", "\x1f", "\x7f", "\x85"):
        with pytest.raises(InvalidInput):
            validate_params({"k": f"a{bad}b"})
