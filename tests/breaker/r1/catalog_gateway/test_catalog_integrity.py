"""Breaker r1 / catalog-gateway — F3: no integrity check on the data catalog.

Claim: "the catalog data files ... load fails loudly if a file is missing,
truncated or tampered."

``catalog.code_to_symbol`` is a lazy, ``lru_cache``d ``json.loads`` with no count
check, no checksum and no schema:
  * a *tampered* file (valid JSON, altered entries) loads silently and returns
    the wrong symbol;
  * a *truncated* file is not noticed at startup (load is lazy on first lookup)
    and, when it finally fails inside a tool, the ``JSONDecodeError`` is caught by
    the generic tool wrapper and reported as "INTERNAL_ERROR / Unexpected server
    error" — i.e. swallowed, not a loud "catalog corrupt".

(The spec's N2 count assertions — module/call/mutating totals on endpoints.json —
are not implemented at this commit; see test_not_yet_implemented_n2.py.)
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp import catalog
from vigi_nvr_mcp.core.errors import ConfigError
from vigi_nvr_mcp.tools import raw


class _FakePath:
    def __init__(self, text: str) -> None:
        self._text = text

    def joinpath(self, *_a: str) -> "_FakePath":
        return self

    def read_text(self, *_a: object, **_k: object) -> str:
        return self._text


class _FakeResources:
    def __init__(self, text: str) -> None:
        self._text = text

    def files(self, _pkg: str) -> _FakePath:
        return _FakePath(self._text)


def _install_corrupt_catalog(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(catalog, "resources", _FakeResources(text))
    catalog.code_to_symbol.cache_clear()


def test_tampered_errcodes_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    # FIXED (brief item 3): the loader now validates the symbol count and fails
    # loudly with ConfigError on a tampered/truncated file, rather than silently
    # serving a wrong symbol. The 1-entry tampered file has the wrong count.
    tampered = '{"ETOTALLY_WRONG": -40401}'
    try:
        _install_corrupt_catalog(monkeypatch, tampered)
        with pytest.raises(ConfigError):
            catalog.symbol_for(-40401)
    finally:
        catalog.code_to_symbol.cache_clear()


async def test_truncated_catalog_mislabeled_and_leaks_internals(
    monkeypatch: pytest.MonkeyPatch, make_ctx, fake
) -> None:
    truncated = '{"EUNAUTH": -404'  # cut mid-file
    fake.api_handler = lambda _t, _b: {"error_code": -99999}  # forces a symbol lookup
    ctx = make_ctx()
    try:
        _install_corrupt_catalog(monkeypatch, truncated)
        # RECONCILED (N1->N2): the N1 generic gateway is now nvr_raw_call.
        result = await raw.nvr_raw_call(ctx, "get", "system", {})
    finally:
        catalog.code_to_symbol.cache_clear()
    # Claim: load fails loudly. A clear config/catalog error would name the
    # corruption. Instead json.JSONDecodeError (a ValueError subclass) is caught
    # by the generic tool wrapper's `except ValueError` and mislabeled as the
    # CLIENT's INVALID_INPUT -- and the raw parser offset is leaked in message.
    assert result["error"]["code"] == "CONFIG_ERROR", (
        f"corrupt catalog mis-reported as {result['error']['code']} "
        f"with leaked internals: {result['error']['message']!r}"
    )
