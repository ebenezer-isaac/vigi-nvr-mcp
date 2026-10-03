"""Breaker r2 — vector catalog-integrity — F2: tamper detection is counts-only.

The claim: ``validate_catalogs()`` "refuses to serve if data/endpoints.json is ...
tampered". The only integrity gate in ``Catalog.load`` is a compare of three totals
(61 modules / 586 calls / 217 mutating) against hard-coded constants — there is no
checksum or per-entry validation. Any edit that preserves those three totals is
served without error:

* flipping one ``mutates`` true->false AND another false->true (counts unchanged);
* editing a ``params_example`` / ``key`` / ``description`` / ``ui_context`` (never
  counted at all) — so ``nvr_describe_call`` can be made to emit attacker-chosen
  example parameters;
* swapping a mutating call's ``method`` (e.g. ``do``->``get``) — the index key
  changes but no total does.

These tests drive the real ``Catalog.load()`` against tampered bytes (via a patched
resource reader) and assert it raises ``ConfigError`` as the claim requires. It does
not. (Reaching the state needs write access to the installed package file, so this is
a supply-chain/tamper goal, not an ordinary path — scored accordingly in FINDINGS.)
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

import vigi_nvr_mcp.catalog as catalog_mod
from vigi_nvr_mcp.catalog import Catalog
from vigi_nvr_mcp.core.errors import ConfigError

REAL_PATH = "vigi_nvr_mcp/data/endpoints.json"


def _load_real() -> dict[str, Any]:
    with open(REAL_PATH, encoding="utf-8") as fh:
        return json.load(fh)


class _FakeResource:
    def __init__(self, text: str) -> None:
        self._text = text

    def joinpath(self, *_parts: str) -> _FakeResource:
        return self

    def read_text(self, *_args: Any, **_kwargs: Any) -> str:
        return self._text


def _load_tampered(data: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> Catalog:
    """Run the product's own Catalog.load() over tampered bytes."""
    text = json.dumps(data, ensure_ascii=False)
    monkeypatch.setattr(
        catalog_mod.resources, "files", lambda _pkg: _FakeResource(text), raising=True
    )
    return Catalog.load()


def test_paired_mutates_flip_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Flip one mutating flag off and another on: all three totals are preserved."""
    data = _load_real()
    flipped_off = flipped_on = None
    for name, info in data["modules"].items():
        for call in info["calls"]:
            if call.get("mutates") and flipped_off is None:
                call["mutates"] = False
                flipped_off = (name, call["method"], call["key"])
            elif not call.get("mutates") and flipped_on is None:
                call["mutates"] = True
                flipped_on = (name, call["method"], call["key"])
        if flipped_off and flipped_on:
            break

    with pytest.raises(ConfigError):
        cat = _load_tampered(data, monkeypatch)
        # If load() did NOT raise, prove the tamper is live before failing the test.
        assert cat.find(*flipped_off).mutates is False  # the flipped-off write call
        pytest.fail(
            "Catalog.load() accepted a tampered inventory: a call that is mutating in "
            f"the real file ({flipped_off}) now reports mutates=False, yet counts still "
            "read 61/586/217, so nothing was detected."
        )


def test_params_example_tamper_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rewrite a call's params_example (never counted) — describe_call would serve it."""
    data = _load_real()
    target = None
    for name, info in data["modules"].items():
        for call in info["calls"]:
            if isinstance(call.get("params_example"), dict) and call["params_example"]:
                call["params_example"] = {"attacker_controlled": "<x>"}
                target = (name, call["method"], call["key"])
                break
        if target:
            break

    with pytest.raises(ConfigError):
        cat = _load_tampered(data, monkeypatch)
        assert cat.find(*target).params_example == {"attacker_controlled": "<x>"}
        pytest.fail(
            "Catalog.load() accepted a tampered params_example "
            f"({target}); nvr_describe_call would hand the LLM attacker-chosen "
            "example parameters with no integrity error."
        )


def test_method_swap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Change a mutating call's method do->get: index key changes, no total does."""
    data = _load_real()
    original = copy.deepcopy(data)
    target = None
    for name, info in data["modules"].items():
        for call in info["calls"]:
            if call.get("mutates") and call["method"] == "do":
                call["method"] = "get"
                target = (name, "get", call["key"])
                break
        if target:
            break
    assert data != original

    with pytest.raises(ConfigError):
        cat = _load_tampered(data, monkeypatch)
        assert cat.find(*target) is not None
        pytest.fail(
            f"Catalog.load() accepted a method-swapped call ({target}); the catalog "
            "now indexes a mutating action under method 'get' with counts intact."
        )
