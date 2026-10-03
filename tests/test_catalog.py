"""Catalog loading, lookup, nearest-match and build_body validation."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from vigi_nvr_mcp.catalog import (
    MAX_DEPTH,
    MAX_KEYS,
    MAX_STRING_BYTES,
    CallSpec,
    Catalog,
    get_catalog,
)

VENDORED = Path(__file__).resolve().parent.parent / "vigi_nvr_mcp" / "data" / "endpoints.json"

EXPECTED_MODULES = 61
EXPECTED_CALLS = 586
EXPECTED_MUTATING = 217


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return Catalog.load()


# ---- counts (a trimmed file must fail) ---------------------------------------


def test_counts_match_the_vendored_file_and_the_contract(catalog: Catalog) -> None:
    raw = json.loads(VENDORED.read_text(encoding="utf-8"))
    calls = [c for m in raw["modules"].values() for c in m["calls"]]
    file_counts = (len(raw["modules"]), len(calls), sum(1 for c in calls if c.get("mutates")))

    # The file itself must carry exactly the contracted inventory...
    assert file_counts == (EXPECTED_MODULES, EXPECTED_CALLS, EXPECTED_MUTATING)
    assert raw["module_count"] == EXPECTED_MODULES
    # ...and the catalog must expose the same numbers.
    assert catalog.module_count == EXPECTED_MODULES
    assert catalog.call_count == EXPECTED_CALLS
    assert catalog.mutating_count == EXPECTED_MUTATING
    assert len(catalog.modules()) == EXPECTED_MODULES


def test_module_summaries_sum_to_totals(catalog: Catalog) -> None:
    rows = catalog.modules()
    assert sum(r["call_count"] for r in rows) == EXPECTED_CALLS
    assert sum(r["mutating_count"] for r in rows) == EXPECTED_MUTATING
    assert all(r["name"] and r["call_count"] >= 1 for r in rows)


def test_get_catalog_is_cached() -> None:
    assert get_catalog() is get_catalog()


# ---- lookup and nearest ------------------------------------------------------


def test_find_returns_callspec(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    assert isinstance(spec, CallSpec)
    assert (spec.module, spec.method, spec.key) == ("chm", "get", "channel")
    assert spec.mutates is False


def test_find_unknown_raises_lookuperror(catalog: Catalog) -> None:
    with pytest.raises(LookupError):
        catalog.find("chm", "get", "no_such_key")
    with pytest.raises(LookupError):
        catalog.find("no_such_module", "get", "x")


def test_calls_lists_only_that_module(catalog: Catalog) -> None:
    calls = catalog.calls("chm")
    assert calls and all(c.module == "chm" for c in calls)


def test_calls_unknown_module_raises(catalog: Catalog) -> None:
    with pytest.raises(KeyError):
        catalog.calls("not_a_module")


def test_nearest_offers_three_matches_for_a_typo(catalog: Catalog) -> None:
    near = catalog.nearest("chm", "get", "channl")  # typo of a real key
    assert len(near) == 3
    assert all(set(m) == {"module", "method", "key"} for m in near)
    assert {"module": "chm", "method": "get", "key": "channel"} in near


def test_nearest_always_returns_up_to_n_even_when_dissimilar(catalog: Catalog) -> None:
    assert len(catalog.nearest("zzzzz", "zzz", "zzzzz", n=3)) == 3
    assert catalog.nearest_modules("chmm")[0] == "chm"


# ---- build_body: shape -------------------------------------------------------


def test_build_body_wraps_method_and_module(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    body = catalog.build_body(spec, {"display": "x"})
    assert body == {"method": "get", "chm": {"display": "x"}}
    assert json.loads(json.dumps(body))["method"] == "get"


def test_build_body_none_params(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    assert catalog.build_body(spec, None) == {"method": "get", "chm": None}


def test_build_body_rejects_unknown_top_level_keys_unless_allowed(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")  # has a params_example shape
    with pytest.raises(ValueError, match="unknown parameter"):
        catalog.build_body(spec, {"not_a_real_field": 1})
    # allow_extra bypasses the shape check
    body = catalog.build_body(spec, {"not_a_real_field": 1}, allow_extra=True)
    assert body == {"method": "get", "chm": {"not_a_real_field": 1}}


def test_specs_without_example_accept_any_keys(catalog: Catalog) -> None:
    spec = next(c for c in catalog.calls("chm") if c.params_example is None)
    assert catalog.build_body(spec, {"anything": 1})["chm"] == {"anything": 1}


# ---- build_body: param validation (adversarial, before any I/O) --------------


def test_rejects_non_object_params(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    with pytest.raises(ValueError, match="object or null"):
        catalog.build_body(spec, ["not", "a", "dict"])  # type: ignore[arg-type]


def test_rejects_depth_bomb(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    bomb: dict = {"a": "deep"}
    for _ in range(MAX_DEPTH + 2):
        bomb = {"a": bomb}
    with pytest.raises(ValueError, match="nested deeper"):
        catalog.build_body(spec, bomb, allow_extra=True)


def test_rejects_too_many_keys(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    wide = {f"k{i}": 1 for i in range(MAX_KEYS + 10_000)}
    with pytest.raises(ValueError, match="more than"):
        catalog.build_body(spec, wide, allow_extra=True)


def test_rejects_oversized_string(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    with pytest.raises(ValueError, match="4 KB"):
        catalog.build_body(spec, {"x": "A" * (MAX_STRING_BYTES + 1)}, allow_extra=True)


@pytest.mark.parametrize("bad", ["\x00nul", "line\nbreak", "tab\there", "bell\x07"])
def test_rejects_control_characters(catalog: Catalog, bad: str) -> None:
    spec = catalog.find("chm", "get", "channel")
    with pytest.raises(ValueError, match="control characters"):
        catalog.build_body(spec, {"x": bad}, allow_extra=True)


@pytest.mark.parametrize("bad_key", ["a b", "a/b", "../x", "x" * 65, "has$ign", ""])
def test_rejects_bad_keys(catalog: Catalog, bad_key: str) -> None:
    spec = catalog.find("chm", "get", "channel")
    with pytest.raises(ValueError, match="invalid parameter key"):
        catalog.build_body(spec, {bad_key: 1}, allow_extra=True)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_rejects_non_finite_numbers(catalog: Catalog, bad: float) -> None:
    spec = catalog.find("chm", "get", "channel")
    with pytest.raises(ValueError, match="finite"):
        catalog.build_body(spec, {"x": bad}, allow_extra=True)


def test_rejects_non_json_value(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    with pytest.raises(ValueError, match="non-JSON"):
        catalog.build_body(spec, {"x": {1, 2, 3}}, allow_extra=True)  # type: ignore[arg-type]


def test_accepts_nested_within_limits(catalog: Catalog) -> None:
    spec = catalog.find("chm", "get", "channel")
    ok_params = {"a": {"b": {"c": ["x", 1, True, None, 1.5]}}}
    assert catalog.build_body(spec, ok_params, allow_extra=True)["chm"] == ok_params


# ---- fuzz: every build_body output is valid JSON carrying "method" -----------


def test_fuzz_fifty_specs_build_valid_json(catalog: Catalog) -> None:
    rng = random.Random(1234)  # noqa: S311 -- fuzzing test data, not cryptographic
    specs = [catalog.find(m, meth, k) for (m, meth, k) in _all_triples(catalog)]
    for spec in rng.sample(specs, 50):
        params = _random_params(rng, spec)
        body = catalog.build_body(spec, params, allow_extra=True)
        encoded = json.dumps(body)  # must be serialisable
        round_tripped = json.loads(encoded)
        assert round_tripped["method"] == spec.method
        assert spec.module in round_tripped


def _all_triples(catalog: Catalog) -> list[tuple[str, str, str]]:
    return [
        (row["name"], c.method, c.key)
        for row in catalog.modules()
        for c in catalog.calls(row["name"])
    ]


def _random_params(rng: random.Random, spec: CallSpec) -> dict:
    keys = list(spec.params_example or {}) or ["a", "b"]
    choices = ["x", 1, True, None, 1.5, ["n"], {"k": "v"}]
    return {k: rng.choice(choices) for k in rng.sample(keys, k=min(len(keys), 3))}
