"""The catalog sanitiser: scrubs real LAN data, preserves the inventory shape."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VENDORED = ROOT / "vigi_nvr_mcp" / "data" / "endpoints.json"


def _ip(*octets: int) -> str:
    """Assemble an IPv4 at runtime so no literal address appears in this source."""
    return ".".join(str(o) for o in octets)


def _mac(*octets: str, sep: str = ":") -> str:
    return sep.join(octets)


def _load_sanitizer():
    path = ROOT / "scripts" / "sanitize_catalog.py"
    spec = importlib.util.spec_from_file_location("sanitize_catalog", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sc = _load_sanitizer()


# ---- string-level scrubbing --------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (_ip(10, 0, 0, 5), "192.0.2.5"),
        (_ip(172, 16, 3, 9), "192.0.2.9"),
        (_ip(192, 168, 1, 77), "192.0.2.77"),
        (f"cam at {_ip(192, 168, 9, 4)} online", "cam at 192.0.2.4 online"),
    ],
)
def test_private_ipv4_is_rewritten(value, expected) -> None:
    assert sc.sanitize_string(None, value) == expected


def test_documentation_ip_is_left_alone() -> None:
    assert sc.sanitize_string(None, _ip(192, 0, 2, 50)) == "192.0.2.50"


def test_mac_is_rewritten_to_documentation_range() -> None:
    dirty = _mac("AA", "BB", "CC", "DD", "EE", "12")
    assert sc.sanitize_string(None, dirty) == "00:00:5E:00:53:12"
    dashed = _mac("aa", "bb", "cc", "dd", "ee", "ff", sep="-")
    assert sc.sanitize_string(None, dashed) == "00-00-5E-00-53-ff"


def test_hex_identifiers_are_zeroed() -> None:
    assert sc.sanitize_string(None, "a1b2c3d4e5f6") == "0" * 12
    assert sc.sanitize_string(None, "f" * 32) == "0" * 32


def test_placeholder_values_are_untouched() -> None:
    assert sc.sanitize_string("name", "<value>") == "<value>"
    assert sc.sanitize_string("hostname", "<value>") == "<value>"


def test_serial_and_hostname_fields_are_scrubbed() -> None:
    assert sc.sanitize_string("serial_number", "TPABC12345") == "SERIAL0000"
    assert sc.sanitize_string("barcode", "9876543210") == "SERIAL0000"
    assert sc.sanitize_string("hostname", "garage-pi") == "example"
    assert sc.sanitize_string("alias", "Front Door") == "example"


def test_generic_model_hostname_is_kept() -> None:
    assert sc.sanitize_string("alias", "VIGI C340") == "VIGI C340"
    assert sc.sanitize_string("hostname", "NVR1016H") == "NVR1016H"


# ---- structure-level ---------------------------------------------------------


def test_sanitize_value_is_recursive_and_pure() -> None:
    source = {
        "net": {"ip": _ip(10, 0, 0, 1), "mac": _mac("AA", "BB", "CC", "DD", "EE", "01")},
        "list": [_ip(192, 168, 0, 9)],
    }
    snapshot = json.loads(json.dumps(source))
    out = sc.sanitize_value(None, source)
    assert out == {"net": {"ip": "192.0.2.1", "mac": "00:00:5E:00:53:01"}, "list": ["192.0.2.9"]}
    assert source == snapshot  # input not mutated


def test_count_inventory() -> None:
    raw = json.loads(VENDORED.read_text(encoding="utf-8"))
    assert sc.count_inventory(raw) == (61, 586, 217)


# ---- end-to-end file run, including the secret-scan assertion -----------------


def test_sanitize_file_scrubs_injected_data_and_keeps_counts(tmp_path) -> None:
    raw = json.loads(VENDORED.read_text(encoding="utf-8"))
    # Inject real-looking LAN data into one call's example.
    first_module = next(iter(raw["modules"]))
    raw["modules"][first_module]["calls"][0]["params_example"] = {
        "ip": _ip(192, 168, 4, 23),
        "mac": _mac("AA", "BB", "CC", "DD", "EE", "07"),
        "hostname": "attic-cam",
    }
    src = tmp_path / "dirty.json"
    src.write_text(json.dumps(raw), encoding="utf-8")
    out = tmp_path / "clean.json"

    clean = sc.sanitize_file(src, out)  # asserts counts + runs check_no_secrets

    assert sc.count_inventory(clean) == (61, 586, 217)
    example = clean["modules"][first_module]["calls"][0]["params_example"]
    assert example == {"ip": "192.0.2.23", "mac": "00:00:5E:00:53:07", "hostname": "example"}
    assert out.exists()


def test_sanitize_file_rejects_a_trimmed_inventory(tmp_path) -> None:
    raw = json.loads(VENDORED.read_text(encoding="utf-8"))
    raw["modules"].pop(next(iter(raw["modules"])))  # drop a module
    src = tmp_path / "trimmed.json"
    src.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(AssertionError, match="counts"):
        sc.sanitize_file(src, tmp_path / "out.json")
