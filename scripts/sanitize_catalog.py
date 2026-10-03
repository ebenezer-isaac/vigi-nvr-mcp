#!/usr/bin/env python3
"""Sanitise the discovery endpoint inventory before vendoring it into the package.

The raw inventory (scratchpad ``nvr/discovery/endpoints.json``) is built from a
live NVR and may carry real LAN data in its examples. This rewrites, in every
string value:

* private IPv4 (``10.*``, ``172.16-31.*``, ``192.168.*``) -> RFC 5737 ``192.0.2.x``
* MAC addresses                                           -> RFC 7042 ``00:00:5E:00:53:xx``
* 32- then 12-hex identifiers (uuids)                     -> all-zero placeholders

and, by field name, every serial/barcode value to ``SERIAL0000`` and every
non-generic hostname/alias to ``example``. Placeholder values such as
``<value>`` are left untouched. It then asserts the structure is intact
(61 modules / 586 calls / 217 mutating) and that ``scripts/check_no_secrets.py``
finds nothing in the result.

Usage:
    python scripts/sanitize_catalog.py <input.json> <output.json>

The vendored file ``vigi_nvr_mcp/data/endpoints.json`` was produced by running
this over the discovery inventory; re-running it is idempotent.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# Expected inventory shape; a trimmed or bloated file fails the gate below.
EXPECTED_MODULES = 61
EXPECTED_CALLS = 586
EXPECTED_MUTATING = 217

_PLACEHOLDER = re.compile(r"^<[^>]*>$")
_PRIVATE_IPV4 = re.compile(
    r"(?<![\d.])(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")(?![\d])"
)
_MAC = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
    r"(?![0-9A-Fa-f:-])"
)
_HEX32 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
_HEX12 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")

_SERIAL_KEY = re.compile(r"(?i)(serial|barcode|(^|_)sn(_|$))")
_HOST_KEYS = frozenset(
    {"hostname", "host_name", "alias", "dev_alias", "devalias", "devname", "dev_name"}
)
# Keep values that name a generic device model rather than a real host.
_GENERIC_MODEL = re.compile(
    r"(?i)\b(nvr|vigi|tapo|archer|tl-|ipc|camera|model)\b|^[A-Z]{1,4}\d{2,}"
)


def _ip_sub(match: re.Match[str]) -> str:
    return "192.0.2." + match.group(0).rsplit(".", 1)[-1]


def _mac_sub(match: re.Match[str]) -> str:
    sep = match.group(1)
    last = re.split(r"[:-]", match.group(0))[-1]
    return sep.join(("00", "00", "5E", "00", "53", last))


def sanitize_string(key: str | None, value: str) -> str:
    """Return ``value`` with any real network data replaced; placeholders are kept."""
    if _PLACEHOLDER.match(value):
        return value
    out = _PRIVATE_IPV4.sub(_ip_sub, value)
    out = _MAC.sub(_mac_sub, out)
    out = _HEX32.sub(lambda _m: "0" * 32, out)
    out = _HEX12.sub(lambda _m: "0" * 12, out)
    if key is not None:
        lowered = key.lower()
        if _SERIAL_KEY.search(lowered):
            return "SERIAL0000"
        if lowered in _HOST_KEYS and not _GENERIC_MODEL.search(out):
            return "example"
    return out


def sanitize_value(key: str | None, value: Any) -> Any:
    """Recursively sanitise a JSON value, returning new objects (no mutation)."""
    if isinstance(value, dict):
        return {k: sanitize_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(key, item) for item in value]
    if isinstance(value, str):
        return sanitize_string(key, value)
    return value


def count_inventory(data: dict[str, Any]) -> tuple[int, int, int]:
    """Return (modules, calls, mutating) for an inventory dict."""
    modules = data["modules"]
    calls = [c for m in modules.values() for c in m["calls"]]
    mutating = sum(1 for c in calls if c.get("mutates"))
    return len(modules), len(calls), mutating


def _assert_clean(output_path: Path) -> None:
    # Imported lazily so the pure helpers above can be used without scripts/ on
    # the import path (e.g. from tests via importlib).
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import check_no_secrets

    findings = check_no_secrets.scan_file(output_path, output_path.name)
    if findings:
        joined = "\n".join(str(f) for f in findings)
        raise AssertionError(f"check_no_secrets flagged the sanitised output:\n{joined}")


def sanitize_file(input_path: Path, output_path: Path) -> dict[str, Any]:
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    before = count_inventory(raw)
    clean = sanitize_value(None, raw)
    after = count_inventory(clean)

    if after != before:
        raise AssertionError(f"sanitising changed the inventory shape: {before} -> {after}")
    if after != (EXPECTED_MODULES, EXPECTED_CALLS, EXPECTED_MUTATING):
        raise AssertionError(
            f"inventory counts {after} do not match the expected "
            f"({EXPECTED_MODULES}, {EXPECTED_CALLS}, {EXPECTED_MUTATING})"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" keeps the vendored file byte-identical across platforms.
    output_path.write_text(
        json.dumps(clean, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    _assert_clean(output_path)
    return clean


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    sanitize_file(Path(argv[1]), Path(argv[2]))
    print(
        f"sanitised {argv[1]} -> {argv[2]}: "
        f"{EXPECTED_MODULES} modules / {EXPECTED_CALLS} calls / {EXPECTED_MUTATING} mutating; "
        "secret scan clean"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
