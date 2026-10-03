"""x1c round 2 - F5: the conformance suite does NOT prove "all of this".

The claim: "the export lock (export_lock.py) built on the same store has the same
guarantees; the package-agnostic conformance suite proves all of this identically in
every repo." Two structural gaps falsify that:

1. The canonical ``tests/conformance/test_breaker_contract.py`` exercises only
   ``LoginBreaker``. It never constructs ``ExportSerial`` nor the store's own
   ``reserve()`` primitive - the exact surfaces that still carry round-1 F1 (see
   test_export_lock_overadmit.py). So the suite cannot "prove the export lock has the
   same guarantees"; it never looks at it.

2. ``export_lock.py`` is absent from ``core/VERSION``'s identity manifest. The X1
   identity test only hashes files under ``core/`` plus the conformance test, so
   ``export_lock.py`` can drift between repos and over revisions with nothing to
   catch it - it is neither copied-verbatim-with-teeth nor behaviourally conformed.

Both assertions describe the intended guarantee and FAIL on shipped code.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONFORMANCE = ROOT / "tests" / "conformance" / "test_breaker_contract.py"
VERSION = ROOT / "vigi_nvr_mcp" / "core" / "VERSION"


def test_conformance_suite_covers_the_export_lock() -> None:
    text = CONFORMANCE.read_text(encoding="utf-8")
    assert "ExportSerial" in text or "export" in text.lower(), (
        "the conformance suite never references the export lock, yet the claim says it "
        "'proves all of this identically' including the export lock's guarantees"
    )


def test_export_lock_is_pinned_by_the_identity_manifest() -> None:
    manifest = json.loads(VERSION.read_text(encoding="utf-8"))["manifest"]
    keys = set(manifest)
    assert any("export_lock" in k for k in keys), (
        "export_lock.py is built on the shared store but is not hashed by core/VERSION, "
        "so it is excluded from the X1 verbatim-identity guarantee the claim relies on; "
        f"manifest covers: {sorted(keys)}"
    )
