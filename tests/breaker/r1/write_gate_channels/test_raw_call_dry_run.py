"""Breaker r1 — vector write-gate/channels.

F2: the claim says "with ``VIGI_NVR_DRY_RUN=true`` nothing is sent and the exact
body is returned". The raw gateway ``nvr_call`` (tools/raw.py) has no dry-run
branch: when both write gates are open it calls ``client.call`` directly, so a
mutating request is transmitted even under ``VIGI_NVR_DRY_RUN=true``. The typed
channel tools honour dry-run; the escape-hatch that can send *any* module/method
does not. The assertions encode the claim and FAIL against current code.
"""

# RECONCILED (N1->N2 gateway split, per orchestrator triage WG-F2 'reconcile at
# merge'): these tests were written at the N1-era SHA where tools/raw.py exposed a
# single generic gateway named nvr_call(ctx, method, module, params, ...). N2 split
# that into the catalogued nvr_call(ctx, module, method, key, ...) plus the
# off-catalog escape hatch nvr_raw_call(ctx, method, module, params, ...), which has
# the exact signature and role these tests exercise. Call sites are pointed at
# nvr_raw_call; every assertion is preserved.

from __future__ import annotations

from typing import Any

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.tools import raw


@pytest.fixture
def dctx(make_ctx):
    # Writes enabled AND dry-run enabled: the operator's "preview the body" mode.
    return make_ctx(ALLOW_WRITES="true", DRY_RUN="true")


async def test_nvr_call_write_honours_dry_run(dctx, fake: FakeNvr) -> None:
    """A mutating raw call must not reach the device under DRY_RUN=true."""
    result = await raw.nvr_raw_call(dctx, "set", "system", {"x": 1}, confirm_write=True)

    assert fake.writes == [], (
        "mutating raw call was SENT to the device despite VIGI_NVR_DRY_RUN=true: "
        + repr(fake.writes)
    )
    assert isinstance(result.get("data"), dict)
    assert result["data"].get("dry_run") is True, (
        "nvr_call did not return the dry-run body under data.dry_run"
    )


async def test_nvr_call_destructive_do_honours_dry_run(dctx, fake: FakeNvr) -> None:
    """The most dangerous case: a channel delete issued through the raw gateway.

    Under dry-run the device must see nothing; here the chm_del_dev body is sent.
    """
    captured: list[dict[str, Any]] = []

    def handler(token: str, body: dict[str, Any]) -> dict[str, Any]:
        captured.append(body)
        return {"error_code": 0}

    fake.api_handler = handler
    await raw.nvr_raw_call(
        dctx, "do", "chm", {"chm_del_dev": {"ids": ["9"]}}, confirm_write=True
    )

    assert captured == [], (
        "a chm_del_dev delete reached the device via nvr_call under DRY_RUN=true: "
        + repr(captured)
    )
