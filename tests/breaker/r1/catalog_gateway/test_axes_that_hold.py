"""Breaker r1 / catalog-gateway — axes that produced NO finding.

These tests pass against the current code; they document the parts of the claim
that hold, so the round's "no finding" verdict on these axes is evidenced rather
than asserted. (Passing tests are not findings.)
"""

# RECONCILED (N1->N2 gateway split, per orchestrator triage WG-F2 'reconcile at
# merge'): these tests were written at the N1-era SHA where tools/raw.py exposed a
# single generic gateway named nvr_call(ctx, method, module, params, ...). N2 split
# that into the catalogued nvr_call(ctx, module, method, key, ...) plus the
# off-catalog escape hatch nvr_raw_call(ctx, method, module, params, ...), which has
# the exact signature and role these tests exercise. Call sites are pointed at
# nvr_raw_call; every assertion is preserved.

from __future__ import annotations

import pytest

from tests.helpers import FAKE_STOK_1
from vigi_nvr_mcp.core.errors import TokenExpired
from vigi_nvr_mcp.tools import raw


# --- write gating by method != get (two-key gate) --------------------------------
@pytest.mark.parametrize("method", ["set", "do", "add", "delete"])
async def test_non_get_methods_are_write_gated_with_no_io(make_ctx, fake, method) -> None:
    ctx = make_ctx()  # ALLOW_WRITES defaults to false
    result = await raw.nvr_raw_call(ctx, method, "system", {"x": 1}, confirm_write=True)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_confirm_write_is_not_coerced_from_truthy_string(make_ctx, fake) -> None:
    ctx = make_ctx(ALLOW_WRITES="true")
    result = await raw.nvr_raw_call(ctx, "set", "system", {"x": 1}, confirm_write="true")  # type: ignore[arg-type]
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_readonly_do_submethod_is_over_blocked(make_ctx, fake) -> None:
    # Minor usability: a read-only `do` (chm_get_msg_alarm_list_extend) is write-gated
    # because there is no catalog `mutates` flag; method != get is the only signal.
    # Consistent with the claim's "... OR by method != get is write-gated".
    ctx = make_ctx()
    result = await raw.nvr_raw_call(ctx, "do", "chm", {"chm_get_msg_alarm_list_extend": None})
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


# --- error_code shape robustness: reported, never swallowed -----------------------
@pytest.mark.parametrize(
    "code",
    [2**31, -40401.0, "-40401", None],  # huge-unknown / float / string / missing
)
async def test_odd_error_codes_are_reported_not_swallowed(make_ctx, fake, code) -> None:
    if code is None:
        fake.api_handler = lambda _t, _b: {"foo": 1}  # error_code absent
    else:
        fake.api_handler = lambda _t, _b: {"error_code": code}
    ctx = make_ctx()
    result = await raw.nvr_raw_call(ctx, "get", "system", {})
    assert result["success"] is False
    # Never a silent success, never an INTERNAL_ERROR swallow.
    assert result["error"]["code"] in {"DEVICE_API_ERROR", "TRANSPORT_ERROR"}


# --- token expiry mid multi-call: re-auth once, replay once ------------------------
async def test_expiry_midbatch_reauths_once_and_replays(ctx, fake) -> None:
    fake.api_handler = lambda _t, _b: {"error_code": 0, "ok": True}
    await ctx.client.call("get", "system", {})  # first call issues FAKE_STOK_1
    fake.revoked.add(FAKE_STOK_1)  # session token expires mid-batch
    result = await ctx.client.call("get", "system", {})  # expiry -> re-auth -> replay
    assert result["error_code"] == 0
    assert fake.login_attempts == 2  # exactly one extra login, not a storm


async def test_expiry_on_replay_propagates_without_third_login(ctx, fake, monkeypatch) -> None:
    calls = {"n": 0}

    async def always_expired(_token: str, _body: dict) -> dict:
        calls["n"] += 1
        raise TokenExpired("expired again")

    monkeypatch.setattr(ctx.client._transport, "post_api", always_expired)
    with pytest.raises(TokenExpired):
        await ctx.client.call("get", "system", {})
    assert calls["n"] == 2  # original + exactly one replay, then it gives up
    assert fake.login_attempts == 2  # initial login + one re-auth, never a third
