"""F1 — the persistent breaker does not survive *concurrent* processes.

Round 1 found the breaker was in-memory; the fix made it a per-host JSON file,
loaded on every ``check`` and written on every ``record_*``. That closes the
*sequential* restart hole (R1-F1). It does NOT close the *concurrent* hole,
because the file protocol is a lock-free read-modify-write:

    check()          -> _load()            (no lock, no flock)
    record_failure() -> _load(); _save()   (no lock, no flock)

Two OS processes that start at the same instant both load an empty ledger
(``failed=0``), both pass ``check`` and both send a real login POST, and then
both write ``failed=1`` -- a lost update. The device therefore sees *two* login
attempts under a budget of one, and the saved count under-reports the real
number of attempts. The claim ("lockout state persists across process
instances ... blocks further logins after a failure") holds only when the
invocations do not overlap.

These tests use mocks/fakes only; no device, no real network.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.core import breaker as breaker_mod
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.core.errors import AuthFailed, LockoutGuard
from vigi_nvr_mcp.transport import NvrTransport


def _settings(state_dir) -> DeviceSettings:
    # Default budget: one failure, then the breaker must block every further login.
    return load_device_settings(NVR_PREFIX, nvr_env(STATE_DIR=str(state_dir)))


def test_lost_update_two_processes_record_only_one_failure(tmp_path) -> None:
    """Two processes each record a distinct failed login; the file keeps only one.

    This is the exact interleaving of two overlapping ``record_failure`` calls:
    each loads the ledger before the other has written. Deterministic, no timing.
    """
    settings = _settings(tmp_path)
    host = settings.host
    proc_a = breaker_mod.LoginBreaker(tmp_path, host, settings)
    proc_b = breaker_mod.LoginBreaker(tmp_path, host, settings)

    # Both processes pass the gate on an empty ledger -> both are allowed to POST.
    proc_a.check(explicit=True)
    proc_b.check(explicit=True)

    # Each then records its own failed attempt. Modelled as the two load/save
    # pairs interleaving (both load 0, both save 1) -- which is what happens when
    # neither process has flushed before the other loads.
    ledger_a = breaker_mod.record_failure(proc_a._load(), {"device_error_code": -40401})
    ledger_b = breaker_mod.record_failure(proc_b._load(), {"device_error_code": -40401})
    proc_a._save(ledger_a)
    proc_b._save(ledger_b)

    final = breaker_mod.LoginBreaker(tmp_path, host, settings)._load()
    assert final.failed == 2, (
        "lost update: two real failed logins were recorded as "
        f"{final.failed}; the budget counter under-reports attempts, so a "
        "crash-loop of overlapping processes keeps re-opening the breaker"
    )


async def test_two_concurrent_logins_both_reach_the_device(tmp_path) -> None:
    """Two concurrent explicit logins against a fresh breaker both POST.

    A barrier guarantees both coroutines are past ``check`` (loaded ``failed=0``)
    before either records its failure, exactly as two parallel processes behave.
    With a budget of one, the device must see at most ONE wrong-credential login
    across all callers; here it sees two.
    """
    settings = _settings(tmp_path)
    barrier = asyncio.Barrier(2)

    class _Gate(httpx.AsyncBaseTransport):
        """Delegates to a FakeNvr transport, but holds the first POST (the
        challenge) at a shared barrier so both logins run in lock-step."""

        def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
            self._inner = inner
            self._gated = False

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if not self._gated:
                self._gated = True
                await barrier.wait()
            return await self._inner.handle_async_request(request)

    fake1 = FakeNvr(password="wrong-on-purpose")
    fake2 = FakeNvr(password="wrong-on-purpose")
    t1 = NvrTransport(settings, http_transport=_Gate(fake1.transport()))
    t2 = NvrTransport(settings, http_transport=_Gate(fake2.transport()))
    auth1 = Authenticator(settings, t1)
    auth2 = Authenticator(settings, t2)

    results = await asyncio.gather(
        auth1.login(), auth2.login(), return_exceptions=True
    )
    await t1.aclose()
    await t2.aclose()

    # Both failed as credential failures (not one blocked by the breaker).
    assert all(isinstance(r, AuthFailed) for r in results), results
    assert not any(isinstance(r, LockoutGuard) for r in results), (
        "expected both to be allowed through concurrently (that is the bug)"
    )

    device_attempts = fake1.login_attempts + fake2.login_attempts
    assert device_attempts <= settings.max_login_failures, (
        f"{device_attempts} login POSTs reached the device under a budget of "
        f"{settings.max_login_failures}: the persistent breaker does not block "
        "concurrent processes, only sequential reruns"
    )
