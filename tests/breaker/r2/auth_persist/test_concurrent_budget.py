"""R2 auth-persist F1 — concurrent processes cannot overspend the budget (X1).

The finding: ``check()`` was a lock-free read and ``record_failure`` a lock-free
read-modify-write, so two overlapping processes both passed ``check`` on an empty
ledger, both POSTed a real login under a budget of one, and the lost update left
``failed=1`` after two failures.

X1 collapses admit-and-record into one locked, atomic increment
(:meth:`LoginBreaker.reserve_attempt`): the increment IS the admission, taken under a
cross-process file lock, so a second caller loads a ledger whose ``reserved`` already
reflects the first and is refused. These tests prove the fix in-process; the real
``multiprocessing`` proof (>= 8 processes, exactly one admitted; no lost update) lives
in ``tests/conformance/test_breaker_contract.py``.
"""

from __future__ import annotations

import asyncio

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.core.breaker import LoginBreaker, canonical_device_key
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.core.errors import AuthFailed, BreakerOpen
from vigi_nvr_mcp.core.state import Outcome
from vigi_nvr_mcp.transport import NvrTransport


def _settings(state_dir) -> DeviceSettings:
    return load_device_settings(NVR_PREFIX, nvr_env(STATE_DIR=str(state_dir)))


def test_no_lost_update_between_two_instances(tmp_path) -> None:
    """Two instances on one ledger (budget 2): each reservation is a locked RMW, so
    both failures are recorded - no lost update - and the budget is then spent."""
    key = canonical_device_key("192.0.2.10")
    a = LoginBreaker(tmp_path, key, max_failures=2)
    b = LoginBreaker(tmp_path, key, max_failures=2)
    a.reserve_attempt().release(Outcome.FAILURE, failure={"device_error_code": -40401})
    b.reserve_attempt().release(Outcome.FAILURE, failure={"device_error_code": -40401})
    final = LoginBreaker(tmp_path, key, max_failures=2).status()
    assert final["failures"] == 2 and final["reserved"] == 0


def test_second_concurrent_reservation_is_refused_under_budget_one(tmp_path) -> None:
    """Budget 1: the first reservation is admitted, the second refused before any
    login - the lost-update window is closed."""
    key = canonical_device_key("192.0.2.10")
    a = LoginBreaker(tmp_path, key, max_failures=1)
    b = LoginBreaker(tmp_path, key, max_failures=1)
    a.reserve_attempt()  # admitted (reserved -> 1)
    try:
        b.reserve_attempt()
    except BreakerOpen:
        pass
    else:  # pragma: no cover - would be the F1 bug
        raise AssertionError("second reservation was admitted under a budget of one")


async def test_two_concurrent_logins_only_one_reaches_the_device(tmp_path) -> None:
    """Two concurrent explicit logins share one breaker: exactly one reaches the
    device; the other is refused at reservation with no login POST."""
    settings = _settings(tmp_path)
    fake1 = FakeNvr(password="wrong-on-purpose")
    fake2 = FakeNvr(password="wrong-on-purpose")
    t1 = NvrTransport(settings, http_transport=fake1.transport())
    t2 = NvrTransport(settings, http_transport=fake2.transport())
    auth1 = Authenticator(settings, t1)
    auth2 = Authenticator(settings, t2)

    results = await asyncio.gather(auth1.login(), auth2.login(), return_exceptions=True)
    await t1.aclose()
    await t2.aclose()

    kinds = sorted(type(r).__name__ for r in results)
    assert kinds == ["AuthFailed", "BreakerOpen"], results
    assert isinstance(next(r for r in results if isinstance(r, AuthFailed)), AuthFailed)

    device_attempts = fake1.login_attempts + fake2.login_attempts
    assert device_attempts == 1, (
        f"{device_attempts} login POSTs reached the device under a budget of 1; "
        "the atomic reservation must admit exactly one"
    )
