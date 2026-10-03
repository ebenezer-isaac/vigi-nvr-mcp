"""F1 — the login breaker does not persist across process instances.

Claim under attack: "...persist breaker state across process instances...".
Spec 01-NVR-SPEC.md §N1 line 32: "failed login -> no retry, breaker written".
MASTER-PLAN §1.3: "a persistent breaker (file under <PREFIX>_STATE_DIR...) that
blocks further logins after a failure until a human clears it (breaker --clear)".

``core/breaker.py`` keeps an in-memory ``LoginLedger`` only; nothing is written
to disk. A fresh Authenticator (a new OS process) therefore starts with
``failed=0`` and will issue another real login attempt against the device,
walking the owner's account toward a hard lockout -- exactly what the breaker is
supposed to prevent. These tests assert the persistent behaviour the claim
promises; they fail against the in-memory implementation.
"""

from __future__ import annotations

import pytest

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.backend import NvrBackend
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.core.errors import AuthFailed, LockoutGuard
from vigi_nvr_mcp.transport import NvrTransport


def _settings() -> DeviceSettings:
    # Default budget: 1 failure per process.
    return load_device_settings(NVR_PREFIX, nvr_env())


async def _fail_one_login(settings: DeviceSettings) -> FakeNvr:
    """Simulate one OS process: a single failed login spends the breaker budget."""
    fake = FakeNvr(password="wrong-on-purpose")  # env password mismatches -> -40401
    transport = NvrTransport(settings, http_transport=fake.transport())
    auth = Authenticator(settings, transport)
    with pytest.raises(AuthFailed):
        await auth.login()
    assert fake.login_attempts == 1
    # In-process the breaker is now open: a second login is refused with no I/O.
    with pytest.raises(LockoutGuard):
        await auth.login()
    await transport.aclose()
    return fake


async def test_breaker_stays_open_after_process_restart() -> None:
    settings = _settings()
    await _fail_one_login(settings)  # "process 1" exhausts the budget

    # "process 2": a brand-new Authenticator for the same device/credentials.
    fake2 = FakeNvr(password="wrong-on-purpose")
    transport2 = NvrTransport(settings, http_transport=fake2.transport())
    auth2 = Authenticator(settings, transport2)
    try:
        # The claim/spec: the persisted breaker is still open, so this must be
        # refused locally with ZERO network login attempts.
        with pytest.raises(LockoutGuard):
            await auth2.login()
        assert fake2.login_attempts == 0, (
            "breaker did not persist: a new process issued a fresh login attempt"
        )
    finally:
        await transport2.aclose()


async def test_cli_check_auth_login_reruns_are_breaker_limited() -> None:
    """Re-running ``--check-auth --login`` (a new process each time) while the
    credentials are wrong must NOT keep hitting the device: the breaker is meant
    to block the second invocation. It does not, because state is per-process."""
    settings = _settings()

    # First invocation: one login attempt, fails.
    fake1 = FakeNvr(password="wrong-on-purpose")
    backend1 = NvrBackend(settings, http_transport=fake1.transport())
    await backend1.check_auth(login=True)
    await backend1.aclose()
    assert fake1.login_attempts == 1

    # Second invocation (new process): breaker should already be open.
    fake2 = FakeNvr(password="wrong-on-purpose")
    backend2 = NvrBackend(settings, http_transport=fake2.transport())
    result = await backend2.check_auth(login=True)
    await backend2.aclose()
    assert fake2.login_attempts == 0, (
        "no cross-process breaker: repeated CLI login attempts reach the device "
        "and will lock the account; result="
        f"{result['success']}"
    )
