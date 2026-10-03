"""Breaker r1 / config-cli-server — F2.

Claim under attack: "CLI exit codes distinguish config error / auth failure /
lockout / success".

``vigi_nvr_mcp.cli.main`` runs ``--check-auth`` as
``emit_envelope(asyncio.run(run_check_auth(...)))`` and ``emit_envelope``
returns 0 on success else 1. So a device auth rejection (AUTH_FAILED) and a
local lockout refusal (LOGIN_REFUSED, e.g. VIGI_NVR_LOGIN_DISABLED=true or the
device reporting 0 attempts remaining) BOTH exit 1 and are indistinguishable by
exit code. These tests reproduce the exact exit-code mapping cli.main uses.
"""

from __future__ import annotations

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from vigi_nvr_mcp.backend import NvrBackend
from vigi_nvr_mcp.core.cli import emit_envelope


def _backend(fake: FakeNvr, **overrides: str) -> NvrBackend:
    return NvrBackend.from_env(nvr_env(**overrides), http_transport=fake.transport())


async def _exit_code(fake: FakeNvr, **overrides: str) -> int:
    """Reproduce cli.main's --check-auth --login exit-code path."""
    backend = _backend(fake, **overrides)
    try:
        result = await backend.check_auth(login=True)
    finally:
        await backend.aclose()
    # emit_envelope writes to a throwaway stream and returns the exit code.
    import io

    return emit_envelope(result, stream=io.StringIO())


async def test_auth_failure_and_lockout_have_distinct_exit_codes() -> None:
    # Auth failure: wrong password -> device rejects the login (AUTH_FAILED).
    bad_pw = FakeNvr(password="correct")
    bad_pw.password = "correct"
    auth_backend = NvrBackend.from_env(
        nvr_env(PASSWORD="wrong-password"), http_transport=bad_pw.transport()
    )
    try:
        auth_result = await auth_backend.check_auth(login=True)
    finally:
        await auth_backend.aclose()
    assert auth_result["error"]["code"] == "AUTH_FAILED"
    auth_exit = emit_envelope(auth_result, stream=__import__("io").StringIO())

    # Lockout: login frozen locally -> LOGIN_REFUSED, no network login spent.
    lock_fake = FakeNvr()
    lock_exit = await _exit_code(lock_fake, LOGIN_DISABLED="true")
    # Re-derive the lockout result to assert its error code too.
    lock_backend = _backend(FakeNvr(), LOGIN_DISABLED="true")
    try:
        lock_result = await lock_backend.check_auth(login=True)
    finally:
        await lock_backend.aclose()
    assert lock_result["error"]["code"] == "LOGIN_REFUSED"

    # The claim says these are distinguished by exit code; they are not (both 1).
    assert auth_exit != lock_exit, (
        f"auth failure and lockout share exit code {auth_exit}; "
        "the CLI cannot distinguish them"
    )


async def test_success_and_failure_exit_codes() -> None:
    ok_fake = FakeNvr()
    ok_exit = await _exit_code(ok_fake)
    assert ok_exit == 0
    fail_exit = await _exit_code(FakeNvr(), LOGIN_DISABLED="true")
    assert fail_exit == 1
