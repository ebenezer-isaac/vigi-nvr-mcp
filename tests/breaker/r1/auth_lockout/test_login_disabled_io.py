"""F4 — network I/O still happens when auth is frozen.

Claim under attack: "...perform zero network I/O when VIGI_NVR_LOGIN_DISABLED=true
or when the breaker is open...".
Spec 01-NVR-SPEC.md §N1 line 32: "login_disabled -> no HTTP call at all (assert
transport mock not called); breaker open -> same"; line 25: "Honour login_disabled
and breaker **before** any network call."

``Authenticator.get_challenge`` (and therefore ``backend.check_auth`` /
``backend.healthcheck``) performs a pre-auth POST without consulting
``login_disabled`` or the breaker, so a frozen/locked-out server still talks to
the device on every healthcheck.
"""

from __future__ import annotations

from tests.helpers import FakeNvr
from vigi_nvr_mcp.backend import NvrBackend


# RECONCILED to orchestrator decision AL-F4 / CC-F3 (fixer brief item 1, and the
# amended 01-NVR-SPEC §N1): LOGIN_DISABLED freezes *login attempts* only. The
# credential-free challenge probe stays allowed -- it is the lockout-safe status
# check nvr_status/--check-auth exist for and spends no login attempt. The
# original tests asserted zero I/O; the decision allows the probe but still
# forbids any login POST, which is what these now assert.


async def test_get_challenge_probes_but_never_logs_in_when_login_disabled(
    make_auth, fake: FakeNvr
) -> None:
    auth = make_auth(LOGIN_DISABLED="true")
    await auth.get_challenge()
    # The probe is allowed (reachability), but it must spend no login attempt.
    assert fake.login_attempts == 0, (
        "LOGIN_DISABLED=true but a login POST was sent during the challenge probe"
    )


async def test_check_auth_probes_but_never_logs_in_when_login_disabled(
    make_settings, fake: FakeNvr
) -> None:
    settings = make_settings(LOGIN_DISABLED="true")
    backend = NvrBackend(settings, http_transport=fake.transport())
    try:
        await backend.check_auth(login=False)
    finally:
        await backend.aclose()
    assert fake.login_attempts == 0, (
        "LOGIN_DISABLED=true but check_auth spent a login attempt"
    )
