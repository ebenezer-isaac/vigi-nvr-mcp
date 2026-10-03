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


async def test_get_challenge_makes_no_io_when_login_disabled(make_auth, fake: FakeNvr) -> None:
    auth = make_auth(LOGIN_DISABLED="true")
    await auth.get_challenge()
    assert fake.requests == [], (
        "LOGIN_DISABLED=true but a pre-auth challenge POST was still sent: "
        f"{[p for p, _ in fake.requests]}"
    )


async def test_check_auth_makes_no_io_when_login_disabled(make_settings, fake: FakeNvr) -> None:
    settings = make_settings(LOGIN_DISABLED="true")
    backend = NvrBackend(settings, http_transport=fake.transport())
    try:
        await backend.check_auth(login=False)
    finally:
        await backend.aclose()
    assert fake.requests == [], (
        "LOGIN_DISABLED=true but check_auth probed the device: "
        f"{[p for p, _ in fake.requests]}"
    )
