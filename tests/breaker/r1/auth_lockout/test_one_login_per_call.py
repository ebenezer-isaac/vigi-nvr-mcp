"""F5 — a single explicit login can send two login HTTP POSTs.

Claim under attack: "...can never issue more than one HTTP login attempt per
explicit call...".
Spec 01-NVR-SPEC.md §N1 line 25: "login() -> Token (exactly one HTTP login...)".

On ``-40410`` (nonce stale/reused) ``_login_locked`` fetches a new challenge and
POSTs the login a second time. The code assumes the firmware does not count a
nonce-rejected POST toward the account lockout counter, but that assumption is
not live-verified (see client.py docstring). With ``verify_tls`` defaulting to
False, a LAN man-in-the-middle can return ``-40410`` deliberately to force the
extra password-bearing POST.
"""

from __future__ import annotations

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.core.errors import NonceInvalid

# RECONCILED to orchestrator decision AL-F5 (fixer brief item 1): on -40410 the
# login is NOT resent inside the same call. Exactly one login POST per explicit
# login(); NonceInvalid is raised (retryable, not counted as a credential
# failure). The original test expected an automatic resend that succeeded
# (login_attempts == 2 was the builder's behaviour the breaker flagged); the
# decision removes the resend entirely, which this now asserts.


async def test_single_explicit_login_sends_at_most_one_login_post(
    make_auth, fake: FakeNvr
) -> None:
    fake.nonce_invalid_times = 1  # first (and only) login POST is rejected with -40410
    auth = make_auth()
    with pytest.raises(NonceInvalid):
        await auth.login()
    # Never more than one HTTP login attempt per explicit call, and no resend.
    assert fake.login_attempts == 1, (
        f"one explicit login() issued {fake.login_attempts} login POSTs"
    )
    # Root-cause spec §3: the reserved attempt is spent conservatively (counted),
    # since the firmware is not proven to ignore a nonce-rejected POST.
    assert auth.status()["failed_logins"] == 1
