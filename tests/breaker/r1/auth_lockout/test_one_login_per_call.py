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

from tests.helpers import FAKE_STOK_1, FakeNvr


async def test_single_explicit_login_sends_at_most_one_login_post(
    make_auth, fake: FakeNvr
) -> None:
    fake.nonce_invalid_times = 1  # first login POST is rejected with -40410
    auth = make_auth()
    token = await auth.login()
    assert token == FAKE_STOK_1
    # Claim: never more than one HTTP login attempt per explicit call.
    assert fake.login_attempts == 1, (
        "one explicit login() issued "
        f"{fake.login_attempts} login POSTs (two password-bearing requests "
        "reached the device)"
    )
