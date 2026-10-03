"""Lockout-protection and session-handling tests, all against a mocked NVR."""

from __future__ import annotations

import asyncio
import logging

import httpx
import pytest

from tests.helpers import FAKE_STOK_1, FAKE_STOK_2, TEST_PASSWORD, FakeNvr
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.core.errors import (
    ApiError,
    AuthFailed,
    LockoutGuard,
    NonceInvalid,
    TokenExpired,
    TransportError,
)
from vigi_nvr_mcp.transport import NvrTransport

# ---- protocol shape ---------------------------------------------------------


async def test_challenge_request_shape(make_auth, fake: FakeNvr) -> None:
    challenge = await make_auth().get_challenge()
    assert fake.requests[0] == (
        "/",
        {"user_management": {"get_encrypt_info": None}, "method": "do"},
    )
    assert challenge.nonce == fake.nonce
    assert challenge.encrypt_type == ["1", "2"]
    assert fake.login_attempts == 0


async def test_login_body_shape_rsa(make_auth, fake: FakeNvr) -> None:
    assert await make_auth().login() == FAKE_STOK_1
    _, body = fake.requests[-1]
    assert body["method"] == "do"
    login = body["login"]
    assert set(login) == {"username", "password", "passwdType", "encrypt_type"}
    assert (login["username"], login["passwdType"], login["encrypt_type"]) == ("admin", "md5", "2")
    assert TEST_PASSWORD not in login["password"]


async def test_login_encrypt_type_1_when_rsa_not_offered(make_auth, fake: FakeNvr) -> None:
    fake.encrypt_types = ["1"]
    assert await make_auth().login() == FAKE_STOK_1
    login = fake.requests[-1][1]["login"]
    assert login["encrypt_type"] == "1"
    assert len(login["password"]) == 32  # bare md5_auth_pwd


async def test_request_headers(settings) -> None:
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json={"error_code": 0})

    t = NvrTransport(settings, http_transport=httpx.MockTransport(handler))
    await t.post_preauth({"method": "do"})
    await t.aclose()
    assert seen[0]["content-type"] == "application/json; charset=UTF-8"
    assert seen[0]["x-requested-with"] == "XMLHttpRequest"


# ---- (4) token cache --------------------------------------------------------


async def test_token_cached_for_process_lifetime(make_auth, fake: FakeNvr) -> None:
    auth = make_auth()
    assert await auth.token() == await auth.token() == FAKE_STOK_1
    assert fake.login_attempts == 1
    assert auth.status()["authenticated"] is True


async def test_concurrent_token_requests_share_one_login(make_auth, fake: FakeNvr) -> None:
    auth = make_auth()
    tokens = await asyncio.gather(*(auth.token() for _ in range(10)))
    assert set(tokens) == {FAKE_STOK_1}
    assert fake.login_attempts == 1


# ---- (1)(2) failed login: no retry, counters surfaced -----------------------


async def test_failed_login_not_retried_and_surfaces_attempts_left(make_auth, fake) -> None:
    fake.password, fake.attempts_left, fake.max_attempts = "different", 5, 10
    with pytest.raises(AuthFailed) as info:
        await make_auth().login()
    assert fake.login_attempts == 1
    err = info.value
    assert (err.code, err.attempts_left, err.max_attempts) == (-40401, 4, 10)
    assert err.details()["attempts_left"] == 4
    assert "4 of 10 login attempts left" in str(err)
    assert "Not retrying" in str(err)


async def test_lockout_reply_surfaces_sec_left(make_auth, fake) -> None:
    fake.login_error = {"error_code": -40404, "data": {"sec_left": 1740}}
    with pytest.raises(AuthFailed) as info:
        await make_auth().login()
    assert info.value.lock_seconds_left == 1740
    assert info.value.locked is True
    assert info.value.details()["symbol"] == "ESYSLOCKED"
    assert "1740" in str(info.value)


async def test_permanent_lock_is_flagged_locked(make_auth, fake) -> None:
    fake.login_error = {"error_code": -40408}
    with pytest.raises(AuthFailed) as info:
        await make_auth().login()
    assert info.value.locked is True


async def test_factory_reset_state_is_explained(make_auth, fake) -> None:
    fake.login_error = {"error_code": -40405}
    with pytest.raises(AuthFailed, match="factory-reset"):
        await make_auth().login()


async def test_after_failure_implicit_login_refused_without_network(make_auth, fake) -> None:
    fake.password = "different"
    auth = make_auth(MAX_LOGIN_FAILURES="3")
    with pytest.raises(AuthFailed):
        await auth.token()
    before = len(fake.requests)
    with pytest.raises(LockoutGuard):
        await auth.token()
    assert len(fake.requests) == before
    assert fake.login_attempts == 1


async def test_explicit_login_refused_once_budget_spent(make_auth, fake) -> None:
    fake.password = "different"
    auth = make_auth()  # default budget: 1 failure per process
    with pytest.raises(AuthFailed):
        await auth.login()
    before = len(fake.requests)
    for _ in range(5):
        with pytest.raises(LockoutGuard, match="restart"):
            await auth.login()
    assert len(fake.requests) == before
    assert auth.status()["failed_logins"] == 1


async def test_explicit_login_allowed_within_larger_budget(make_auth, fake) -> None:
    fake.password, fake.attempts_left = "different", 9
    auth = make_auth(MAX_LOGIN_FAILURES="2")
    for _ in range(2):
        with pytest.raises(AuthFailed):
            await auth.login()
    with pytest.raises(LockoutGuard):
        await auth.login()
    assert fake.login_attempts == 2


async def test_successful_login_does_not_reset_failure_budget(make_auth, fake) -> None:
    fake.password = "different"
    auth = make_auth(MAX_LOGIN_FAILURES="2")
    with pytest.raises(AuthFailed):
        await auth.login()
    fake.password = TEST_PASSWORD
    await auth.login()
    assert auth.status()["failed_logins"] == 1


async def test_transport_error_during_login_counts_as_failure(make_settings) -> None:
    fake, calls = FakeNvr(), {"n": 0}

    def wrapped(request: httpx.Request) -> httpx.Response:
        if b"login" in request.content:
            calls["n"] += 1
            raise httpx.ReadTimeout("slow", request=request)
        return fake._handle(request)

    s = make_settings()
    t = NvrTransport(s, http_transport=httpx.MockTransport(wrapped))
    auth = Authenticator(s, t)
    with pytest.raises(AuthFailed, match="outcome unknown"):
        await auth.login()
    with pytest.raises(LockoutGuard):
        await auth.login()
    assert calls["n"] == 1
    await t.aclose()


# ---- -40410 nonce invalid: one re-challenge -------------------------------


async def test_nonce_invalid_raises_without_resend(make_auth, fake) -> None:
    # Decision AL-F5: on -40410 the login is NOT resent inside the same call.
    # Exactly one login POST; NonceInvalid is raised (retryable), not counted.
    fake.nonce_invalid_times = 1
    auth = make_auth()
    with pytest.raises(NonceInvalid):
        await auth.login()
    assert fake.login_attempts == 1
    assert auth.status()["failed_logins"] == 0


async def test_nonce_invalid_is_retryable_not_counted(make_auth, fake) -> None:
    # A nonce rejection is retryable: once the device stops rejecting the nonce,
    # the very next explicit login succeeds, and no failure was ever recorded.
    fake.nonce_invalid_times = 1
    auth = make_auth()
    with pytest.raises(NonceInvalid):
        await auth.login()
    assert await auth.login() == FAKE_STOK_1
    assert fake.login_attempts == 2  # one per explicit call, never two in one
    assert auth.status()["failed_logins"] == 0


# ---- (6) LOGIN_DISABLED -----------------------------------------------------


async def test_login_disabled_makes_zero_requests(make_auth, fake) -> None:
    auth = make_auth(LOGIN_DISABLED="true")
    with pytest.raises(LockoutGuard, match="VIGI_NVR_LOGIN_DISABLED"):
        await auth.login()
    with pytest.raises(LockoutGuard):
        await auth.token()
    assert fake.requests == []
    assert auth.status()["login_disabled"] is True


# ---- challenge-side guards --------------------------------------------------


async def test_challenge_reporting_zero_attempts_blocks_login(make_auth, fake) -> None:
    fake.challenge_extra = {"time": 0, "max_time": 10}
    auth = make_auth()
    with pytest.raises(LockoutGuard, match="0 login attempts remaining"):
        await auth.login()
    assert fake.login_attempts == 0
    assert auth.status()["failed_logins"] == 0


async def test_low_remaining_attempts_blocks_only_implicit_login(make_auth, fake) -> None:
    fake.challenge_extra = {"time": 2, "max_time": 10}
    auth = make_auth()
    with pytest.raises(LockoutGuard, match="only 2"):
        await auth.token()
    assert fake.login_attempts == 0
    assert await auth.login() == FAKE_STOK_1


@pytest.mark.parametrize(
    "data",
    [
        {"encrypt_type": ["3"], "key": "k", "nonce": "n"},
        {"encrypt_type": ["1", "2"], "nonce": "n"},
        {"encrypt_type": ["1", "2"], "key": "k"},
        {"encrypt_type": []},
        None,
    ],
)
async def test_malformed_or_unsupported_challenge_never_attempts_login(make_settings, data) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert b"login" not in request.content
        return httpx.Response(200, json={"error_code": -40401, "data": data})

    s = make_settings()
    t = NvrTransport(s, http_transport=httpx.MockTransport(handler))
    auth = Authenticator(s, t)
    with pytest.raises((ApiError, TransportError)):
        await auth.login()
    assert auth.status()["failed_logins"] == 0
    await t.aclose()


async def test_invalid_stok_in_success_reply_is_rejected(make_auth, fake) -> None:
    fake.stoks = ["not-a-token"]
    auth = make_auth()
    with pytest.raises(TransportError):
        await auth.login()
    assert auth.status()["authenticated"] is False


# ---- (3) token expiry vs auth failure --------------------------------------


async def test_expired_token_triggers_exactly_one_reauth(client, fake: FakeNvr) -> None:
    await client.call("get", "device_info", {"name": ["basic_info"]})
    fake.revoked.add(FAKE_STOK_1)
    assert (await client.call("get", "device_info", {}))["error_code"] == 0
    assert fake.login_attempts == 2
    assert fake.api_requests[-1][0] == f"/stok={FAKE_STOK_2}/ds"


async def test_session_timeout_code_also_reauths(client, fake: FakeNvr) -> None:
    replies = iter([{"error_code": -40403}, {"error_code": 0}])
    fake.api_handler = lambda token, body: next(replies)
    assert (await client.call("get", "device_info", {}))["error_code"] == 0
    assert fake.login_attempts == 2


async def test_second_expiry_after_reauth_is_raised_not_looped(client, fake) -> None:
    fake.revoked.update({FAKE_STOK_1, FAKE_STOK_2})
    with pytest.raises(TokenExpired):
        await client.call("get", "device_info", {})
    assert fake.login_attempts == 2
    assert len(fake.api_requests) == 2


async def test_failed_reauth_after_expiry_stops(client, fake: FakeNvr) -> None:
    await client.call("get", "device_info", {})
    fake.revoked.add(FAKE_STOK_1)
    fake.password = "rotated"
    with pytest.raises(AuthFailed):
        await client.call("get", "device_info", {})
    with pytest.raises(LockoutGuard):
        await client.call("get", "device_info", {})
    assert fake.login_attempts == 2


async def test_minus_40401_on_api_is_token_expired(transport) -> None:
    with pytest.raises(TokenExpired):
        await transport.post_api(FAKE_STOK_1, {"method": "get"})  # never issued


async def test_other_api_error_is_not_reauthenticated(client, fake: FakeNvr) -> None:
    fake.api_handler = lambda token, body: {"error_code": -71521}
    with pytest.raises(ApiError) as info:
        await client.call("get", "device_info", {})
    assert info.value.code == -71521
    assert "ENVRCHMDELINVP" in str(info.value)  # symbol from the vendored catalog
    assert fake.login_attempts == 1


async def test_concurrent_expiry_reauths_once(client, fake: FakeNvr) -> None:
    await client.call("get", "device_info", {})
    fake.revoked.add(FAKE_STOK_1)
    await asyncio.gather(*(client.call("get", "device_info", {}) for _ in range(5)))
    assert fake.login_attempts == 2


# ---- logging hygiene --------------------------------------------------------


async def test_password_and_token_never_logged(caplog, make_auth, fake) -> None:
    caplog.set_level(logging.DEBUG)
    auth = make_auth()
    token = await auth.login()
    s_transport = auth._transport  # same transport the authenticator used
    await s_transport.post_api(token, {"method": "get", "x": {}})
    text = caplog.text
    assert TEST_PASSWORD not in text
    assert token not in text
    login_field = next(b for _, b in fake.raw if "login" in b)["login"]["password"]
    assert login_field not in text
