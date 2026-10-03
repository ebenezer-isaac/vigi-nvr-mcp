"""Lockout-protection and session-handling tests, all against a mocked NVR."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import unquote

import httpx
import pytest

from tests.helpers import FAKE_STOK_1, FAKE_STOK_2, TEST_PASSWORD, FakeNvr
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.errors import (
    NvrApiError,
    NvrAuthError,
    NvrLockoutGuard,
    NvrTokenExpired,
    NvrTransportError,
)
from vigi_nvr_mcp.transport import NvrTransport

# ---- login body / protocol shape -------------------------------------------


async def test_challenge_request_shape(transport, settings, fake: FakeNvr) -> None:
    auth = Authenticator(settings, transport)
    challenge = await auth.get_challenge()
    assert fake.requests[0] == (
        "/",
        {"user_management": {"get_encrypt_info": None}, "method": "do"},
    )
    assert challenge.nonce == fake.nonce
    assert "2" in challenge.encrypt_type
    assert fake.login_attempts == 0


async def test_login_body_shape_and_success(transport, settings, fake: FakeNvr) -> None:
    auth = Authenticator(settings, transport)
    token = await auth.login()
    assert token == FAKE_STOK_1
    path, body = fake.requests[-1]
    assert path == "/"
    assert body["method"] == "do"
    login = body["login"]
    assert set(login) == {"username", "password", "passwdType", "encrypt_type"}
    assert login["username"] == "admin"
    assert login["passwdType"] == "md5"
    assert login["encrypt_type"] == "2"
    assert "%" in login["password"]  # URL-encoded base64
    assert TEST_PASSWORD not in login["password"]
    assert unquote(login["password"]) != login["password"]


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


async def test_token_cached_for_process_lifetime(transport, settings, fake: FakeNvr) -> None:
    auth = Authenticator(settings, transport)
    first = await auth.token()
    second = await auth.token()
    assert first == second == FAKE_STOK_1
    assert fake.login_attempts == 1
    assert auth.status()["authenticated"] is True


async def test_concurrent_token_requests_share_one_login(
    transport, settings, fake: FakeNvr
) -> None:
    auth = Authenticator(settings, transport)
    tokens = await asyncio.gather(*(auth.token() for _ in range(10)))
    assert set(tokens) == {FAKE_STOK_1}
    assert fake.login_attempts == 1


# ---- (1)(2) failed login: no retry, counters surfaced -----------------------


async def test_failed_login_is_not_retried_and_surfaces_counters(
    make_settings, make_client
) -> None:
    fake = FakeNvr(password="different", fail_time=4, fail_max_time=10)
    s = make_settings()
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    with pytest.raises(NvrAuthError) as info:
        await auth.login()
    assert fake.login_attempts == 1
    err = info.value
    assert (err.code, err.time, err.max_time) == (-40401, 4, 10)
    assert err.details()["attempts_remaining"] == 6
    assert "4" in str(err) and "10" in str(err)
    await t.aclose()


async def test_after_failure_implicit_login_is_refused_without_network(make_settings) -> None:
    fake = FakeNvr(password="different")
    s = make_settings(VIGI_NVR_MAX_LOGIN_FAILURES="3")
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    with pytest.raises(NvrAuthError):
        await auth.token()
    before = len(fake.requests)
    with pytest.raises(NvrLockoutGuard):
        await auth.token()
    assert len(fake.requests) == before
    assert fake.login_attempts == 1
    await t.aclose()


async def test_explicit_login_refused_once_failure_budget_spent(make_settings) -> None:
    fake = FakeNvr(password="different")
    s = make_settings()  # default budget: 1 failure per process
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    with pytest.raises(NvrAuthError):
        await auth.login()
    before = len(fake.requests)
    for _ in range(5):
        with pytest.raises(NvrLockoutGuard, match="restart"):
            await auth.login()
    assert len(fake.requests) == before
    assert fake.login_attempts == 1
    assert auth.status()["failed_logins"] == 1
    await t.aclose()


async def test_explicit_login_allowed_within_larger_budget(make_settings) -> None:
    fake = FakeNvr(password="different")
    s = make_settings(VIGI_NVR_MAX_LOGIN_FAILURES="2")
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    for _ in range(2):
        with pytest.raises(NvrAuthError):
            await auth.login()
    with pytest.raises(NvrLockoutGuard):
        await auth.login()
    assert fake.login_attempts == 2
    await t.aclose()


async def test_successful_login_does_not_reset_failure_budget(make_settings) -> None:
    fake = FakeNvr(password="different")
    s = make_settings(VIGI_NVR_MAX_LOGIN_FAILURES="2")
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    with pytest.raises(NvrAuthError):
        await auth.login()
    fake.password = TEST_PASSWORD
    await auth.login()
    assert auth.status()["failed_logins"] == 1
    await t.aclose()


async def test_transport_error_during_login_counts_as_failure(make_settings) -> None:
    calls = {"n": 0}
    s = make_settings()
    fake = FakeNvr()

    def wrapped(request: httpx.Request) -> httpx.Response:
        if b"login" in request.content:
            calls["n"] += 1
            raise httpx.ReadTimeout("slow", request=request)
        return fake._handle(request)

    t = NvrTransport(s, http_transport=httpx.MockTransport(wrapped))
    auth = Authenticator(s, t)
    with pytest.raises(NvrAuthError, match="outcome unknown"):
        await auth.login()
    with pytest.raises(NvrLockoutGuard):
        await auth.login()
    assert calls["n"] == 1
    await t.aclose()


# ---- (6) LOGIN_DISABLED -----------------------------------------------------


async def test_login_disabled_makes_zero_requests(make_settings) -> None:
    fake = FakeNvr()
    s = make_settings(VIGI_NVR_LOGIN_DISABLED="true")
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    with pytest.raises(NvrLockoutGuard, match="VIGI_NVR_LOGIN_DISABLED"):
        await auth.login()
    with pytest.raises(NvrLockoutGuard):
        await auth.token()
    assert fake.requests == []
    assert auth.status()["login_disabled"] is True
    await t.aclose()


# ---- challenge-side guards --------------------------------------------------


async def test_challenge_reporting_exhausted_attempts_blocks_login(make_settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert b"login" not in request.content, "login must not be attempted"
        return httpx.Response(
            200,
            json={
                "error_code": -40401,
                "data": {
                    "code": -40407,
                    "encrypt_type": ["2"],
                    "key": "x",
                    "nonce": "n",
                    "time": 10,
                    "max_time": 10,
                },
            },
        )

    s = make_settings()
    t = NvrTransport(s, http_transport=httpx.MockTransport(handler))
    auth = Authenticator(s, t)
    with pytest.raises(NvrLockoutGuard, match="10/10"):
        await auth.login()
    assert auth.status()["failed_logins"] == 0
    await t.aclose()


@pytest.mark.parametrize(
    "data",
    [
        {"encrypt_type": ["1"], "key": "k", "nonce": "n"},  # md5/RSA mode not offered
        {"encrypt_type": ["1", "2"], "nonce": "n"},  # no key
        {"encrypt_type": ["1", "2"], "key": "k"},  # no nonce
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
    with pytest.raises((NvrApiError, NvrTransportError)):
        await auth.login()
    assert auth.status()["failed_logins"] == 0
    await t.aclose()


async def test_invalid_stok_in_success_reply_is_rejected(make_settings) -> None:
    fake = FakeNvr(stoks=["../../etc"])
    s = make_settings()
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    with pytest.raises(NvrTransportError):
        await auth.login()
    assert auth.status()["authenticated"] is False
    await t.aclose()


# ---- (3) token expiry vs auth failure --------------------------------------


async def test_expired_token_triggers_exactly_one_reauth(client, fake: FakeNvr) -> None:
    await client.call("get", "device_info", {"name": ["basic_info"]})
    fake.revoked.add(FAKE_STOK_1)
    reply = await client.call("get", "device_info", {"name": ["basic_info"]})
    assert reply["error_code"] == 0
    assert fake.login_attempts == 2
    assert fake.api_requests[-1][0] == f"/stok={FAKE_STOK_2}/ds"


async def test_second_expiry_after_reauth_is_raised_not_looped(client, fake: FakeNvr) -> None:
    fake.revoked.update({FAKE_STOK_1, FAKE_STOK_2})
    with pytest.raises(NvrTokenExpired):
        await client.call("get", "device_info", {"name": ["basic_info"]})
    assert fake.login_attempts == 2  # initial login + one re-auth, never more
    assert len(fake.api_requests) == 2


async def test_failed_reauth_after_expiry_stops(client, fake: FakeNvr) -> None:
    await client.call("get", "device_info", {})
    fake.revoked.add(FAKE_STOK_1)
    fake.password = "rotated"
    with pytest.raises(NvrAuthError):
        await client.call("get", "device_info", {})
    with pytest.raises(NvrLockoutGuard):
        await client.call("get", "device_info", {})
    assert fake.login_attempts == 2


async def test_minus_40401_on_login_is_auth_error_not_expiry(make_settings) -> None:
    fake = FakeNvr(password="different")
    s = make_settings()
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    with pytest.raises(NvrAuthError) as info:
        await auth.login()
    assert not isinstance(info.value, NvrTokenExpired)
    await t.aclose()


async def test_minus_40401_on_api_is_token_expired(transport) -> None:
    with pytest.raises(NvrTokenExpired):
        await transport.post_api(FAKE_STOK_1, {"method": "get"})  # never issued


async def test_other_api_error_is_not_reauthenticated(client, fake: FakeNvr) -> None:
    fake.api_handler = lambda token, body: {"error_code": -40106}
    with pytest.raises(NvrApiError) as info:
        await client.call("get", "device_info", {})
    assert info.value.code == -40106
    assert fake.login_attempts == 1


async def test_concurrent_expiry_reauths_once(client, fake: FakeNvr) -> None:
    await client.call("get", "device_info", {})
    fake.revoked.add(FAKE_STOK_1)
    await asyncio.gather(*(client.call("get", "device_info", {}) for _ in range(5)))
    assert fake.login_attempts == 2


# ---- logging hygiene --------------------------------------------------------


async def test_password_and_token_never_logged(caplog, transport, settings, fake) -> None:
    caplog.set_level(logging.DEBUG)
    auth = Authenticator(settings, transport)
    token = await auth.login()
    await transport.post_api(token, {"method": "get", "x": {}})
    text = caplog.text
    assert TEST_PASSWORD not in text
    assert token not in text
    login_body = fake.requests[1][1]["login"]["password"]
    assert login_body not in text
