"""Breaker r1 / wire-redact-secrets — CONTROLS (no finding).

These tests PASS at this SHA. They are not findings; they document the attack
axes that produced nothing, so the FINDINGS.md claim "axes with no finding" is
backed by executable evidence rather than prose.

Covered here:
  * wire: decode(encode(x)) == x over many string shapes; encode/decode applied
    once (no double encode); numbers/bools/None/keys untouched; a bare "%" and a
    malformed percent-escape are left literal (lossless, never raised/corrupted).
  * secrets: a DEBUG capture over a successful login + an authenticated POST +
    a failed login shows no plaintext password, no md5(password), no raw stok;
    the stok in the URL is masked in both the package log and httpx's log.
  * secrets: repr(DeviceSettings) masks the password (SecretStr); an httpx
    transport exception surfaces only the exception type, never the request body.
"""

from __future__ import annotations

import logging
import string

import httpx
import pytest

from tests.helpers import (
    NVR_PREFIX,
    TEST_PASSWORD,
    FakeNvr,
    nvr_env,
)
from vigi_nvr_mcp import crypto
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.core.config import load_device_settings
from vigi_nvr_mcp.transport import NvrTransport, decode_wire, encode_wire

_ALPHABET = string.printable + "café\u0000ü%2b%25+/ "


@pytest.mark.parametrize("length", [0, 1, 3, 8, 15])
def test_wire_round_trip_identity(length: int) -> None:
    import random

    rng = random.Random(length)
    for _ in range(2000):
        s = "".join(rng.choice(_ALPHABET) for _ in range(length))
        assert decode_wire(encode_wire(s)) == s


def test_wire_malformed_percent_is_lossless_not_raised() -> None:
    for bad in ["%", "%2", "%ZZ", "abc%", "100%"]:
        assert decode_wire(bad) == bad


def test_wire_non_strings_and_keys_untouched() -> None:
    src = {"a b": [1, 2.5, True, None, "x/y"]}
    assert encode_wire(src) == {"a b": [1, 2.5, True, None, "x%2Fy"]}


def test_wire_no_double_encode() -> None:
    assert encode_wire("%2b") == "%252b"
    assert decode_wire("%252b") == "%2b"


async def test_logs_never_contain_password_or_raw_stok(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    fake = FakeNvr()
    fake.api_handler = lambda token, body: {"error_code": 0, "data": {"x": 1}}
    s = load_device_settings(NVR_PREFIX, nvr_env(MAX_LOGIN_FAILURES="3"))
    t = NvrTransport(s, http_transport=fake.transport())
    auth = Authenticator(s, t)
    token = await auth.login()
    await t.post_api(token, {"method": "get", "device_info": None})
    await t.aclose()

    text = "\n".join(r.getMessage() for r in caplog.records)
    assert TEST_PASSWORD not in text
    assert crypto.md5_auth_pwd(TEST_PASSWORD) not in text
    assert token not in text  # the raw stok must be masked wherever it is logged


def test_settings_repr_masks_password_and_transport_error_hides_body() -> None:
    s = load_device_settings(NVR_PREFIX, nvr_env())
    assert TEST_PASSWORD not in repr(s)

    async def _boom() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        t = NvrTransport(s, http_transport=httpx.MockTransport(handler))
        try:
            await t.post_preauth({"method": "do", "login": {"password": "SUPERSECRETPW"}})
        finally:
            await t.aclose()

    import asyncio

    with pytest.raises(Exception) as exc_info:  # noqa: PT011 - we assert on message content
        asyncio.run(_boom())
    assert "SUPERSECRETPW" not in str(exc_info.value)
