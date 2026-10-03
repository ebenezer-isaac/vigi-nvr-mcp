"""Wire encoding: encodeURIComponent on every request string leaf, decode once on replies."""

from __future__ import annotations

import copy
import json
from urllib.parse import quote

import httpx
import pytest

from tests.helpers import FakeNvr, firmware_style_key, make_rsa_keypair
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.transport import NvrTransport, decode_wire, encode_wire


@pytest.mark.parametrize(
    ("plain", "wire"),
    [
        ("a+b", "a%2Bb"),
        ("a/b", "a%2Fb"),
        ("a=b", "a%3Db"),
        ("100%", "100%25"),
        ("two words", "two%20words"),
        ("café", "caf%C3%A9"),
        ("\U0001f512", "%F0%9F%94%92"),
        ("safe-_.!~*'()", "safe-_.!~*'()"),
        ("&?#:@", "%26%3F%23%3A%40"),
        ("", ""),
    ],
)
def test_encode_matches_encode_uri_component(plain: str, wire: str) -> None:
    assert encode_wire(plain) == wire
    assert decode_wire(wire) == plain


def test_nested_structures_keys_untouched_scalars_untouched() -> None:
    src = {
        "a b": {"list": ["x y", 1, 2.5, True, None, ["n/m"]]},
        "num": 0,
        "flag": False,
    }
    assert encode_wire(src) == {
        "a b": {"list": ["x%20y", 1, 2.5, True, None, ["n%2Fm"]]},
        "num": 0,
        "flag": False,
    }


def test_round_trip_is_identity() -> None:
    src = {"name": "Front door / gate+1 100%", "ids": ["1", "2"], "deep": [{"k": "ü"}]}
    assert decode_wire(encode_wire(src)) == src


def test_encode_and_decode_are_pure() -> None:
    src = {"a": ["x y"]}
    snapshot = copy.deepcopy(src)
    encode_wire(src)
    decode_wire(src)
    assert src == snapshot


def test_decode_is_single_pass() -> None:
    assert decode_wire("%252b") == "%2b"
    assert decode_wire("%2b") == "+"
    assert decode_wire("a+b") == "a+b"  # '+' is not a space in URI decoding


def test_firmware_key_lowercase_escapes_decode_to_base64() -> None:
    _, b64 = make_rsa_keypair()
    assert "%2b" in firmware_style_key() or "%2f" in firmware_style_key()
    assert decode_wire(firmware_style_key()) == b64


def test_depth_bomb_rejected() -> None:
    deep: list = []
    cursor = deep
    for _ in range(100):
        nxt: list = []
        cursor.append(nxt)
        cursor = nxt
    with pytest.raises(ValueError):
        encode_wire(deep)


async def test_requests_are_wire_encoded_and_replies_decoded(settings) -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"error_code": 0, "name": "Gate%20%2B%201"})

    t = NvrTransport(settings, http_transport=httpx.MockTransport(handler))
    reply = await t.post_preauth({"method": "do", "x": {"label": "a b/c"}})
    await t.aclose()
    assert seen[0] == {"method": "do", "x": {"label": "a%20b%2Fc"}}
    assert reply["name"] == "Gate + 1"


async def test_login_password_is_encoded_exactly_once(make_settings) -> None:
    fake = FakeNvr()
    s = make_settings()
    t = NvrTransport(s, http_transport=fake.transport())
    await Authenticator(s, t).login()
    await t.aclose()
    ((_, wire_body),) = [(p, b) for p, b in fake.raw if "login" in b]
    ((_, body),) = [(p, b) for p, b in fake.requests if "login" in b]
    b64 = body["login"]["password"]
    assert "%" not in b64  # decoded once on the device side -> plain base64
    assert wire_body["login"]["password"] == quote(b64, safe="")
    assert "%25" not in wire_body["login"]["password"]  # no double encoding
