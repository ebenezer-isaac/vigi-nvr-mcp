from __future__ import annotations

import httpx
import pytest

from tests.helpers import FAKE_STOK_1, FakeNvr
from vigi_nvr_mcp.client import READ_QUERIES, extract_rows, validate_call
from vigi_nvr_mcp.core.errors import TransportError
from vigi_nvr_mcp.transport import NvrTransport


async def test_call_body_and_path(client, fake: FakeNvr) -> None:
    await client.call("get", "device_info", {"name": ["basic_info"]})
    path, body = fake.api_requests[-1]
    assert path == f"/stok={FAKE_STOK_1}/ds"
    assert body == {"method": "get", "device_info": {"name": ["basic_info"]}}


@pytest.mark.parametrize("name", sorted(READ_QUERIES))
async def test_every_read_helper_is_a_get(client, fake: FakeNvr, name: str) -> None:
    await client.query(name)
    assert fake.api_requests[-1][1]["method"] == "get"


@pytest.mark.parametrize(
    ("method", "module", "params"),
    [
        ("GET", "device_info", None),
        ("login", "device_info", None),
        ("get", "", None),
        ("get", "1abc", None),
        ("get", "a/../b", None),
        ("get", "a" * 65, None),
        ("get", "method", None),
        ("get", "device_info", ["not", "a", "dict"]),
        ("get", "device_info", {"x": "y" * 70000}),
    ],
)
def test_validate_call_rejects(method: str, module: str, params: object) -> None:
    with pytest.raises(ValueError):
        validate_call(method, module, params)


async def test_validation_happens_before_any_network(client, fake: FakeNvr) -> None:
    with pytest.raises(ValueError):
        await client.call("get", "bad module", None)
    assert fake.requests == []


@pytest.mark.parametrize(
    ("status", "content"),
    [(500, b"{}"), (200, b"<html>"), (200, b"[1,2]"), (200, b'{"error_code":"0"}'), (200, b"{}")],
)
async def test_malformed_replies_raise_transport_error(settings, status, content) -> None:
    t = NvrTransport(
        settings,
        http_transport=httpx.MockTransport(lambda r: httpx.Response(status, content=content)),
    )
    with pytest.raises(TransportError):
        await t.post_preauth({"method": "do"})
    await t.aclose()


async def test_network_error_is_wrapped_without_details(settings) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret-ish detail", request=request)

    t = NvrTransport(settings, http_transport=httpx.MockTransport(boom))
    with pytest.raises(TransportError) as info:
        await t.post_preauth({"method": "do"})
    assert "secret-ish" not in str(info.value)
    await t.aclose()


async def test_malformed_token_never_reaches_url(transport, fake: FakeNvr) -> None:
    with pytest.raises(TransportError):
        await transport.post_api("../../x", {"method": "get"})
    assert fake.requests == []


def test_extract_rows_unwraps_tplink_table_rows() -> None:
    reply = {
        "error_code": 0,
        "chm": {
            "added_dev": [
                {"chn_1": {"uuid": "u1", "ip": "192.0.2.21"}},
                {"chn_2": {"uuid": "u2", "ip": "192.0.2.22"}},
            ]
        },
    }
    assert extract_rows(reply) == [
        {"_row_key": "chn_1", "uuid": "u1", "ip": "192.0.2.21"},
        {"_row_key": "chn_2", "uuid": "u2", "ip": "192.0.2.22"},
    ]


def test_extract_rows_flat_rows_and_missing() -> None:
    assert extract_rows({"a": [{"uuid": "u", "id": 1, "x": 2}]}) == [{"uuid": "u", "id": 1, "x": 2}]
    assert extract_rows({"a": [{"no": "marker"}]}) == []
    assert extract_rows("junk") == []


def test_extract_rows_does_not_mutate_input() -> None:
    row = {"chn_1": {"uuid": "u"}}
    extract_rows({"t": [row]})
    assert row == {"chn_1": {"uuid": "u"}}
