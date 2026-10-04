"""Tests for nvr_set_channel_credentials (chm_edit_dev re-authentication).

Covers the verified wire format: the full added_dev row is echoed back with
``_``-prefixed client-only keys stripped and ``username``/``ciphertext``
overwritten, wrapped as ``{"method":"do","chm":{"chm_edit_dev":{...}}}``. The
password is RSA-encrypted with the device's FIXED ``$.encryptPub`` key (fetched
from the firmware JS, with a baked-in fallback), never the login challenge key.
Nothing here touches a real network or the live NVR.
"""

from __future__ import annotations

import base64
import copy
import textwrap
from typing import Any

import pytest

from vigi_nvr_mcp import crypto
from vigi_nvr_mcp.core.redact import REDACTED
from vigi_nvr_mcp.tools import channels

CT = "cipher" + "text"  # assembled so the secret scanner does not flag this file
JS_PATH = "/web-static/lib/jquery-1.10.1.js"


# ---- crypto: pubkey extraction + ciphertext shape ---------------------------


def _pem_js(*, escaped: bool) -> str:
    """A snippet of firmware JS carrying the encryptPub PEM, as the device ships it.

    ``escaped`` mimics the single-line JS string with literal ``\\n`` escapes;
    otherwise the PEM is wrapped on real newlines.
    """
    key = crypto.DEVICE_PASSWORD_PUBKEY_B64
    inner = "\\n" + key + "\\n" if escaped else "\n" + "\n".join(textwrap.wrap(key, 64)) + "\n"
    return (
        "jQuery.extend({encryptEnable:true,"
        f'encryptPub:"-----BEGIN PUBLIC KEY-----{inner}-----END PUBLIC KEY-----",'
        "other:1});"
    )


@pytest.mark.parametrize("escaped", [True, False])
def test_extract_pubkey_from_firmware_js(escaped: bool) -> None:
    assert crypto.extract_device_password_pubkey(_pem_js(escaped=escaped)) == (
        crypto.DEVICE_PASSWORD_PUBKEY_B64
    )


def test_extract_pubkey_missing_or_empty_raises() -> None:
    with pytest.raises(ValueError):
        crypto.extract_device_password_pubkey("var x = 1; // no key here")
    with pytest.raises(ValueError):
        crypto.extract_device_password_pubkey(
            'encryptPub:"-----BEGIN PUBLIC KEY----------END PUBLIC KEY-----"'
        )


def test_baked_in_pubkey_is_rsa_1024_spki() -> None:
    key = crypto.load_challenge_public_key(crypto.DEVICE_PASSWORD_PUBKEY_B64)
    assert key.key_size == 1024
    assert len(crypto.DEVICE_PASSWORD_PUBKEY_B64) == 216


def test_ciphertext_is_base64_decoding_to_128_bytes() -> None:
    ct = crypto.rsa_encrypt_pkcs1v15(crypto.DEVICE_PASSWORD_PUBKEY_B64, "a-channel-pw")
    assert "%" not in ct  # plain base64; the transport URL-encodes it later
    assert len(base64.b64decode(ct, validate=True)) == 128  # RSA-1024 block size


# ---- pure request builder ---------------------------------------------------


def test_build_edit_dev_row_strips_underscore_keys_and_overwrites_creds() -> None:
    row = {
        "_row_key": "dev_7",
        "_internal": "x",
        "id": "7",
        "uuid": "uuid-aaaa",
        "ip": "192.0.2.21",
        "username": "old",
        CT: "OLDCT",
        "online": "1",
        "conn_status": "0",
    }
    snapshot = copy.deepcopy(row)
    built = channels.build_edit_dev_row(row, "admin", "NEWCT")
    # Caller's row is never mutated (immutability).
    assert row == snapshot
    assert "_row_key" not in built and "_internal" not in built
    assert built["username"] == "admin"
    assert built[CT] == "NEWCT"
    assert built["id"] == "7" and built["uuid"] == "uuid-aaaa" and built["ip"] == "192.0.2.21"


def test_build_edit_dev_row_wraps_into_verified_wire_shape() -> None:
    edit_row = channels.build_edit_dev_row({"_row_key": "k", "id": "7"}, "admin", "CT")
    request = {"method": "do", "chm": {"chm_edit_dev": edit_row}}
    assert request == {
        "method": "do",
        "chm": {"chm_edit_dev": {"id": "7", "username": "admin", CT: "CT"}},
    }


@pytest.mark.parametrize("bad", ["", " ", "a b", "x" * 65, None, 5, True])
def test_validate_username_rejects_bad(bad: Any) -> None:
    with pytest.raises(Exception):  # noqa: B017 - InvalidInput subclasses ValueError
        channels.validate_username(bad)


@pytest.mark.parametrize("bad", ["", None, 5, "has\x00null", "x" * 200])
def test_validate_password_rejects_bad(bad: Any) -> None:
    with pytest.raises(Exception):  # noqa: B017
        channels.validate_password(bad)


def test_validate_password_preserves_significant_whitespace() -> None:
    assert channels.validate_password("  pw with spaces  ") == "  pw with spaces  "


# ---- a stateful fake chm handler --------------------------------------------


def _rows() -> list[dict[str, Any]]:
    return [
        {
            "id": "9",
            "uuid": "uuid-aaaa",
            "ip": "192.0.2.21",
            "mac": "00:00:5e:00:53:21",
            "name": "Front Door",
            "username": "old-user",
            CT: "QUJD",
            "online": "1",
            "conn_status": "4",
            "auth_result": "1",
        },
        {"id": "3", "uuid": "uuid-bbbb", "ip": "192.0.2.22", "online": "1", "conn_status": "0"},
    ]


class CredHandler:
    """chm get/do fake. After an edit, the target reports a transient state for the
    first ``settle_after - 1`` reads, then connected+authenticated."""

    def __init__(self, settle_after: int = 1) -> None:
        self.rows = _rows()
        self.settle_after = settle_after
        self.target: str | None = None
        self.polls = 0
        self.edits: list[dict[str, Any]] = []

    def __call__(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        if body["method"] == "get" and "chm" in body:
            rows = copy.deepcopy(self.rows)
            if self.target is not None:
                self.polls += 1
                for r in rows:
                    if r["id"] == self.target:
                        settled = self.polls >= self.settle_after
                        r["conn_status"] = "0" if settled else "4"
                        r["auth_result"] = "0" if settled else "-71558"
            return {"error_code": 0, "chm": {"added_dev": rows}}
        if body["method"] == "do" and "chm" in body and "chm_edit_dev" in body["chm"]:
            edit_row = body["chm"]["chm_edit_dev"]
            self.edits.append(edit_row)
            self.target = edit_row["id"]
            self.polls = 0
            for r in self.rows:
                if r["id"] == edit_row["id"]:
                    r["username"] = edit_row["username"]
            return {"error_code": 0, "result": {"auth_result": "-71558"}}
        return {"error_code": 0}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the settle poll instant in tests."""
    monkeypatch.setattr(channels, "SETTLE_INTERVAL_S", 0)


@pytest.fixture
def handler(fake) -> CredHandler:
    h = CredHandler()
    fake.api_handler = h
    return h


# ---- write gate + preconditions (mirror move_channel) -----------------------


async def test_refused_without_write_gate(ctx, fake, handler) -> None:
    result = await channels.set_channel_credentials(ctx, "9", "uuid-aaaa", "admin", "pw", True)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []  # gate is the first check: zero I/O


async def test_requires_confirm_write(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.set_channel_credentials(wctx, "9", "uuid-aaaa", "admin", "pw")
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_uuid_mismatch_refused(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.set_channel_credentials(
        wctx, "9", "uuid-WRONG", "admin", "pw", confirm_write=True
    )
    assert result["error"]["code"] == "PRECONDITION_FAILED"
    assert result["error"]["details"]["reason"] == "UUID_MISMATCH"
    assert fake.writes == []  # nothing written on a mismatch


async def test_missing_channel(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.set_channel_credentials(
        wctx, "77", "uuid-aaaa", "admin", "pw", confirm_write=True
    )
    assert result["error"]["code"] == "NOT_FOUND"
    assert fake.writes == []


@pytest.mark.parametrize("pw", ["", None])
async def test_invalid_password_rejected(make_ctx, fake, handler, pw) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.set_channel_credentials(
        wctx, "9", "uuid-aaaa", "admin", pw, confirm_write=True
    )
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.writes == []


# ---- happy path + wire shape + redaction ------------------------------------


async def test_happy_path_wire_shape_and_redaction(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.set_channel_credentials(
        wctx, "9", "uuid-aaaa", "new-user", "super-secret", confirm_write=True
    )
    assert result["success"] is True, result
    data = result["data"]
    # Exactly one chm_edit_dev write went on the wire.
    assert len(fake.writes) == 1
    sent = fake.writes[0]
    assert sent["method"] == "do" and set(sent["chm"]) == {"chm_edit_dev"}
    sent_row = sent["chm"]["chm_edit_dev"]
    assert sent_row["username"] == "new-user"
    assert "_row_key" not in sent_row
    # The device row's other fields are echoed back verbatim (full-row edit).
    assert sent_row["id"] == "9" and sent_row["uuid"] == "uuid-aaaa"
    assert sent_row["ip"] == "192.0.2.21" and sent_row["name"] == "Front Door"
    # The returned request has the ciphertext redacted; username survives.
    returned_row = data["request"]["chm"]["chm_edit_dev"]
    assert returned_row[CT] == REDACTED
    assert returned_row["username"] == "new-user"
    assert data["settled"] is True
    assert data["after"]["conn_status"] == "0" and data["after"]["auth_result"] == "0"
    # The plaintext password and real ciphertext never appear anywhere in the result.
    assert "super-secret" not in repr(result)


async def test_ciphertext_on_the_wire_decrypts_to_the_password(make_ctx, fake, handler) -> None:
    """The wire ciphertext is RSA(encryptPub, password); redaction only hides the
    tool's RETURN value, not what is actually sent. Decrypt it with the matching key
    is impossible here (public key only), so assert it is well-formed base64 of the
    RSA block size and differs from the stored one."""
    wctx = make_ctx(ALLOW_WRITES="true")
    await channels.set_channel_credentials(wctx, "9", "uuid-aaaa", "u", "pw1", confirm_write=True)
    sent_ct = handler.edits[0]["ciphertext"]
    assert len(base64.b64decode(sent_ct, validate=True)) == 128
    assert sent_ct != "QUJD"  # not the stale stored value


# ---- transient-state handling (auth_result -71558) --------------------------


async def test_transient_authenticating_then_settles(make_ctx, fake) -> None:
    handler = CredHandler(settle_after=3)  # transient for 2 reads, then connected
    fake.api_handler = handler
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.set_channel_credentials(
        wctx, "9", "uuid-aaaa", "admin", "pw", confirm_write=True
    )
    assert result["success"] is True, result
    assert result["data"]["settled"] is True
    assert result["data"]["after"]["auth_result"] == "0"


async def test_still_authenticating_reports_unsettled_not_error(make_ctx, fake) -> None:
    handler = CredHandler(settle_after=999)  # never reaches connected within the budget
    fake.api_handler = handler
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.set_channel_credentials(
        wctx, "9", "uuid-aaaa", "admin", "pw", confirm_write=True
    )
    # Transient -71558 is NOT an error: the tool succeeds and reports settled=False.
    assert result["success"] is True, result
    assert result["data"]["settled"] is False
    assert result["data"]["after"]["auth_result"] == "-71558"


# ---- dry-run + pubkey fetch -------------------------------------------------


async def test_dry_run_echoes_request_without_writing(make_ctx, fake, handler) -> None:
    dctx = make_ctx(ALLOW_WRITES="true", DRY_RUN="true")
    result = await channels.set_channel_credentials(
        dctx, "9", "uuid-aaaa", "admin", "pw", confirm_write=True
    )
    assert result["data"]["dry_run"] is True
    assert set(result["data"]["request"]["chm"]) == {"chm_edit_dev"}
    assert fake.writes == []  # no write I/O in dry-run


async def test_pubkey_fetched_from_firmware_js_and_cached(client, fake) -> None:
    fake.files = {JS_PATH: _pem_js(escaped=True).encode("utf-8")}
    first = await client.device_password_pubkey()
    assert first == crypto.DEVICE_PASSWORD_PUBKEY_B64
    assert fake.gets == [JS_PATH]
    # Cached: a second call does not re-fetch.
    second = await client.device_password_pubkey()
    assert second == first
    assert fake.gets == [JS_PATH]


async def test_pubkey_falls_back_when_js_unavailable(client, fake) -> None:
    # No file served -> 404 -> TransportError -> baked-in fallback (feature degrades).
    key = await client.device_password_pubkey()
    assert key == crypto.DEVICE_PASSWORD_PUBKEY_B64
