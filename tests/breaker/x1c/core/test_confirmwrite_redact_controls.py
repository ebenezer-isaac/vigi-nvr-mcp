"""x1c / core — ConfirmWrite and redact (controls; both halves of the claim hold).

ConfirmWrite: every non-``True`` JSON value collapses to ``False`` (``1``, ``1.0``,
``"true"``, ``"1"``, ``"yes"``, ``None``, ``0`` all -> ``False``; only the boolean
``True`` -> ``True``) and the advertised JSON schema stays ``{"type": "boolean"}``.
There is no ``bool`` subclass in Python to smuggle a truthy value past ``is True``.

redact: the documented union rule set is implemented exactly — the protected,
non-secret keys (``auth_result``, ``online``, ``conn_status``, ``uuid``, ``row_id``,
``key_present``) survive, while the exact/contains/endswith secret spellings are
stripped, at depth and inside lists, without mutating the input.
"""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter

from vigi_nvr_mcp.core.redact import REDACTED, is_sensitive_key, redact
from vigi_nvr_mcp.core.types import ConfirmWrite

_CW = TypeAdapter(ConfirmWrite)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        (1, False),
        (1.0, False),
        ("true", False),
        ("True", False),
        ("1", False),
        ("yes", False),
        (0, False),
        (None, False),
        ([], False),
        ({}, False),
    ],
)
def test_confirmwrite_only_true_confirms(value: object, expected: bool) -> None:
    assert _CW.validate_python(value) is expected


def test_confirmwrite_schema_is_a_plain_boolean() -> None:
    assert _CW.json_schema()["type"] == "boolean"


@pytest.mark.parametrize(
    "safe",
    ["auth_result", "online", "conn_status", "uuid", "row_id", "key_present", "online_count"],
)
def test_protected_keys_survive(safe: str) -> None:
    assert is_sensitive_key(safe) is False


@pytest.mark.parametrize(
    "secret",
    [
        "password",
        "cpassword",
        "old_password",
        "new_pwd",
        "passwd",
        "api_token",
        "stok",
        "nonce",
        "cookie",
        "sysauth",
        "h_p_ssid",
        "authorization",
        "Authorization",
        "ciphertext",
        "pubkey",
        "public_key",
        "rsa_key",
        "secret",
        "key",
    ],
)
def test_secret_keys_are_stripped(secret: str) -> None:
    assert is_sensitive_key(secret) is True
    out = redact({secret: "value"})
    assert out[secret] == REDACTED


def test_redact_is_deep_and_pure() -> None:
    src = {"outer": [{"token": "t", "online": True}], "uuid": "u"}
    out = redact(src)
    assert out == {"outer": [{"token": REDACTED, "online": True}], "uuid": "u"}
    assert src["outer"][0]["token"] == "t"  # input not mutated
