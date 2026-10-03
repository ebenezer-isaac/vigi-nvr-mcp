"""Breaker r1 / wire-redact-secrets — F1.

Disproves: "redact() strips every secret-bearing key spelling the device uses"
and the central claim that a ``nonce`` or an RSA ``key`` can never appear in a
tool result envelope.

``vigi_nvr_mcp/core/redact.py`` only strips the exact keys
{ciphertext, key, stok, passwd, pwd, token, secret} plus the prefix ``password``.
MASTER-PLAN §1.6 explicitly requires ``nonce`` and ``cookie`` to be stripped too,
and the claim's protected set names ``nonce`` and the RSA key. These tests show
the secret-bearing spellings survive redaction verbatim.

These are breaker tests: they are EXPECTED TO FAIL against the code at this SHA.
A failure is the finding; do not weaken them.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.core.redact import REDACTED, redact

# Each key is a spelling a TP-Link/VIGI device can emit that carries a secret
# (or is enumerated by MASTER-PLAN §1.6 as must-strip) but that redact() misses.
MISSED_SECRET_KEYS = [
    "nonce",  # MASTER-PLAN §1.6 AND the claim's protected set
    "cookie",  # MASTER-PLAN §1.6 (a session cookie == a session token)
    "pubkey",  # the challenge RSA key when not named exactly "key"
    "old_password",  # password-change flow: the current password in clear
    "new_pwd",  # password-change flow: the new password in clear
    "Authorization",  # a bearer/basic credential header value
]


@pytest.mark.parametrize("key", MISSED_SECRET_KEYS)
def test_secret_bearing_key_is_redacted(key: str) -> None:
    """redact() must replace the value of every secret-bearing key spelling."""
    out = redact({key: "TOP-SECRET-VALUE"})
    assert out[key] == REDACTED, (
        f"redact() leaked {key!r} verbatim: {out[key]!r}. "
        "Spec §1.6 and the claim require this key to be stripped."
    )


def test_nonce_and_cookie_from_spec_are_stripped() -> None:
    """The two keys MASTER-PLAN §1.6 names that are absent from the key set."""
    out = redact({"nonce": "N0NCE", "cookie": "SESSIONID=deadbeef"})
    assert out == {"nonce": REDACTED, "cookie": REDACTED}


def test_rsa_pubkey_does_not_reach_output_in_clear() -> None:
    """The challenge RSA key must never survive, regardless of its key spelling."""
    der_b64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8=redacted-rsa-key"
    out = redact({"pubkey": der_b64})
    assert out["pubkey"] == REDACTED
