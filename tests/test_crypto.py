from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, unquote

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tests.helpers import make_rsa_keypair
from vigi_nvr_mcp import crypto

# Computed independently with Python's hashlib:
#   hashlib.md5(b"TPCQ75NF2Y:TestPass123").hexdigest().upper()
TESTPASS123_MD5 = "F8A44BD7A62BEC2512DE5EB295A68997"  # secret-scan: allow (public test vector)


def test_md5_auth_pwd_known_vector() -> None:
    assert crypto.md5_auth_pwd("TestPass123") == TESTPASS123_MD5


def test_md5_auth_pwd_matches_hashlib_for_arbitrary_input() -> None:
    for pw in ["", "a", "pässwörd", "with space", "x" * 200, "emoji-\U0001f512"]:
        expected = hashlib.md5(("TPCQ75NF2Y:" + pw).encode("utf-8")).hexdigest().upper()
        assert crypto.md5_auth_pwd(pw) == expected


def test_md5_auth_pwd_is_uppercase_hex_of_length_32() -> None:
    digest = crypto.md5_auth_pwd("anything")
    assert len(digest) == 32
    assert digest == digest.upper()
    int(digest, 16)


def test_md5_auth_pwd_rejects_non_str() -> None:
    with pytest.raises(TypeError):
        crypto.md5_auth_pwd(b"bytes")  # type: ignore[arg-type]


def test_build_login_plaintext_without_nonce_is_bare_md5() -> None:
    assert (
        crypto.build_login_plaintext("TestPass123", "AbCd1234", include_nonce=False)
        == TESTPASS123_MD5
    )


def test_build_login_plaintext_with_nonce_appends_colon_nonce() -> None:
    assert (
        crypto.build_login_plaintext("TestPass123", "AbCd1234", include_nonce=True)
        == TESTPASS123_MD5 + ":AbCd1234"
    )


def test_build_login_plaintext_requires_keyword_flag() -> None:
    with pytest.raises(TypeError):
        crypto.build_login_plaintext("p", "n", True)  # type: ignore[misc]


@pytest.mark.parametrize("nonce", ["", "a:b", "has space", "x" * 129, "bad\x00"])
def test_build_login_plaintext_rejects_bad_nonce_when_used(nonce: str) -> None:
    with pytest.raises(ValueError):
        crypto.build_login_plaintext("p", nonce, include_nonce=True)


def test_nonce_policy_is_a_single_boolean_constant() -> None:
    assert isinstance(crypto.LOGIN_PLAINTEXT_INCLUDES_NONCE, bool)


def test_build_login_plaintext_for_firmware_uses_the_constant() -> None:
    got = crypto.login_plaintext_for_firmware("TestPass123", "AbCd1234")
    want = crypto.build_login_plaintext(
        "TestPass123", "AbCd1234", include_nonce=crypto.LOGIN_PLAINTEXT_INCLUDES_NONCE
    )
    assert got == want


def _decrypt(private_key: rsa.RSAPrivateKey, encoded: str) -> str:
    raw = base64.b64decode(unquote(encoded))
    return private_key.decrypt(raw, padding.PKCS1v15()).decode("utf-8")


def test_rsa_encrypt_round_trips_with_url_encoded_key() -> None:
    private_key, key_param = make_rsa_keypair()
    assert "%" in key_param or "+" not in key_param  # key arrives URL-encoded
    enc = crypto.rsa_encrypt_pkcs1v15(key_param, "HELLO:nonce")
    assert _decrypt(private_key, enc) == "HELLO:nonce"


def test_rsa_encrypt_output_is_url_encoded_base64() -> None:
    _, key_param = make_rsa_keypair()
    enc = crypto.rsa_encrypt_pkcs1v15(key_param, "x")
    assert "+" not in enc and "/" not in enc and "=" not in enc
    assert quote(unquote(enc), safe="") == enc


def test_rsa_encrypt_accepts_lowercase_percent_escapes() -> None:
    private_key, key_param = make_rsa_keypair()
    lowered = key_param.replace("%2B", "%2b").replace("%2F", "%2f").replace("%3D", "%3d")
    assert _decrypt(private_key, crypto.rsa_encrypt_pkcs1v15(lowered, "y")) == "y"


def test_rsa_encrypt_is_randomised() -> None:
    _, key_param = make_rsa_keypair()
    assert crypto.rsa_encrypt_pkcs1v15(key_param, "same") != crypto.rsa_encrypt_pkcs1v15(
        key_param, "same"
    )


@pytest.mark.parametrize("bad", ["", "not base64 !!", base64.b64encode(b"junk").decode()])
def test_rsa_encrypt_rejects_invalid_key(bad: str) -> None:
    with pytest.raises(ValueError):
        crypto.rsa_encrypt_pkcs1v15(bad, "x")


def test_rsa_encrypt_rejects_plaintext_too_long_for_key() -> None:
    _, key_param = make_rsa_keypair()
    with pytest.raises(ValueError):
        crypto.rsa_encrypt_pkcs1v15(key_param, "x" * 4096)


def test_rsa_encrypt_rejects_non_rsa_key() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    der = ec_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(ValueError):
        crypto.rsa_encrypt_pkcs1v15(quote(base64.b64encode(der).decode(), safe=""), "x")


def test_encrypt_login_password_composes_plaintext_and_rsa() -> None:
    private_key, key_param = make_rsa_keypair()
    enc = crypto.encrypt_login_password("TestPass123", "AbCd1234", key_param)
    assert _decrypt(private_key, enc) == crypto.login_plaintext_for_firmware(
        "TestPass123", "AbCd1234"
    )


VECTORS_FILE = Path(__file__).parent / "fixtures" / "auth-vectors.json"


@pytest.mark.skipif(
    not VECTORS_FILE.exists(),
    reason="TODO(auth-vectors): awaiting tests/fixtures/auth-vectors.json from discovery",
)
def test_todo_auth_vectors_json_from_discovery_agent() -> None:
    """Verify the plaintext composition against the delivered vector file.

    Expected format (synthetic values only, never a real password):
      {"include_nonce": bool,
       "vectors": [{"password": "...", "nonce": "...", "plaintext": "..."}]}
    """
    data = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    assert data["include_nonce"] is crypto.LOGIN_PLAINTEXT_INCLUDES_NONCE
    for vector in data["vectors"]:
        assert (
            crypto.login_plaintext_for_firmware(vector["password"], vector["nonce"])
            == vector["plaintext"]
        )
