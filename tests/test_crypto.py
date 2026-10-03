from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from tests.helpers import make_rsa_keypair
from vigi_nvr_mcp import crypto

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "auth_vectors.json").read_text("utf-8"))
PW = VECTORS["inputs"]["password"]
NONCE = VECTORS["inputs"]["nonce"]

# Independently computed with hashlib: md5(b"TPCQ75NF2Y:TestPass123").hexdigest().upper()
TESTPASS123_MD5 = "F8A44BD7A62BEC2512DE5EB295A68997"  # secret-scan: allow (public test vector)


# ---- vendor vector file -----------------------------------------------------


def test_vendor_vector_md5() -> None:
    assert crypto.md5_auth_pwd(PW) == VECTORS["md5AuthPwd"] == TESTPASS123_MD5
    assert VECTORS["md5_input_string"] == crypto.AUTH_PWD_SALT + PW
    assert VECTORS["vendor_md5_lowercase"].upper() == TESTPASS123_MD5


def test_vendor_vector_rsa_plaintext_exact_string() -> None:
    plain = crypto.rsa_login_plaintext(PW, NONCE)
    assert plain == VECTORS["pre_rsa_plaintext_encrypt_type_2"]
    assert plain == TESTPASS123_MD5 + ":abcdefgh"
    assert plain.encode("utf-8").hex() == VECTORS["pre_rsa_plaintext_utf8_hex"]
    assert len(plain.encode("utf-8")) == VECTORS["pre_rsa_plaintext_length_bytes"] == 41


def test_vendor_vector_encrypt_type_selection() -> None:
    assert (
        crypto.select_encrypt_type(["1", "2"])
        == VECTORS["encrypt_type_sent_when_server_offers_1_and_2"]
    )
    assert (
        crypto.select_encrypt_type(["1"]) == VECTORS["encrypt_type_sent_when_server_offers_only_1"]
    )


def test_vendor_vector_encrypt_type_1_field_is_bare_md5() -> None:
    field, etype = crypto.encode_login_password(PW, offered=["1"], nonce=NONCE, key=None)
    assert (field, etype) == (VECTORS["encrypt_type_1_password_field_value"], "1")


def test_vendor_vector_rsa_shape_with_1024_bit_key() -> None:
    private_key, key_b64 = make_rsa_keypair()
    field, etype = crypto.encode_login_password(PW, offered=["1", "2"], nonce=NONCE, key=key_b64)
    assert etype == "2"
    raw = base64.b64decode(field, validate=True)
    assert len(raw) == VECTORS["rsa"]["ciphertext_bytes"] == 128
    assert len(field) == VECTORS["rsa"]["ciphertext_base64_length"] == 172
    assert (
        private_key.decrypt(raw, padding.PKCS1v15()).decode()
        == VECTORS["pre_rsa_plaintext_encrypt_type_2"]
    )


def test_pkcs1_v15_type2_padding_structure() -> None:
    """Raw-RSA the ciphertext and check EME-PKCS1-v1_5: 00 02 PS(>=8 non-zero) 00 M."""
    private_key, key_b64 = make_rsa_keypair()
    ct = base64.b64decode(crypto.rsa_encrypt_pkcs1v15(key_b64, "M"))
    numbers = private_key.private_numbers()
    em = pow(int.from_bytes(ct, "big"), numbers.d, numbers.public_numbers.n).to_bytes(128, "big")
    assert em[0:2] == b"\x00\x02"
    sep = em.index(b"\x00", 2)
    assert sep - 2 >= 8
    assert b"\x00" not in em[2:sep]
    assert em[sep + 1 :] == b"M"


# ---- md5 / plaintext builder --------------------------------------------------


def test_md5_auth_pwd_matches_hashlib_for_arbitrary_input() -> None:
    for pw in ["", "a", "pässwörd", "with space", "x" * 200, "emoji-\U0001f512"]:
        expected = hashlib.md5(("TPCQ75NF2Y:" + pw).encode("utf-8")).hexdigest().upper()
        assert crypto.md5_auth_pwd(pw) == expected


def test_md5_auth_pwd_rejects_non_str() -> None:
    with pytest.raises(TypeError):
        crypto.md5_auth_pwd(b"bytes")  # type: ignore[arg-type]


def test_build_login_plaintext_flag() -> None:
    assert crypto.build_login_plaintext(PW, NONCE, include_nonce=False) == TESTPASS123_MD5
    assert (
        crypto.build_login_plaintext(PW, NONCE, include_nonce=True) == TESTPASS123_MD5 + ":abcdefgh"
    )
    with pytest.raises(TypeError):
        crypto.build_login_plaintext(PW, NONCE, True)  # type: ignore[misc]


@pytest.mark.parametrize("nonce", ["", "a:b", "has space", "x" * 129, "bad\x00"])
def test_bad_nonce_rejected(nonce: str) -> None:
    with pytest.raises(ValueError):
        crypto.rsa_login_plaintext(PW, nonce)


# ---- RSA ----------------------------------------------------------------------


def test_rsa_output_is_plain_base64_not_url_encoded() -> None:
    _, key_b64 = make_rsa_keypair()
    enc = crypto.rsa_encrypt_pkcs1v15(key_b64, "x")
    assert "%" not in enc
    base64.b64decode(enc, validate=True)


def test_rsa_is_randomised() -> None:
    _, key_b64 = make_rsa_keypair()
    assert crypto.rsa_encrypt_pkcs1v15(key_b64, "s") != crypto.rsa_encrypt_pkcs1v15(key_b64, "s")


def test_key_must_already_be_wire_decoded() -> None:
    """A still-URL-encoded key is rejected: decoding happens once, in the transport."""
    _, key_b64 = make_rsa_keypair()
    from urllib.parse import quote

    with pytest.raises(ValueError):
        crypto.rsa_encrypt_pkcs1v15(quote(key_b64, safe=""), "x")


@pytest.mark.parametrize("bad", ["", "   ", "not base64 !!", base64.b64encode(b"junk").decode()])
def test_invalid_key_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        crypto.rsa_encrypt_pkcs1v15(bad, "x")


def test_plaintext_too_long_rejected() -> None:
    _, key_b64 = make_rsa_keypair()
    with pytest.raises(ValueError):
        crypto.rsa_encrypt_pkcs1v15(key_b64, "x" * 200)


def test_non_rsa_key_rejected() -> None:
    der = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(ValueError):
        crypto.rsa_encrypt_pkcs1v15(base64.b64encode(der).decode(), "x")


@pytest.mark.parametrize("offered", [[], ["3"], ["RSA"]])
def test_unsupported_encrypt_type_offer(offered: list[str]) -> None:
    with pytest.raises(ValueError):
        crypto.select_encrypt_type(offered)


def test_rsa_path_requires_key_and_nonce() -> None:
    _, key_b64 = make_rsa_keypair()
    with pytest.raises(ValueError):
        crypto.encode_login_password(PW, offered=["2"], nonce=None, key=key_b64)
    with pytest.raises(ValueError):
        crypto.encode_login_password(PW, offered=["2"], nonce=NONCE, key=None)


def test_no_security_encode_in_login_path() -> None:
    assert not hasattr(crypto, "security_encode")
    assert not hasattr(crypto, "org_auth_pwd")


def test_generated_key_is_1024_bits() -> None:
    private_key, _ = make_rsa_keypair()
    assert isinstance(private_key, rsa.RSAPrivateKey) and private_key.key_size == 1024
