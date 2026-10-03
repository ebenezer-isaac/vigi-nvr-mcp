"""Login password encoding for VIGI NVR firmware that uses ``passwdType: "md5"``.

All functions are pure. The flow, as captured from an NVR1016H on firmware 1.1.3:

1. ``md5_auth_pwd(password)`` = upper-case hex MD5 of ``"TPCQ75NF2Y:" + password``.
2. The login plaintext is built from that digest (see ``LOGIN_PLAINTEXT_INCLUDES_NONCE``).
3. The plaintext is RSA-encrypted (PKCS#1 v1.5) with the public key from the
   challenge, base64-encoded, then URL-encoded.

Other firmware lines use different schemes (some SHA-256 based). Confirm yours with
``tools/capture-login`` before trusting this module.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from urllib.parse import quote, unquote

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

AUTH_PWD_SALT = "TPCQ75NF2Y:"  # noqa: S105 - public constant from the vendor web UI

# ---------------------------------------------------------------------------
# AUTH PLAINTEXT COMPOSITION -- the ONE place to flip.
#
# False: plaintext = md5_auth_pwd(password)
# True:  plaintext = md5_auth_pwd(password) + ":" + nonce
#
# TODO(auth-vectors): set from tests/fixtures/auth-vectors.json once the
# discovery capture confirms the composition. test_crypto.py checks the file
# against this constant automatically when it exists.
# ---------------------------------------------------------------------------
LOGIN_PLAINTEXT_INCLUDES_NONCE: bool = True

_NONCE_RE = re.compile(r"^[\x21-\x39\x3b-\x7e]{1,128}$")  # printable ASCII, no ':' or space
_PKCS1V15_OVERHEAD = 11


def md5_auth_pwd(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be str")
    digest = hashlib.md5((AUTH_PWD_SALT + password).encode("utf-8"), usedforsecurity=False)
    return digest.hexdigest().upper()


def build_login_plaintext(password: str, nonce: str, *, include_nonce: bool) -> str:
    hashed = md5_auth_pwd(password)
    if not include_nonce:
        return hashed
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise ValueError("challenge nonce is missing or malformed")
    return f"{hashed}:{nonce}"


def login_plaintext_for_firmware(password: str, nonce: str) -> str:
    """Plaintext composition for the supported firmware (see the constant above)."""
    return build_login_plaintext(password, nonce, include_nonce=LOGIN_PLAINTEXT_INCLUDES_NONCE)


def load_challenge_public_key(pubkey_b64_urlencoded: str) -> rsa.RSAPublicKey:
    """Decode the challenge ``key``: URL-encoded base64 of a DER SubjectPublicKeyInfo."""
    if not isinstance(pubkey_b64_urlencoded, str) or not pubkey_b64_urlencoded.strip():
        raise ValueError("challenge public key is empty")
    b64 = unquote(pubkey_b64_urlencoded.strip())
    try:
        der = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("challenge public key is not valid base64") from exc
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("challenge public key is not a DER public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("challenge public key is not an RSA key")
    return key


def rsa_encrypt_pkcs1v15(pubkey_b64_urlencoded: str, plaintext: str) -> str:
    """Encrypt and return URL-encoded base64 (``+``, ``/``, ``=`` percent-escaped)."""
    key = load_challenge_public_key(pubkey_b64_urlencoded)
    data = plaintext.encode("utf-8")
    max_len = key.key_size // 8 - _PKCS1V15_OVERHEAD
    if len(data) > max_len:
        raise ValueError(f"plaintext too long for RSA key ({len(data)} > {max_len} bytes)")
    ciphertext = key.encrypt(data, padding.PKCS1v15())
    return quote(base64.b64encode(ciphertext).decode("ascii"), safe="")


def encrypt_login_password(password: str, nonce: str, pubkey_b64_urlencoded: str) -> str:
    """Full ``<ENC>`` value for the ``login.password`` field."""
    return rsa_encrypt_pkcs1v15(
        pubkey_b64_urlencoded, login_plaintext_for_firmware(password, nonce)
    )
