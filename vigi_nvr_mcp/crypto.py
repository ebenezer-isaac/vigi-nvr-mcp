"""Login password encoding for VIGI NVR firmware (``passwdType: "md5"``).

Verified by executing the vendor web UI's own JavaScript (``class.js``
``md5AuthPwd``, ``jquery`` ``$.dynEncryptPwd``, ``jsencrypt``) on firmware 1.1.3:

* ``md5_auth_pwd(p)`` = upper-case hex MD5 of ``"TPCQ75NF2Y:" + p``.
* ``encrypt_type "2"`` (RSA; used whenever the challenge offers "2"):
  password field = base64(RSA-PKCS#1 v1.5(md5_auth_pwd(p) + ":" + nonce)); the
  transport's ``encode_wire`` then URL-encodes it like every other string.
* ``encrypt_type "1"`` (only if "2" is not offered): password field = md5_auth_pwd(p).

``securityEncode``/``orgAuthPwd`` are NOT part of login (they obfuscate the
password for media streams) and are deliberately not implemented. Other
firmware lines may differ; check yours with ``vigi-nvr-mcp --check-auth``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Sequence

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

AUTH_PWD_SALT = "TPCQ75NF2Y:"  # noqa: S105 - public constant from the vendor web UI
ENCRYPT_TYPE_RSA = "2"
ENCRYPT_TYPE_DEFAULT = "1"

_NONCE_RE = re.compile(r"^[\x21-\x39\x3b-\x7e]{1,128}$")  # printable ASCII, no ':' or space
_PKCS1V15_OVERHEAD = 11

# The device-password RSA public key (`$.encryptPub` in the firmware's jQuery). This
# is a FIXED key baked into the firmware JS -- NOT the per-session login challenge
# key -- used to encrypt a channel (camera) password for `chm_edit_dev`. It is a
# public key, not a secret; it is fetched at runtime from the device's static JS and
# this baked-in value is only a fallback / test fixture for one verified unit.
# secret-scan: allow (public RSA-1024 SubjectPublicKeyInfo from firmware JS, not a secret)
DEVICE_PASSWORD_PUBKEY_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6jsSvQoIXMDZzGvlchWD+g2Yc"  # noqa: S105
    "IMH8GqcWQj/efEySFswD07o85hj1xaO5Nlj9OAGuidtBhnUvUMuytfeYkXKAiDX6"
    "EcIYIaq1YAYU/MiA52ZXptKgcy/6Xe9C5ludLUoKAPCURqMwmMhIFy2uL8HyeoI"
    "3HsIRfagQUMcBMrtZQQIDAQAB"
)

# $.encryptPub holds a PEM public key; capture the base64 DER between the markers.
_ENCRYPT_PUB_RE = re.compile(
    r'encryptPub\s*:\s*"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----',
    re.DOTALL,
)


def extract_device_password_pubkey(js_text: str) -> str:
    """Extract the fixed device-password public key (``$.encryptPub``) from firmware JS.

    Returns the base64 DER SubjectPublicKeyInfo with the PEM header/footer and any
    line breaks (real or JS-escaped ``\\n``) stripped. Raises ``ValueError`` if the
    key is absent, empty or not a loadable RSA public key.
    """
    if not isinstance(js_text, str):
        raise TypeError("js_text must be str")
    match = _ENCRYPT_PUB_RE.search(js_text)
    if match is None:
        raise ValueError("encryptPub public key not found in device JS")
    body = match.group(1).replace("\\r", "").replace("\\n", "")
    b64 = re.sub(r"\s+", "", body)
    if not b64:
        raise ValueError("encryptPub public key is empty")
    load_challenge_public_key(b64)  # validate it is a real RSA SPKI (fail loud)
    return b64


def md5_auth_pwd(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be str")
    digest = hashlib.md5((AUTH_PWD_SALT + password).encode("utf-8"), usedforsecurity=False)
    return digest.hexdigest().upper()


def build_login_plaintext(password: str, nonce: str, *, include_nonce: bool) -> str:
    """Pure builder. The RSA path uses ``include_nonce=True`` (verified)."""
    hashed = md5_auth_pwd(password)
    if not include_nonce:
        return hashed
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise ValueError("challenge nonce is missing or malformed")
    return f"{hashed}:{nonce}"


def rsa_login_plaintext(password: str, nonce: str) -> str:
    """Pre-RSA plaintext for encrypt_type 2: ``md5_auth_pwd(p) + ":" + nonce``."""
    return build_login_plaintext(password, nonce, include_nonce=True)


def load_challenge_public_key(pubkey_b64: str) -> rsa.RSAPublicKey:
    """Load the challenge ``key``: base64 of a DER SubjectPublicKeyInfo.

    The key is URL-encoded on the wire; the transport's ``decode_wire`` has
    already decoded it once, so it must not be unquoted again here.
    """
    if not isinstance(pubkey_b64, str) or not pubkey_b64.strip():
        raise ValueError("challenge public key is empty")
    b64 = pubkey_b64.strip()
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


def rsa_encrypt_pkcs1v15(pubkey_b64: str, plaintext: str) -> str:
    """RSA PKCS#1 v1.5 encrypt; return plain base64 (URL-encoding is the transport's job)."""
    key = load_challenge_public_key(pubkey_b64)
    data = plaintext.encode("utf-8")
    max_len = key.key_size // 8 - _PKCS1V15_OVERHEAD
    if len(data) > max_len:
        raise ValueError(f"plaintext too long for RSA key ({len(data)} > {max_len} bytes)")
    ciphertext = key.encrypt(data, padding.PKCS1v15())
    return base64.b64encode(ciphertext).decode("ascii")


def select_encrypt_type(offered: Sequence[str]) -> str:
    """Mirror the UI's ``getAuthEncryptType``: "2" if offered, else "1"."""
    if ENCRYPT_TYPE_RSA in offered:
        return ENCRYPT_TYPE_RSA
    if ENCRYPT_TYPE_DEFAULT in offered:
        return ENCRYPT_TYPE_DEFAULT
    raise ValueError(f"unsupported encrypt_type offer {list(offered)!r}")


def encode_login_password(
    password: str, *, offered: Sequence[str], nonce: str | None, key: str | None
) -> tuple[str, str]:
    """Return ``(password_field, encrypt_type)`` for the login body."""
    encrypt_type = select_encrypt_type(offered)
    if encrypt_type == ENCRYPT_TYPE_DEFAULT:
        return md5_auth_pwd(password), encrypt_type
    if not key or not nonce:
        raise ValueError("encrypt_type 2 requires the challenge key and nonce")
    return rsa_encrypt_pkcs1v15(key, rsa_login_plaintext(password, nonce)), encrypt_type
