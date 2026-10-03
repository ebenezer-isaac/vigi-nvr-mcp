"""Shared test helpers: synthetic keys and a fake VIGI NVR on httpx.MockTransport.

Nothing here touches a real network. All addresses are RFC 5737 examples and
all identifiers are synthetic. The fake speaks the real wire convention:
request string leaves arrive URL-encoded, response string leaves are sent
URL-encoded (the RSA key with lowercase escapes, as the firmware does).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vigi_nvr_mcp import crypto
from vigi_nvr_mcp.transport import decode_wire, encode_wire

DOC_HOST = "192.0.2.10"  # RFC 5737 TEST-NET-1
TEST_PASSWORD = "TestPass123"
TEST_NONCE = "abcdefgh"
FAKE_STOK_1 = "ab" * 16
FAKE_STOK_2 = "cd" * 16
NVR_PREFIX = "VIGI_NVR_"


@lru_cache(maxsize=1)
def make_rsa_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    """Return (private_key, plain base64 DER SPKI)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, base64.b64encode(der).decode("ascii")


def firmware_style_key() -> str:
    """The challenge key as the firmware sends it: URL-encoded, lowercase escapes."""
    _, b64 = make_rsa_keypair()
    encoded = quote(b64, safe="")
    return encoded.replace("%2B", "%2b").replace("%2F", "%2f").replace("%3D", "%3d")


def nvr_env(**overrides: str) -> dict[str, str]:
    base = {f"{NVR_PREFIX}HOST": DOC_HOST, f"{NVR_PREFIX}PASSWORD": TEST_PASSWORD}
    return {**base, **{f"{NVR_PREFIX}{k}": v for k, v in overrides.items()}}


ApiHandler = Callable[[str, dict[str, Any]], dict[str, Any]]


@dataclass
class FakeNvr:
    """Scriptable fake. ``requests`` holds (path, decoded_body); ``raw`` the wire bodies."""

    password: str = TEST_PASSWORD
    nonce: str = TEST_NONCE
    stoks: list[str] = field(default_factory=lambda: [FAKE_STOK_1, FAKE_STOK_2])
    encrypt_types: list[str] = field(default_factory=lambda: ["1", "2"])
    attempts_left: int = 4
    max_attempts: int = 10
    challenge_extra: dict[str, Any] = field(default_factory=dict)
    login_error: dict[str, Any] | None = None
    nonce_invalid_times: int = 0
    api_handler: ApiHandler | None = None
    files: dict[str, bytes] = field(default_factory=dict)
    requests: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    raw: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    gets: list[str] = field(default_factory=list)
    issued: list[str] = field(default_factory=list)
    revoked: set[str] = field(default_factory=set)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    @property
    def login_attempts(self) -> int:
        return sum(1 for path, body in self.requests if path == "/" and "login" in body)

    @property
    def api_requests(self) -> list[tuple[str, dict[str, Any]]]:
        return [(p, b) for p, b in self.requests if p != "/"]

    @property
    def writes(self) -> list[dict[str, Any]]:
        return [b for _, b in self.api_requests if b.get("method") != "get"]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET":
            self.gets.append(path)
            if path in self.files:
                return httpx.Response(200, content=self.files[path])
            return httpx.Response(404)
        wire = json.loads(request.content.decode("utf-8"))
        body = decode_wire(wire)
        self.raw.append((path, wire))
        self.requests.append((path, body))
        if path == "/":
            return self._respond(self._preauth(body))
        token = path.removeprefix("/stok=").removesuffix("/ds")
        if token not in self.issued or token in self.revoked:
            return self._respond({"error_code": -40401, "data": {"code": -40407}})
        if self.api_handler is None:
            return self._respond({"error_code": 0})
        return self._respond(self.api_handler(token, body))

    def _respond(self, reply: dict[str, Any]) -> httpx.Response:
        encoded = encode_wire(reply)
        data = encoded.get("data")
        if isinstance(data, dict) and "key" in data:
            encoded = {**encoded, "data": {**data, "key": firmware_style_key()}}
        return httpx.Response(200, json=encoded)

    def _preauth(self, body: dict[str, Any]) -> dict[str, Any]:
        _, key_b64 = make_rsa_keypair()
        if "user_management" in body:
            return {
                "error_code": -40401,
                "data": {
                    "code": -40407,
                    "encrypt_type": list(self.encrypt_types),
                    "key": key_b64,
                    "nonce": self.nonce,
                    **self.challenge_extra,
                },
            }
        if "login" in body:
            if self.nonce_invalid_times > 0:
                self.nonce_invalid_times -= 1
                return {"error_code": -40410}
            if self.login_error is not None:
                return self.login_error
            if self._password_ok(body["login"]):
                stok = self.stoks[len(self.issued) % len(self.stoks)]
                self.issued.append(stok)
                return {"error_code": 0, "stok": stok, "user_group": "root"}
            self.attempts_left = max(self.attempts_left - 1, 0)
            return {
                "error_code": -40401,
                "data": {"code": -40401, "time": self.attempts_left, "max_time": self.max_attempts},
            }
        return {"error_code": -40106}

    def _password_ok(self, login: dict[str, Any]) -> bool:
        if login.get("passwdType") != "md5":
            return False
        if login.get("encrypt_type") == "1":
            return login["password"] == crypto.md5_auth_pwd(self.password)
        private_key, _ = make_rsa_keypair()
        try:
            plain = private_key.decrypt(
                base64.b64decode(login["password"], validate=True), padding.PKCS1v15()
            ).decode("utf-8")
        except ValueError:
            return False
        return plain == crypto.rsa_login_plaintext(self.password, self.nonce)
