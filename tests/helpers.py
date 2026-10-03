"""Shared test helpers: synthetic keys and a fake NVR built on httpx.MockTransport.

Nothing here touches a real network. All addresses are RFC 5737 examples.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import quote, unquote

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vigi_nvr_mcp import crypto

DOC_HOST = "192.0.2.10"  # RFC 5737 TEST-NET-1
TEST_PASSWORD = "TestPass123"
TEST_NONCE = "AbCd1234"
FAKE_STOK_1 = "ab" * 16
FAKE_STOK_2 = "cd" * 16


@lru_cache(maxsize=1)
def make_rsa_keypair() -> tuple[rsa.RSAPrivateKey, str]:
    """Return (private_key, URL-encoded base64 DER SPKI) like the NVR challenge."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, quote(base64.b64encode(der).decode("ascii"), safe="")


def settings_env(**overrides: str) -> dict[str, str]:
    env = {
        "VIGI_NVR_HOST": DOC_HOST,
        "VIGI_NVR_PASSWORD": TEST_PASSWORD,
    }
    return {**env, **overrides}


Handler = Callable[[str, dict[str, Any]], dict[str, Any]]


@dataclass
class FakeNvr:
    """Scriptable fake. Records every request as (path, parsed_body)."""

    password: str = TEST_PASSWORD
    nonce: str = TEST_NONCE
    stoks: list[str] = field(default_factory=lambda: [FAKE_STOK_1, FAKE_STOK_2])
    fail_time: int = 2
    fail_max_time: int = 10
    api_handler: Handler | None = None
    requests: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    issued: list[str] = field(default_factory=list)
    revoked: set[str] = field(default_factory=set)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    @property
    def login_attempts(self) -> int:
        return sum(1 for path, body in self.requests if path == "/" and "login" in body)

    @property
    def challenge_requests(self) -> int:
        return sum(1 for path, body in self.requests if path == "/" and "user_management" in body)

    @property
    def api_requests(self) -> list[tuple[str, dict[str, Any]]]:
        return [(p, b) for p, b in self.requests if p != "/"]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        path = request.url.path
        self.requests.append((path, body))
        if path == "/":
            return httpx.Response(200, json=self._preauth(body))
        token = path.removeprefix("/stok=").removesuffix("/ds")
        if token not in self.issued or token in self.revoked:
            return httpx.Response(200, json={"error_code": -40401, "data": {"code": -40407}})
        if self.api_handler is None:
            return httpx.Response(200, json={"error_code": 0})
        return httpx.Response(200, json=self.api_handler(token, body))

    def _preauth(self, body: dict[str, Any]) -> dict[str, Any]:
        _, key_param = make_rsa_keypair()
        if "user_management" in body:
            return {
                "error_code": -40401,
                "data": {
                    "code": -40407,
                    "encrypt_type": ["1", "2"],
                    "key": key_param,
                    "nonce": self.nonce,
                },
            }
        if "login" in body:
            if self._password_ok(body["login"]["password"]):
                stok = self.stoks[len(self.issued) % len(self.stoks)]
                self.issued.append(stok)
                return {"error_code": 0, "stok": stok, "user_group": "root"}
            return {
                "error_code": -40401,
                "data": {
                    "code": -40401,
                    "time": self.fail_time,
                    "max_time": self.fail_max_time,
                },
            }
        return {"error_code": -40106}

    def _password_ok(self, enc: str) -> bool:
        private_key, _ = make_rsa_keypair()
        try:
            plain = private_key.decrypt(base64.b64decode(unquote(enc)), padding.PKCS1v15()).decode(
                "utf-8"
            )
        except ValueError:
            return False
        return plain == crypto.login_plaintext_for_firmware(self.password, self.nonce)
