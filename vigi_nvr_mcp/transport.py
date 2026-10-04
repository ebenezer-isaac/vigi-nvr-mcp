"""VIGI NVR JSON API transport.

* Pre-auth:      ``POST https://<host>:<port>/``
* Authenticated: ``POST https://<host>:<port>/stok=<token>/ds``

Wire encoding (verified from the vendor client): every string leaf of a request
body is ``encodeURIComponent``-escaped and every string leaf of a response is
``decodeURIComponent``-decoded; keys are untouched. ``encode_wire`` and
``decode_wire`` implement this and are applied to every request and response
here, so nothing above the transport ever sees or produces wire-encoded strings.
Every reply must carry an integer ``error_code`` (0 = OK).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection
from typing import Any
from urllib.parse import quote, unquote

import httpx
from pydantic import BaseModel, ConfigDict, StrictInt, ValidationError

from .core.config import DeviceSettings
from .core.errors import ApiError, TokenExpired, TransportError
from .core.transport import JsonHttpTransport, register_token_mask
from .errors import SESSION_TIMEOUT, UNAUTHORISED, describe_error_code, error_symbol

HEADERS = {
    "Content-Type": "application/json; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
}
EXPIRY_CODES = frozenset({UNAUTHORISED, SESSION_TIMEOUT})
STOK_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
register_token_mask(r"stok=[^/\s\"']+", "stok=<redacted>")
MAX_BACKUP_BYTES = 64 * 1024 * 1024
MAX_STATIC_BYTES = 8 * 1024 * 1024

# Characters encodeURIComponent leaves unescaped (besides ASCII alphanumerics).
_URI_COMPONENT_SAFE = "-_.!~*'()"
_MAX_DEPTH = 32


def _map_strings(value: Any, fn: Callable[[str], str], depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("structure nested too deeply")
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: _map_strings(v, fn, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_map_strings(v, fn, depth + 1) for v in value]
    return value


def encode_wire(obj: Any) -> Any:
    """``encodeURIComponent`` every string leaf; keys, numbers, bools, None untouched.

    Pure: returns new containers.
    """
    return _map_strings(obj, lambda s: quote(s, safe=_URI_COMPONENT_SAFE, encoding="utf-8"))


def decode_wire(obj: Any) -> Any:
    """``decodeURIComponent`` every string leaf exactly once. Pure.

    ``+`` is NOT turned into a space (that is form decoding, not URI decoding).
    """
    return _map_strings(obj, lambda s: unquote(s, encoding="utf-8", errors="replace"))


class NvrResponse(BaseModel):
    """Minimal schema every NVR reply must satisfy."""

    model_config = ConfigDict(extra="allow", frozen=True)
    error_code: StrictInt


class NvrTransport:
    def __init__(
        self,
        settings: DeviceSettings,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._http = JsonHttpTransport(
            settings.base_url,
            verify_tls=settings.verify_tls,
            timeout_seconds=settings.timeout_seconds,
            headers=HEADERS,
            http_transport=http_transport,
            tls_fingerprint=settings.tls_fingerprint_sha256,
            host=settings.host,
            port=settings.port,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    @property
    def observed_fingerprint(self) -> str | None:
        """The peer certificate's observed SHA-256 (None until a TLS request is made)."""
        return self._http.observed_fingerprint

    async def post_preauth(
        self, body: dict[str, Any], *, accept_codes: Collection[int] = (0,)
    ) -> dict[str, Any]:
        """POST to ``/``. Raises ApiError unless ``error_code`` is in ``accept_codes``."""
        reply = await self._post("/", body)
        code = reply["error_code"]
        if code not in accept_codes:
            raise self._api_error(code, reply)
        return reply

    async def post_api(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST to ``/stok=<token>/ds``.

        Raises TokenExpired on -40401/-40403 and ApiError on any other non-zero code.
        """
        reply = await self._post(f"/stok={self._checked(token)}/ds", body)
        code = reply["error_code"]
        if code in EXPIRY_CODES:
            raise TokenExpired("NVR session token is invalid or expired")
        if code != 0:
            raise self._api_error(code, reply)
        return reply

    async def get_session_file(self, token: str, relative_url: str) -> bytes:
        """GET a file the NVR exposes under the session (e.g. a config backup)."""
        path = relative_url if relative_url.startswith("/") else "/" + relative_url
        if ".." in path or "//" in path or "\\" in path:
            raise TransportError("NVR returned an unsafe download path")
        return await self._http.get_bytes(
            f"/stok={self._checked(token)}{path}", max_bytes=MAX_BACKUP_BYTES
        )

    async def get_static_file(self, relative_url: str) -> bytes:
        """GET an UNAUTHENTICATED static asset the NVR serves (no stok), e.g. the
        firmware's bundled JS. Same TLS pinning and size cap as every other GET."""
        path = relative_url if relative_url.startswith("/") else "/" + relative_url
        if ".." in path or "//" in path or "\\" in path:
            raise TransportError("refusing to fetch an unsafe static path")
        return await self._http.get_bytes(path, max_bytes=MAX_STATIC_BYTES)

    @staticmethod
    def _checked(token: str) -> str:
        if not STOK_RE.fullmatch(token):
            raise TransportError("refusing to use a malformed session token")
        return token

    @staticmethod
    def _api_error(code: int, reply: dict[str, Any]) -> ApiError:
        symbol = error_symbol(code)
        return ApiError(
            code,
            message=f"NVR returned error_code {code} ({symbol})",
            data=reply.get("data"),
            symbol=symbol,
            meaning=describe_error_code(code),
        )

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        payload = await self._http.post_json(path, encode_wire(body))
        try:
            NvrResponse.model_validate(payload)
        except ValidationError:
            raise TransportError("NVR response is missing an integer error_code") from None
        try:
            return decode_wire(payload)
        except ValueError:
            raise TransportError("NVR response contains invalid URI encoding") from None
