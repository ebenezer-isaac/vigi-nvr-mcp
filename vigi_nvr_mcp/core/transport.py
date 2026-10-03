"""Generic JSON-over-HTTPS transport (httpx).

Request and response bodies are never logged. Device packages register the
shape of any session token that appears in URLs with ``register_token_mask``;
matches are masked in every log line, including httpx's own request lines.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import re
import ssl
from typing import Any

import httpx

from .errors import TlsPinMismatch, TransportError

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MASKS: list[tuple[re.Pattern[str], str]] = []


def fingerprint_sha256(der: bytes) -> str:
    """Lower-case hex SHA-256 of a DER-encoded certificate."""
    return hashlib.sha256(der).hexdigest()


def verify_cert_fingerprint(der: bytes, pin: str) -> None:
    """Raise ``TlsPinMismatch`` unless ``der``'s SHA-256 equals ``pin`` (fail closed)."""
    if fingerprint_sha256(der) != pin:
        raise TlsPinMismatch("device TLS certificate fingerprint does not match the configured pin")


def register_token_mask(pattern: str, replacement: str) -> None:
    """Mask ``pattern`` as ``replacement`` in all logs and logged paths (idempotent)."""
    compiled = re.compile(pattern)
    if all(existing.pattern != compiled.pattern for existing, _ in _MASKS):
        _MASKS.append((compiled, replacement))


def mask_tokens(text: str) -> str:
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


class _MaskTokenFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if _MASKS:
            message = record.getMessage()
            masked = mask_tokens(message)
            if masked != message:
                record.msg = masked
                record.args = None
        return True


for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).addFilter(_MaskTokenFilter())


def body_summary(body: dict[str, Any]) -> str:
    modules = sorted(k for k in body if k != "method")
    return f"method={body.get('method')!s} modules={modules}"


class JsonHttpTransport:
    def __init__(
        self,
        base_url: str,
        *,
        verify_tls: bool,
        timeout_seconds: float,
        headers: dict[str, str] | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        tls_fingerprint: str | None = None,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers or {},
            verify=verify_tls,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            transport=http_transport,
        )
        self._pin = tls_fingerprint
        self._host = host
        self._port = port
        self._pin_checked = False
        self._observed: str | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def observed_fingerprint(self) -> str | None:
        """The peer certificate's observed SHA-256, once seen (helps an operator pin it)."""
        return self._observed

    async def _ensure_pinned(self) -> None:
        """Before the first request body is sent, verify the peer cert against the pin."""
        if self._pin is None or self._pin_checked:
            return
        self._pin_checked = True
        der = await self._peer_cert_der()  # pragma: no cover - needs a real TLS socket
        self._observed = fingerprint_sha256(der)  # pragma: no cover
        verify_cert_fingerprint(der, self._pin)  # pragma: no cover

    async def _peer_cert_der(self) -> bytes:  # pragma: no cover - requires a real TLS socket
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.open_connection(self._host, self._port, ssl=context)
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        if not der:
            raise TransportError("could not read the device certificate for pinning")
        return der

    def _capture_observed(self, response: httpx.Response) -> None:
        if self._observed is not None:
            return
        stream = response.extensions.get("network_stream")
        if stream is None:
            return
        ssl_object = stream.get_extra_info("ssl_object")  # pragma: no cover - real TLS only
        if ssl_object is not None:  # pragma: no cover
            der = ssl_object.getpeercert(binary_form=True)
            if der:
                self._observed = fingerprint_sha256(der)

    async def post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST ``body`` as JSON; return the decoded JSON object or raise TransportError."""
        log_path = mask_tokens(path)
        log.debug("POST %s %s", log_path, body_summary(body))
        await self._ensure_pinned()
        try:
            response = await self._client.post(path, json=body)
        except httpx.TimeoutException as exc:
            raise TransportError(f"Device request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"Device request failed ({type(exc).__name__})") from None
        self._capture_observed(response)
        if response.status_code != 200:
            raise TransportError(f"Device returned HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise TransportError("Device response exceeds size limit")
        try:
            payload = response.json()
        except ValueError:
            raise TransportError("Device returned a non-JSON response") from None
        if not isinstance(payload, dict):
            raise TransportError("Device returned JSON that is not an object")
        return payload

    async def get_bytes(self, path: str, *, max_bytes: int) -> bytes:
        """GET ``path`` and return the body, streaming with a hard size cap."""
        log.debug("GET %s", mask_tokens(path))
        await self._ensure_pinned()
        try:
            async with self._client.stream("GET", path) as response:
                if response.status_code != 200:
                    raise TransportError(f"Device returned HTTP {response.status_code}")
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise TransportError("Device download exceeds size limit")
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise TransportError(f"Device request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"Device request failed ({type(exc).__name__})") from None
        return b"".join(chunks)
