"""HTTP transport for the VIGI JSON API.

* Pre-auth:      ``POST https://<host>:<port>/``
* Authenticated: ``POST https://<host>:<port>/stok=<token>/ds``

Request and response bodies are never logged; only the method and module
names are, and the token is masked in any logged path.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Collection
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, StrictInt, ValidationError

from .config import Settings
from .errors import NvrApiError, NvrTokenExpired, NvrTransportError

log = logging.getLogger(__name__)

HEADERS = {
    "Content-Type": "application/json; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
}
UNAUTHORISED = -40401
STOK_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


_STOK_IN_TEXT = re.compile(r"stok=[^/\s\"']+")


class _MaskStokFilter(logging.Filter):
    """httpx logs full request URLs at INFO; mask the session token in them."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if "stok=" in message:
            record.msg = _STOK_IN_TEXT.sub("stok=<redacted>", message)
            record.args = None
        return True


for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).addFilter(_MaskStokFilter())


class NvrResponse(BaseModel):
    """Minimal schema every NVR reply must satisfy."""

    model_config = ConfigDict(extra="allow", frozen=True)
    error_code: StrictInt


def _summary(body: dict[str, Any]) -> str:
    modules = sorted(k for k in body if k != "method")
    return f"method={body.get('method')!s} modules={modules}"


class NvrTransport:
    def __init__(
        self,
        settings: Settings,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.base_url,
            headers=HEADERS,
            verify=settings.verify_tls,
            timeout=httpx.Timeout(settings.timeout_seconds),
            follow_redirects=False,
            transport=http_transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def post_preauth(
        self, body: dict[str, Any], *, accept_codes: Collection[int] = (0,)
    ) -> dict[str, Any]:
        """POST to ``/``. Raises NvrApiError unless ``error_code`` is in ``accept_codes``."""
        reply = await self._post("/", "/", body)
        code = reply["error_code"]
        if code not in accept_codes:
            raise NvrApiError(code, data=reply.get("data"))
        return reply

    async def post_api(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST to ``/stok=<token>/ds``.

        Raises NvrTokenExpired on -40401 (session invalid) and NvrApiError on any
        other non-zero ``error_code``.
        """
        if not STOK_RE.fullmatch(token):
            raise NvrTransportError("refusing to use a malformed session token")
        reply = await self._post(f"/stok={token}/ds", "/stok=<redacted>/ds", body)
        code = reply["error_code"]
        if code == UNAUTHORISED:
            raise NvrTokenExpired("NVR session token is invalid or expired")
        if code != 0:
            raise NvrApiError(code, data=reply.get("data"))
        return reply

    async def _post(self, path: str, log_path: str, body: dict[str, Any]) -> dict[str, Any]:
        log.debug("POST %s %s", log_path, _summary(body))
        try:
            response = await self._client.post(path, json=body)
        except httpx.TimeoutException as exc:
            raise NvrTransportError(f"NVR request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise NvrTransportError(f"NVR request failed ({type(exc).__name__})") from None
        if response.status_code != 200:
            raise NvrTransportError(f"NVR returned HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise NvrTransportError("NVR response exceeds size limit")
        try:
            payload = response.json()
        except ValueError:
            raise NvrTransportError("NVR returned a non-JSON response") from None
        if not isinstance(payload, dict):
            raise NvrTransportError("NVR returned JSON that is not an object")
        try:
            NvrResponse.model_validate(payload)
        except ValidationError:
            raise NvrTransportError("NVR response is missing an integer error_code") from None
        log.debug("reply %s error_code=%s", log_path, payload["error_code"])
        return payload
