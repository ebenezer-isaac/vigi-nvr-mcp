"""VIGI NVR DeviceBackend: wires settings, transport, auth, client and tools."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from ...core.config import DeviceSettings, host_is_set, load_device_settings
from ...core.envelope import fail, from_error, ok
from ...core.errors import ConfigError, DeviceError
from . import crypto
from .auth import Authenticator
from .client import NvrClient
from .tools import ToolContext, backup, channels, device, raw, storage
from .transport import NvrTransport


class VigiNvrBackend:
    name = "nvr"
    settings_prefix = "TPLINK_NVR_"
    tool_prefix = "nvr_"
    description = "TP-Link VIGI NVR (tested: NVR1016H fw 1.1.3)"

    def __init__(
        self,
        settings: DeviceSettings | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self._http_transport = http_transport
        self.context: ToolContext | None = None
        if settings is not None:
            transport = NvrTransport(settings, http_transport=http_transport)
            client = NvrClient(settings, transport, Authenticator(settings, transport))
            self.context = ToolContext(settings=settings, client=client)

    def is_configured(self, environ: Mapping[str, str]) -> bool:
        return host_is_set(self.settings_prefix, environ)

    def configure(self, environ: Mapping[str, str]) -> VigiNvrBackend:
        settings = load_device_settings(self.settings_prefix, environ)
        return VigiNvrBackend(settings, http_transport=self._http_transport)

    def _ctx(self) -> ToolContext:
        if self.context is None:
            raise ConfigError("NVR backend is not configured (TPLINK_NVR_HOST unset)")
        return self.context

    def register_tools(self, mcp: FastMCP) -> list[str]:
        ctx = self._ctx()
        names: list[str] = []
        for module in (device, raw, channels, storage, backup):
            names = [*names, *module.register(mcp, ctx)]
        return names

    async def _challenge_report(self) -> dict[str, Any]:
        auth = self._ctx().client.auth
        challenge = await auth.get_challenge()
        try:
            selected: str | None = crypto.select_encrypt_type(challenge.encrypt_type)
        except ValueError:
            selected = None
        return {
            "reachable": True,
            "encrypt_type_offered": list(challenge.encrypt_type),
            "encrypt_type_selected": selected,
            "challenge_code": challenge.code,
            "attempts_left": challenge.time,
            "max_attempts": challenge.max_time,
            "lock_seconds_left": challenge.sec_left,
            "key_present": challenge.key is not None,
            "nonce_present": challenge.nonce is not None,
            "auth": auth.status(),
        }

    async def healthcheck(self) -> dict[str, Any]:
        """Fetch the pre-auth challenge only. Never logs in."""
        try:
            return ok(await self._challenge_report())
        except DeviceError as exc:
            return from_error(exc)

    async def check_auth(self, *, login: bool) -> dict[str, Any]:
        """Challenge report; with ``login=True`` exactly ONE explicit login attempt."""
        try:
            report = await self._challenge_report()
        except DeviceError as exc:
            return from_error(exc)
        if not login:
            return ok({**report, "login": "skipped (pass --login to attempt one login)"})
        try:
            await self._ctx().client.auth.login()
        except DeviceError as exc:
            result = from_error(exc)
            return fail(
                result["error"]["code"],
                result["error"]["message"],
                {**result["error"]["details"], "challenge": report},
            )
        return ok({**report, "login": "succeeded", "auth": self._ctx().client.auth.status()})

    async def aclose(self) -> None:
        if self.context is not None:
            await self.context.client.aclose()
