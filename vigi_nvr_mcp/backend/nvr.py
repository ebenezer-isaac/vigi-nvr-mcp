"""NVR backend: wires settings, transport, auth, client and tools together, and
provides the login-free healthcheck and the ``--check-auth`` flow."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from .. import crypto
from ..auth import Authenticator
from ..client import NvrClient
from ..core.config import DeviceSettings, load_device_settings
from ..core.envelope import fail, from_error, ok
from ..core.errors import DeviceError
from ..tools import (
    ToolContext,
    backup,
    catalog,
    channels,
    detection,
    device,
    events,
    media,
    raw,
    storage,
    system,
)
from ..transport import NvrTransport

ENV_PREFIX = "VIGI_NVR_"
TOOL_MODULES = (device, raw, catalog, channels, storage, backup, media, detection, events, system)


class NvrBackend:
    def __init__(
        self,
        settings: DeviceSettings,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        transport = NvrTransport(settings, http_transport=http_transport)
        client = NvrClient(settings, transport, Authenticator(settings, transport))
        self.context = ToolContext(settings=settings, client=client)

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> NvrBackend:
        return cls(load_device_settings(ENV_PREFIX, environ), http_transport=http_transport)

    def register_tools(self, mcp: FastMCP) -> list[str]:
        names: list[str] = []
        for module in TOOL_MODULES:
            names = [*names, *module.register(mcp, self.context)]
        return names

    async def _challenge_report(self) -> dict[str, Any]:
        auth = self.context.client.auth
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
            "tls_fingerprint_observed": self.context.client.observed_fingerprint,
        }

    def _policy(self) -> dict[str, Any]:
        s = self.settings
        return {
            "writes_enabled": s.allow_writes,
            "dry_run": s.dry_run,
            "login_disabled": s.login_disabled,
            "max_login_failures": s.max_login_failures,
            "verify_tls": s.verify_tls,
        }

    async def healthcheck(self) -> dict[str, Any]:
        """Pre-auth challenge + local state. Never logs in."""
        auth_status = self.context.client.auth.status()
        try:
            report = await self._challenge_report()
        except DeviceError as exc:
            failure = from_error(exc)
            return fail(
                failure["error"]["code"],
                failure["error"]["message"],
                {**failure["error"]["details"], "auth": auth_status, "policy": self._policy()},
            )
        return ok({**report, "auth": auth_status, "policy": self._policy()})

    async def check_auth(self, *, login: bool) -> dict[str, Any]:
        """Challenge report; with ``login=True`` exactly ONE explicit login attempt."""
        try:
            report = await self._challenge_report()
        except DeviceError as exc:
            return from_error(exc)
        if not login:
            return ok({**report, "login": "skipped (pass --login to attempt one login)"})
        auth = self.context.client.auth
        try:
            await auth.login()
        except DeviceError as exc:
            failure = from_error(exc)
            return fail(
                failure["error"]["code"],
                failure["error"]["message"],
                {**failure["error"]["details"], "challenge": report},
            )
        return ok({**report, "login": "succeeded", "auth": auth.status()})

    async def aclose(self) -> None:
        await self.context.client.aclose()
