"""Settings loaded from the environment and validated once at startup.

Everything is read from ``VIGI_*`` environment variables. Validation errors name
the variable and the rule, never the offending value (it may be a password).
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from .errors import NvrConfigError

ENV_TO_FIELD: dict[str, str] = {
    "VIGI_NVR_HOST": "nvr_host",
    "VIGI_NVR_PORT": "nvr_port",
    "VIGI_NVR_USERNAME": "nvr_username",
    "VIGI_NVR_PASSWORD": "nvr_password",
    "VIGI_NVR_VERIFY_TLS": "verify_tls",
    "VIGI_NVR_TIMEOUT_SECONDS": "timeout_seconds",
    "VIGI_NVR_ALLOW_WRITES": "allow_writes",
    "VIGI_NVR_LOGIN_DISABLED": "login_disabled",
    "VIGI_NVR_MAX_LOGIN_FAILURES": "max_login_failures",
    "VIGI_MCP_TRANSPORT": "mcp_transport",
    "VIGI_MCP_HOST": "mcp_host",
    "VIGI_MCP_PORT": "mcp_port",
}
FIELD_TO_ENV: dict[str, str] = {v: k for k, v in ENV_TO_FIELD.items()}

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_NUMERIC_DOTTED = re.compile(r"^[\d.]+$")
_USERNAME = re.compile(r"^[\x21-\x7e]{1,64}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

Port = Annotated[int, Field(ge=1, le=65535)]


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    nvr_host: str
    nvr_port: Port = 443
    nvr_username: str = "admin"
    nvr_password: SecretStr = Field(min_length=1, max_length=128)
    verify_tls: bool = False
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0, allow_inf_nan=False)
    allow_writes: bool = False
    login_disabled: bool = False
    max_login_failures: int = Field(default=1, ge=1, le=5)
    mcp_transport: Literal["stdio", "streamable-http"] = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: Port = 8765

    @field_validator("nvr_host", mode="before")
    @classmethod
    def _validate_host(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("must be a string")
        host = value.strip()
        if not host:
            raise ValueError("must not be empty")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return host
        if len(host) > 253 or _NUMERIC_DOTTED.fullmatch(host):
            raise ValueError("must be a hostname or IP address (no scheme, port or path)")
        if not all(_HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("must be a hostname or IP address (no scheme, port or path)")
        return host

    @field_validator("nvr_username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        if not _USERNAME.fullmatch(value):
            raise ValueError("must be 1-64 printable ASCII characters without spaces")
        return value

    @field_validator("nvr_password")
    @classmethod
    def _validate_password(cls, value: SecretStr) -> SecretStr:
        if _CONTROL_CHARS.search(value.get_secret_value()):
            raise ValueError("must not contain control characters")
        return value

    @field_validator("mcp_host")
    @classmethod
    def _validate_bind(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("must be an IP address literal such as 127.0.0.1") from exc
        return value

    @property
    def base_url(self) -> str:
        host = f"[{self.nvr_host}]" if ":" in self.nvr_host else self.nvr_host
        return f"https://{host}:{self.nvr_port}"

    @property
    def mcp_host_is_loopback(self) -> bool:
        return ipaddress.ip_address(self.mcp_host).is_loopback


def _format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors(include_input=False, include_url=False):
        field = str(err["loc"][0]) if err["loc"] else "?"
        name = FIELD_TO_ENV.get(field, field)
        msg = str(err["msg"]).removeprefix("Value error, ")
        lines.append(f"{name}: {msg}")
    return "Invalid configuration: " + "; ".join(lines)


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from ``environ`` (defaults to ``os.environ``). Fails fast."""
    source = os.environ if environ is None else environ
    raw = {field: source[env] for env, field in ENV_TO_FIELD.items() if env in source}
    try:
        return Settings.model_validate(raw)
    except ValidationError as exc:
        raise NvrConfigError(_format_validation_error(exc)) from None
