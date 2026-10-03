"""Command line: ``vigi-nvr-mcp`` / ``python -m vigi_nvr_mcp``.

vigi-nvr-mcp                        # serve (VIGI_MCP_TRANSPORT: stdio | streamable-http)
vigi-nvr-mcp --check-auth           # fetch the auth challenge, no login
vigi-nvr-mcp --check-auth --login   # plus exactly ONE login attempt
vigi-nvr-mcp --list-tools           # print registered tool names; no device I/O
vigi-nvr-mcp breaker --show         # show the persistent login breaker state
vigi-nvr-mcp breaker --clear        # clear it after fixing credentials

Exit codes: 0 success · 1 auth failed · 2 config error ·
3 lockout / breaker open / login disabled · 4 transport error.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .auth import APP_NAME
from .backend import ENV_PREFIX, NvrBackend
from .core import breaker as breaker_mod
from .core.breaker import canonical_device_key
from .core.cli import configure_logging, emit_envelope, emit_lines
from .core.cli import run_breaker as _run_breaker
from .core.config import DeviceSettings, load_device_settings, load_global_settings
from .core.errors import ConfigError, DeviceError
from .server import MCP_ENV_PREFIX, build_server

log = logging.getLogger("vigi_nvr_mcp")

# Placeholder device used only by --list-tools; never contacted.
_LISTING_SETTINGS = {
    "env_prefix": ENV_PREFIX,
    "host": "192.0.2.1",
    "password": "unused",
    "login_disabled": True,
}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vigi-nvr-mcp", description="Local, browser-free MCP server for a TP-Link VIGI NVR."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check-auth", action="store_true", help="print the auth challenge (no login) and exit"
    )
    mode.add_argument(
        "--list-tools", action="store_true", help="print registered tool names and exit"
    )
    parser.add_argument(
        "--login", action="store_true", help="with --check-auth: make exactly ONE login attempt"
    )
    parser.add_argument("--env-file", default=None, help="load variables from this .env file")
    args = parser.parse_args(argv)
    if args.login and not args.check_auth:
        parser.error("--login requires --check-auth")
    return args


def list_tools() -> list[str]:
    backend = NvrBackend(DeviceSettings.model_validate(_LISTING_SETTINGS))
    _, names = build_server(load_global_settings(MCP_ENV_PREFIX, {}), backend)
    return sorted(names)


async def run_check_auth(*, login: bool, environ: Mapping[str, str]) -> dict[str, Any]:
    if not environ.get(f"{ENV_PREFIX}HOST", "").strip():
        raise ConfigError(f"{ENV_PREFIX}HOST is not set")
    backend = NvrBackend.from_env(environ)
    try:
        return await backend.check_auth(login=login)
    finally:
        await backend.aclose()


def _breaker_for(environ: Mapping[str, str]) -> breaker_mod.LoginBreaker:
    settings = load_device_settings(ENV_PREFIX, environ)
    state_dir = (
        Path(settings.state_dir) if settings.state_dir else breaker_mod.default_state_dir(APP_NAME)
    )
    return breaker_mod.LoginBreaker(
        state_dir,
        canonical_device_key(settings.host),
        max_failures=settings.max_login_failures,
        login_disabled=settings.login_disabled,
        disabled_hint=f"{settings.env_name('LOGIN_DISABLED')}=true",
    )


def run_breaker(action: str, environ: Mapping[str, str]) -> int:
    """``breaker --show|--clear``: inspect or clear the persistent login breaker.

    ``--show`` never crashes (exit 0 even on a corrupt state file); ``--clear`` maps
    a store failure to the breaker exit code (3).
    """
    breaker = _breaker_for(environ)
    try:
        return _run_breaker(breaker, action)
    except DeviceError as exc:
        print(f"breaker error: {exc}", file=sys.stderr)
        return 3


def serve(environ: Mapping[str, str]) -> None:
    settings = load_global_settings(MCP_ENV_PREFIX, environ)
    backend = NvrBackend.from_env(environ)
    if settings.mcp_transport == "streamable-http" and not settings.mcp_host_is_loopback:
        log.warning(
            "binding MCP HTTP to non-loopback %s; this server has no auth of its own. "
            "Prefer 127.0.0.1 behind Tailscale or an SSH tunnel.",
            settings.mcp_host,
        )
    mcp, names = build_server(settings, backend)
    log.info("serving %d tools over %s", len(names), settings.mcp_transport)
    mcp.run(transport=settings.mcp_transport)


def _parse_breaker(argv: Sequence[str]) -> str:
    parser = argparse.ArgumentParser(prog="vigi-nvr-mcp breaker")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--show", action="store_true", help="print the breaker state (default)")
    group.add_argument("--clear", action="store_true", help="clear the breaker after a fix")
    parser.add_argument("--env-file", default=None, help="load variables from this .env file")
    ns = parser.parse_args(argv)
    return "clear" if ns.clear else "show"


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "breaker":
        rest = raw[1:]
        env_file = None
        if "--env-file" in rest:
            idx = rest.index("--env-file")
            env_file = rest[idx + 1] if idx + 1 < len(rest) else None
        action = _parse_breaker(rest)
        load_dotenv(env_file, override=False)
        configure_logging("VIGI_MCP_LOG_LEVEL")
        try:
            return run_breaker(action, os.environ)
        except ConfigError as exc:
            print(f"configuration error: {exc}", file=sys.stderr)
            return 2
    args = parse_args(raw)
    if args.list_tools:
        return emit_lines(list_tools())
    load_dotenv(args.env_file, override=False)
    configure_logging("VIGI_MCP_LOG_LEVEL")
    try:
        if args.check_auth:
            return emit_envelope(asyncio.run(run_check_auth(login=args.login, environ=os.environ)))
        serve(os.environ)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    return 0
