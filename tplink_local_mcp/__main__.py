"""Entry point: ``tplink-local-mcp`` / ``python -m tplink_local_mcp``.

Serve (default)::

    tplink-local-mcp

Verify the auth flow on your own device without the MCP layer::

    tplink-local-mcp --check-auth --device nvr           # challenge only, no login
    tplink-local-mcp --check-auth --login --device nvr   # plus exactly ONE login
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from dotenv import load_dotenv

from .core.errors import ConfigError
from .devices import all_backends
from .server import build_server, discover_backends

log = logging.getLogger("tplink_local_mcp")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tplink-local-mcp",
        description="Local, browser-free MCP server for TP-Link devices.",
    )
    parser.add_argument(
        "--check-auth",
        action="store_true",
        help="fetch the device's auth challenge and print it (no login), then exit",
    )
    parser.add_argument(
        "--login",
        action="store_true",
        help="with --check-auth: also make exactly ONE login attempt",
    )
    parser.add_argument(
        "--device",
        choices=[b.name for b in all_backends()],
        default="nvr",
        help="device backend for --check-auth (default: nvr)",
    )
    parser.add_argument("--env-file", default=None, help="load variables from this .env file")
    args = parser.parse_args(argv)
    if args.login and not args.check_auth:
        parser.error("--login requires --check-auth")
    return args


async def run_check_auth(device: str, *, login: bool, environ: Mapping[str, str]) -> dict[str, Any]:
    backend = next(b for b in all_backends() if b.name == device)
    if not backend.is_configured(environ):
        raise ConfigError(f"{backend.settings_prefix}HOST is not set")
    configured = backend.configure(environ)
    try:
        check = getattr(configured, "check_auth", None)
        if check is None:
            return await configured.healthcheck()
        return await check(login=login)
    finally:
        await configured.aclose()


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    load_dotenv(args.env_file, override=False)
    logging.basicConfig(
        level=os.environ.get("TPLINK_MCP_LOG_LEVEL", "INFO").upper(),
        stream=sys.stderr,  # stdout is the MCP stdio channel
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.check_auth:
            result = asyncio.run(run_check_auth(args.device, login=args.login, environ=os.environ))
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["success"] else 1
        from .core.config import load_global_settings

        settings = load_global_settings()
        discovery = discover_backends(os.environ)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if not discovery.configured:
        log.warning("no device backends configured; only tplink_status will be available")
    if settings.mcp_transport == "streamable-http" and not settings.mcp_host_is_loopback:
        log.warning(
            "binding MCP HTTP to non-loopback %s; this server has no auth of its own. "
            "Prefer 127.0.0.1 behind Tailscale or an SSH tunnel.",
            settings.mcp_host,
        )
    build_server(settings, discovery).run(transport=settings.mcp_transport)
    return 0


if __name__ == "__main__":
    sys.exit(main())
