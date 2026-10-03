"""NVR configuration backup.

Mirrors the web UI (SysConf page): ``{"method":"do","system":{"download_conf":null}}``
returns a relative ``url``, which the UI then fetches under the session.

**The download URL composition (``/stok=<token>/<url>``) is UNVERIFIED** — it
follows the UI's ``orgURL`` helper but has not been confirmed against a live NVR;
the first live run (Phase N5) confirms it. Because a wrong path commonly returns
an HTML login/redirect page or a JSON error envelope rather than the config blob,
the downloaded bytes are validated before being accepted as a backup: HTML/XML, a
JSON error envelope, or an implausibly small body (< 1 KB) is rejected so a bogus
file is never presented as a safety net before destructive cleanup.

The backup does not modify the NVR, so it is NOT write-gated: it must be callable
before any cleanup. The file is written to ``VIGI_NVR_BACKUP_DIR`` (default
``./backups``, git-ignored) with mode 0600. It may contain credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..core.errors import TransportError
from . import ToolContext, run_tool

MAX_URL_LENGTH = 512
# A plausible NVR config blob is well over 1 KB; smaller bodies are error pages.
MIN_BACKUP_BYTES = 1024


def _extract_url(reply: dict[str, Any]) -> str:
    candidates = [reply.get("url"), (reply.get("system") or {}).get("url")]
    url = next((c for c in candidates if isinstance(c, str) and c.strip()), None)
    if url is None or len(url) > MAX_URL_LENGTH:
        raise TransportError("NVR did not return a usable backup url")
    return url.strip()


def _validate_backup_content(data: bytes) -> str:
    """Return a content-type label, or raise ``TransportError`` if the bytes are
    clearly not a config blob (HTML/XML page, JSON error envelope, or too small)."""
    if len(data) < MIN_BACKUP_BYTES:
        raise TransportError(
            f"Backup response is implausibly small ({len(data)} bytes < {MIN_BACKUP_BYTES}); "
            "the download URL is unverified and likely returned an error page, not a backup."
        )
    head = data.lstrip()[:1]
    if head == b"<":
        raise TransportError(
            "Backup response is HTML/XML (an error or login page), not a configuration blob."
        )
    if head in (b"{", b"["):
        try:
            parsed = json.loads(data.decode("utf-8", errors="replace"))
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and "error_code" in parsed:
            raise TransportError("Backup response is a JSON error envelope, not a backup.")
        return "application/json"
    return "application/octet-stream"


def write_private_file(directory: Path, name: str, data: bytes) -> Path:
    """Create ``directory/name`` exclusively with mode 0600 (dir 0700)."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return target


async def backup_config(ctx: ToolContext) -> dict[str, Any]:
    async def action() -> dict[str, Any]:
        reply = await ctx.client.request_config_backup()
        data = await ctx.client.download_session_file(_extract_url(reply))
        content_type = _validate_backup_content(data)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = write_private_file(Path(ctx.settings.backup_dir), f"nvr-config-{stamp}.bin", data)
        return {
            "path": str(path.resolve()),
            "size": len(data),
            "content_type": content_type,
            "sha256": hashlib.sha256(data).hexdigest(),
            "created_utc": stamp,
            "warning": "Backup files can contain credentials. Keep them private. "
            "The download URL is unverified until the first live run confirms it.",
        }

    return await run_tool("nvr_backup_config", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_backup_config")
    async def _backup() -> dict[str, Any]:
        """Download the NVR configuration backup to the server's backup directory
        (mode 0600). Read-only on the NVR; run this before any channel cleanup."""
        return await backup_config(ctx)

    return ["nvr_backup_config"]
