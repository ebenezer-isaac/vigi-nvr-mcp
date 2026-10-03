"""Tool implementations. Each module exposes plain async functions taking a
``ToolContext`` (easy to test) and a ``register(app, ctx)`` that binds them to
FastMCP. Every tool returns the ``{success, data, error}`` envelope and every
payload passes through ``redact`` before it leaves the process.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ..client import NvrClient
from ..config import Settings
from ..envelope import fail, from_error, ok
from ..errors import NvrError
from ..redact import redact

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolContext:
    settings: Settings
    client: NvrClient


async def run_tool(name: str, action: Callable[[], Awaitable[Any]]) -> dict[str, Any]:
    """Run ``action`` and wrap its result (redacted) or its error in an envelope."""
    try:
        return ok(redact(await action()))
    except NvrError as exc:
        log.warning("tool %s failed: %s (%s)", name, exc.kind, exc)
        return from_error(exc)
    except ValueError as exc:
        return fail("INVALID_INPUT", str(exc))
    except Exception:
        log.exception("tool %s raised an unexpected error", name)
        return fail("INTERNAL_ERROR", "Unexpected server error; see server logs.")
