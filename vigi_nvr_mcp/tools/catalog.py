"""Catalog-browsing tools: discover which calls the gateway (``nvr_call``) accepts.

All three are read-only and make no device I/O; they read the vendored
inventory. Pair them with ``nvr_call`` (catalogued, validated, write-gated) or
``nvr_raw_call`` (off-catalog escape hatch).
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..catalog import get_catalog
from ..core.envelope import fail, ok
from . import ToolContext


async def list_modules(ctx: ToolContext) -> dict[str, Any]:
    cat = get_catalog()
    return ok(
        {
            "module_count": cat.module_count,
            "call_count": cat.call_count,
            "mutating_count": cat.mutating_count,
            "modules": cat.modules(),
        }
    )


async def list_calls(ctx: ToolContext, module: str) -> dict[str, Any]:
    cat = get_catalog()
    try:
        calls = cat.calls(module)
    except KeyError:
        return fail(
            "NOT_FOUND",
            f"No module named {module!r}. Use nvr_list_modules to see them all.",
            {"nearest_modules": cat.nearest_modules(module)},
        )
    return ok({"module": module, "calls": [spec.model_dump() for spec in calls]})


async def describe_call(ctx: ToolContext, module: str, method: str, key: str) -> dict[str, Any]:
    cat = get_catalog()
    try:
        spec = cat.find(module, method, key)
    except LookupError:
        return fail(
            "NOT_FOUND",
            f"No catalogued call {module}/{method}/{key}.",
            {"nearest": cat.nearest(module, method, key)},
        )
    return ok(spec.model_dump())


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_list_modules")
    async def _modules() -> dict[str, Any]:
        """List every API module the NVR exposes, with per-module call and
        mutating-call counts (read-only; no device I/O)."""
        return await list_modules(ctx)

    @mcp.tool(name="nvr_list_calls")
    async def _calls(module: str) -> dict[str, Any]:
        """List the catalogued calls for one module (method, key, whether it
        mutates, an example and a response-shape hint). Read-only."""
        return await list_calls(ctx, module)

    @mcp.tool(name="nvr_describe_call")
    async def _describe(module: str, method: str, key: str) -> dict[str, Any]:
        """Describe one call by (module, method, key): its example parameters,
        whether it mutates and its response shape. Read-only."""
        return await describe_call(ctx, module, method, key)

    return ["nvr_list_modules", "nvr_list_calls", "nvr_describe_call"]
