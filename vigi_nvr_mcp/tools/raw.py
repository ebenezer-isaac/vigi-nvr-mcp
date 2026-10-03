"""Gateways to any NVR module.

``nvr_call`` is the catalog-validated gateway: it refuses any (module, method,
key) not in the vendored inventory (offering the three nearest matches), builds
and validates the request body, and applies the two-key write gate to anything
the catalog flags as mutating or whose method is not ``get``.

``nvr_raw_call`` is the off-catalog escape hatch for calls the inventory misses;
it is write-gated the same way (anything but ``get``) and logged at WARNING so
off-catalog use is visible. Both always refuse the ``login`` and
``user_management`` modules, and both honour ``VIGI_NVR_DRY_RUN``.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..catalog import get_catalog
from ..client import validate_call
from ..core.envelope import fail
from ..core.types import ConfirmWrite
from ..core.write_gate import check_write_gate
from . import ToolContext, run_tool

log = logging.getLogger(__name__)

# Never reachable through either gateway: logins must go through the
# lockout-guarded authenticator, and account management is out of scope.
DENIED_MODULES = frozenset({"login", "user_management"})
# Force every method through the write gate (used for catalog-flagged mutations).
_FORCE_GATE: frozenset[str] = frozenset()


def _denied(module: str) -> dict[str, Any] | None:
    if module.lower() in DENIED_MODULES:
        return fail(
            "MODULE_DENIED",
            f"Module '{module}' cannot be called through the gateway; it is handled by the "
            "dedicated auth tools and is never exposed here.",
        )
    return None


async def nvr_call(
    ctx: ToolContext,
    module: str,
    method: str,
    key: str,
    params: dict[str, Any] | None = None,
    confirm_write: bool = False,
    allow_extra: bool = False,
) -> dict[str, Any]:
    denied = _denied(module)
    if denied is not None:
        return denied
    cat = get_catalog()
    try:
        spec = cat.find(module, method, key)
    except LookupError:
        return fail(
            "CALL_NOT_FOUND",
            f"No catalogued call {module}/{method}/{key}. Use nvr_list_calls to find it, or "
            "nvr_raw_call to send an off-catalog request.",
            {"nearest": cat.nearest(module, method, key)},
        )
    mutating = spec.mutates or method != "get"
    if mutating:
        refusal = check_write_gate(ctx.settings, method, confirm_write, read_methods=_FORCE_GATE)
        if refusal is not None:
            return refusal

    async def action() -> Any:
        # Build the exact wire body (shape-aware) here so a validation error maps
        # through run_tool as INVALID_INPUT, never a raw codec/ValueError leak.
        body = cat.build_body(spec, params, allow_extra=allow_extra)

        async def send() -> Any:
            return await ctx.client.call(method, module, body[module])

        if mutating:
            return await ctx.writes.run(body, send)
        return await send()

    return await run_tool("nvr_call", action)


async def nvr_raw_call(
    ctx: ToolContext,
    method: str,
    module: str,
    params: dict[str, Any] | None = None,
    confirm_write: bool = False,
) -> dict[str, Any]:
    denied = _denied(module)
    if denied is not None:
        return denied
    gated = method != "get"
    if gated:
        refusal = check_write_gate(ctx.settings, method, confirm_write)
        if refusal is not None:
            return refusal
    log.warning("nvr_raw_call bypassing the catalog: method=%s module=%s", method, module)

    async def action() -> Any:
        # Validate inside run_tool so an InvalidInput maps cleanly and any other
        # error (e.g. an internal fault) never surfaces as INVALID_INPUT.
        validate_call(method, module, params)

        async def send() -> Any:
            return await ctx.client.call(method, module, params)

        if gated:
            return await ctx.writes.run({"method": method, module: params}, send)
        return await send()

    return await run_tool("nvr_raw_call", action)


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_call")
    async def _call(
        module: str,
        method: str,
        key: str,
        params: dict[str, Any] | None = None,
        confirm_write: ConfirmWrite = False,
        allow_extra: bool = False,
    ) -> dict[str, Any]:
        """Catalogued gateway to any NVR call. Identify the call with
        (module, method, key) from nvr_list_calls/nvr_describe_call; pass the
        module body as params. Unknown calls are refused with the nearest
        matches. Anything the catalog flags as mutating, or whose method is not
        "get", needs VIGI_NVR_ALLOW_WRITES=true AND confirm_write=true. Set
        allow_extra=true to send keys outside the call's example. With
        VIGI_NVR_DRY_RUN the exact body is returned as data.request (and
        data.dry_run=true) and not sent. Credential fields in the reply are redacted.
        """
        return await nvr_call(ctx, module, method, key, params, confirm_write, allow_extra)

    @mcp.tool(name="nvr_raw_call")
    async def _raw(
        method: str,
        module: str,
        params: dict[str, Any] | None = None,
        confirm_write: ConfirmWrite = False,
    ) -> dict[str, Any]:
        """Off-catalog escape hatch: send {"method": method, module: params}
        directly. Prefer nvr_call. Everything but method="get" needs both write
        gates; the login and user_management modules are always refused. Logged
        at WARNING. Honours VIGI_NVR_DRY_RUN. Reply credentials are redacted.
        """
        return await nvr_raw_call(ctx, method, module, params, confirm_write)

    return ["nvr_call", "nvr_raw_call"]
