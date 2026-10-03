"""Generic, write-gated access to any NVR module."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..client import validate_call
from ..core.envelope import fail
from ..core.write_gate import check_write_gate
from . import ToolContext, run_tool

# Never reachable through the raw tool: logins must go through the lockout-guarded
# authenticator, and account management is out of scope.
DENIED_MODULES = frozenset({"login", "user_management"})


async def nvr_call(
    ctx: ToolContext,
    method: str,
    module: str,
    params: dict[str, Any] | None = None,
    confirm_write: bool = False,
) -> dict[str, Any]:
    try:
        validate_call(method, module, params)
    except ValueError as exc:
        return fail("INVALID_INPUT", str(exc))
    if module.lower() in DENIED_MODULES:
        return fail("MODULE_DENIED", f"Module '{module}' cannot be called through nvr_call.")
    refusal = check_write_gate(ctx.settings, method, confirm_write)
    if refusal is not None:
        return refusal

    def action():
        return ctx.client.call(method, module, params)

    if method == "get":
        return await run_tool("nvr_call", action)
    return await run_tool("nvr_call", lambda: ctx.writes.run(action))


def register(mcp: FastMCP, ctx: ToolContext) -> list[str]:
    @mcp.tool(name="nvr_call")
    async def _nvr_call(
        method: str,
        module: str,
        params: dict[str, Any] | None = None,
        confirm_write: bool = False,
    ) -> dict[str, Any]:
        """Send one raw NVR request: {"method": method, module: params}.

        method is one of get|set|do|add|delete. Anything other than "get" is refused
        unless the server has VIGI_NVR_ALLOW_WRITES=true AND confirm_write=true.
        The login and user_management modules are always refused. Credential
        fields in the reply are redacted.
        """
        return await nvr_call(ctx, method, module, params, confirm_write)

    return ["nvr_call"]
