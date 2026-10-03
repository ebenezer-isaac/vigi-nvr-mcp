"""Generic, write-gated access to any NVR module."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from ..client import validate_call
from ..envelope import fail
from . import ToolContext, run_tool

# Never reachable through the raw tool: logins must go through the lockout-guarded
# authenticator, and account management is out of scope.
DENIED_MODULES = frozenset({"login", "user_management"})


def check_write_gate(ctx: ToolContext, method: str, confirm_write: bool) -> dict[str, Any] | None:
    """Return a refusal envelope if a non-``get`` call is not permitted, else None."""
    if method == "get":
        return None
    if not ctx.settings.allow_writes:
        return fail(
            "WRITE_REFUSED",
            f"Method '{method}' modifies the NVR and writes are disabled. "
            "Set VIGI_NVR_ALLOW_WRITES=true on the server to enable them.",
        )
    if confirm_write is not True:
        return fail(
            "WRITE_REFUSED",
            f"Method '{method}' modifies the NVR. Re-send with confirm_write=true "
            "after confirming the change with the operator.",
        )
    return None


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
    refusal = check_write_gate(ctx, method, confirm_write)
    if refusal is not None:
        return refusal
    return await run_tool("nvr_call", lambda: ctx.client.call(method, module, params))


def register(app: FastMCP, ctx: ToolContext) -> None:
    @app.tool(name="nvr_call")
    async def _nvr_call(
        method: str,
        module: str,
        params: dict[str, Any] | None = None,
        confirm_write: bool = False,
    ) -> dict[str, Any]:
        """Send one raw request: {"method": method, module: params}.

        method is one of get|set|do|add|delete. Anything other than "get" is refused
        unless the server has VIGI_NVR_ALLOW_WRITES=true AND confirm_write=true.
        The login and user_management modules are always refused. Credential
        fields in the reply are redacted.
        """
        return await nvr_call(ctx, method, module, params, confirm_write)
