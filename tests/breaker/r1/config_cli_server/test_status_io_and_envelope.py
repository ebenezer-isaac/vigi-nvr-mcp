"""Breaker r1 / config-cli-server — F3 and F4.

Claims under attack:
  * "nvr_status ... perform[s] zero device I/O"
  * "every registered tool returns a {success,data,error} envelope and never
     raises into the MCP framework, including on ... transport errors ..."

F3: nvr_status -> backend.healthcheck() -> get_challenge() does a pre-auth POST
    to "/", so nvr_status performs device I/O on every call.

F4: nvr_status (``server._status``) is the ONLY registered tool not wrapped by
    ``core.tooling.run_tool``. healthcheck() only catches ``DeviceError``; any
    other exception raised below it (here a RuntimeError from the transport, as
    an httpx custom transport or an infra bug can raise) propagates as a FastMCP
    ToolError instead of an envelope. Every run_tool-wrapped tool returns a
    clean INTERNAL_ERROR envelope for the same fault.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from tests.helpers import FakeNvr, nvr_env
from vigi_nvr_mcp.backend import NvrBackend
from vigi_nvr_mcp.core.config import load_global_settings
from vigi_nvr_mcp.server import MCP_ENV_PREFIX, build_server


def _build(backend: NvrBackend):
    return build_server(load_global_settings(MCP_ENV_PREFIX, {}), backend)


async def _envelope(mcp, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    result = await mcp.call_tool(name, args or {})
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if isinstance(structured, dict) and "success" in structured:
        return structured
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


async def test_status_probes_but_never_logs_in() -> None:
    # RECONCILED to orchestrator decision CC-F3 / AL-F4 (fixer brief, amended
    # 01-NVR-SPEC §N1): nvr_status is a reachability healthcheck, so a
    # credential-free challenge probe is expected and allowed; what it must never
    # do is spend a login attempt. The original claim conflated "no login" with
    # "no I/O"; this asserts the clarified rule (probe allowed, login never).
    fake = FakeNvr()
    backend = NvrBackend.from_env(nvr_env(), http_transport=fake.transport())
    mcp, _ = _build(backend)
    await _envelope(mcp, "nvr_status")
    await backend.aclose()
    assert fake.login_attempts == 0, f"nvr_status spent a login attempt: {fake.requests}"


async def test_status_returns_envelope_on_non_device_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("boom in transport")

    backend = NvrBackend.from_env(nvr_env(), http_transport=httpx.MockTransport(handler))
    mcp, _ = _build(backend)
    raised: BaseException | None = None
    try:
        await _envelope(mcp, "nvr_status")
    except BaseException as exc:  # noqa: BLE001 - proving a raise escapes
        raised = exc
    await backend.aclose()
    assert raised is None, (
        f"nvr_status raised {type(raised).__name__} into the MCP framework "
        "instead of returning an envelope"
    )


async def test_other_tools_return_envelope_on_non_device_error() -> None:
    """Contrast: a run_tool-wrapped tool survives the same fault (this passes)."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("boom in transport")

    backend = NvrBackend.from_env(nvr_env(), http_transport=httpx.MockTransport(handler))
    mcp, _ = _build(backend)
    env = await _envelope(mcp, "nvr_get_device_info")
    await backend.aclose()
    assert env["success"] is False
    assert env["error"]["code"] == "INTERNAL_ERROR"
