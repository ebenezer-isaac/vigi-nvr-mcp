"""X1b: ``core.types.ConfirmWrite`` and its wiring into every NVR write tool.

Two levels:

* a unit check of the annotated type itself (only the JSON boolean ``true``
  survives as ``True``; everything else collapses to ``False``; the advertised
  schema stays a plain boolean);
* end-to-end checks through the real ``mcp.call_tool`` boundary for the mutating
  tools, proving that a truthy string/number no longer coerces past the write
  gate: ``"true"``/``"1"``/``1``/``"yes"`` (and falsey values / ``null``) are
  refused with a single ``WRITE_REFUSED`` envelope and zero device I/O, while the
  genuine boolean ``true`` proceeds (to the dry-run echo here).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import BaseModel, TypeAdapter

from tests.helpers import nvr_env
from vigi_nvr_mcp.backend import NvrBackend
from vigi_nvr_mcp.core.config import load_global_settings
from vigi_nvr_mcp.core.types import ConfirmWrite
from vigi_nvr_mcp.server import MCP_ENV_PREFIX, build_server

# --- unit: the annotated type -------------------------------------------------


class _Model(BaseModel):
    confirm_write: ConfirmWrite = False


@pytest.mark.parametrize("value", ["true", "1", "yes", "on", "false", "0", "no", "", "sure", "2"])
def test_only_boolean_true_confirms_strings(value: str) -> None:
    assert _Model(confirm_write=value).confirm_write is False


@pytest.mark.parametrize("value", [1, 0, 2, -1, 1.0])
def test_numbers_do_not_confirm(value: Any) -> None:
    assert _Model(confirm_write=value).confirm_write is False


def test_none_defaults_and_does_not_confirm() -> None:
    assert _Model().confirm_write is False
    assert _Model(confirm_write=None).confirm_write is False


def test_genuine_boolean_true_confirms() -> None:
    assert _Model(confirm_write=True).confirm_write is True
    assert _Model(confirm_write=False).confirm_write is False


def test_published_schema_is_a_plain_boolean() -> None:
    # A well-behaved client must still see {"type": "boolean"}, not an enum/const.
    schema = TypeAdapter(ConfirmWrite).json_schema()
    assert schema["type"] == "boolean"


# --- boundary: every write tool through mcp.call_tool -------------------------

# (tool_name, args without confirm_write). The write gate is the first check in
# each of these, so a refused confirm_write performs zero device I/O.
WRITE_TOOLS: list[tuple[str, dict[str, Any]]] = [
    ("nvr_raw_call", {"method": "set", "module": "system", "params": {}}),
    ("nvr_remove_channel", {"channel_id": "3", "expected_uuid": "uuid-ghost"}),
    ("nvr_move_channel", {"old_id": "3", "new_id": "4", "expected_uuid": "uuid-ghost"}),
    ("nvr_enable_rtsp", {}),
    ("nvr_delete_export", {"name": "clip.mp4"}),
    ("nvr_purge_exports", {}),
]

# Values a caller might send instead of the JSON boolean true: none may confirm.
NON_CONFIRMING = ["true", "1", 1, "yes", "false", "0", 0, "sure", "2", None]


def _envelope(result: Any) -> dict[str, Any]:
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if isinstance(structured, dict) and "success" in structured:
        return structured
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


def _build(fake, **env: str):
    fake.api_handler = lambda t, b: {"error_code": 0}
    backend = NvrBackend.from_env(nvr_env(**env), http_transport=fake.transport())
    mcp, _ = build_server(load_global_settings(MCP_ENV_PREFIX, {}), backend)
    return mcp


@pytest.mark.parametrize("tool,args", WRITE_TOOLS)
@pytest.mark.parametrize("confirm", NON_CONFIRMING)
async def test_non_true_confirm_is_refused_with_zero_io(fake, tool, args, confirm) -> None:
    # ALLOW_WRITES is on, so the ONLY thing standing between the caller and the
    # device is confirm_write. A non-boolean-true value must still refuse.
    mcp = _build(fake, ALLOW_WRITES="true")
    fake.requests.clear()
    result = await mcp.call_tool(tool, {**args, "confirm_write": confirm})
    env = _envelope(result)
    assert env["success"] is False, f"{tool} confirm_write={confirm!r} must be refused"
    assert env["error"]["code"] == "WRITE_REFUSED", f"{tool}/{confirm!r} must be WRITE_REFUSED"
    assert fake.writes == [], f"{tool} confirm_write={confirm!r} must perform zero write I/O"
    assert fake.api_requests == [], f"{tool} confirm_write={confirm!r} must perform zero I/O"


@pytest.mark.parametrize("tool,args", WRITE_TOOLS)
async def test_boolean_true_proceeds_to_dry_run(fake, tool, args) -> None:
    # confirm_write=true (the genuine boolean) passes the gate; DRY_RUN then makes
    # the guarded writer echo the request and perform zero device I/O.
    mcp = _build(fake, ALLOW_WRITES="true", DRY_RUN="true")
    fake.requests.clear()
    result = await mcp.call_tool(tool, {**args, "confirm_write": True})
    env = _envelope(result)
    assert env["success"] is True, f"{tool} confirm_write=true must proceed"
    assert env["data"]["dry_run"] is True, f"{tool} must reach the dry-run echo"
    assert fake.writes == [], f"{tool} dry-run must perform zero write I/O"
