"""Breaker round 2 — vector write-gate-central: axes that HOLD.

Passing tests are not findings (per the protocol); they are evidence for the
"Axes with no finding" section of FINDINGS.md. Each documents a claim sub-clause
that survived attack, or a round-1 fix that is genuinely in place.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests.helpers import FAKE_STOK_1, FakeNvr, nvr_env
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.client import NvrClient
from vigi_nvr_mcp.core.config import load_device_settings, load_global_settings
from vigi_nvr_mcp.tools import ToolContext, channels, raw
from vigi_nvr_mcp.transport import NvrTransport


def _rows() -> list[dict[str, Any]]:
    return [
        {"id": "9", "uuid": "uuid-live", "ip": "192.0.2.21", "online": "1", "conn_status": "0"},
        {"id": "3", "uuid": "uuid-ghost", "ip": "192.0.2.22", "online": "0", "conn_status": "1"},
    ]


class _Table:
    """A mutable fake channel table that counts list reads and applies deletes."""

    def __init__(self) -> None:
        self.rows = _rows()
        self.list_reads = 0

    def __call__(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        if body["method"] == "get" and "chm" in body:
            self.list_reads += 1
            return {"error_code": 0, "chm": {"added_dev": copy.deepcopy(self.rows)}}
        if body["method"] == "do" and "chm" in body and "chm_del_dev" in body["chm"]:
            ids = set(body["chm"]["chm_del_dev"]["ids"])
            self.rows = [r for r in self.rows if r["id"] not in ids]
            return {"error_code": 0}
        return {"error_code": 0}


@pytest.fixture
def table(fake: FakeNvr) -> _Table:
    t = _Table()
    fake.api_handler = t
    return t


# ---- round-1 F1 (depth bomb) is fixed: returns an envelope, no RecursionError ----


async def test_depth_bomb_returns_envelope(make_ctx, fake: FakeNvr) -> None:
    d: Any = {"x": 1}
    for _ in range(4000):
        d = {"a": d}
    ctx = make_ctx()
    result = await raw.nvr_raw_call(ctx, "get", "system", d)
    assert result["success"] is False
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.api_requests == []


# ---- remove: online guard, force override, and uuid-before-online ordering --------


async def test_online_row_refused_without_force(make_ctx, fake, table) -> None:
    ctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.remove_channel(ctx, "9", "uuid-live", confirm_write=True)
    assert result["error"]["details"]["reason"] == "CHANNEL_ONLINE"
    assert fake.writes == []
    assert any(r["id"] == "9" for r in table.rows)


async def test_online_row_removed_with_force(make_ctx, fake, table) -> None:
    ctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.remove_channel(ctx, "9", "uuid-live", confirm_write=True, force=True)
    assert result["success"] is True and result["data"]["removed"] is True
    assert all(r["id"] != "9" for r in table.rows)


async def test_force_does_not_bypass_uuid_check(make_ctx, fake, table) -> None:
    """force overrides the ONLINE guard only; a uuid mismatch still refuses."""
    ctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.remove_channel(ctx, "9", "WRONG-UUID", confirm_write=True, force=True)
    assert result["error"]["details"]["reason"] == "UUID_MISMATCH"
    assert fake.writes == []


# ---- move: occupied target refused on the fresh re-read --------------------------


async def test_move_onto_occupied_refused(make_ctx, fake, table) -> None:
    ctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.move_channel(ctx, "3", "9", "uuid-ghost", confirm_write=True)
    assert result["error"]["details"]["reason"] == "TARGET_OCCUPIED"
    assert fake.writes == []


# ---- dry-run: zero device I/O for the GuardedWriter-backed tools ------------------


async def test_remove_dry_run_zero_io(make_ctx, fake, table) -> None:
    ctx = make_ctx(ALLOW_WRITES="true", DRY_RUN="true")
    result = await channels.remove_channel(ctx, "3", "uuid-ghost", confirm_write=True)
    assert result["data"]["dry_run"] is True
    assert fake.api_requests == []  # not even the re-read happens


async def test_raw_set_dry_run_zero_io(make_ctx, fake) -> None:
    ctx = make_ctx(ALLOW_WRITES="true", DRY_RUN="true")
    result = await raw.nvr_raw_call(ctx, "set", "system", {"x": 1}, confirm_write=True)
    assert result["data"]["dry_run"] is True
    assert fake.writes == []


# ---- concurrency: writes serialise, and each re-reads after the prior write -------


async def test_concurrent_removes_serialise_and_each_rereads(fake) -> None:
    import asyncio

    settings = load_device_settings("VIGI_NVR_", nvr_env(ALLOW_WRITES="true"))
    state = {"rows": [{"id": str(i), "uuid": f"u{i}", "online": "0", "conn_status": "1"}
                      for i in range(10)]}
    reads = {"n": 0}

    def handler(token: str, body: dict[str, Any]) -> dict[str, Any]:
        if body["method"] == "get" and "chm" in body:
            reads["n"] += 1
            return {"error_code": 0, "chm": {"added_dev": copy.deepcopy(state["rows"])}}
        if body["method"] == "do" and "chm_del_dev" in body.get("chm", {}):
            ids = set(body["chm"]["chm_del_dev"]["ids"])
            state["rows"] = [r for r in state["rows"] if r["id"] not in ids]
            return {"error_code": 0}
        return {"error_code": 0}

    fake.api_handler = handler
    transport = NvrTransport(settings, http_transport=fake.transport())
    client = NvrClient(settings, transport, Authenticator(settings, transport))
    ctx = ToolContext(settings=settings, client=client)  # one shared GuardedWriter/lock
    results = await asyncio.gather(
        *[channels.remove_channel(ctx, str(i), f"u{i}", confirm_write=True) for i in range(10)]
    )
    await client.aclose()

    assert all(r["success"] for r in results)
    assert state["rows"] == []
    # 2 list reads per remove (before + after); serialisation keeps them from
    # collapsing, and each re-read runs after the previous delete committed.
    assert reads["n"] == 20


# ---- backup content validation (round-1 F3 fixed) + reported fields ---------------


async def test_backup_rejects_html(make_ctx, fake, tmp_path) -> None:
    from vigi_nvr_mcp.tools import backup

    fake.api_handler = lambda t, b: {"error_code": 0, "url": "/backup/config.bin"}
    fake.files = {f"/stok={FAKE_STOK_1}/backup/config.bin": b"   <html><body>login</body></html>"}
    result = await backup.backup_config(make_ctx(BACKUP_DIR=str(tmp_path / "bk")))
    assert result["success"] is False and result["error"]["code"] == "TRANSPORT_ERROR"


async def test_backup_rejects_under_1kb(make_ctx, fake, tmp_path) -> None:
    from vigi_nvr_mcp.tools import backup

    fake.api_handler = lambda t, b: {"error_code": 0, "url": "/backup/config.bin"}
    fake.files = {f"/stok={FAKE_STOK_1}/backup/config.bin": b"x" * 1023}  # < 1 KB
    result = await backup.backup_config(make_ctx(BACKUP_DIR=str(tmp_path / "bk")))
    assert result["success"] is False and result["error"]["code"] == "TRANSPORT_ERROR"


async def test_backup_accepts_blob_and_reports_fields(make_ctx, fake, tmp_path) -> None:
    from vigi_nvr_mcp.tools import backup

    fake.api_handler = lambda t, b: {"error_code": 0, "url": "/backup/config.bin"}
    fake.files = {f"/stok={FAKE_STOK_1}/backup/config.bin": b"\x00CFG" + b"y" * 2048}
    result = await backup.backup_config(make_ctx(BACKUP_DIR=str(tmp_path / "bk")))
    assert result["success"] is True
    for field in ("content_type", "size", "sha256"):
        assert field in result["data"]
    assert result["data"]["size"] == 2052
    assert len(result["data"]["sha256"]) == 64


# ---- confirm_write at the real FastMCP boundary: only the boolean true confirms ---


async def _boundary_call(mcp, name: str, args: dict[str, Any]) -> dict[str, Any] | None:
    try:
        result = await mcp.call_tool(name, args)
    except Exception:
        return None  # pydantic rejected the arg type: fail-closed (no tool body ran)
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if isinstance(structured, dict) and "success" in structured:
        return structured
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


async def test_confirm_write_boundary_only_true_confirms(fake) -> None:
    """X1b: the ``confirm_write`` parameter is now typed ``ConfirmWrite``, whose
    BeforeValidator collapses every value except the JSON boolean ``true`` to
    ``False``. So a truthy string/number no longer coerces to ``True`` and slips
    past the gate: it reaches the gate as ``False`` and is refused with a single
    ``WRITE_REFUSED`` envelope and zero I/O (no schema error, no ToolError)."""
    from vigi_nvr_mcp.backend import NvrBackend
    from vigi_nvr_mcp.server import MCP_ENV_PREFIX, build_server

    fake.api_handler = lambda t, b: {"error_code": 0}
    backend = NvrBackend.from_env(nvr_env(ALLOW_WRITES="true"), http_transport=fake.transport())
    mcp, _ = build_server(load_global_settings(MCP_ENV_PREFIX, {}), backend)

    async def sent(val: Any) -> dict[str, Any] | None:
        fake.requests.clear()
        r = await _boundary_call(
            mcp, "nvr_raw_call",
            {"method": "set", "module": "system", "params": {}, "confirm_write": val},
        )
        wrote = bool([b for _, b in fake.api_requests if b.get("method") != "get"])
        return {"env": r, "wrote": wrote}

    # Only the genuine JSON boolean true authorises the write.
    ok = await sent(True)
    assert ok["env"]["success"] is True and ok["wrote"] is True

    # Every non-boolean-true value is refused with the standard envelope and no I/O.
    for val in ("true", "1", 1, "yes", "false", "0", 0, "sure", "2", None):
        out = await sent(val)
        assert out["env"] is not None, f"{val!r} must fail closed with an envelope, not a ToolError"
        assert out["env"]["success"] is False, f"confirm_write={val!r} must be refused"
        assert out["env"]["error"]["code"] == "WRITE_REFUSED", f"{val!r} must be WRITE_REFUSED"
        assert out["wrote"] is False, f"confirm_write={val!r} must perform zero write I/O"
