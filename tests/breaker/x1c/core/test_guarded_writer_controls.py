"""x1c / core — GuardedWriter (controls; dry-run and serialisation hold).

* ``run(require_gate=False)`` with ``dry_run`` set returns the dry-run envelope and
  performs NO I/O (the action never runs) — dry-run is honoured even for the
  ungated read-only export path.
* ``run(require_gate=False)`` without dry-run runs the action even with
  ``allow_writes`` off (the read-only export runs before destructive cleanup) and
  serialises it under the per-device lock.
* ``run(require_gate=True)`` with ``allow_writes`` off fails closed (``WriteNotEnabled``).
* An exception inside the action releases the serial lock (no deadlock on the next run).

Documented, no finding: ``SerialLock`` is a non-reentrant ``asyncio.Lock`` — nesting
``run`` inside an action deadlocks, exactly as the module docstring warns ("acquire
it at the tool level only"). Not scored: no path nests it.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.core.config import DeviceSettings
from vigi_nvr_mcp.core.errors import WriteNotEnabled
from vigi_nvr_mcp.core.serial import GuardedWriter


def _settings(**over: object) -> DeviceSettings:
    base = {"env_prefix": "X_", "host": "192.0.2.1", "password": "pw"}
    base.update(over)
    return DeviceSettings(**base)


async def test_dry_run_skips_action_even_without_gate() -> None:
    gw = GuardedWriter(_settings(dry_run=True, allow_writes=False))
    ran: list[int] = []

    async def action() -> str:
        ran.append(1)
        return "did"

    result = await gw.run({"method": "x"}, action, require_gate=False)
    assert result == {"dry_run": True, "request": {"method": "x"}}
    assert ran == []


async def test_ungated_export_runs_with_writes_off() -> None:
    gw = GuardedWriter(_settings(dry_run=False, allow_writes=False))

    async def action() -> str:
        return "exported"

    assert await gw.run({"method": "backup"}, action, require_gate=False) == "exported"


async def test_gated_write_fails_closed_without_allow_writes() -> None:
    gw = GuardedWriter(_settings(dry_run=False, allow_writes=False))

    async def action() -> str:  # pragma: no cover - must not run
        return "wrote"

    with pytest.raises(WriteNotEnabled):
        await gw.run({"method": "set"}, action, require_gate=True)


async def test_exception_in_action_releases_the_lock() -> None:
    gw = GuardedWriter(_settings(dry_run=False, allow_writes=True))

    async def boom() -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await gw.run({"method": "set"}, boom)
    assert gw.busy is False

    async def ok() -> str:
        return "ok"

    assert await gw.run({"method": "set"}, ok) == "ok"
