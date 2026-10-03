"""Export serial: one export in flight per device, crash-visible, over the store."""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.core.errors import PreconditionFailed, StateUnavailable
from vigi_nvr_mcp.core.state import Outcome
from vigi_nvr_mcp.export_lock import ExportSerial


def test_one_export_at_a_time(tmp_path) -> None:
    serial = ExportSerial(tmp_path, "dev")
    res = serial.reserve()
    assert serial.status()["in_flight"] is True
    with pytest.raises(PreconditionFailed, match="in progress"):
        serial.reserve()
    res.release(Outcome.SUCCESS)
    # Once released, a new export may run.
    serial.reserve().release(Outcome.SUCCESS)
    assert serial.status()["in_flight"] is False


def test_reservation_is_crash_visible(tmp_path) -> None:
    serial = ExportSerial(tmp_path, "dev")
    serial.reserve()  # handle dropped (crash between reserve and release)
    assert serial.status()["in_flight"] is True
    # A fresh instance (next process) still sees the in-flight reservation.
    assert ExportSerial(tmp_path, "dev").status()["in_flight"] is True


def test_stale_reservation_is_reclaimed(tmp_path) -> None:
    now = [1000.0]
    serial = ExportSerial(tmp_path, "dev", clock=lambda: now[0], stale_after_s=60.0)
    serial.reserve()  # crashed holder, never released
    now[0] = 2000.0  # well past the staleness window
    # The dead reservation is reclaimed rather than blocking exports forever.
    serial.reserve().release(Outcome.SUCCESS)
    assert serial.status()["in_flight"] is False


def test_unwritable_store_fails_closed(tmp_path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    serial = ExportSerial(blocker / "state", "dev")
    with pytest.raises(StateUnavailable):
        serial.reserve()


def test_context_manager_releases_on_exit(tmp_path) -> None:
    serial = ExportSerial(tmp_path, "dev")
    with serial.reserve():
        assert serial.status()["in_flight"] is True
    assert serial.status()["in_flight"] is False


def test_equivalent_hosts_share_one_export_slot(tmp_path) -> None:
    a = ExportSerial(tmp_path, "fe80::1")
    b = ExportSerial(tmp_path, "fe80::1")
    assert a.path == b.path
    a.reserve()
    with pytest.raises(PreconditionFailed):
        b.reserve()
