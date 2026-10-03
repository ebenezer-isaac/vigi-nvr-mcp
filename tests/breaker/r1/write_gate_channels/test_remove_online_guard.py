"""Breaker r1 — vector write-gate/channels.

F1: the claim says ``nvr_remove_channel`` "cannot remove an ``online=="1"`` row
without ``force``". The implementation has no ``force`` parameter and performs no
``online`` check, so a live (``online=="1"``) camera binding is unbound on the
first authorised call. These tests encode the claimed guard and therefore FAIL
against the current code — the failure is the finding.
"""

from __future__ import annotations

import copy
import inspect
from typing import Any

import pytest

from tests.helpers import FakeNvr
from vigi_nvr_mcp.tools import channels


def _rows() -> list[dict[str, Any]]:
    # Row "9" is a LIVE camera: online == "1", conn_status == "0".
    return [
        {"id": "9", "uuid": "uuid-live", "ip": "192.0.2.21", "online": "1", "conn_status": "0"},
        {"id": "3", "uuid": "uuid-other", "ip": "192.0.2.22", "online": "1", "conn_status": "0"},
    ]


class _Table:
    def __init__(self) -> None:
        self.rows = _rows()

    def __call__(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        if body["method"] == "get" and "chm" in body:
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


@pytest.fixture
def wctx(make_ctx):
    return make_ctx(ALLOW_WRITES="true")


async def test_remove_online_row_refused_without_force(wctx, fake, table) -> None:
    """A live (online=="1") camera must NOT be removable without force.

    Current behaviour: it is removed. The write leaves the process, the device
    row disappears, and the tool reports success — a real camera channel gone.
    """
    live = next(r for r in table.rows if r["id"] == "9")
    assert live["online"] == "1"

    result = await channels.remove_channel(wctx, "9", "uuid-live", confirm_write=True)

    # The claim: an online row cannot be removed without force. Expect a refusal
    # and nothing sent. The code instead deletes the live camera.
    assert result["success"] is False, (
        "live online camera was removed with no force guard: " + repr(result)
    )
    assert fake.writes == [], "a chm_del_dev was sent for an online channel"
    assert any(r["id"] == "9" for r in table.rows), "online camera row was unbound"


async def test_remove_channel_exposes_a_force_override(wctx, fake, table) -> None:
    """The claimed guard implies a ``force`` escape hatch; the tool has none."""
    sig = inspect.signature(channels.remove_channel)
    assert "force" in sig.parameters, (
        "nvr_remove_channel has no 'force' parameter, so the online guard the "
        "claim describes cannot exist"
    )
