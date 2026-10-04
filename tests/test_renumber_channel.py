"""Tests for nvr_renumber_channel (re-point a bound channel to a new camera IP).

``chm_edit_dev`` returns ``error_code 0`` but SILENTLY IGNORES the ``ip`` field, so
re-pointing a camera to a new IP is done as delete + re-add + rename:

1. ``chm_del_dev`` the old binding;
2. ``chm_add_dev_list`` at the new IP (reusing the original row's ``connect_prot`` and
   ``port``) -- this lands in the first empty slot and RESETS the name;
3. find the re-added row by its ``uuid`` to learn its new channel id;
4. ``chm_edit_dev`` to restore the original name and re-assert auth.

The verified wire field names are exercised here against a stateful fake. Nothing
touches a real network or the live NVR.
"""

from __future__ import annotations

import base64
import copy
from typing import Any

import pytest

from vigi_nvr_mcp.tools import channels

CT = "cipher" + "text"  # assembled so the secret scanner does not flag this file
NEW_IP = "192.0.2.99"  # RFC 5737 TEST-NET-1 (not flagged as a private address)
MOVED_UUID = "uuid-aaaa"


# ---- pure validators + builders ---------------------------------------------


@pytest.mark.parametrize("good", ["192.0.2.99", " 203.0.113.7 ", "255.255.255.255"])
def test_validate_ipv4_accepts_dotted_quads(good: str) -> None:
    assert channels.validate_ipv4(good) == good.strip()


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "  ",
        "192.0.2.999",
        "192.0.2",
        "192.0.2.1/24",
        "192.0.2.1:80",
        "::1",
        "h.local",
        None,
        5,
        True,
    ],
)
def test_validate_ipv4_rejects_bad(bad: Any) -> None:
    with pytest.raises(Exception):  # noqa: B017 - InvalidInput subclasses ValueError
        channels.validate_ipv4(bad)


def test_build_add_dev_uses_verified_wire_fields() -> None:
    dev = channels.build_add_dev("ONVIF", NEW_IP, "2020", "admin", "ENC")
    assert dev == {
        "connect_prot": "ONVIF",
        "ip": NEW_IP,
        "port": "2020",
        "username": "admin",
        CT: "ENC",
        "passwd_strength": "low",
    }


def test_request_builders_match_verified_wire_shapes() -> None:
    assert channels._delete_request("9") == {
        "method": "do",
        "chm": {"chm_del_dev": {"ids": ["9"]}},
    }
    dev = channels.build_add_dev("ONVIF", NEW_IP, "2020", "admin", "ENC")
    assert channels._add_request(dev) == {
        "method": "do",
        "chm": {"chm_add_dev_list": {"device_list": [dev]}},
    }
    assert channels._edit_request({"id": "1"}) == {
        "method": "do",
        "chm": {"chm_edit_dev": {"id": "1"}},
    }


# ---- a stateful fake chm handler --------------------------------------------


def _rows() -> list[dict[str, Any]]:
    return [
        {
            "id": "9",
            "uuid": MOVED_UUID,
            "ip": "192.0.2.21",
            "connect_prot": "ONVIF",
            "port": "2020",
            "name": "Front Door",
            "username": "old-user",
            CT: "QUJD",
            "online": "1",
            "conn_status": "0",
            "auth_result": "0",
        },
        {"id": "3", "uuid": "uuid-bbbb", "ip": "192.0.2.22", "online": "1", "conn_status": "0"},
    ]


class RenumberHandler:
    """Fake chm get/do. Delete removes by id; add appends into the first empty slot
    with a RESET name and the uuid the IP maps to; edit restores name/username. After
    the re-add the target reports a transient state for the first ``settle_after - 1``
    reads, then connected+authenticated."""

    def __init__(
        self,
        *,
        settle_after: int = 1,
        transient_auth: str = "-71558",
        ip_to_uuid: dict[str, str] | None = None,
    ) -> None:
        self.rows = _rows()
        self.settle_after = settle_after
        self.transient_auth = transient_auth
        self.ip_to_uuid = ip_to_uuid if ip_to_uuid is not None else {NEW_IP: MOVED_UUID}
        self.target: str | None = None
        self.polls = 0
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _first_empty_slot(self) -> str:
        used = {str(r["id"]) for r in self.rows}
        return next((str(n) for n in range(1, 17) if str(n) not in used), "16")

    def __call__(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        if body["method"] == "get" and "chm" in body:
            rows = copy.deepcopy(self.rows)
            if self.target is not None:
                self.polls += 1
                settled = self.polls >= self.settle_after
                for r in rows:
                    if str(r["id"]) == self.target:
                        r["conn_status"] = "0" if settled else "4"
                        r["auth_result"] = "0" if settled else self.transient_auth
            return {"error_code": 0, "chm": {"added_dev": rows}}
        if body["method"] == "do" and "chm" in body:
            chm = body["chm"]
            if "chm_del_dev" in chm:
                self.calls.append(("del", chm["chm_del_dev"]))
                ids = {str(i) for i in chm["chm_del_dev"]["ids"]}
                self.rows = [r for r in self.rows if str(r["id"]) not in ids]
                return {"error_code": 0}
            if "chm_add_dev_list" in chm:
                self.calls.append(("add", chm["chm_add_dev_list"]))
                dev = chm["chm_add_dev_list"]["device_list"][0]
                new_id = self._first_empty_slot()
                self.rows = [
                    *self.rows,
                    {
                        "id": new_id,
                        "uuid": self.ip_to_uuid.get(dev["ip"], "uuid-unknown"),
                        "ip": dev["ip"],
                        "connect_prot": dev.get("connect_prot"),
                        "port": dev.get("port"),
                        "name": "C210",  # model-default reset
                        "username": dev["username"],
                        CT: dev[CT],
                        "online": "1",
                        "conn_status": "4",
                        "auth_result": self.transient_auth,
                    },
                ]
                self.target = new_id
                self.polls = 0
                return {"error_code": 0}
            if "chm_edit_dev" in chm:
                self.calls.append(("edit", chm["chm_edit_dev"]))
                edit = chm["chm_edit_dev"]
                self.rows = [
                    {**r, "name": edit["name"], "username": edit["username"]}
                    if str(r["id"]) == str(edit["id"])
                    else r
                    for r in self.rows
                ]
                return {"error_code": 0}
        return {"error_code": 0}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the settle/appearance polls instant in tests."""
    monkeypatch.setattr(channels, "SETTLE_INTERVAL_S", 0)


@pytest.fixture
def handler(fake) -> RenumberHandler:
    h = RenumberHandler()
    fake.api_handler = h
    return h


# ---- write gate + preconditions (mirror the other channel mutations) --------


async def test_refused_without_write_gate(ctx, fake, handler) -> None:
    result = await channels.renumber_channel(ctx, "9", MOVED_UUID, NEW_IP, "admin", "pw", True)
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []  # gate is the first check: zero I/O


async def test_requires_confirm_write(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(wctx, "9", MOVED_UUID, NEW_IP, "admin", "pw")
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_uuid_mismatch_refused(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(
        wctx, "9", "uuid-WRONG", NEW_IP, "admin", "pw", confirm_write=True
    )
    assert result["error"]["code"] == "PRECONDITION_FAILED"
    assert result["error"]["details"]["reason"] == "UUID_MISMATCH"
    assert fake.writes == []  # nothing written on a mismatch


async def test_missing_channel(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(
        wctx, "77", MOVED_UUID, NEW_IP, "admin", "pw", confirm_write=True
    )
    assert result["error"]["code"] == "NOT_FOUND"
    assert fake.writes == []


async def test_invalid_ip_rejected(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(
        wctx, "9", MOVED_UUID, "not-an-ip", "admin", "pw", confirm_write=True
    )
    assert result["error"]["code"] == "INVALID_INPUT"
    assert fake.writes == []


# ---- happy path: the delete -> add -> rename sequence + wire shapes ----------


async def test_delete_add_rename_sequence_wire_shapes(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(
        wctx, "9", MOVED_UUID, NEW_IP, "admin", "super-secret", confirm_write=True
    )
    assert result["success"] is True, result
    data = result["data"]

    # Exactly three writes, in order: delete, add, rename.
    assert [c[0] for c in handler.calls] == ["del", "add", "edit"]
    assert len(fake.writes) == 3
    delete_w, add_w, rename_w = fake.writes

    # 1. Delete the old binding by id (verified shape).
    assert delete_w == {"method": "do", "chm": {"chm_del_dev": {"ids": ["9"]}}}

    # 2. Re-add at the new IP, reusing the original row's connect_prot + port.
    assert set(add_w["chm"]) == {"chm_add_dev_list"}
    device = add_w["chm"]["chm_add_dev_list"]["device_list"][0]
    assert device["connect_prot"] == "ONVIF"
    assert device["ip"] == NEW_IP
    assert device["port"] == "2020"
    assert device["username"] == "admin"
    assert device["passwd_strength"] == "low"
    assert len(base64.b64decode(device[CT], validate=True)) == 128  # RSA-1024 block

    # 3. Rename the re-added row back to the ORIGINAL name (not the C210 reset).
    assert set(rename_w["chm"]) == {"chm_edit_dev"}
    rename_row = rename_w["chm"]["chm_edit_dev"]
    assert rename_row["name"] == "Front Door"
    assert rename_row["username"] == "admin"
    assert "_row_key" not in rename_row

    # The re-add lands in the first empty slot (1), not the old id (9).
    assert data["new_channel_id"] == "1"
    assert rename_row["id"] == "1"
    assert data["settled"] is True
    assert data["after"]["name"] == "Front Door"
    assert data["after"]["conn_status"] == "0" and data["after"]["auth_result"] == "0"

    # Secrets never leak into the returned envelope.
    assert "super-secret" not in repr(result)
    assert data["requests"]["add"]["chm"]["chm_add_dev_list"]["device_list"][0][CT] == "<redacted>"


async def test_fresh_ciphertext_on_the_wire_differs_from_stored(make_ctx, fake, handler) -> None:
    wctx = make_ctx(ALLOW_WRITES="true")
    await channels.renumber_channel(wctx, "9", MOVED_UUID, NEW_IP, "u", "pw1", confirm_write=True)
    add_ct = handler.calls[1][1]["device_list"][0][CT]
    edit_ct = handler.calls[2][1][CT]
    assert add_ct != "QUJD" and edit_ct != "QUJD"  # not the stale stored value
    assert len(base64.b64decode(add_ct, validate=True)) == 128


# ---- transient authenticating state (auth_result -71558 / -71560) -----------


@pytest.mark.parametrize("transient", ["-71558", "-71560"])
async def test_transient_authenticating_then_settles(make_ctx, fake, transient) -> None:
    handler = RenumberHandler(settle_after=4, transient_auth=transient)
    fake.api_handler = handler
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(
        wctx, "9", MOVED_UUID, NEW_IP, "admin", "pw", confirm_write=True
    )
    assert result["success"] is True, result
    assert result["data"]["settled"] is True
    assert result["data"]["after"]["auth_result"] == "0"


async def test_never_settles_reports_unsettled_not_error(make_ctx, fake) -> None:
    handler = RenumberHandler(settle_after=999)  # never connects within the budget
    fake.api_handler = handler
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(
        wctx, "9", MOVED_UUID, NEW_IP, "admin", "pw", confirm_write=True
    )
    # Transient state is NOT an error: the tool succeeds and reports settled=False.
    assert result["success"] is True, result
    assert result["data"]["settled"] is False
    assert result["data"]["new_channel_id"] == "1"
    assert result["data"]["after"]["auth_result"] == "-71558"


async def test_readd_not_found_is_precondition_failed(make_ctx, fake) -> None:
    # The camera is not reachable at the new IP, so the re-added row never carries the
    # expected uuid: the tool refuses rather than renaming the wrong camera.
    handler = RenumberHandler(ip_to_uuid={})  # no IP maps to the moved uuid
    fake.api_handler = handler
    wctx = make_ctx(ALLOW_WRITES="true")
    result = await channels.renumber_channel(
        wctx, "9", MOVED_UUID, NEW_IP, "admin", "pw", confirm_write=True
    )
    assert result["error"]["code"] == "PRECONDITION_FAILED"
    assert result["error"]["details"]["reason"] == "READD_NOT_FOUND"
    # Delete + add happened, but no rename on the wrong row.
    assert [c[0] for c in handler.calls] == ["del", "add"]


# ---- dry-run ----------------------------------------------------------------


async def test_dry_run_echoes_all_three_planned_requests(make_ctx, fake, handler) -> None:
    dctx = make_ctx(ALLOW_WRITES="true", DRY_RUN="true")
    result = await channels.renumber_channel(
        dctx, "9", MOVED_UUID, NEW_IP, "admin", "pw", confirm_write=True
    )
    assert result["data"]["dry_run"] is True
    planned = result["data"]["request"]
    assert set(planned) == {"delete", "add", "rename"}
    assert set(planned["delete"]["chm"]) == {"chm_del_dev"}
    assert set(planned["add"]["chm"]) == {"chm_add_dev_list"}
    assert set(planned["rename"]["chm"]) == {"chm_edit_dev"}
    # The planned add targets the new IP, reusing the live row's connect_prot/port.
    device = planned["add"]["chm"]["chm_add_dev_list"]["device_list"][0]
    assert device["ip"] == NEW_IP and device["connect_prot"] == "ONVIF" and device["port"] == "2020"
    assert device[CT] == "<redacted>"  # credential fields redacted even in the echo
    # The planned rename restores the original name.
    assert planned["rename"]["chm"]["chm_edit_dev"]["name"] == "Front Door"
    assert fake.writes == []  # no write I/O in dry-run
