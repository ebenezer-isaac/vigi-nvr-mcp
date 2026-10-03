"""Breaker round 2 — vector write-gate-central.

F1: the round-2 claim says *every* mutating path — explicitly including
"``nvr_backup_config``'s writes if any" — "goes through exactly one
``GuardedWriter.run(request, action)`` ... and under ``VIGI_NVR_DRY_RUN`` returns
``{dry_run: true, request}`` performing zero I/O".

``nvr_backup_config`` does neither. ``backup_config`` calls
``ctx.client.request_config_backup()``, which issues
``{"method":"do","system":{"download_conf":null}}`` — a NON-``get`` request —
directly through ``client.call``, never through ``ctx.writes`` (the GuardedWriter).
Because the GuardedWriter is the *only* place dry-run is decided and backup never
reaches it, ``VIGI_NVR_DRY_RUN=true`` is ignored: the ``do`` is transmitted to the
device and a (credential-bearing) file is written to disk.

The assertions below encode the claim and FAIL against the current code — the
failure is the finding. (Mocks only; no device or real network.)
"""

from __future__ import annotations

import pytest

from tests.helpers import FAKE_STOK_1, FakeNvr


@pytest.fixture
def served(fake: FakeNvr) -> FakeNvr:
    # download_conf -> a relative url the fake serves as a 2 KB "config" blob,
    # large enough to clear the >=1 KB content check so the tool reports success.
    fake.api_handler = lambda t, b: {"error_code": 0, "url": "/backup/config.bin"}
    fake.files = {f"/stok={FAKE_STOK_1}/backup/config.bin": b"CFG\x00" + b"X" * 2048}
    return fake


async def test_backup_performs_no_device_io_under_dry_run(make_ctx, served, tmp_path) -> None:
    """Under DRY_RUN=true the claim guarantees zero I/O for every mutating path.

    nvr_backup_config instead sends do/download_conf to the device.
    """
    from vigi_nvr_mcp.tools import backup

    bctx = make_ctx(DRY_RUN="true", BACKUP_DIR=str(tmp_path / "bk"))
    await backup.backup_config(bctx)

    sent_non_get = [b for _, b in served.api_requests if b.get("method") != "get"]
    assert sent_non_get == [], (
        "nvr_backup_config transmitted a non-get request to the device despite "
        "VIGI_NVR_DRY_RUN=true (it bypasses GuardedWriter): " + repr(sent_non_get)
    )


async def test_backup_writes_no_file_under_dry_run(make_ctx, served, tmp_path) -> None:
    """A dry-run preview must not leave a (credential-bearing) backup on disk."""
    from vigi_nvr_mcp.tools import backup

    bk = tmp_path / "bk"
    bctx = make_ctx(DRY_RUN="true", BACKUP_DIR=str(bk))
    result = await backup.backup_config(bctx)

    written = list(bk.glob("*.bin")) if bk.exists() else []
    assert written == [], (
        "nvr_backup_config wrote a file to disk under VIGI_NVR_DRY_RUN=true: "
        + repr([str(p) for p in written])
    )
    # The claim's dry-run shape for a mutating path is {dry_run: true, request}.
    assert result.get("data", {}).get("dry_run") is True, (
        "nvr_backup_config did not honour dry-run at all: " + repr(result)
    )
