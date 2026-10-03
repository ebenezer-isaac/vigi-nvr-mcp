"""Breaker r1 — vector write-gate/channels.

F3 (beyond the strict claim text, within the "backup" attack axis): the claim
restricts ``nvr_backup_config`` to location + mode, which hold. But the tool
performs no content validation on the downloaded bytes: any non-empty body is
saved as ``nvr-config-*.bin`` and reported as a successful backup. If the session
file GET returns an HTML login page (expired/!redirected session), that page is
stored as "the backup", making the "run nvr_backup_config first" safety net
hollow before a destructive cleanup. Reproducible only with this mock, so
likelihood is scored 1 (no device evidence).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import FAKE_STOK_1, FakeNvr


@pytest.fixture
def table(fake: FakeNvr):
    # Answer download_conf with a relative url the fake serves as a file.
    fake.api_handler = lambda t, b: {"error_code": 0, "url": "/backup/config.bin"}
    return fake


async def test_backup_rejects_html_login_page(make_ctx, fake: FakeNvr, table, tmp_path) -> None:
    from vigi_nvr_mcp.tools import backup

    html = (
        b"<!doctype html><html><head><title>Log In</title></head>"
        b"<body><form id='login'></form></body></html>"
    )
    fake.files = {f"/stok={FAKE_STOK_1}/backup/config.bin": html}
    bctx = make_ctx(BACKUP_DIR=str(tmp_path / "bk"))

    result = await backup.backup_config(bctx)

    assert result["success"] is False, (
        "an HTML login page was accepted and saved as a config backup: " + repr(result)
    )
    # And nothing resembling an HTML page should be sitting on disk as a backup.
    written = list((tmp_path / "bk").glob("*.bin")) if (tmp_path / "bk").exists() else []
    for path in written:
        assert b"<html" not in Path(path).read_bytes().lower(), (
            f"HTML page persisted as backup at {path}"
        )
