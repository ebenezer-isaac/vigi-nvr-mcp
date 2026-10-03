"""Server build, nvr_status, CLI (--list-tools, --check-auth), and core isolation."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.helpers import FAKE_STOK_1, FakeNvr, nvr_env
from vigi_nvr_mcp import cli
from vigi_nvr_mcp.backend import NvrBackend
from vigi_nvr_mcp.core.config import load_global_settings
from vigi_nvr_mcp.core.errors import ConfigError
from vigi_nvr_mcp.server import MCP_ENV_PREFIX, build_server

PACKAGE = Path(__file__).resolve().parent.parent / "vigi_nvr_mcp"

EXPECTED_TOOLS = {
    "nvr_status",
    "nvr_call",
    "nvr_raw_call",
    "nvr_list_modules",
    "nvr_list_calls",
    "nvr_describe_call",
    "nvr_login",
    "nvr_auth_status",
    "nvr_get_device_info",
    "nvr_get_module_spec",
    "nvr_get_system_info",
    "nvr_get_network_info",
    "nvr_get_video_resolutions",
    "nvr_list_channels",
    "nvr_get_channel",
    "nvr_find_duplicate_channels",
    "nvr_remove_channel",
    "nvr_move_channel",
    "nvr_list_disks",
    "nvr_get_recording_status",
    "nvr_backup_config",
}


def _backend(fake: FakeNvr, **overrides: str) -> NvrBackend:
    return NvrBackend.from_env(nvr_env(**overrides), http_transport=fake.transport())


def _build(fake: FakeNvr, **overrides: str):
    return build_server(load_global_settings(MCP_ENV_PREFIX, {}), _backend(fake, **overrides))


async def _call(mcp, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    result = await mcp.call_tool(name, args or {})
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if isinstance(structured, dict) and "success" in structured:
        return structured
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


# ---- registration ---------------------------------------------------------------


async def test_registered_tools_match_expected_and_mcp_view(fake) -> None:
    mcp, names = _build(fake)
    assert set(names) == EXPECTED_TOOLS
    assert len(names) == len(set(names))
    assert {t.name for t in await mcp.list_tools()} == EXPECTED_TOOLS
    assert all(n.startswith("nvr_") for n in names)
    assert fake.requests == []  # building makes no device calls


def test_list_tools_needs_no_configuration(monkeypatch) -> None:
    for key in [k for k in __import__("os").environ if k.startswith("VIGI_")]:
        monkeypatch.delenv(key)
    assert set(cli.list_tools()) == EXPECTED_TOOLS


def test_cli_list_tools_prints_sorted_names(capsys) -> None:
    assert cli.main(["--list-tools"]) == 0
    assert capsys.readouterr().out.split() == sorted(EXPECTED_TOOLS)


def test_backend_from_env_fails_fast_on_bad_settings() -> None:
    with pytest.raises(ConfigError, match="VIGI_NVR_PORT"):
        NvrBackend.from_env(nvr_env(PORT="0"))
    with pytest.raises(ConfigError, match="VIGI_NVR_HOST"):
        NvrBackend.from_env({})


# ---- nvr_status -----------------------------------------------------------------


async def test_status_reports_health_without_logging_in(fake) -> None:
    mcp, _ = _build(fake, ALLOW_WRITES="true", DRY_RUN="true")
    status = await _call(mcp, "nvr_status")
    assert status["success"] is True
    health = status["data"]["health"]["data"]
    assert health["encrypt_type_selected"] == "2"
    assert health["auth"]["authenticated"] is False
    assert health["policy"] == {
        "writes_enabled": True,
        "dry_run": True,
        "login_disabled": False,
        "max_login_failures": 1,
        "verify_tls": False,
    }
    assert fake.login_attempts == 0


async def test_status_reports_unreachable_nvr() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    backend = NvrBackend.from_env(nvr_env(), http_transport=httpx.MockTransport(down))
    mcp, _ = build_server(load_global_settings(MCP_ENV_PREFIX, {}), backend)
    status = await _call(mcp, "nvr_status")
    assert status["error"]["code"] == "TRANSPORT_ERROR"
    assert status["error"]["details"]["policy"]["writes_enabled"] is False


async def test_write_refused_end_to_end_via_mcp(fake) -> None:
    mcp, _ = _build(fake)
    result = await _call(mcp, "nvr_raw_call", {"method": "set", "module": "system", "params": {}})
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


async def test_catalog_tools_end_to_end_via_mcp(fake) -> None:
    mcp, _ = _build(fake)
    mods = await _call(mcp, "nvr_list_modules")
    assert mods["data"]["module_count"] == 61
    calls = await _call(mcp, "nvr_list_calls", {"module": "chm"})
    assert calls["success"] is True and calls["data"]["calls"]
    desc = await _call(
        mcp, "nvr_describe_call", {"module": "chm", "method": "get", "key": "channel"}
    )
    assert desc["data"]["mutates"] is False
    assert fake.requests == []  # all served from the vendored catalog, no device I/O


async def test_nvr_call_read_end_to_end_via_mcp(fake) -> None:
    fake.api_handler = lambda t, b: {"error_code": 0}
    mcp, _ = _build(fake)
    result = await _call(mcp, "nvr_call", {"module": "chm", "method": "get", "key": "channel"})
    assert result["success"] is True
    assert fake.api_requests[-1][1] == {"method": "get", "chm": None}


# ---- check-auth -----------------------------------------------------------------


async def test_check_auth_without_login_never_logs_in(fake) -> None:
    backend = _backend(fake)
    result = await backend.check_auth(login=False)
    await backend.aclose()
    assert result["data"]["encrypt_type_offered"] == ["1", "2"]
    assert "skipped" in result["data"]["login"]
    assert fake.login_attempts == 0


async def test_check_auth_with_login_makes_exactly_one_attempt(fake) -> None:
    backend = _backend(fake)
    result = await backend.check_auth(login=True)
    await backend.aclose()
    assert result["data"]["login"] == "succeeded"
    assert fake.login_attempts == 1
    assert FAKE_STOK_1 not in json.dumps(result)


async def test_check_auth_failed_login_reports_counters(fake) -> None:
    fake.password = "wrong"
    backend = _backend(fake)
    result = await backend.check_auth(login=True)
    await backend.aclose()
    assert result["error"]["code"] == "AUTH_FAILED"
    assert result["error"]["details"]["attempts_left"] == 3
    assert result["error"]["details"]["challenge"]["encrypt_type_selected"] == "2"
    assert fake.login_attempts == 1


async def test_check_auth_unreachable() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    backend = NvrBackend.from_env(nvr_env(), http_transport=httpx.MockTransport(down))
    assert (await backend.check_auth(login=True))["error"]["code"] == "TRANSPORT_ERROR"


async def test_run_check_auth_requires_host() -> None:
    with pytest.raises(ConfigError, match="VIGI_NVR_HOST"):
        await cli.run_check_auth(login=False, environ={})


def test_cli_flag_validation() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(["--login"])
    with pytest.raises(SystemExit):
        cli.parse_args(["--check-auth", "--list-tools"])
    assert cli.parse_args(["--check-auth", "--login"]).login is True


def test_cli_check_auth_missing_host_exit_code(monkeypatch, capsys) -> None:
    for key in [k for k in __import__("os").environ if k.startswith("VIGI_")]:
        monkeypatch.delenv(key)
    assert cli.main(["--check-auth", "--env-file", "/nonexistent/.env"]) == 2
    assert "VIGI_NVR_HOST" in capsys.readouterr().err


def test_cli_serve_config_error_exit_code(monkeypatch, capsys) -> None:
    for key in [k for k in __import__("os").environ if k.startswith("VIGI_")]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("VIGI_MCP_TRANSPORT", "sse")
    assert cli.main(["--env-file", "/nonexistent/.env"]) == 2
    assert "VIGI_MCP_TRANSPORT" in capsys.readouterr().err


def test_cli_serve_runs_selected_transport(monkeypatch, caplog) -> None:
    ran: list[str] = []
    monkeypatch.setattr(
        "mcp.server.fastmcp.FastMCP.run", lambda self, transport: ran.append(transport)
    )
    env = {**nvr_env(), "VIGI_MCP_TRANSPORT": "streamable-http", "VIGI_MCP_HOST": "0.0.0.0"}  # noqa: S104
    cli.serve(env)
    assert ran == ["streamable-http"]
    assert "non-loopback" in caplog.text


# ---- core isolation ---------------------------------------------------------------


def test_core_imports_nothing_from_the_package() -> None:
    """core/ is copied verbatim into sibling repos: only stdlib/third-party + core."""
    for path in (PACKAGE / "core").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level >= 2:
                    pytest.fail(f"{path.name} imports outside core: level {node.level}")
                if node.module and node.module.startswith("vigi_nvr_mcp"):
                    pytest.fail(f"{path.name} imports {node.module}")
            if isinstance(node, ast.Import):
                assert not any(a.name.startswith("vigi_nvr_mcp") for a in node.names)


def test_core_is_device_agnostic() -> None:
    words = ("vigi", "nvr", "stok=<", "tp-link", "tplink")
    for path in (PACKAGE / "core").glob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for word in words:
            assert word not in text, f"{path.name} mentions {word!r}"
