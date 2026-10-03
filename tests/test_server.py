"""Backend discovery/registration, the tplink_status tool, and the CLI."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.helpers import DOC_HOST, FAKE_STOK_1, FakeNvr, nvr_env
from tplink_local_mcp import __main__ as cli
from tplink_local_mcp.core.backend import DeviceBackend
from tplink_local_mcp.core.config import load_global_settings
from tplink_local_mcp.core.errors import ConfigError
from tplink_local_mcp.devices import all_backends
from tplink_local_mcp.devices.archer_router import ArcherRouterBackend
from tplink_local_mcp.devices.easysmart_switch import EasySmartSwitchBackend
from tplink_local_mcp.devices.vigi_nvr import VigiNvrBackend
from tplink_local_mcp.server import build_server, discover_backends

NVR_TOOLS = {
    "nvr_call",
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


def _candidates(fake: FakeNvr) -> list[DeviceBackend]:
    return [
        VigiNvrBackend(http_transport=fake.transport()),
        ArcherRouterBackend(),
        EasySmartSwitchBackend(),
    ]


async def _tool_names(mcp) -> set[str]:
    return {t.name for t in await mcp.list_tools()}


async def _call(mcp, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    result = await mcp.call_tool(name, args or {})
    structured = result[1] if isinstance(result, tuple) else result
    if isinstance(structured, dict) and "result" in structured and "success" not in structured:
        structured = structured["result"]
    if isinstance(structured, dict) and "success" in structured:
        return structured
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


def test_all_backends_satisfy_protocol() -> None:
    backends = all_backends()
    assert [b.name for b in backends] == ["nvr", "router", "switch"]
    assert [b.settings_prefix for b in backends] == [
        "TPLINK_NVR_",
        "TPLINK_ROUTER_",
        "TPLINK_SWITCH_",
    ]
    assert [b.tool_prefix for b in backends] == ["nvr_", "router_", "switch_"]
    assert all(isinstance(b, DeviceBackend) for b in backends)


def test_nothing_configured(fake) -> None:
    d = discover_backends({}, _candidates(fake))
    assert d.configured == ()
    assert [b.name for b in d.skipped] == ["nvr", "router", "switch"]


def test_only_nvr_configured(fake, caplog) -> None:
    caplog.set_level("INFO")
    d = discover_backends(nvr_env(), _candidates(fake))
    assert [b.name for b in d.configured] == ["nvr"]
    assert [b.name for b in d.skipped] == ["router", "switch"]
    assert "TPLINK_ROUTER_HOST unset" in caplog.text


def test_configure_returns_new_instance(fake) -> None:
    template = VigiNvrBackend(http_transport=fake.transport())
    configured = template.configure(nvr_env())
    assert configured is not template
    assert template.context is None and configured.context is not None


def test_invalid_settings_fail_fast(fake) -> None:
    with pytest.raises(ConfigError, match="TPLINK_NVR_PORT"):
        discover_backends(nvr_env(PORT="0"), _candidates(fake))
    with pytest.raises(ConfigError, match="TPLINK_ROUTER_PASSWORD"):
        discover_backends({"TPLINK_ROUTER_HOST": "192.0.2.1"}, _candidates(fake))


def test_unconfigured_backend_cannot_register_tools() -> None:
    from mcp.server.fastmcp import FastMCP

    with pytest.raises(ConfigError):
        VigiNvrBackend().register_tools(FastMCP("t"))


async def test_registration_configured_vs_not(fake) -> None:
    env = {**nvr_env(), "TPLINK_SWITCH_HOST": "192.0.2.2", "TPLINK_SWITCH_PASSWORD": "pw"}
    mcp = build_server(load_global_settings({}), discover_backends(env, _candidates(fake)))
    names = await _tool_names(mcp)
    assert names == NVR_TOOLS | {"tplink_status"}
    assert not any(n.startswith(("router_", "switch_")) for n in names)
    assert fake.requests == []  # building the server makes no device calls


async def test_no_backends_only_status_tool(fake) -> None:
    mcp = build_server(load_global_settings({}), discover_backends({}, _candidates(fake)))
    assert await _tool_names(mcp) == {"tplink_status"}


async def test_status_tool_reports_backends_and_health(fake) -> None:
    env = {**nvr_env(), "TPLINK_ROUTER_HOST": "192.0.2.1", "TPLINK_ROUTER_PASSWORD": "pw"}
    mcp = build_server(load_global_settings({}), discover_backends(env, _candidates(fake)))
    status = await _call(mcp, "tplink_status")
    assert status["success"] is True
    by_name = {b["name"]: b for b in status["data"]["backends"]}
    nvr = by_name["nvr"]
    assert nvr["configured"] is True
    assert set(nvr["tools"]) == NVR_TOOLS
    assert nvr["health"]["success"] is True
    assert nvr["health"]["data"]["encrypt_type_selected"] == "2"
    assert nvr["health"]["data"]["auth"]["authenticated"] is False
    assert by_name["router"]["configured"] is True
    assert by_name["router"]["health"]["error"]["code"] == "NOT_IMPLEMENTED"
    assert by_name["switch"] == {
        "name": "switch",
        "configured": False,
        "tool_prefix": "switch_",
        "hint": "set TPLINK_SWITCH_HOST to enable",
    }
    assert fake.login_attempts == 0  # healthcheck never logs in


async def test_status_health_reports_unreachable_nvr() -> None:
    import httpx

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    backend = VigiNvrBackend(http_transport=httpx.MockTransport(down)).configure(nvr_env())
    health = await backend.healthcheck()
    assert health["error"]["code"] == "TRANSPORT_ERROR"


async def test_nvr_tool_end_to_end_via_mcp(fake) -> None:
    mcp = build_server(load_global_settings({}), discover_backends(nvr_env(), _candidates(fake)))
    result = await _call(mcp, "nvr_call", {"method": "set", "module": "system", "params": {}})
    assert result["error"]["code"] == "WRITE_REFUSED"
    assert fake.requests == []


# ---- check-auth ------------------------------------------------------------------


async def test_check_auth_without_login_never_logs_in(fake) -> None:
    backend = VigiNvrBackend(http_transport=fake.transport()).configure(nvr_env())
    result = await backend.check_auth(login=False)
    await backend.aclose()
    assert result["success"] is True
    assert result["data"]["encrypt_type_offered"] == ["1", "2"]
    assert "skipped" in result["data"]["login"]
    assert fake.login_attempts == 0


async def test_check_auth_with_login_makes_exactly_one_attempt(fake) -> None:
    backend = VigiNvrBackend(http_transport=fake.transport()).configure(nvr_env())
    result = await backend.check_auth(login=True)
    await backend.aclose()
    assert result["data"]["login"] == "succeeded"
    assert fake.login_attempts == 1
    assert FAKE_STOK_1 not in json.dumps(result)


async def test_check_auth_failed_login_reports_counters(fake) -> None:
    fake.password = "wrong"
    backend = VigiNvrBackend(http_transport=fake.transport()).configure(nvr_env())
    result = await backend.check_auth(login=True)
    await backend.aclose()
    assert result["error"]["code"] == "AUTH_FAILED"
    assert result["error"]["details"]["attempts_left"] == 3
    assert result["error"]["details"]["challenge"]["encrypt_type_selected"] == "2"
    assert fake.login_attempts == 1


async def test_check_auth_for_pending_backend() -> None:
    env = {"TPLINK_ROUTER_HOST": "192.0.2.1", "TPLINK_ROUTER_PASSWORD": "pw"}
    result = await cli.run_check_auth("router", login=True, environ=env)
    assert result["error"]["code"] == "NOT_IMPLEMENTED"


async def test_check_auth_requires_host() -> None:
    with pytest.raises(ConfigError, match="TPLINK_NVR_HOST"):
        await cli.run_check_auth("nvr", login=False, environ={})


def test_cli_login_requires_check_auth() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(["--login"])


def test_cli_device_choices() -> None:
    assert cli.parse_args(["--check-auth", "--device", "switch"]).device == "switch"
    with pytest.raises(SystemExit):
        cli.parse_args(["--check-auth", "--device", "toaster"])


def test_cli_check_auth_missing_host_exit_code(monkeypatch, capsys) -> None:
    for key in [k for k in __import__("os").environ if k.startswith("TPLINK_")]:
        monkeypatch.delenv(key)
    assert cli.main(["--check-auth", "--env-file", "/nonexistent/.env"]) == 2
    assert "TPLINK_NVR_HOST" in capsys.readouterr().err


def test_doc_host_constant_is_rfc5737() -> None:
    assert DOC_HOST.startswith("192.0.2.")
