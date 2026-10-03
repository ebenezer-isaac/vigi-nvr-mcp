from __future__ import annotations

import pytest

from tests.helpers import DOC_HOST, NVR_PREFIX, TEST_PASSWORD, nvr_env
from tplink_local_mcp.core.config import (
    DeviceSettings,
    host_is_set,
    load_device_settings,
    load_global_settings,
)
from tplink_local_mcp.core.errors import ConfigError


def load(**overrides: str) -> DeviceSettings:
    return load_device_settings(NVR_PREFIX, nvr_env(**overrides))


def test_device_defaults() -> None:
    s = load()
    assert s.env_prefix == NVR_PREFIX
    assert s.host == DOC_HOST
    assert s.port == 443
    assert s.username == "admin"
    assert s.password.get_secret_value() == TEST_PASSWORD
    assert s.verify_tls is False
    assert s.allow_writes is False
    assert s.login_disabled is False
    assert s.dry_run is False
    assert s.max_login_failures == 1
    assert s.backup_dir == "backups"
    assert s.base_url == f"https://{DOC_HOST}:443"
    assert s.env_name("ALLOW_WRITES") == "TPLINK_NVR_ALLOW_WRITES"


def test_prefixes_are_isolated() -> None:
    env = {
        **nvr_env(),
        "TPLINK_ROUTER_HOST": "192.0.2.1",
        "TPLINK_ROUTER_PASSWORD": "other",
        "TPLINK_ROUTER_PORT": "8443",
    }
    nvr = load_device_settings(NVR_PREFIX, env)
    router = load_device_settings("TPLINK_ROUTER_", env)
    assert (nvr.host, nvr.port) == (DOC_HOST, 443)
    assert (router.host, router.port) == ("192.0.2.1", 8443)


def test_host_is_set() -> None:
    assert host_is_set(NVR_PREFIX, nvr_env()) is True
    assert host_is_set(NVR_PREFIX, {}) is False
    assert host_is_set(NVR_PREFIX, {"TPLINK_NVR_HOST": "   "}) is False


def test_bad_prefix_rejected() -> None:
    with pytest.raises(ConfigError):
        load_device_settings("BAD_", {"BAD_HOST": DOC_HOST, "BAD_PASSWORD": "x"})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("1", True), ("YES", True), ("false", False), ("0", False), ("off", False)],
)
def test_boolean_parsing(raw: str, expected: bool) -> None:
    s = load(ALLOW_WRITES=raw, LOGIN_DISABLED=raw, DRY_RUN=raw)
    assert (s.allow_writes, s.login_disabled, s.dry_run) == (expected, expected, expected)


@pytest.mark.parametrize("raw", ["maybe", "", "2", "tru"])
def test_bad_boolean_rejected(raw: str) -> None:
    with pytest.raises(ConfigError, match="TPLINK_NVR_VERIFY_TLS"):
        load(VERIFY_TLS=raw)


@pytest.mark.parametrize(
    "host", ["nvr.example.internal", "nvr-1.example.com", DOC_HOST, "2001:db8::1", "NVR"]
)
def test_valid_hosts(host: str) -> None:
    assert load(HOST=host).host == host


def test_ipv6_base_url_is_bracketed() -> None:
    assert load(HOST="2001:db8::1").base_url == "https://[2001:db8::1]:443"


@pytest.mark.parametrize(
    "host",
    [
        "   ",
        "https://" + DOC_HOST,
        DOC_HOST + "/path",
        DOC_HOST + ":443",
        "bad host",
        "host\x00null",
        "-leading-dash",
        "a" * 254,
        "under_score.example",
        "<nvr-host>",
        "999.1.1.1",
    ],
)
def test_invalid_hosts_rejected(host: str) -> None:
    with pytest.raises(ConfigError, match="TPLINK_NVR_HOST"):
        load(HOST=host)


def test_host_is_trimmed() -> None:
    assert load(HOST=f"  {DOC_HOST}  ").host == DOC_HOST


@pytest.mark.parametrize("port", ["0", "70000", "-1", "65536", "nan", "NaN", "inf", "1.5", "abc"])
def test_invalid_ports_rejected(port: str) -> None:
    with pytest.raises(ConfigError):
        load(PORT=port)
    with pytest.raises(ConfigError):
        load_global_settings({"TPLINK_MCP_PORT": port})


@pytest.mark.parametrize("port", ["1", "443", "65535"])
def test_valid_port_boundaries(port: str) -> None:
    assert load(PORT=port).port == int(port)


@pytest.mark.parametrize("timeout", ["nan", "inf", "-inf", "0", "0.5", "121"])
def test_invalid_timeout_rejected(timeout: str) -> None:
    with pytest.raises(ConfigError):
        load(TIMEOUT_SECONDS=timeout)


def test_missing_password_fails_fast() -> None:
    with pytest.raises(ConfigError, match="TPLINK_NVR_PASSWORD"):
        load_device_settings(NVR_PREFIX, {"TPLINK_NVR_HOST": DOC_HOST})


@pytest.mark.parametrize("password", ["", "x" * 129, "bad\x00pw", "tab\tpw"])
def test_invalid_password_rejected(password: str) -> None:
    with pytest.raises(ConfigError):
        load(**{"PASSWORD": password})


def test_config_error_never_echoes_password() -> None:
    secret = "S3cret-" + "x" * 130
    with pytest.raises(ConfigError) as info:
        load(**{"PASSWORD": secret})
    assert "S3cret" not in str(info.value)


def test_password_hidden_in_repr() -> None:
    s = load()
    assert TEST_PASSWORD not in repr(s)
    assert TEST_PASSWORD not in str(s.model_dump())


@pytest.mark.parametrize("username", ["", "a" * 65, "ad\nmin", " "])
def test_invalid_username_rejected(username: str) -> None:
    with pytest.raises(ConfigError):
        load(USERNAME=username)


@pytest.mark.parametrize("value", ["0", "6", "nan"])
def test_max_login_failures_bounds(value: str) -> None:
    with pytest.raises(ConfigError):
        load(MAX_LOGIN_FAILURES=value)


def test_backup_dir_rejects_control_chars() -> None:
    with pytest.raises(ConfigError):
        load(BACKUP_DIR="bad\x00dir")


def test_settings_are_immutable() -> None:
    s = load()
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        s.port = 1  # type: ignore[misc]


def test_extra_fields_rejected_on_direct_construction() -> None:
    with pytest.raises(Exception):  # noqa: B017
        DeviceSettings.model_validate(
            {"env_prefix": NVR_PREFIX, "host": DOC_HOST, "password": "x", "bogus": 1}
        )


# ---- global (MCP) settings ----------------------------------------------------


def test_global_defaults() -> None:
    g = load_global_settings({})
    assert (g.mcp_transport, g.mcp_host, g.mcp_port) == ("stdio", "127.0.0.1", 8765)
    assert g.mcp_host_is_loopback is True


def test_global_transport_choice() -> None:
    assert (
        load_global_settings({"TPLINK_MCP_TRANSPORT": "streamable-http"}).mcp_transport
        == "streamable-http"
    )
    with pytest.raises(ConfigError, match="TPLINK_MCP_TRANSPORT"):
        load_global_settings({"TPLINK_MCP_TRANSPORT": "sse"})


@pytest.mark.parametrize("bind", ["localhost", "not an ip", ""])
def test_mcp_host_must_be_ip_literal(bind: str) -> None:
    with pytest.raises(ConfigError):
        load_global_settings({"TPLINK_MCP_HOST": bind})


def test_non_loopback_bind_is_flagged() -> None:
    assert load_global_settings({"TPLINK_MCP_HOST": "0.0.0.0"}).mcp_host_is_loopback is False  # noqa: S104
