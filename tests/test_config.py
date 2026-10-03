from __future__ import annotations

import pytest

from tests.helpers import DOC_HOST, TEST_PASSWORD, settings_env
from vigi_nvr_mcp.config import Settings, load_settings
from vigi_nvr_mcp.errors import NvrConfigError


def test_defaults() -> None:
    s = load_settings(settings_env())
    assert s.nvr_host == DOC_HOST
    assert s.nvr_port == 443
    assert s.nvr_username == "admin"
    assert s.nvr_password.get_secret_value() == TEST_PASSWORD
    assert s.verify_tls is False
    assert s.allow_writes is False
    assert s.login_disabled is False
    assert s.max_login_failures == 1
    assert s.mcp_transport == "stdio"
    assert s.mcp_host == "127.0.0.1"
    assert s.base_url == f"https://{DOC_HOST}:443"


def test_unrelated_env_vars_are_ignored() -> None:
    s = load_settings({**settings_env(), "PATH": "/usr/bin", "VIGI_UNKNOWN": "x"})
    assert s.nvr_host == DOC_HOST


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("true", True), ("1", True), ("YES", True), ("false", False), ("0", False), ("off", False)],
)
def test_boolean_parsing(raw: str, expected: bool) -> None:
    s = load_settings(settings_env(VIGI_NVR_ALLOW_WRITES=raw, VIGI_NVR_LOGIN_DISABLED=raw))
    assert s.allow_writes is expected
    assert s.login_disabled is expected


@pytest.mark.parametrize("raw", ["maybe", "", "2", "tru"])
def test_bad_boolean_rejected(raw: str) -> None:
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_NVR_VERIFY_TLS=raw))


@pytest.mark.parametrize(
    "host",
    ["nvr.example.internal", "nvr-1.example.com", DOC_HOST, "2001:db8::1", "NVR"],
)
def test_valid_hosts(host: str) -> None:
    assert load_settings(settings_env(VIGI_NVR_HOST=host)).nvr_host == host


def test_ipv6_base_url_is_bracketed() -> None:
    s = load_settings(settings_env(VIGI_NVR_HOST="2001:db8::1"))
    assert s.base_url == "https://[2001:db8::1]:443"


@pytest.mark.parametrize(
    "host",
    [
        "",
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
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_NVR_HOST=host))


def test_host_is_trimmed() -> None:
    assert load_settings(settings_env(VIGI_NVR_HOST=f"  {DOC_HOST}  ")).nvr_host == DOC_HOST


@pytest.mark.parametrize("port", ["0", "70000", "-1", "65536", "nan", "NaN", "inf", "1.5", "abc"])
def test_invalid_ports_rejected(port: str) -> None:
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_NVR_PORT=port))
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_MCP_PORT=port))


@pytest.mark.parametrize("port", ["1", "443", "65535"])
def test_valid_port_boundaries(port: str) -> None:
    assert load_settings(settings_env(VIGI_NVR_PORT=port)).nvr_port == int(port)


@pytest.mark.parametrize("timeout", ["nan", "inf", "-inf", "0", "0.5", "121"])
def test_invalid_timeout_rejected(timeout: str) -> None:
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_NVR_TIMEOUT_SECONDS=timeout))


def test_missing_host_fails_fast() -> None:
    env = settings_env()
    del env["VIGI_NVR_HOST"]
    with pytest.raises(NvrConfigError, match="VIGI_NVR_HOST"):
        load_settings(env)


@pytest.mark.parametrize("password", ["", "x" * 129, "bad\x00pw", "tab\tpw"])
def test_invalid_password_rejected(password: str) -> None:
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(**{"VIGI_NVR_PASSWORD": password}))


def test_missing_password_fails_fast() -> None:
    env = settings_env()
    del env["VIGI_NVR_PASSWORD"]
    with pytest.raises(NvrConfigError, match="VIGI_NVR_PASSWORD"):
        load_settings(env)


def test_config_error_never_echoes_password() -> None:
    secret = "S3cret-" + "x" * 130  # too long, so validation fails
    with pytest.raises(NvrConfigError) as info:
        load_settings(settings_env(**{"VIGI_NVR_PASSWORD": secret}))
    assert secret not in str(info.value)
    assert "S3cret" not in str(info.value)


def test_password_hidden_in_repr() -> None:
    s = load_settings(settings_env())
    assert TEST_PASSWORD not in repr(s)
    assert TEST_PASSWORD not in str(s.model_dump())


@pytest.mark.parametrize("username", ["", "a" * 65, "ad\nmin", " "])
def test_invalid_username_rejected(username: str) -> None:
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_NVR_USERNAME=username))


@pytest.mark.parametrize("value", ["0", "6", "nan"])
def test_max_login_failures_bounds(value: str) -> None:
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_NVR_MAX_LOGIN_FAILURES=value))


def test_transport_choice() -> None:
    s = load_settings(settings_env(VIGI_MCP_TRANSPORT="streamable-http"))
    assert s.mcp_transport == "streamable-http"
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_MCP_TRANSPORT="sse"))


@pytest.mark.parametrize("bind", ["localhost", "not an ip", ""])
def test_mcp_host_must_be_ip_literal(bind: str) -> None:
    with pytest.raises(NvrConfigError):
        load_settings(settings_env(VIGI_MCP_HOST=bind))


def test_mcp_host_loopback_flag() -> None:
    assert load_settings(settings_env()).mcp_host_is_loopback is True
    s = load_settings(settings_env(VIGI_MCP_HOST="0.0.0.0"))  # noqa: S104
    assert s.mcp_host_is_loopback is False


def test_settings_are_immutable() -> None:
    s = load_settings(settings_env())
    with pytest.raises(Exception):  # noqa: B017 - pydantic raises ValidationError
        s.nvr_port = 1  # type: ignore[misc]


def test_extra_fields_rejected_on_direct_construction() -> None:
    with pytest.raises(Exception):  # noqa: B017
        Settings.model_validate({"nvr_host": DOC_HOST, "nvr_password": "x", "bogus": 1})
