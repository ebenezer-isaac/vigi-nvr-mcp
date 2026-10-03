"""Breaker r1 / config-cli-server — F1.

Claim under attack: "settings fail fast and loudly on any invalid value
(... port 0/65536/'443 ', ...)".

These tests assert that the numeric settings reject malformed-but-coercible
strings. They FAIL because pydantic's lax int/float coercion silently strips
surrounding whitespace, accepts a leading '+', accepts PEP-515 underscore
grouping, and accepts integral float syntax. The claim's own example
``VIGI_NVR_PORT='443 '`` is accepted as 443.
"""

from __future__ import annotations

import pytest

from tests.helpers import DOC_HOST, NVR_PREFIX, TEST_PASSWORD
from vigi_nvr_mcp.core.config import load_device_settings, load_global_settings
from vigi_nvr_mcp.core.errors import ConfigError


def _load(**overrides: str):
    env = {f"{NVR_PREFIX}HOST": DOC_HOST, f"{NVR_PREFIX}PASSWORD": TEST_PASSWORD}
    env.update({f"{NVR_PREFIX}{k}": v for k, v in overrides.items()})
    return load_device_settings(NVR_PREFIX, env)


# The claim says every one of these invalid values must fail fast and loudly.
@pytest.mark.parametrize(
    "raw",
    [
        "443 ",   # the claim's own example: trailing whitespace
        " 443",   # leading whitespace
        "+443",   # explicit plus sign
        "4_4_3",  # PEP-515 underscore grouping
        "443.0",  # integral float syntax
    ],
)
def test_port_rejects_malformed_but_coercible_strings(raw: str) -> None:
    # Expected per the claim: a loud ConfigError. Actual: silently accepted as 443.
    with pytest.raises(ConfigError):
        _load(PORT=raw)


@pytest.mark.parametrize("raw", ["443 ", " 443", "443.0"])
def test_mcp_port_rejects_malformed_but_coercible_strings(raw: str) -> None:
    with pytest.raises(ConfigError):
        load_global_settings("VIGI_MCP_", {"VIGI_MCP_PORT": raw})


@pytest.mark.parametrize("raw", ["10 ", " 10", "1_0"])
def test_timeout_rejects_whitespace_and_underscores(raw: str) -> None:
    with pytest.raises(ConfigError):
        _load(TIMEOUT_SECONDS=raw)


@pytest.mark.parametrize("raw", ["3 ", " 3", "+3"])
def test_max_login_failures_rejects_whitespace(raw: str) -> None:
    with pytest.raises(ConfigError):
        _load(MAX_LOGIN_FAILURES=raw)
