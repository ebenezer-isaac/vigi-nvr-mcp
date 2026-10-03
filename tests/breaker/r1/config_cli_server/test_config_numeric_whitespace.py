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


# WON'T-FIX per orchestrator decision CC-F1 (fixer brief): lenient numeric parsing
# of env/.env values is desirable -- a trailing space or similar typo in a systemd
# EnvironmentFile should coerce to the intended value, not crash the server. The
# claim was over-strict. These tests are inverted to pin the accepted, coercing
# behaviour (and its spec wording is amended accordingly).
@pytest.mark.parametrize("raw", ["443 ", " 443", "+443", "4_4_3", "443.0"])
def test_port_accepts_coercible_strings(raw: str) -> None:
    assert _load(PORT=raw).port == 443


@pytest.mark.parametrize("raw", ["443 ", " 443", "443.0"])
def test_mcp_port_accepts_coercible_strings(raw: str) -> None:
    assert load_global_settings("VIGI_MCP_", {"VIGI_MCP_PORT": raw}).mcp_port == 443


@pytest.mark.parametrize("raw", ["10 ", " 10", "1_0"])
def test_timeout_accepts_whitespace_and_underscores(raw: str) -> None:
    assert _load(TIMEOUT_SECONDS=raw).timeout_seconds == 10.0


@pytest.mark.parametrize("raw", ["3 ", " 3", "+3"])
def test_max_login_failures_accepts_whitespace(raw: str) -> None:
    assert _load(MAX_LOGIN_FAILURES=raw).max_login_failures == 3
