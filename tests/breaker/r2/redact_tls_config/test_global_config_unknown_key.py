"""Breaker r2 / redact-tls-config — F3 (unknown ``VIGI_MCP_*`` keys are silently
ignored; the r1 F6 fix was applied only to the device loader).

Claim under attack: "any ``VIGI_NVR_*``/``VIGI_MCP_*`` key not in the schema fails
loudly naming it".

The r1 fix added an unknown-key scan to ``load_device_settings`` (``VIGI_NVR_*``)
but NOT to ``load_global_settings`` (``VIGI_MCP_*``). The global loader still
pre-filters the environment to its three known suffixes, so pydantic's
``extra='forbid'`` never sees the stray key and no error is raised. A typo such as
``VIGI_MCP_TRANPORT=streamable-http`` is silently dropped and the server keeps the
default transport, with no mention of the offending name.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.core.config import load_global_settings
from vigi_nvr_mcp.core.errors import ConfigError

MCP_PREFIX = "VIGI_MCP_"


def test_unknown_global_key_fails_loudly_and_names_it() -> None:
    env = {
        f"{MCP_PREFIX}HOST": "127.0.0.1",
        f"{MCP_PREFIX}TRANPORT": "streamable-http",  # typo of TRANSPORT
    }
    with pytest.raises(ConfigError) as excinfo:
        load_global_settings(MCP_PREFIX, env)
    assert "TRANPORT" in str(excinfo.value), (
        "an unknown VIGI_MCP_* variable must fail loudly and name the offending key"
    )


def test_unknown_global_key_is_not_silently_dropped() -> None:
    # RT-F3 fix (fixer r2): load_global_settings now rejects unknown VIGI_MCP_* keys
    # via the shared reject_unknown_env, so the typo is no longer silently dropped
    # (the operator's intent is never lost without a word). This companion asserted
    # the pre-fix drop; it now asserts the key is refused rather than ignored.
    env = {
        f"{MCP_PREFIX}HOST": "127.0.0.1",
        f"{MCP_PREFIX}TRANPORT": "streamable-http",
    }
    with pytest.raises(ConfigError):
        load_global_settings(MCP_PREFIX, env)
