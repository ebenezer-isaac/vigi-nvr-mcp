"""R2 auth-persist F3 — one device, one budget, under any spelling (migrated to X1).

The finding: the ledger was keyed by the raw host string, so ``fe80::1`` and
``fe80:0:0:0:0:0:0:1`` (and ``NVR.local`` vs ``nvr.local`` on a case-sensitive FS)
got two files and two independent budgets, and a ``--clear`` under one spelling left
the other open.

X1 derives the identity once with :func:`canonical_device_key` (the store, CLI and
tests all call it), so equivalent spellings share one ledger and one budget. These
tests prove the fixed behaviour.
"""

from __future__ import annotations

import ipaddress

import pytest

from tests.helpers import NVR_PREFIX, nvr_env
from vigi_nvr_mcp.core.breaker import LoginBreaker, canonical_device_key
from vigi_nvr_mcp.core.config import load_device_settings
from vigi_nvr_mcp.core.errors import BreakerOpen
from vigi_nvr_mcp.core.state import Outcome

IPV6_SHORT = "fe80::1"
IPV6_LONG = "fe80:0:0:0:0:0:0:1"


def test_ipv6_spellings_both_validate_as_the_same_address() -> None:
    assert ipaddress.ip_address(IPV6_SHORT) == ipaddress.ip_address(IPV6_LONG)
    load_device_settings(NVR_PREFIX, nvr_env(HOST=IPV6_SHORT))
    load_device_settings(NVR_PREFIX, nvr_env(HOST=IPV6_LONG))


def test_equivalent_hosts_share_one_breaker_budget(tmp_path) -> None:
    short = LoginBreaker(tmp_path, canonical_device_key(IPV6_SHORT), max_failures=1)
    long = LoginBreaker(tmp_path, canonical_device_key(IPV6_LONG), max_failures=1)
    assert short.path == long.path  # one ledger for one device

    short.reserve_attempt().release(Outcome.FAILURE)
    # The same device under the other spelling is locked out too.
    with pytest.raises(BreakerOpen):
        long.reserve_attempt()

    # A --clear under either spelling clears the other.
    long.clear()
    short.reserve_attempt().release(Outcome.SUCCESS)
