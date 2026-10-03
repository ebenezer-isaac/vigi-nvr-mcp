"""F4 — the breaker key is the raw host string, not a normalised identity.

The claim: a "per-host JSON file". The file name is
``breaker-<_UNSAFE.sub('_', device)>.json`` where ``device`` is ``settings.host``
verbatim. ``validate_host`` only strips surrounding whitespace; it does not
canonicalise. So two spellings of one device produce two files and therefore two
independent failure budgets, and a ``breaker --clear`` for one spelling leaves
the other open.

IPv6 is the clean, cross-platform witness: ``fe80::1`` and its fully-expanded
form ``fe80:0:0:0:0:0:0:1`` are the same address (``ipaddress`` treats them as
equal) and both pass ``validate_host``, but map to distinct, case-sensitively
different file names. (Case-variant hostnames -- ``NVR.local`` vs ``nvr.local``,
equal under DNS -- do the same on the case-sensitive Linux deploy target, though
they collide on a case-insensitive dev FS, so IPv6 is used here.)

Mocks only; no device.
"""

from __future__ import annotations

import pytest

from tests.helpers import NVR_PREFIX, nvr_env
from vigi_nvr_mcp.core import breaker as breaker_mod
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.core.errors import LockoutGuard

IPV6_SHORT = "fe80::1"
IPV6_LONG = "fe80:0:0:0:0:0:0:1"


def _settings(tmp_path) -> DeviceSettings:
    return load_device_settings(NVR_PREFIX, nvr_env(STATE_DIR=str(tmp_path)))


def test_ipv6_spellings_both_validate_as_the_same_address() -> None:
    import ipaddress

    assert ipaddress.ip_address(IPV6_SHORT) == ipaddress.ip_address(IPV6_LONG)
    # Both accepted by config validation (so an operator can enter either).
    load_device_settings(NVR_PREFIX, nvr_env(HOST=IPV6_SHORT))
    load_device_settings(NVR_PREFIX, nvr_env(HOST=IPV6_LONG))


def test_equivalent_hosts_share_one_breaker_budget(tmp_path) -> None:
    settings = _settings(tmp_path)
    short = breaker_mod.LoginBreaker(tmp_path, IPV6_SHORT, settings)
    long = breaker_mod.LoginBreaker(tmp_path, IPV6_LONG, settings)

    # Spend the whole budget (default 1) on one spelling of the device.
    short.record_failure({"device_error_code": -40401})
    with pytest.raises(LockoutGuard):
        short.check(explicit=True)

    # The *same device* under the other spelling must also be locked out.
    with pytest.raises(LockoutGuard):
        long.check(explicit=True)
