"""Breaker r1 / config-cli-server — F6 (security / spec deviation).

Claim under attack: "settings fail fast and loudly on any invalid value".
Master-plan 00 section 3 also requires the core DeviceSettings to carry
``tls_fingerprint_sha256`` and the transport to support "verify_tls or SHA-256
fingerprint pinning".

Findings:
  * Unknown ``VIGI_NVR_*`` variables are silently dropped by
    ``load_device_settings`` (it pre-filters to known suffixes), so the model's
    ``extra='forbid'`` never sees them. A typo'd or unsupported variable is NOT
    rejected -- it is ignored.
  * There is no ``tls_fingerprint_sha256`` setting and no pinning in the
    transport, and ``verify_tls`` defaults to False. With a self-signed device
    cert (verify_tls=True fails the handshake) there is therefore NO supported
    configuration that authenticates the NVR's certificate, leaving the login
    (which carries the admin password, encrypted only with a public key fetched
    over the same unauthenticated channel) interceptable by a LAN on-path
    attacker. An owner who sets VIGI_NVR_TLS_FINGERPRINT_SHA256 expecting
    pinning is silently given none.
"""

from __future__ import annotations

import pytest

from tests.helpers import DOC_HOST, NVR_PREFIX, TEST_PASSWORD
from vigi_nvr_mcp.core.config import DeviceSettings, load_device_settings
from vigi_nvr_mcp.core.errors import ConfigError


def _env(**overrides: str) -> dict[str, str]:
    env = {f"{NVR_PREFIX}HOST": DOC_HOST, f"{NVR_PREFIX}PASSWORD": TEST_PASSWORD}
    env.update({f"{NVR_PREFIX}{k}": v for k, v in overrides.items()})
    return env


def test_unknown_prefixed_var_is_rejected() -> None:
    # A misspelled/unsupported VIGI_NVR_* var is an invalid configuration; the
    # claim says settings fail fast and loudly. Actual: silently ignored.
    with pytest.raises(ConfigError):
        load_device_settings(NVR_PREFIX, _env(VERIFYTLS="true", ALLOW_WRITE="true"))


def test_bogus_tls_fingerprint_is_rejected() -> None:
    # An invalid fingerprint value must fail loudly. Actual: no such setting, so
    # it is dropped and load succeeds.
    with pytest.raises(ConfigError):
        load_device_settings(
            NVR_PREFIX, _env(TLS_FINGERPRINT_SHA256="ZZZZ:not:a:real:hash")
        )


def test_device_certificate_can_be_authenticated() -> None:
    # Either a fingerprint-pinning field (master-plan s3) must exist, or
    # verify_tls must default to True. Neither is the case: no way to
    # authenticate the device cert.
    fields = set(DeviceSettings.model_fields)
    settings = load_device_settings(NVR_PREFIX, _env())
    assert "tls_fingerprint_sha256" in fields or settings.verify_tls is True, (
        "no supported way to authenticate the NVR TLS certificate: "
        f"fields={sorted(fields)}, verify_tls default={settings.verify_tls}"
    )
