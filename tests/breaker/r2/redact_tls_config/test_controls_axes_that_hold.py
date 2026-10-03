"""Breaker r2 / redact-tls-config — controls: axes that produced NO disproof.

These tests PASS against the code at this SHA; they are not findings. They pin down
the parts of the claim that hold and the boundaries of the three findings
(``test_tls_pin_failopen``, ``test_tls_pin_wrong_connection``,
``test_global_config_unknown_key``), so a future change that regresses them is
caught.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.core.config import (
    DeviceSettings,
    load_device_settings,
    load_global_settings,
    normalise_fingerprint,
)
from vigi_nvr_mcp.core.errors import ConfigError
from vigi_nvr_mcp.core.redact import REDACTED, is_sensitive_key, redact

SECRET = "SUPER-SECRET-VALUE"

# ---- Redaction: the documented rules are implemented and match MASTER-PLAN §1.6 ----

# Exactly the §1.6 "equals" set.
_SPEC_EXACT = [
    "ciphertext",
    "stok",
    "token",
    "nonce",
    "cookie",
    "secret",
    "authorization",
    "pubkey",
    "key",
]
# §1.6 "contains" fragments -> representative real spellings (incl. the r1-F1 misses).
_SPEC_CONTAINS = [
    "password",
    "old_password",
    "new_pwd",
    "passwd",
    "api_token",
    "ciphertext",
    "client_secret",
    "Authorization",
]
_SPEC_ENDSWITH = ["public_key", "rsa_key", "_key"]
# §1.6 explicit survivors.
_SPEC_SURVIVORS = ["auth_result", "online", "conn_status", "uuid", "key_present"]


@pytest.mark.parametrize("field", _SPEC_EXACT + _SPEC_CONTAINS + _SPEC_ENDSWITH)
def test_spec_keys_are_redacted_at_top_level_and_nested_in_lists(field: str) -> None:
    assert redact({field: SECRET})[field] == REDACTED
    nested = redact({"a": [{"b": {field: SECRET}}]})
    assert nested["a"][0]["b"][field] == REDACTED


@pytest.mark.parametrize("field", _SPEC_SURVIVORS)
def test_spec_survivors_are_kept(field: str) -> None:
    assert redact({field: "v"}) == {field: "v"}


def test_r1_f1_missed_spellings_are_now_caught() -> None:
    # The round-1 Major (nonce/cookie/pubkey/old_password/new_pwd/Authorization
    # leaking) is fixed by the rule-based redactor.
    leaky = {
        "nonce": SECRET,
        "cookie": SECRET,
        "pubkey": SECRET,
        "old_password": SECRET,
        "new_pwd": SECRET,
        "Authorization": SECRET,
    }
    out = redact(leaky)
    assert all(v == REDACTED for v in out.values())
    assert SECRET not in str(out)


def test_redact_does_not_mutate_and_converts_tuples() -> None:
    src = {"t": ("x", {"key": SECRET})}
    out = redact(src)
    assert src == {"t": ("x", {"key": SECRET})}  # unchanged
    assert out == {"t": ["x", {"key": REDACTED}]}


# ---- Redaction boundaries that are OUT OF SCOPE of the key-based rules ----
# (documented here; scored in FINDINGS as Minor / Won't-fix, not disproofs.)


def test_homoglyph_key_is_not_matched_by_ascii_rules() -> None:
    # 'Pаssword' uses a Cyrillic 'а' (U+0430); it is not the ASCII substring 'pass'.
    # The device emits ASCII keys, so this is an adversary-authored key hiding an
    # adversary-authored value -> no real secret gain. Current (correct-per-rules)
    # behaviour: the key survives.
    cyrillic = "Pаssword"
    assert is_sensitive_key(cyrillic) is False
    assert redact({cyrillic: SECRET}) == {cyrillic: SECRET}


def test_secret_inside_a_json_encoded_string_value_is_not_descended() -> None:
    # redact() redacts KEYS in dict/list structures; a secret embedded in a string
    # VALUE (e.g. a JSON blob) is not parsed. Out of scope of the key rules; a
    # residual only if a real device nests JSON strings carrying a token.
    blob = '{"stok":"' + SECRET + '"}'
    assert redact({"data": blob}) == {"data": blob}


def test_over_matching_is_accepted_by_design() -> None:
    # The docstring accepts harmless over-matching. '_row_key' (a real channel row
    # identifier, client.py) ends with '_key' and 'tokens_remaining' contains
    # 'token', so both are redacted. Functionally harmless: channel tools recompute
    # and preserve 'channel_id' separately. Scored Minor (over-redaction).
    assert redact({"_row_key": "chn_1"})["_row_key"] == REDACTED
    assert redact({"tokens_remaining": 5})["tokens_remaining"] == REDACTED


# ---- TLS pin normalisation / validation at config load ----


def test_fingerprint_normalisation_accepts_case_and_colons() -> None:
    bare = "ab" * 32
    assert normalise_fingerprint(bare.upper()) == bare
    assert normalise_fingerprint(":".join(["ab"] * 32)) == bare


@pytest.mark.parametrize(
    "bad",
    ["ab" * 31 + "a", "ab" * 32 + "a", "sha256:" + "ab" * 32, "zz" * 32, ""],
)
def test_fingerprint_63_65_prefixed_and_nonhex_are_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        normalise_fingerprint(bad)


def test_device_settings_validate_and_normalise_the_pin_at_load() -> None:
    env = {
        "VIGI_NVR_HOST": "192.0.2.10",
        "VIGI_NVR_PASSWORD": "pw",
        "VIGI_NVR_TLS_FINGERPRINT_SHA256": ":".join(["AB"] * 32),
    }
    settings = load_device_settings("VIGI_NVR_", env)
    assert settings.tls_fingerprint_sha256 == "ab" * 32
    assert settings.base_url == "https://192.0.2.10:443"  # scheme always https

    env["VIGI_NVR_TLS_FINGERPRINT_SHA256"] = "not-a-fingerprint"
    with pytest.raises(ConfigError):
        load_device_settings("VIGI_NVR_", env)


def test_device_loader_does_reject_unknown_keys() -> None:
    # Contrast with F3: the device loader WAS fixed; only the global loader was not.
    env = {"VIGI_NVR_HOST": "192.0.2.10", "VIGI_NVR_PASSWORD": "pw", "VIGI_NVR_NONSENSE": "x"}
    with pytest.raises(ConfigError):
        load_device_settings("VIGI_NVR_", env)


def test_valid_global_config_still_loads() -> None:
    s = load_global_settings("VIGI_MCP_", {"VIGI_MCP_TRANSPORT": "streamable-http"})
    assert s.mcp_transport == "streamable-http"


def test_fields_exist_for_pin_and_observed_reporting() -> None:
    # The claim's reporting surface exists.
    assert "tls_fingerprint_sha256" in DeviceSettings.model_fields
