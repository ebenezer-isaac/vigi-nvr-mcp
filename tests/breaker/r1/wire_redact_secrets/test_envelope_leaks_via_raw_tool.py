"""Breaker r1 / wire-redact-secrets — F1 reachability.

Disproves the central claim that "no ... nonce ... or RSA key can ever appear in
... tool result envelopes".

The registered ``nvr_call`` tool returns the device's reply after a single pass
through ``redact()`` (see ``core/tooling.run_tool``). Because redact() misses
``nonce``, ``cookie``, ``pubkey`` and ``new_pwd``, a device reply carrying those
fields produces a ``{"success": true}`` envelope whose ``data`` still contains the
plaintext secrets — while ``password`` and ``stok`` in the same reply ARE redacted,
proving the redactor ran but is incomplete.

``verify_tls`` defaults to False (core/config.py), so a LAN host's reply body is
trusted verbatim; the field spelling is therefore attacker-reachable. Mocks only.

Breaker test: EXPECTED TO FAIL at this SHA.
"""

from __future__ import annotations

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.client import NvrClient
from vigi_nvr_mcp.core.config import load_device_settings
from vigi_nvr_mcp.tools import ToolContext
from vigi_nvr_mcp.tools.raw import nvr_call
from vigi_nvr_mcp.transport import NvrTransport

LEAKY_REPLY = {
    "error_code": 0,
    "data": {
        "nonce": "LIVE-NONCE-abc123",
        "cookie": "SESSIONID=secret-session-token",
        "pubkey": "RSA-PUBLIC-KEY-DER-BASE64",
        "new_pwd": "hunter2",
        # controls: these MUST be redacted, proving the redactor ran
        "password": "should-be-redacted",
        "stok": "should-be-redacted",
    },
}


def _flatten_strings(obj: object) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out += _flatten_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _flatten_strings(v)
    elif isinstance(obj, str):
        out.append(obj)
    return out


async def test_nvr_call_envelope_contains_no_plaintext_secret() -> None:
    fake = FakeNvr()
    fake.api_handler = lambda token, body: LEAKY_REPLY
    settings = load_device_settings(NVR_PREFIX, nvr_env())
    transport = NvrTransport(settings, http_transport=fake.transport())
    ctx = ToolContext(
        settings=settings,
        client=NvrClient(settings, transport, Authenticator(settings, transport)),
    )
    try:
        envelope = await nvr_call(ctx, "get", "network", None, False)
    finally:
        await transport.aclose()

    assert envelope["success"] is True
    strings = _flatten_strings(envelope["data"])
    # The controls confirm redaction ran at all.
    assert "should-be-redacted" not in strings
    # The claim: no nonce, session cookie, RSA key, or password in the envelope.
    for secret in (
        "LIVE-NONCE-abc123",
        "SESSIONID=secret-session-token",
        "RSA-PUBLIC-KEY-DER-BASE64",
        "hunter2",
    ):
        assert secret not in strings, (
            f"tool envelope leaked {secret!r} in {envelope['data']!r}"
        )
