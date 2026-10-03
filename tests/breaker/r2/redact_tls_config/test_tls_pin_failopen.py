"""Breaker r2 / redact-tls-config — F1 (TLS pinning fails OPEN after one probe error).

Claim under attack: "with a pin configured, the transport ... fails closed with
``TlsPinMismatch`` before any request is sent".

``JsonHttpTransport._ensure_pinned`` sets ``self._pin_checked = True`` *before* it
awaits ``_peer_cert_der()``. If that probe raises (a transient TLS/connect blip on
first use, or an attacker who RSTs the one-shot probe socket), the first request
errors out — but the flag is already latched, so EVERY subsequent request on the
same (process-lifetime) transport skips the pin check entirely and is sent
unauthenticated. Pinning is silently disabled for the life of the server.

All I/O is mocked: the data connection is an ``httpx.MockTransport`` and the cert
probe is a monkeypatched coroutine. No socket is opened.
"""

from __future__ import annotations

import httpx

from vigi_nvr_mcp.core.errors import TransportError
from vigi_nvr_mcp.core.transport import JsonHttpTransport, fingerprint_sha256

GOOD_DER = b"the-device-certificate"
PIN = fingerprint_sha256(GOOD_DER)


def _ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"error_code": 0})


async def test_pin_is_reverified_after_a_transient_probe_failure() -> None:
    probe_calls: list[int] = []

    async def flaky_probe() -> bytes:
        probe_calls.append(1)
        if len(probe_calls) == 1:
            raise TransportError("transient probe blip")
        return GOOD_DER

    transport = JsonHttpTransport(
        "https://192.0.2.10:443",
        verify_tls=False,
        timeout_seconds=5.0,
        http_transport=httpx.MockTransport(_ok),
        tls_fingerprint=PIN,
        host="192.0.2.10",
        port=443,
    )
    transport._peer_cert_der = flaky_probe  # type: ignore[assignment]

    # First request: the probe blips, so the request errors (acceptable).
    first_error = None
    try:
        await transport.post_json("/", {"method": "get"})
    except TransportError as exc:
        first_error = exc
    assert first_error is not None

    # Second request on the SAME transport. A pin that "fails closed before any
    # request is sent" must re-verify the certificate here (or refuse). Instead the
    # latched ``_pin_checked`` flag makes the probe be skipped and the request is
    # sent with no pinning at all.
    second_sent = False
    try:
        await transport.post_json("/", {"method": "get"})
        second_sent = True
    except TransportError:
        pass
    await transport.aclose()

    assert len(probe_calls) >= 2, (
        "TLS pinning failed OPEN: after one transient probe error the certificate "
        f"was never re-verified (probe called {len(probe_calls)}x) yet the second "
        f"request was sent (sent={second_sent}). The pin is silently disabled for "
        "the life of the transport."
    )
