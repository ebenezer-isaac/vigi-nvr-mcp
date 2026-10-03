"""Breaker r2 / redact-tls-config — F2 (the pin guards a SEPARATE connection, not
the one that carries the request / credentials).

Claim under attack: "with a pin configured, the transport compares the leaf
certificate's SHA-256 (DER) and fails closed with ``TlsPinMismatch`` before any
request is sent".

``_ensure_pinned`` does NOT inspect the certificate of the httpx connection that
actually sends the request. It opens its own one-shot TLS socket
(``_peer_cert_der`` -> ``asyncio.open_connection(..., ssl=CERT_NONE)``), pins that,
and then lets httpx make an entirely independent connection for the real POST. The
certificate presented on the request-serving connection is captured by
``_capture_observed`` but NEVER compared to the pin (indeed, because the probe
already set ``_observed``, ``_capture_observed`` early-returns and the data
connection's cert is never even read).

Consequence: a LAN on-path attacker who answers the probe honestly (or lets it
reach the real device) while serving a forged certificate on the data connection
is not detected — exactly the attack pinning is supposed to stop. Reaching this is
an adversary's goal (adversary-reading: yes).

Mocks only: the data connection is ``httpx.MockTransport`` whose response carries a
fake ``network_stream``/``ssl_object``; the probe is a monkeypatched coroutine.
"""

from __future__ import annotations

import httpx

from vigi_nvr_mcp.core.errors import TlsPinMismatch
from vigi_nvr_mcp.core.transport import JsonHttpTransport, fingerprint_sha256

PROBE_DER = b"genuine-device-cert-on-the-probe"
IMPOSTOR_DER = b"attacker-cert-on-the-data-connection"
PIN = fingerprint_sha256(PROBE_DER)  # operator pinned the genuine cert


class _FakeSSLObject:
    def __init__(self, der: bytes, calls: list[int]) -> None:
        self._der = der
        self._calls = calls

    def getpeercert(self, binary_form: bool = True) -> bytes:
        self._calls.append(1)
        return self._der


class _FakeNetworkStream:
    def __init__(self, ssl_object: _FakeSSLObject) -> None:
        self._ssl_object = ssl_object

    def get_extra_info(self, name: str):  # noqa: ANN201
        return self._ssl_object if name == "ssl_object" else None


async def test_request_serving_certificate_is_the_one_pinned() -> None:
    data_cert_reads: list[int] = []
    impostor_ssl = _FakeSSLObject(IMPOSTOR_DER, data_cert_reads)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"error_code": 0},
            extensions={"network_stream": _FakeNetworkStream(impostor_ssl)},
        )

    async def probe() -> bytes:
        # The probe connection presents the genuine cert (matches the pin).
        return PROBE_DER

    transport = JsonHttpTransport(
        "https://192.0.2.10:443",
        verify_tls=False,
        timeout_seconds=5.0,
        http_transport=httpx.MockTransport(handler),
        tls_fingerprint=PIN,
        host="192.0.2.10",
        port=443,
    )
    transport._peer_cert_der = probe  # type: ignore[assignment]

    mismatch = False
    try:
        await transport.post_json("/", {"method": "get"})
    except TlsPinMismatch:
        mismatch = True
    observed = transport.observed_fingerprint
    await transport.aclose()

    # The connection that carried the request presented IMPOSTOR_DER (!= pin). A
    # correct pin check validates THAT certificate and fails closed. Here the pin
    # only ever looked at the separate probe connection, so neither did the request
    # fail nor was the data connection's certificate even read.
    assert mismatch or data_cert_reads, (
        "the request-serving connection's certificate was never compared to the "
        "pin: the forged data-connection cert "
        f"({fingerprint_sha256(IMPOSTOR_DER)[:12]}...) was accepted, reads="
        f"{len(data_cert_reads)}, and the pin validated a separate probe connection "
        "instead (TOCTOU / wrong-connection pinning)."
    )

    # Bonus evidence that --check-auth / nvr_status would misreport: the 'observed'
    # fingerprint is the probe cert, not the cert that actually served the request.
    assert observed != fingerprint_sha256(PROBE_DER), (
        "tls_fingerprint_observed reports the side-channel probe certificate, not "
        "the certificate of the connection that served the request/credentials."
    )
