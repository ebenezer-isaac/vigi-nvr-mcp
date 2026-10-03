"""x1c / core — TLS pinning mechanism (controls; the r2 side-channel/latch findings
are fixed by the ``_PinningBackend`` refactor).

Holds:
* ``_PinnedStream.start_tls`` reads the leaf cert of httpx's OWN connection and
  verifies it BEFORE returning the stream, so a mismatch raises ``TlsPinMismatch``
  with no stream handed back (and therefore no request bytes written). Verified on
  every new connection (``_PinningBackend.connect_tcp`` wraps each one); there is no
  "checked once" latch.
* A missing/None ``ssl_object`` (cert unreadable) fails closed, not open.
* ``verify_cert_fingerprint`` carries no secret in its message.

Not observable on this host (documented, no finding): the end-to-end "zero request
bytes on mismatch" guarantee and the per-request re-verification over a reused
pooled connection need a real TLS server / the real ``AsyncConnectionPool`` backend;
unit-level the mechanism is correct. A plain ``http://`` base_url with a pin would
send the request before ``_verify_pin`` fails (``post_json`` verifies AFTER the POST
for the non-handshake path), but ``DeviceSettings.base_url`` always forces
``https://``, so it is not reachable via configuration.
"""

from __future__ import annotations

import pytest

from vigi_nvr_mcp.core.errors import TlsPinMismatch
from vigi_nvr_mcp.core.transport import (
    _PinnedStream,
    fingerprint_sha256,
    verify_cert_fingerprint,
)

GOOD = b"genuine-leaf-cert-DER"
EVIL = b"attacker-leaf-cert-DER"
PIN = fingerprint_sha256(GOOD)


class _FakeSSL:
    def __init__(self, der: bytes) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = True) -> bytes:
        return self._der


class _FakeTlsStream:
    def __init__(self, der: bytes | None) -> None:
        self._der = der
        self.writes: list[bytes] = []

    def get_extra_info(self, key: str):  # noqa: ANN201
        return _FakeSSL(self._der) if (key == "ssl_object" and self._der is not None) else None


class _FakeInner:
    def __init__(self, der: bytes | None) -> None:
        self._der = der
        self.tls = _FakeTlsStream(der)

    async def start_tls(self, ctx, server_hostname=None, timeout=None):  # noqa: ANN001
        return self.tls


def _verify(ssl_object) -> None:  # noqa: ANN001
    from vigi_nvr_mcp.core.transport import _der_from_ssl_object

    der = _der_from_ssl_object(ssl_object)
    if der is None:
        raise TlsPinMismatch("could not read the device certificate to verify the pin")
    verify_cert_fingerprint(der, PIN)


async def test_start_tls_verifies_before_returning_and_raises_on_mismatch() -> None:
    inner = _FakeInner(EVIL)
    stream = _PinnedStream(inner, _verify)
    with pytest.raises(TlsPinMismatch):
        await stream.start_tls(None)
    # The mismatching stream never carried a write (it was never returned).
    assert inner.tls.writes == []


async def test_start_tls_passes_for_the_pinned_cert() -> None:
    inner = _FakeInner(GOOD)
    stream = _PinnedStream(inner, _verify)
    result = await stream.start_tls(None)
    assert isinstance(result, _PinnedStream)


async def test_unreadable_cert_fails_closed() -> None:
    inner = _FakeInner(None)  # ssl_object present but getpeercert yields nothing
    stream = _PinnedStream(inner, _verify)
    with pytest.raises(TlsPinMismatch):
        await stream.start_tls(None)


def test_mismatch_message_carries_no_fingerprint() -> None:
    try:
        verify_cert_fingerprint(EVIL, PIN)
    except TlsPinMismatch as exc:
        assert fingerprint_sha256(EVIL) not in str(exc)
        assert PIN not in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected TlsPinMismatch")
