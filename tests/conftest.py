from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import pytest

from tests.helpers import NVR_PREFIX, FakeNvr, nvr_env
from tplink_local_mcp.core.config import DeviceSettings, load_device_settings
from tplink_local_mcp.devices.vigi_nvr.auth import Authenticator
from tplink_local_mcp.devices.vigi_nvr.client import NvrClient
from tplink_local_mcp.devices.vigi_nvr.tools import ToolContext
from tplink_local_mcp.devices.vigi_nvr.transport import NvrTransport


@pytest.fixture
def fake() -> FakeNvr:
    return FakeNvr()


@pytest.fixture
def make_settings() -> Callable[..., DeviceSettings]:
    def _make(**overrides: str) -> DeviceSettings:
        return load_device_settings(NVR_PREFIX, nvr_env(**overrides))

    return _make


@pytest.fixture
def settings(make_settings: Callable[..., DeviceSettings]) -> DeviceSettings:
    return make_settings()


@pytest.fixture
async def transport(settings: DeviceSettings, fake: FakeNvr) -> AsyncIterator[NvrTransport]:
    t = NvrTransport(settings, http_transport=fake.transport())
    yield t
    await t.aclose()


@pytest.fixture
def make_client(fake: FakeNvr) -> Callable[[DeviceSettings], NvrClient]:
    def _make(s: DeviceSettings) -> NvrClient:
        t = NvrTransport(s, http_transport=fake.transport())
        return NvrClient(s, t, Authenticator(s, t))

    return _make


@pytest.fixture
async def client(
    settings: DeviceSettings, make_client: Callable[[DeviceSettings], NvrClient]
) -> AsyncIterator[NvrClient]:
    c = make_client(settings)
    yield c
    await c.aclose()


@pytest.fixture
def make_auth(fake: FakeNvr, make_settings):
    """Build (Authenticator, transport) against ``fake`` with setting overrides."""
    made: list[NvrTransport] = []

    def _make(**overrides: str) -> Authenticator:
        s = make_settings(**overrides)
        t = NvrTransport(s, http_transport=fake.transport())
        made.append(t)
        return Authenticator(s, t)

    yield _make


@pytest.fixture
def ctx(client: NvrClient) -> ToolContext:
    return ToolContext(settings=client.settings, client=client)


@pytest.fixture
def make_ctx(make_settings, make_client):
    def _make(**overrides: str) -> ToolContext:
        s = make_settings(**overrides)
        return ToolContext(settings=s, client=make_client(s))

    return _make
