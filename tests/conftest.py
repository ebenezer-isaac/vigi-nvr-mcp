from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import pytest

from tests.helpers import FakeNvr, settings_env
from vigi_nvr_mcp.auth import Authenticator
from vigi_nvr_mcp.client import NvrClient
from vigi_nvr_mcp.config import Settings, load_settings
from vigi_nvr_mcp.transport import NvrTransport


@pytest.fixture
def fake() -> FakeNvr:
    return FakeNvr()


@pytest.fixture
def make_settings() -> Callable[..., Settings]:
    def _make(**overrides: str) -> Settings:
        return load_settings(settings_env(**overrides))

    return _make


@pytest.fixture
def settings(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings()


@pytest.fixture
async def transport(settings: Settings, fake: FakeNvr) -> AsyncIterator[NvrTransport]:
    t = NvrTransport(settings, http_transport=fake.transport())
    yield t
    await t.aclose()


@pytest.fixture
def make_client(fake: FakeNvr) -> Callable[[Settings], NvrClient]:
    def _make(s: Settings) -> NvrClient:
        t = NvrTransport(s, http_transport=fake.transport())
        return NvrClient(s, t, Authenticator(s, t))

    return _make


@pytest.fixture
async def client(
    settings: Settings, make_client: Callable[[Settings], NvrClient]
) -> AsyncIterator[NvrClient]:
    c = make_client(settings)
    yield c
    await c.aclose()
