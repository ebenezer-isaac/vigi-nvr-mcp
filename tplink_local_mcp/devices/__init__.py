"""Device backends. ``all_backends()`` lists every family, configured or not."""

from __future__ import annotations

from ..core.backend import DeviceBackend
from .archer_router import ArcherRouterBackend
from .easysmart_switch import EasySmartSwitchBackend
from .vigi_nvr import VigiNvrBackend


def all_backends() -> list[DeviceBackend]:
    return [VigiNvrBackend(), ArcherRouterBackend(), EasySmartSwitchBackend()]
