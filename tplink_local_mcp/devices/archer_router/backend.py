"""TP-Link Archer router backend: scaffold pending protocol discovery.

Tools will be prefixed ``router_``. Until the router's login/session protocol is
captured and verified, this backend validates ``TPLINK_ROUTER_*`` settings,
registers no tools, sends nothing to the device, and reports NOT_IMPLEMENTED.
"""

from __future__ import annotations

from ...core.backend import PendingBackend


class ArcherRouterBackend(PendingBackend):
    name = "router"
    settings_prefix = "TPLINK_ROUTER_"
    tool_prefix = "router_"
    description = "pending protocol discovery"
