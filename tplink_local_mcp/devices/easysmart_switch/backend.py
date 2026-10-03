"""TP-Link Easy Smart switch backend: scaffold pending protocol discovery.

Tools will be prefixed ``switch_``. Until the switch's web protocol is captured
and verified, this backend validates ``TPLINK_SWITCH_*`` settings, registers no
tools, sends nothing to the device, and reports NOT_IMPLEMENTED.
"""

from __future__ import annotations

from ...core.backend import PendingBackend


class EasySmartSwitchBackend(PendingBackend):
    name = "switch"
    settings_prefix = "TPLINK_SWITCH_"
    tool_prefix = "switch_"
    description = "pending protocol discovery"
