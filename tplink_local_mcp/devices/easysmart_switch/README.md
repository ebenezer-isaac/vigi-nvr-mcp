# Easy Smart switch backend

**Status: pending protocol discovery.** No tools are registered yet.

Planned tool prefix: `switch_`. Configuration prefix: `TPLINK_SWITCH_`
(`HOST`, `PORT`, `USERNAME`, `PASSWORD`, `VERIFY_TLS`, `ALLOW_WRITES`,
`LOGIN_DISABLED`, `MAX_LOGIN_FAILURES`, `TIMEOUT_SECONDS`).

If `TPLINK_SWITCH_HOST` is set, the settings are validated at startup and
`tplink_status` reports this backend as configured with a `NOT_IMPLEMENTED`
healthcheck. Nothing is ever sent to the switch.

Before implementing:

1. Capture the login flow of your own switch's web UI, one attempt only.
   Assume the switch may lock out after repeated failures.
2. Implement it in this package following `devices/vigi_nvr/`: pure crypto
   functions, a transport, an authenticator built on `core.lockout`, and tools
   that return envelopes, redact credentials and go through `core.write_gate`.
3. Replace `EasySmartSwitchBackend(PendingBackend)` with a real `DeviceBackend`.
