# Specs

The source-of-truth planning documents for this repo and its two sibling MCP
servers. They are copied here verbatim so the build is auditable from inside the
repository; the authoritative originals live in the orchestrator's workspace.

| File | What it covers |
|---|---|
| [00-MASTER-PLAN.md](00-MASTER-PLAN.md) | The three standalone MCP servers, the shared `core/` template, the non-negotiables (§1), the per-phase agent contract (§2) and the sequencing graph. |
| [01-NVR-SPEC.md](01-NVR-SPEC.md) | `vigi-nvr-mcp` in full: the verified VIGI NVR protocol and phases N1–N6, including N4 (channel-management writes and `nvr_plan_channel_cleanup`). |
| [04-BREAKER-PROTOCOL.md](04-BREAKER-PROTOCOL.md) | The builder/breaker/fixer loop, the breaker brief template, the severity rubric and the `FINDINGS.md` format used to review each phase. |

All three obey Master Plan §1: no secrets and no real network data (RFC 5737
`192.0.2.x` placeholders only). `scripts/check_no_secrets.py` gates them.
