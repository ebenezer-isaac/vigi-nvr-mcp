# Specs

The source-of-truth planning documents for this repo. They are copied here
verbatim so the build is auditable from inside the repository. The master plan
also references two sibling MCP servers (for a TP-Link switch and router) that
share this repo's `core/` template; those repos are tracked separately.

| File | What it covers |
|---|---|
| [00-MASTER-PLAN.md](00-MASTER-PLAN.md) | The three standalone MCP servers, the shared `core/` template, the non-negotiables (§1), the per-phase agent contract (§2), the sequencing graph and the progress tracker (§7). |
| [01-NVR-SPEC.md](01-NVR-SPEC.md) | `vigi-nvr-mcp` in full: the verified VIGI NVR protocol and phases N1–N7b (auth, catalog gateway, typed reads, channel-management writes and `nvr_plan_channel_cleanup`, RTSP media export, investigation primitives). |
| [04-BREAKER-PROTOCOL.md](04-BREAKER-PROTOCOL.md) | The builder/breaker/fixer loop, the breaker brief template, the severity rubric and the `FINDINGS.md` format used to review each phase. |
| [05-ROOT-CAUSE-breaker.md](05-ROOT-CAUSE-breaker.md) | The root-cause analysis that produced the single locked, schema-validated login breaker in `core/` (the `AtomicStateFile`/`ReservationStore` design). |

The wire protocol is documented separately in
[../protocol/vigi-nvr.md](../protocol/vigi-nvr.md).

All of these obey Master Plan §1: no secrets and no real network data (RFC 5737
`192.0.2.x` placeholders only). `scripts/check_no_secrets.py` gates them.
