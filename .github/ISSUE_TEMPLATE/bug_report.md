---
name: Bug report
about: Report a problem with vigi-nvr-mcp
title: ""
labels: bug
assignees: ""
---

<!--
SECURITY ISSUES: do not file them here. Follow SECURITY.md to report privately.
REMOVE ALL SECRETS before posting: passwords, stok/session tokens, ciphertext
values, and real IPs/MACs/serials. Redact output the way --check-auth does.
-->

## What happened

A clear description of the bug and what you expected instead.

## Device

- **NVR model:** <!-- e.g. VIGI NVR1016H(UN) -->
- **Firmware:** <!-- e.g. 1.1.3 Build 260727 -->
- **vigi-nvr-mcp version / commit:**
- **Python version:**
- **OS:**
- **Transport:** <!-- stdio | streamable-http -->
- **MCP client:** <!-- e.g. Claude Desktop, Claude Code -->

## `--check-auth` output (secrets removed)

<!--
Run `vigi-nvr-mcp --check-auth` (no --login first) and paste the output here.
It already masks the token; double-check nothing sensitive remains.
-->

```
paste here
```

## Steps to reproduce

1.
2.
3.

## Tool call / error envelope

<!-- The tool name, arguments (secrets removed), and the {success,data,error} envelope you got back. -->

```json
paste here
```

## Anything else

Logs (`VIGI_MCP_LOG_LEVEL=DEBUG`, secrets removed), screenshots, or context.
