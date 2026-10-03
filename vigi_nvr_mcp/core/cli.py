"""Small helpers shared by device CLIs."""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Mapping
from typing import Any, TextIO


def configure_logging(level_var: str, environ: Mapping[str, str] | None = None) -> None:
    """Log to stderr (stdout is the MCP stdio channel) at ``$level_var`` (default INFO)."""
    source = os.environ if environ is None else environ
    level = str(source.get(level_var, "INFO")).upper()
    logging.basicConfig(
        level=level if level in logging.getLevelNamesMapping() else "INFO",
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# Exit codes let a shell script branch on the kind of failure, not just pass/fail:
#   0 success · 1 auth failed · 2 config error · 3 lockout/breaker/login disabled ·
#   4 transport · 1 anything else.
_EXIT_BY_CODE: dict[str, int] = {
    "AUTH_FAILED": 1,
    "CONFIG_ERROR": 2,
    "LOGIN_REFUSED": 3,
    "BREAKER_OPEN": 3,
    "TRANSPORT_ERROR": 4,
    "TLS_PIN_MISMATCH": 4,
}


def emit_envelope(result: dict[str, Any], stream: TextIO | None = None) -> int:
    """Print an envelope as sorted JSON; return an exit code keyed to the failure.

    0 on success; otherwise the code mapped from ``error.code`` (auth=1, config=2,
    lockout/breaker/login-disabled=3, transport=4), defaulting to 1.
    """
    print(json.dumps(result, indent=2, sort_keys=True), file=stream or sys.stdout)
    if result.get("success") is True:
        return 0
    code = (result.get("error") or {}).get("code")
    return _EXIT_BY_CODE.get(code, 1)


def emit_lines(lines: list[str], stream: TextIO | None = None) -> int:
    for line in lines:
        print(line, file=stream or sys.stdout)
    return 0
