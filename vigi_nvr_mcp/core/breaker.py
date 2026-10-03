"""Login circuit breaker (device-agnostic), persisted across process instances.

Many embedded devices lock the admin account after a handful of failed logins.
The breaker decides, before any network I/O, whether a login may be attempted,
and it must survive restarts: a crash-loop or repeated CLI runs with bad
credentials would otherwise reset the budget every process and walk the account
into a hard lockout.

State is a small JSON file under ``<PREFIX>_STATE_DIR`` (default
``~/.local/state/<app>/``), one file per device host, written atomically
(tmp + ``os.replace``) with mode 0600 and loaded on every check. If the file is
unreadable, corrupt, or cannot be written, the breaker is treated as OPEN and a
``BreakerOpen`` error is raised (fail closed). A human clears it with
``<script> breaker --clear``.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .config import DeviceSettings
from .errors import BreakerOpen, LockoutGuard

# Implicit (automatic) logins stop when the device reports this few attempts left.
IMPLICIT_LOGIN_MIN_REMAINING = 3

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def default_state_dir(app_name: str) -> Path:
    """Default per-user state directory for ``app_name`` (``~/.local/state/<app>``)."""
    return Path.home() / ".local" / "state" / app_name


@dataclass(frozen=True)
class LoginLedger:
    failed: int = 0
    successful: int = 0
    last_failure: dict[str, Any] | None = None


def record_failure(ledger: LoginLedger, failure: dict[str, Any]) -> LoginLedger:
    return replace(ledger, failed=ledger.failed + 1, last_failure=dict(failure))


def record_success(ledger: LoginLedger) -> LoginLedger:
    return replace(ledger, successful=ledger.successful + 1)


def check_login_allowed(ledger: LoginLedger, settings: DeviceSettings, *, explicit: bool) -> None:
    """Raise LockoutGuard if policy forbids a login attempt right now."""
    if settings.login_disabled:
        raise LockoutGuard(
            f"Login refused: {settings.env_name('LOGIN_DISABLED')}=true. Authentication is frozen."
        )
    if ledger.failed >= settings.max_login_failures:
        raise LockoutGuard(
            f"Login refused: {ledger.failed} failed login(s) recorded "
            f"(limit {settings.max_login_failures}, {settings.env_name('MAX_LOGIN_FAILURES')}). "
            "The breaker is open and persists across restarts: fix the credentials, check the "
            "device's lockout state, then clear it with the `breaker --clear` command."
        )
    if not explicit and ledger.failed > 0:
        raise LockoutGuard(
            "Login refused: a previous login failed. Automatic logins are disabled; "
            "use the explicit login tool after fixing the cause."
        )


def check_remaining_attempts(
    remaining: int | None,
    *,
    explicit: bool,
    max_attempts: int | None = None,
    lock_seconds_left: int | None = None,
) -> None:
    """Guard on the device-reported remaining-attempts counter (None = unknown)."""
    if remaining is None:
        return
    if remaining <= 0:
        raise LockoutGuard(
            "Login refused: the device reports 0 login attempts remaining; the account is "
            "locked or about to be. Wait for the lock to expire.",
            attempts_left=remaining,
            max_attempts=max_attempts,
            lock_seconds_left=lock_seconds_left,
        )
    if not explicit and remaining < IMPLICIT_LOGIN_MIN_REMAINING:
        raise LockoutGuard(
            f"Login refused: the device reports only {remaining} attempt(s) remaining. "
            "Automatic login is suspended; use the explicit login tool if you are sure "
            "the credentials are correct.",
            attempts_left=remaining,
            max_attempts=max_attempts,
            lock_seconds_left=lock_seconds_left,
        )


class LoginBreaker:
    """Persistent per-device login breaker. File-backed, fail-closed on I/O error."""

    def __init__(self, state_dir: Path, device: str, settings: DeviceSettings) -> None:
        self._dir = Path(state_dir)
        self._device = device
        self._settings = settings
        self._path = self._dir / f"breaker-{_UNSAFE.sub('_', device)}.json"

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> LoginLedger:
        if not self._path.exists():
            return LoginLedger()
        try:
            data = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            raise BreakerOpen(
                "Login breaker state is unreadable or corrupt; refusing logins (fail closed). "
                "Clear it with the `breaker --clear` command."
            ) from None
        if not isinstance(data, dict):
            raise BreakerOpen(
                "Login breaker state is malformed; refusing logins (fail closed). "
                "Clear it with the `breaker --clear` command."
            )
        last = data.get("last_failure")
        return LoginLedger(
            failed=int(data.get("failed", 0)),
            successful=int(data.get("successful", 0)),
            last_failure=last if isinstance(last, dict) else None,
        )

    def _save(self, ledger: LoginLedger) -> None:
        payload = {
            "device": self._device,
            "failed": ledger.failed,
            "successful": ledger.successful,
            "last_failure": ledger.last_failure,
        }
        tmp = self._dir / f"{self._path.name}.{os.getpid()}.tmp"
        try:
            self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
            os.replace(tmp, self._path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise BreakerOpen(
                "Login breaker state could not be written; refusing logins (fail closed). "
                f"Check write access to {self._dir}."
            ) from None

    def check(self, *, explicit: bool) -> LoginLedger:
        """Load state and raise if a login is not allowed; return the loaded ledger."""
        ledger = self._load()
        check_login_allowed(ledger, self._settings, explicit=explicit)
        return ledger

    def record_failure(self, failure: dict[str, Any]) -> LoginLedger:
        ledger = record_failure(self._load(), failure)
        self._save(ledger)
        return ledger

    def record_success(self) -> LoginLedger:
        ledger = record_success(self._load())
        self._save(ledger)
        return ledger

    def clear(self) -> None:
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            raise BreakerOpen(f"Could not clear the breaker file at {self._path}.") from None

    def show(self) -> dict[str, Any]:
        try:
            ledger = self._load()
        except BreakerOpen as exc:
            return {"state": "open", "reason": str(exc), "path": str(self._path)}
        is_open = (
            self._settings.login_disabled or ledger.failed >= self._settings.max_login_failures
        )
        return {
            "state": "open" if is_open else "closed",
            "failed": ledger.failed,
            "successful": ledger.successful,
            "max_login_failures": self._settings.max_login_failures,
            "login_disabled": self._settings.login_disabled,
            "last_failure": ledger.last_failure,
            "path": str(self._path),
        }
