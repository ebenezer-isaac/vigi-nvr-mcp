"""Recursive redaction of credential-bearing fields. Pure: always returns new objects.

Single source of truth for which keys are secret-bearing (mirrored in
``docs/specs/00-MASTER-PLAN.md`` §1.6). A key (lower-cased) is redacted when it:

* equals one of the EXACT names:
  ``ciphertext, stok, token, nonce, cookie, secret, authorization, pubkey, key``;
* CONTAINS one of: ``pass, pwd, secret, token, cipher`` (so ``password``,
  ``old_password``, ``new_pwd``, ``passwd``, ``api_token`` … are all caught); or
* ENDS WITH ``_key`` (so ``public_key``, ``rsa_key`` … are caught).

Rule-based rather than a hand-maintained exact list, so spellings the device may
emit (``nonce``, ``cookie``, ``pubkey``, ``Authorization``, password-change
fields) cannot silently slip through. Harmless over-matching (e.g.
``passwd_strength``) is accepted; names like ``auth_result``, ``online``,
``conn_status``, ``uuid``, ``key_present`` deliberately survive.
"""

from __future__ import annotations

from typing import Any

REDACTED = "<redacted>"
TRUNCATED = "<truncated: max depth>"
MAX_DEPTH = 64

_EXACT_KEYS = frozenset(
    {"ciphertext", "stok", "token", "nonce", "cookie", "secret", "authorization", "pubkey", "key"}
)
_CONTAINS = ("pass", "pwd", "secret", "token", "cipher")
_ENDSWITH = ("_key",)


def is_sensitive_key(key: object) -> bool:
    name = str(key).lower()
    return (
        name in _EXACT_KEYS
        or any(fragment in name for fragment in _CONTAINS)
        or name.endswith(_ENDSWITH)
    )


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Return a copy of ``value`` with sensitive fields replaced by ``REDACTED``.

    Dicts and lists/tuples are rebuilt (tuples become lists, matching JSON).
    Nesting deeper than ``MAX_DEPTH`` is replaced by ``TRUNCATED``, which also
    terminates self-referencing structures.
    """
    if _depth >= MAX_DEPTH:
        return TRUNCATED
    if isinstance(value, dict):
        return {
            k: (REDACTED if is_sensitive_key(k) else redact(v, _depth=_depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(item, _depth=_depth + 1) for item in value]
    return value
