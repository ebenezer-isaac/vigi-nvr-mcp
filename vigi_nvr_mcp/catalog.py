"""Vendored firmware catalogs for the VIGI NVR1016H (fw 1.1.3).

Two inventories live in ``data/``:

* ``errcodes.json`` -- symbol -> numeric error code (555 entries). Exposed as
  :func:`symbol_for` for the error layer.
* ``endpoints.json`` -- the full API inventory (61 modules / 586 calls / 217
  mutating), sanitised by ``scripts/sanitize_catalog.py``. Exposed through
  :class:`Catalog`, which validates and builds request bodies for the gateway
  tools so every one of the 586 calls is reachable without 586 registrations.
"""

from __future__ import annotations

import difflib
import json
import math
import re
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict

# --- error-code catalog -------------------------------------------------------


@lru_cache(maxsize=1)
def code_to_symbol() -> MappingProxyType[int, str]:
    text = resources.files(__package__).joinpath("data/errcodes.json").read_text("utf-8")
    return MappingProxyType({code: symbol for symbol, code in json.loads(text).items()})


def symbol_for(code: int) -> str | None:
    return code_to_symbol().get(code)


# --- endpoint catalog ---------------------------------------------------------

MAX_DEPTH = 6
MAX_KEYS = 200
MAX_STRING_BYTES = 4096
_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# Any C0/C1 control character, including NUL, tab, CR and LF.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class CallSpec(BaseModel):
    """One catalogued API call, identified by (module, method, key)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    module: str
    method: str
    key: str
    params_example: dict[str, Any] | None = None
    mutates: bool = False
    pre_auth: bool = False
    ui_context: str | None = None
    response_shape_hint: str | None = None


def _validate_params(params: Any) -> dict[str, Any] | None:
    """Validate caller-supplied params against the gateway's safety rules.

    Rejects (before any I/O) non-objects, nesting deeper than six levels, more
    than 200 keys in total, strings over 4 KB, control characters, keys outside
    ``[A-Za-z0-9_.-]{1,64}`` and non-JSON values (including NaN/Infinity).
    Returns the params unchanged (never mutated).
    """
    if params is None:
        return None
    if not isinstance(params, dict):
        raise ValueError("params must be an object or null")

    key_count = 0

    def walk(obj: Any, depth: int) -> None:
        nonlocal key_count
        if depth > MAX_DEPTH:
            raise ValueError(f"params nested deeper than {MAX_DEPTH} levels")
        if isinstance(obj, dict):
            for key, value in obj.items():
                if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
                    raise ValueError(
                        f"invalid parameter key {key!r}: must match [A-Za-z0-9_.-]{{1,64}}"
                    )
                key_count += 1
                if key_count > MAX_KEYS:
                    raise ValueError(f"params has more than {MAX_KEYS} keys")
                walk(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, depth + 1)
        elif isinstance(obj, str):
            if len(obj.encode("utf-8")) > MAX_STRING_BYTES:
                raise ValueError("string value exceeds 4 KB")
            if _CONTROL.search(obj):
                raise ValueError("string value contains control characters")
        elif isinstance(obj, bool) or obj is None or isinstance(obj, int):
            return
        elif isinstance(obj, float):
            if not math.isfinite(obj):
                raise ValueError("number must be finite (no NaN or Infinity)")
        else:
            raise ValueError(f"params contains a non-JSON value of type {type(obj).__name__}")

    walk(params, 1)
    return params


def _ident(module: str, method: str, key: str) -> str:
    return f"{module}/{method}/{key}"


class Catalog:
    """Read-only view over the vendored endpoint inventory."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._modules: dict[str, dict[str, Any]] = dict(data["modules"])
        self._index: dict[tuple[str, str, str], CallSpec] = {}
        for module, info in self._modules.items():
            for call in info["calls"]:
                spec = CallSpec(module=module, **call)
                self._index[(module, spec.method, spec.key)] = spec
        self._idents = tuple(_ident(m, s.method, s.key) for (m, _, _), s in self._index.items())

    @classmethod
    def load(cls) -> Catalog:
        text = resources.files(__package__).joinpath("data/endpoints.json").read_text("utf-8")
        return cls(json.loads(text))

    @property
    def module_count(self) -> int:
        return len(self._modules)

    @property
    def call_count(self) -> int:
        return sum(len(info["calls"]) for info in self._modules.values())

    @property
    def mutating_count(self) -> int:
        return sum(1 for spec in self._index.values() if spec.mutates)

    def modules(self) -> list[dict[str, Any]]:
        """One summary row per module: name, description and call counts."""
        rows = []
        for name, info in self._modules.items():
            calls = info["calls"]
            rows.append(
                {
                    "name": name,
                    "description": info.get("description"),
                    "call_count": len(calls),
                    "mutating_count": sum(1 for c in calls if c.get("mutates")),
                }
            )
        return rows

    def calls(self, module: str) -> list[CallSpec]:
        if module not in self._modules:
            raise KeyError(module)
        return [spec for (mod, _, _), spec in self._index.items() if mod == module]

    def find(self, module: str, method: str, key: str) -> CallSpec:
        try:
            return self._index[(module, method, key)]
        except KeyError:
            raise LookupError(_ident(module, method, key)) from None

    def nearest(self, module: str, method: str, key: str, n: int = 3) -> list[dict[str, str]]:
        """Up to ``n`` catalogued calls closest to a (possibly wrong) triple."""
        matches = difflib.get_close_matches(
            _ident(module, method, key), self._idents, n=n, cutoff=0.0
        )
        out = []
        for ident in matches:
            mod, meth, k = ident.split("/", 2)
            out.append({"module": mod, "method": meth, "key": k})
        return out

    def nearest_modules(self, module: str, n: int = 3) -> list[str]:
        return difflib.get_close_matches(module, list(self._modules), n=n, cutoff=0.0)

    def build_body(
        self, spec: CallSpec, params: dict[str, Any] | None = None, *, allow_extra: bool = False
    ) -> dict[str, Any]:
        """Validate ``params`` and build the wire body ``{"method", <module>}``.

        ``params`` is the module body the caller wants to send (the ``key``
        identifies which documented call this is, per the catalog). When the
        spec carries a ``params_example`` shape, top-level keys absent from it
        are rejected unless ``allow_extra=True``.
        """
        validated = _validate_params(params)
        if validated and spec.params_example:
            unknown = sorted(set(validated) - set(spec.params_example))
            if unknown and not allow_extra:
                raise ValueError(
                    f"unknown parameter(s) {unknown} for {spec.module}/{spec.method}/{spec.key}; "
                    "pass allow_extra=true to send them anyway"
                )
        return {"method": spec.method, spec.module: validated}


@lru_cache(maxsize=1)
def get_catalog() -> Catalog:
    return Catalog.load()
