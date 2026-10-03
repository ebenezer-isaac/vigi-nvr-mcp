"""Vendored firmware catalogs for the VIGI NVR1016H (fw 1.1.3).

Two inventories live in ``data/``:

* ``errcodes.json`` -- symbol -> numeric error code (555 entries). Exposed as
  :func:`symbol_for` for the error layer.
* ``endpoints.json`` -- the full API inventory (61 modules / 586 calls / 217
  mutating), sanitised by ``scripts/sanitize_catalog.py``. Exposed through
  :class:`Catalog`, which validates and builds request bodies for the gateway
  tools so every one of the 586 calls is reachable without 586 registrations.

Both files carry a sidecar ``<stem>.sha256`` (SHA-256 of the canonical UTF-8
JSON text) written by the sanitiser and verified at load, so a count-preserving
tamper (a flipped ``mutates`` flag, a rewritten ``params_example``, a swapped
``method``) is refused at startup rather than served silently.

Wire shapes
-----------
A call is identified by ``(module, method, key)``. How ``key`` maps onto the wire
body depends on the call's :class:`shape <CallSpec>`:

* ``table``      -> ``{<module>: {"table": <key>}}``        (a get that returns rows)
* ``name``       -> ``{<module>: {"name": <key>}}``         (a get of one section)
* ``name_list``  -> ``{<module>: {"name": [<key>]}}``       (the common get form)
* ``action``     -> ``{<module>: {<key>: {...params}}}``    (do/set/add/delete)
* ``bare``       -> ``{<module>: {...params}}``             (key is ``(dynamic)``)

The shape is derived deterministically from the inventory conventions and the
verified request captures in ``discovery/_tools/raw-calls.json`` (see
``docs/specs/01-NVR-SPEC.md`` §N2).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import math
import re
import unicodedata
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .core.errors import ConfigError, InvalidInput

# --- error-code catalog -------------------------------------------------------

EXPECTED_ERRCODES = 555
EXPECTED_MODULES = 61
EXPECTED_CALLS = 586
EXPECTED_MUTATING = 217

_HEX64 = re.compile(r"[0-9a-f]{64}")


def _verify_content_hash(stem: str, text: str) -> None:
    """Refuse to serve if ``data/<stem>.json`` does not match its ``.sha256`` sidecar.

    ``text`` is exactly what the loader read (UTF-8). The sidecar holds the
    SHA-256 of that canonical text; any edit to the vendored file -- including a
    count-preserving one the aggregate counters miss -- changes the digest and
    raises :class:`ConfigError`. A missing or malformed sidecar is itself a
    failure (fail closed)."""
    actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
    try:
        expected = (
            resources.files(__package__).joinpath(f"data/{stem}.sha256").read_text("utf-8").strip()
        )
    except (FileNotFoundError, OSError, ValueError):
        raise ConfigError(
            f"{stem}.json integrity sidecar is missing or unreadable; cannot verify the "
            "vendored catalog, refusing to serve."
        ) from None
    if not _HEX64.fullmatch(expected) or actual != expected:
        raise ConfigError(
            f"{stem}.json failed its integrity check (content hash mismatch); the vendored "
            "catalog is corrupt or has been tampered with."
        )


@lru_cache(maxsize=1)
def code_to_symbol() -> MappingProxyType[int, tuple[str, ...]]:
    """Map each numeric error code to ALL its symbols (tuple), validated at load.

    ``errcodes.json`` is ``symbol -> code`` with five codes (incl. ``-1``) carrying
    two symbols each; inverting keeps every symbol rather than silently dropping
    one. A missing, truncated or tampered file (wrong symbol count or a content-hash
    mismatch) raises ``ConfigError`` loudly here, not as a mislabelled client error
    inside a tool.
    """
    text = resources.files(__package__).joinpath("data/errcodes.json").read_text("utf-8")
    _verify_content_hash("errcodes", text)
    try:
        table = json.loads(text)
    except ValueError:
        raise ConfigError(
            "errcodes.json is not valid JSON; the error catalog is corrupt."
        ) from None
    if not isinstance(table, dict) or len(table) != EXPECTED_ERRCODES:
        got = len(table) if isinstance(table, dict) else "a non-object"
        raise ConfigError(
            f"errcodes.json is corrupt: expected {EXPECTED_ERRCODES} symbols, got {got}."
        )
    inverted: dict[int, tuple[str, ...]] = {}
    for symbol, code in table.items():
        inverted[code] = (*inverted.get(code, ()), symbol)
    return MappingProxyType(inverted)


def symbol_for(code: int) -> str | None:
    symbols = code_to_symbol().get(code)
    return symbols[0] if symbols else None


def code_to_symbols(code: int) -> tuple[str, ...]:
    """Every documented symbol for ``code`` (a tuple; empty if unknown).

    Colliding codes keep all their symbols, so ``-1`` returns both
    ``EINVCLOUDERRORGENERIC`` and ``ERR_PERCENT`` rather than an arbitrary one."""
    return code_to_symbol().get(code, ())


# --- endpoint catalog ---------------------------------------------------------

MAX_DEPTH = 6
MAX_KEYS = 200
MAX_STRING_BYTES = 4096
_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# Unicode categories rejected in any string value: C0/C1 and other controls (Cc),
# format characters incl. the BOM (Cf), and the line/paragraph separators (Zl/Zp).
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})

Shape = Literal["name_list", "name", "table", "action", "bare"]

# GET keys whose wire wrapper is verified from the firmware captures
# (discovery/_tools/raw-calls.json): ``table`` returns rows, scalar ``name`` reads
# one section. Everything else (a real-keyed get) defaults to the list form
# ``{"name": [<key>]}`` the web client uses throughout; ``(dynamic)`` keys are bare.
TABLE_GET_KEYS: frozenset[tuple[str, str]] = frozenset(
    {
        ("chm", "added_dev"),
        ("chm", "camera"),
        ("chm", "chn_info"),
        ("function", "chn_info"),
        ("harddisk_manage", "camera"),
        ("network", "upnp_status"),
        ("protocol", "upnp_status"),
        ("record_control", "camera"),
        ("upnpc", "upnp_status"),
    }
)
NAME_GET_KEYS: frozenset[tuple[str, str]] = frozenset(
    {
        ("OSD", "clock_status"),
        ("chm", "chn_extend"),
        ("chm", "encode_adapt"),
        ("cloud_config", "basic_info"),
        ("cloud_config", "bind"),
        ("cloud_config", "device_status"),
        ("cloud_config", "info"),
        ("device_info", "basic_info"),
        ("device_info", "info"),
        ("firewall", "ipctrl"),
        ("function", "hdextreme"),
        ("function", "module_spec"),
        ("harddisk_manage", "hdextreme"),
        ("system", "info"),
        ("timing_reboot", "reboot"),
        ("upnpc", "upnpc_info"),
        ("user_management", "module_spec"),
        ("video", "clock_status"),
    }
)

_DYNAMIC_KEY = "(dynamic)"


def derive_shape(module: str, method: str, key: str) -> Shape:
    """Deterministically classify how ``key`` wraps onto the wire for one call.

    See the module docstring and ``docs/specs/01-NVR-SPEC.md`` §N2. Rules, in
    order: a ``(dynamic)``/absent key is ``bare`` (params pass straight through);
    any non-``get`` method nests its params under the action key (``action``); a
    ``get`` whose key is a verified table/scalar-name is ``table``/``name``;
    every other ``get`` uses the list form ``name_list``.
    """
    if not key or key == _DYNAMIC_KEY:
        return "bare"
    if method != "get":
        return "action"
    if (module, key) in TABLE_GET_KEYS:
        return "table"
    if (module, key) in NAME_GET_KEYS:
        return "name"
    return "name_list"


def has_forbidden_chars(value: str) -> bool:
    """True if ``value`` holds any Unicode control/format/line-separator character.

    Rejects categories Cc (C0/C1 controls incl. NUL, tab, CR, LF, NEL), Cf (format
    characters incl. U+FEFF BOM and U+200B), Zl (U+2028 line separator) and Zp
    (U+2029 paragraph separator). The C0/C1 code-point range alone misses the
    non-C0/C1 separators and the BOM, so the check is category-based."""
    return any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value)


def validate_params(params: Any) -> dict[str, Any] | None:
    """Validate caller-supplied params against the gateway's safety rules.

    Rejects (before any I/O, and before any recursion-prone work) non-objects,
    nesting deeper than six levels, more than 200 keys in total, strings over
    4 KB, control/format/separator characters (via :func:`has_forbidden_chars`),
    lone UTF-16 surrogates (which are not encodable), keys outside
    ``[A-Za-z0-9_.-]{1,64}`` and non-JSON values (including NaN/Infinity). Raises
    :class:`InvalidInput` (a ``ValueError``) so it maps to an ``INVALID_INPUT``
    envelope -- never a raw codec error. Returns the params unchanged.
    """
    if params is None:
        return None
    if not isinstance(params, dict):
        raise InvalidInput("params must be an object or null")

    key_count = 0

    def walk(obj: Any, depth: int) -> None:
        nonlocal key_count
        if depth > MAX_DEPTH:
            raise InvalidInput(f"params nested deeper than {MAX_DEPTH} levels")
        if isinstance(obj, dict):
            for key, value in obj.items():
                if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
                    raise InvalidInput(
                        f"invalid parameter key {key!r}: must match [A-Za-z0-9_.-]{{1,64}}"
                    )
                key_count += 1
                if key_count > MAX_KEYS:
                    raise InvalidInput(f"params has more than {MAX_KEYS} keys")
                walk(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, depth + 1)
        elif isinstance(obj, str):
            # Lone surrogates are not UTF-8 encodable; reject them cleanly before
            # any .encode() can raise a UnicodeEncodeError whose message leaks.
            if any(unicodedata.category(ch) == "Cs" for ch in obj):
                raise InvalidInput("invalid unicode in params")
            if has_forbidden_chars(obj):
                raise InvalidInput("string value contains control characters")
            if len(obj.encode("utf-8")) > MAX_STRING_BYTES:
                raise InvalidInput("string value exceeds 4 KB")
        elif isinstance(obj, bool) or obj is None or isinstance(obj, int):
            return
        elif isinstance(obj, float):
            if not math.isfinite(obj):
                raise InvalidInput("number must be finite (no NaN or Infinity)")
        else:
            raise InvalidInput(f"params contains a non-JSON value of type {type(obj).__name__}")

    walk(params, 1)
    return params


def _ident(module: str, method: str, key: str) -> str:
    return f"{module}/{method}/{key}"


class CallSpec(BaseModel):
    """One catalogued API call, identified by (module, method, key)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    module: str
    method: str
    key: str
    shape: Shape = "bare"
    params_example: dict[str, Any] | None = None
    mutates: bool = False
    pre_auth: bool = False
    ui_context: str | None = None
    response_shape_hint: str | None = None


def _check_unknown(spec: CallSpec, fields: Any, allow_extra: bool) -> None:
    """Reject inner fields absent from the call's example (unless ``allow_extra``)."""
    if allow_extra or not fields or not spec.params_example:
        return
    unknown = sorted(set(fields) - set(spec.params_example))
    if unknown:
        raise InvalidInput(
            f"unknown parameter(s) {unknown} for {spec.module}/{spec.method}/{spec.key}; "
            "pass allow_extra=true to send them anyway"
        )


class Catalog:
    """Read-only view over the vendored endpoint inventory."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._modules: dict[str, dict[str, Any]] = dict(data["modules"])
        self._index: dict[tuple[str, str, str], CallSpec] = {}
        for module, info in self._modules.items():
            for call in info["calls"]:
                shape = derive_shape(module, call["method"], call["key"])
                fields = dict(call)
                # A bare call's key is dynamic/unknown, so a stored example cannot be
                # wrapped under it; drop it so describe reports an honest pass-through.
                if shape == "bare" and isinstance(fields.get("params_example"), dict):
                    fields["params_example"] = None
                spec = CallSpec(module=module, shape=shape, **fields)
                self._index[(module, spec.method, spec.key)] = spec
        self._idents = tuple(_ident(m, s.method, s.key) for (m, _, _), s in self._index.items())

    @classmethod
    def load(cls) -> Catalog:
        text = resources.files(__package__).joinpath("data/endpoints.json").read_text("utf-8")
        _verify_content_hash("endpoints", text)
        try:
            data = json.loads(text)
        except ValueError:
            raise ConfigError(
                "endpoints.json is not valid JSON; the call catalog is corrupt."
            ) from None
        if not isinstance(data, dict) or "modules" not in data:
            raise ConfigError("endpoints.json is corrupt: no 'modules' section.")
        catalog = cls(data)
        actual = (catalog.module_count, catalog.call_count, catalog.mutating_count)
        expected = (EXPECTED_MODULES, EXPECTED_CALLS, EXPECTED_MUTATING)
        if actual != expected:
            raise ConfigError(
                "endpoints.json is corrupt: expected "
                f"{expected[0]} modules / {expected[1]} calls / {expected[2]} mutating, "
                f"got {actual[0]} / {actual[1]} / {actual[2]}."
            )
        return catalog

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

    def wire_example(self, spec: CallSpec) -> dict[str, Any]:
        """The exact full wire body for this call using its ``params_example``.

        Shows a caller (and ``nvr_describe_call``) precisely what goes on the wire,
        including the ``name``/``table``/action-key wrapper the firmware dispatches
        on. A ``bare`` call has a dynamic key, so the body is the params verbatim.
        """
        return self.build_body(spec, spec.params_example, allow_extra=True)

    def build_body(
        self, spec: CallSpec, params: dict[str, Any] | None = None, *, allow_extra: bool = False
    ) -> dict[str, Any]:
        """Validate ``params`` and build the exact wire body ``{"method", <module>}``.

        ``params`` is the call's INNER body (the fields the example lists). The
        catalog's :class:`shape <CallSpec>` decides the wrapper, so an LLM that
        follows ``nvr_describe_call`` emits the body the firmware actually
        dispatches on. For an ``action`` call an already-wrapped ``{<key>: {...}}``
        body is accepted too (and not double-wrapped). Inner keys outside the
        example are rejected unless ``allow_extra=True``.
        """
        validated = validate_params(params)
        if spec.shape == "bare":
            return {"method": spec.method, spec.module: validated}
        if spec.shape == "action":
            inner = validated
            if (
                isinstance(inner, dict)
                and set(inner) == {spec.key}
                and isinstance(inner.get(spec.key), dict | type(None))
            ):
                inner = inner[spec.key]
            _check_unknown(spec, inner, allow_extra)
            return {"method": spec.method, spec.module: {spec.key: inner}}
        # get shapes: the key is the section/table being read; params are extra fields.
        extra = dict(validated) if validated else {}
        _check_unknown(spec, extra, allow_extra)
        if spec.shape == "table":
            module_body: dict[str, Any] = {"table": spec.key, **extra}
        elif spec.shape == "name":
            module_body = {"name": spec.key, **extra}
        else:  # name_list
            module_body = {"name": [spec.key], **extra}
        return {"method": spec.method, spec.module: module_body}


@lru_cache(maxsize=1)
def get_catalog() -> Catalog:
    return Catalog.load()


def validate_catalogs() -> None:
    """Force both vendored catalogs to load and validate at startup.

    Raises ``ConfigError`` loudly if either file is missing, truncated, tampered
    (content-hash mismatch) or has the wrong counts, so corruption surfaces at
    startup rather than as a mislabelled error inside a tool call."""
    code_to_symbol()
    get_catalog()
