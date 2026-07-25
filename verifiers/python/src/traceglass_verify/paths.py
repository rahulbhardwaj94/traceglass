"""Leaf walking, path construction and path read-back -- SPEC.md §8.1, §9.4(b).

Paths are built by unescaped string concatenation, which makes some of them
ambiguous or unresolvable (SPEC §12.5). That is a known v1 defect; this module
reproduces it rather than fixing it, because fixing it would change hashes.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from .canonical import is_array_index_key

__all__ = [
    "ABSENT",
    "walk_leaves",
    "split_field",
    "read_path",
    "commitment_view",
]


class _Absent:
    """Sentinel for "the path does not resolve".

    SPEC §9.4(c) says a missing value "reads as absent". The reference
    implementation gets JavaScript ``undefined`` here and then hashes the
    literal text ``"undefined"`` through string coercion (SPEC §12.4). We do
    not reproduce that: an absent value is reported as a mismatch outright,
    which reaches the same verdict by a defensible route.
    """

    _instance = None

    def __new__(cls) -> "_Absent":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


ABSENT = _Absent()


def _is_leaf(value: Any) -> bool:
    """SPEC §8.1: any non-container, plus an *empty* object or array.

    Empty containers are leaves on purpose -- emptiness is a fact worth
    committing to, so ``{"rows": []}`` cannot be swapped for ``{"rows":[1,2,3]}``.
    """
    if isinstance(value, dict):
        return len(value) == 0
    if isinstance(value, (list, tuple)):
        return len(value) == 0
    return True


def _enumeration_order(keys: list[str]) -> list[str]:
    """ECMAScript ``OrdinaryOwnPropertyKeys`` order.

    Array-index keys first in ascending numeric order, then every other key in
    *insertion* order. SPEC §8.1 does not state a visit order at all, but the
    corpus's ``02 walk`` vectors compare an ordered list, and the reference
    producer emits commitments in this order for the same runtime reason §4.2.2
    documents. See FINDINGS.md F3.

    This affects only the order of keys within the ``commitments`` and ``salts``
    maps. Both are canonicalized as objects (whose keys get sorted again by
    §4.2.1), so no hash depends on it.
    """
    indices = [k for k in keys if is_array_index_key(k)]
    indices.sort(key=int)
    return indices + [k for k in keys if not is_array_index_key(k)]


def walk_leaves(value: Any, base: str) -> Iterator[tuple[str, Any]]:
    """Yield ``(path, leaf_value)`` for every leaf under ``value``."""
    if _is_leaf(value):
        yield base, value
        return

    if isinstance(value, dict):
        for key in _enumeration_order(list(value.keys())):
            child_path = f"{base}.{key}" if base else key
            yield from walk_leaves(value[key], child_path)
        return

    for index, child in enumerate(value):
        yield from walk_leaves(child, f"{base}[{index}]")


def split_field(path: str) -> tuple[str, str]:
    """SPEC §9.4(b): split a commitment path into (field name, relative path).

    The split is at the *first* ``.`` or ``[``; a leading ``.`` is dropped from
    the remainder, a leading ``[`` is kept (it is an index, not a separator).
    """
    dot = path.find(".")
    bracket = path.find("[")
    candidates = [pos for pos in (dot, bracket) if pos != -1]
    if not candidates:
        return path, ""
    cut = min(candidates)
    field = path[:cut]
    remainder = path[cut:]
    if remainder.startswith("."):
        remainder = remainder[1:]
    return field, remainder


# A path segment is a (possibly empty) name followed by any number of
# ``[digits]`` groups.
_SEGMENT_RE = re.compile(r"^([^\[\]]*)((?:\[[0-9]+\])*)$")
_INDEX_RE = re.compile(r"\[([0-9]+)\]")


def tokenize(relative_path: str) -> list[str] | None:
    """Split a relative path into container keys, or ``None`` if unparseable.

    An empty name contributes no token. That has two consequences, both of
    which match the behaviour SPEC §12.5 documents:

    * ``"[0]"`` (a payload that is itself an array) tokenizes to ``["0"]``;
    * the empty relative path tokenizes to ``[]``, so read-back returns the
      field value itself -- "returns the parent", which is why a payload with
      an empty-string key fails verification on an honest record.
    """
    if relative_path == "":
        return []

    tokens: list[str] = []
    for part in relative_path.split("."):
        match = _SEGMENT_RE.match(part)
        if match is None:
            return None
        name, brackets = match.groups()
        if name:
            tokens.append(name)
        tokens.extend(_INDEX_RE.findall(brackets))
    return tokens


def read_path(container: Any, relative_path: str) -> Any:
    """Read ``relative_path`` inside ``container``; ``ABSENT`` if it does not resolve."""
    tokens = tokenize(relative_path)
    if tokens is None:
        return ABSENT

    current = container
    for token in tokens:
        if isinstance(current, dict):
            if token not in current:
                return ABSENT
            current = current[token]
        elif isinstance(current, (list, tuple)):
            if not token.isdigit():
                return ABSENT
            index = int(token)
            if index >= len(current):
                return ABSENT
            current = current[index]
        else:
            return ABSENT
    return current


def commitment_view(commitments: dict[str, str], field: str) -> dict[str, str]:
    """SPEC §5.2 step 1 -- the sub-map of commitments belonging to one field.

    A path belongs to ``field`` when it *is* the field name, or starts with
    ``field.`` or ``field[``.
    """
    prefix_dot = field + "."
    prefix_bracket = field + "["
    return {
        path: value
        for path, value in commitments.items()
        if path == field or path.startswith(prefix_dot) or path.startswith(prefix_bracket)
    }
