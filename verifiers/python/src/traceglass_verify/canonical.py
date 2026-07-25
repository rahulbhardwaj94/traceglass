"""``tgcanon/1`` -- the canonical JSON encoding, from SPEC.md §4.

Three things here are easy to get wrong and are the usual cause of a
cross-language verifier disagreeing:

1. **Key order is two buckets** (§4.2.1). Array-index keys come first in
   *numeric* order; everything else follows in UTF-16 code-unit order. This is
   not RFC 8785 (JCS) -- a JCS library sorts ``{"10":1,"2":2}`` the wrong way.
2. **Ordering and escaping are per UTF-16 code unit** (§4.2.3, §4.3), not per
   code point. Python strings are sequences of code points, so an astral
   character has to be expanded into a surrogate pair before comparison.
3. **Numbers** -- see ``numbers.py``.
"""

from __future__ import annotations

import math
import re
from typing import Any

from .numbers import ecma_number_to_string, to_binary64

__all__ = ["canonicalize", "canonical_bytes", "TgCanonError", "is_array_index_key"]


class TgCanonError(ValueError):
    """A value outside the JSON value space was handed to the canonicalizer."""


# SPEC §4.2.1: an array-index key is the canonical decimal form of an integer
# n with 0 <= n <= 2**32 - 2. Note "01", "-1", "1.5", "1e2" are excluded, and
# so is 4294967295 (= 2**32 - 1).
_ARRAY_INDEX_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_MAX_ARRAY_INDEX = 4294967294

_TWO_CHAR_ESCAPES = {
    0x22: '\\"',
    0x5C: "\\\\",
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def is_array_index_key(key: str) -> bool:
    if not _ARRAY_INDEX_RE.match(key):
        return False
    # A 10+ digit run of digits can still exceed the bound; compare as int.
    return int(key) <= _MAX_ARRAY_INDEX


def _utf16_units(text: str) -> list[int]:
    """Expand a Python string into its UTF-16 code units.

    Characters above the BMP become the surrogate pair that JavaScript would
    have stored them as. Lone surrogates that survived JSON parsing (Python
    keeps them; see ``unicode-lone-surrogate``) pass through unchanged.
    """
    units: list[int] = []
    for char in text:
        cp = ord(char)
        if cp > 0xFFFF:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
        else:
            units.append(cp)
    return units


def _utf16_sort_key(text: str) -> bytes:
    """A byte string that sorts identically to the UTF-16 code-unit order.

    Big-endian UTF-16 makes each code unit two bytes, most significant first,
    so lexicographic byte comparison *is* code-unit comparison -- including the
    "shorter prefix sorts first" rule. ``surrogatepass`` keeps lone surrogates
    encodable.
    """
    return text.encode("utf-16-be", "surrogatepass")


def _encode_string(text: str) -> str:
    """SPEC §4.3. Escapes are applied per UTF-16 code unit, in priority order."""
    units = _utf16_units(text)
    out: list[str] = ['"']
    i = 0
    length = len(units)

    while i < length:
        unit = units[i]

        escape = _TWO_CHAR_ESCAPES.get(unit)
        if escape is not None:
            out.append(escape)
        elif unit < 0x20:
            out.append(f"\\u{unit:04x}")
        elif 0xD800 <= unit <= 0xDBFF:
            # A lead surrogate followed by a trail is a well-formed pair and is
            # emitted raw; anything else is an unpaired surrogate and escapes.
            if i + 1 < length and 0xDC00 <= units[i + 1] <= 0xDFFF:
                cp = 0x10000 + ((unit - 0xD800) << 10) + (units[i + 1] - 0xDC00)
                out.append(chr(cp))
                i += 2
                continue
            out.append(f"\\u{unit:04x}")
        elif 0xDC00 <= unit <= 0xDFFF:
            out.append(f"\\u{unit:04x}")
        else:
            # Deliberately NOT escaped: "/", U+007F (DEL), U+2028, U+2029, and
            # non-ASCII generally. See SPEC §4.3.
            out.append(chr(unit))

        i += 1

    out.append('"')
    return "".join(out)


def _sorted_keys(keys: list[str]) -> list[str]:
    """SPEC §4.2.1 -- array-index keys numerically, then the rest by UTF-16."""
    indices: list[str] = []
    others: list[str] = []
    for key in keys:
        (indices if is_array_index_key(key) else others).append(key)
    indices.sort(key=int)
    others.sort(key=_utf16_sort_key)
    return indices + others


def canonicalize(value: Any) -> str:
    """Return the ``tgcanon/1`` canonical form of a parsed JSON value."""
    # bool must be tested before int: in Python ``True`` is an ``int``.
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (int, float)):
        number = to_binary64(value)
        # SPEC §4.4.4: NaN and the infinities encode as the literal null.
        if math.isnan(number) or math.isinf(number):
            return "null"
        return ecma_number_to_string(number)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = list(value.keys())
        for key in keys:
            if not isinstance(key, str):
                raise TgCanonError(f"object keys must be strings, got {type(key).__name__}")
        parts = [_encode_string(k) + ":" + canonicalize(value[k]) for k in _sorted_keys(keys)]
        return "{" + ",".join(parts) + "}"

    # SPEC §12.4 proposes throwing here rather than JavaScript's silent string
    # coercion of ``undefined``. We throw.
    raise TgCanonError(f"value of type {type(value).__name__} is outside the JSON value space")


def canonical_bytes(value: Any) -> bytes:
    """The canonical form as the UTF-8 octets that actually get hashed (§2)."""
    return canonicalize(value).encode("utf-8")
