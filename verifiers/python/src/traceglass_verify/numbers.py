"""ECMAScript ``Number::toString`` (radix 10), implemented from SPEC.md §4.4.

Why this file exists at all
---------------------------
``tgcanon/1`` pins number encoding to ECMA-262 §6.1.6.1.20. Python's own JSON
writer does **not** implement that algorithm, and diverges for every non-zero
magnitude below ``1e-4`` -- which is precisely where per-token AI costs live::

    value       ECMAScript      Python json.dumps
    0.00001     0.00001         1e-05
    0.000025    0.000025        2.5e-05          <- a real per-token cost
    1e-7        1e-7            1e-07            <- zero-padded exponent

Using ``json.dumps`` here would make an untouched record fail verification.
A false integrity alarm is the worst failure mode this product has, so the
algorithm is spelled out below rather than delegated.

What *is* borrowed from Python
------------------------------
Only the digit generation. ``repr(float)`` yields the shortest decimal string
that round-trips to the same binary64 value (CPython uses David Gay's
correctly-rounded shortest-repr since 3.1), which is the same quantity
ECMA-262 calls "the smallest k such that ... s x 10^(n-k) = m". The *layout*
of those digits -- fixed vs exponential, exponent padding, sign -- is the part
Python gets wrong, and that is what this module reimplements.
"""

from __future__ import annotations

import math

__all__ = ["ecma_number_to_string", "to_binary64", "shortest_digits"]


def to_binary64(value: object) -> float:
    """Coerce a parsed JSON number to binary64.

    SPEC §4.4.1: "A conforming implementation MUST parse every JSON number as a
    binary64 double before encoding it." Python's ``json`` module parses
    integers into arbitrary-precision ``int``, so ``9007199254740993`` would
    survive exactly and encode differently from the reference implementation
    (which sees ``9007199254740992``). Force the narrowing here.
    """
    if isinstance(value, float):
        return value
    try:
        return float(value)  # type: ignore[arg-type]
    except OverflowError:
        # An integer literal too large for binary64 becomes an infinity, which
        # SPEC §4.4.4 then encodes as the literal ``null``.
        return math.inf if value > 0 else -math.inf  # type: ignore[operator]


def shortest_digits(x: float) -> tuple[str, int]:
    """Decompose a positive finite float into ``(digits, n)``.

    The value equals ``0.<digits> x 10**n`` with no leading or trailing zero in
    ``digits``. This is ECMA-262's ``s`` (as a digit string of length ``k``)
    and ``n``.
    """
    text = repr(x)

    if "e" in text or "E" in text:
        mantissa, _, exp_text = text.partition("e" if "e" in text else "E")
        exp = int(exp_text)
    else:
        mantissa, exp = text, 0

    int_part, _, frac_part = mantissa.partition(".")
    raw = int_part + frac_part
    # Decimal point sits after ``len(int_part)`` digits of ``raw``, then the
    # literal exponent shifts it.
    n = len(int_part) + exp

    stripped = raw.lstrip("0")
    n -= len(raw) - len(stripped)
    digits = stripped.rstrip("0")

    if not digits:  # pragma: no cover - callers exclude zero
        raise ValueError("shortest_digits() is not defined for zero")

    return digits, n


def ecma_number_to_string(x: float) -> str:
    """Encode a binary64 the way ECMAScript's ``String(number)`` does.

    Non-finite values are *not* handled here; SPEC §4.4.4 makes them the
    literal ``null``, which is a canonicalizer concern, not a number concern.
    """
    if math.isnan(x) or math.isinf(x):
        raise ValueError("non-finite values have no numeric encoding (SPEC §4.4.4)")

    # SPEC §4.4.3: negative zero loses its sign. ``x == 0`` is true for -0.0.
    if x == 0:
        return "0"

    if x < 0:
        return "-" + ecma_number_to_string(-x)

    digits, n = shortest_digits(x)
    k = len(digits)

    # The four rows of SPEC §4.4.1, in order; the first match wins.
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits

    # Exponential. The exponent carries an explicit sign and NO leading zeros:
    # "1e-7", never "1e-07".
    exponent = n - 1
    sign = "+" if exponent >= 0 else "-"
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{sign}{abs(exponent)}"
