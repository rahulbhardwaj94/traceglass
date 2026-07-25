"""Number encoding -- the single most likely source of a false tamper verdict.

The 47 canonicalization vectors cover 20 numbers. That is enough to catch a
verifier that reached for ``json.dumps``, but not enough to trust the
formatter across the whole binary64 range. So this file adds two things:

* ``tests/data/ecma_numbers.json`` -- 428 frozen ``(bit pattern -> string)``
  pairs taken straight from V8, covering every branch of the SPEC §4.4.1 table
  and its boundaries. These run offline; no Node required.
* structural tests for the four formatting rows and the documented divergences
  from Python's own JSON writer.

Provenance: the frozen table is a sample of a differential run of 49,525
doubles (random bit patterns plus targeted magnitudes) against
``String(value)`` in Node, which found zero mismatches.
"""

from __future__ import annotations

import json
import math
import struct
from pathlib import Path

import pytest

from traceglass_verify.canonical import canonicalize
from traceglass_verify.numbers import ecma_number_to_string, to_binary64

DATA = json.loads((Path(__file__).parent / "data" / "ecma_numbers.json").read_text())
CASES = sorted(DATA["cases"].items())


def _double(bits_hex: str) -> float:
    return struct.unpack("<d", bytes.fromhex(bits_hex))[0]


@pytest.mark.parametrize("bits,expected", CASES, ids=[c[1] for c in CASES])
def test_matches_v8(bits, expected):
    assert ecma_number_to_string(_double(bits)) == expected


def test_frozen_table_is_not_trivially_small():
    assert len(CASES) >= 400


# --------------------------------------------------------------------------
# The four rows of SPEC §4.4.1
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        # Row 1: k <= n <= 21 -- integer digits then zeros, no fraction.
        (100.0, "100"),
        (1e20, "100000000000000000000"),
        (0.0, "0"),
        # Row 2: 0 < n <= 21 -- decimal point inserted.
        (4.7, "4.7"),
        (0.30000000000000004, "0.30000000000000004"),
        # Row 3: -6 < n <= 0 -- leading "0." then zeros.
        (0.0001, "0.0001"),
        (0.00001, "0.00001"),
        (0.000001, "0.000001"),
        (0.000025, "0.000025"),
        # Row 4: exponential.
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (5e-324, "5e-324"),
        (1.5e-7, "1.5e-7"),
    ],
)
def test_formatting_rows(value, expected):
    assert ecma_number_to_string(value) == expected


def test_exponent_has_a_sign_and_no_leading_zeros():
    """SPEC §4.4.1 -- "1e-7", never "1e-07", never "1e-007"."""
    for value in (1e-7, 1e-8, 1e-9, 1e21, 1e22, 1e100):
        text = ecma_number_to_string(value)
        exponent = text.split("e")[1]
        assert exponent[0] in "+-"
        assert not exponent[1:].startswith("0")


def test_the_divergence_band_against_pythons_own_json_writer():
    """SPEC §4.4.2. These are the values a naive port gets wrong.

    Each of these is a plausible per-token cost; a record containing one would
    be rejected as tampered by a verifier that used ``json.dumps``.
    """
    divergent = {
        0.00001: ("0.00001", "1e-05"),
        0.000025: ("0.000025", "2.5e-05"),
        0.000001: ("0.000001", "1e-06"),
        1e-7: ("1e-7", "1e-07"),
    }
    for value, (ecma, python) in divergent.items():
        assert json.dumps(value) == python, "Python's writer changed; re-read SPEC §4.4.2"
        assert ecma_number_to_string(value) == ecma
        assert ecma_number_to_string(value) != json.dumps(value)


def test_where_python_happens_to_agree():
    """The other half of SPEC §4.4.2 -- agreement is coincidence, not design."""
    for value in (0.30000000000000004, 4.7, 0.0001, 1e21, 5e-324):
        assert ecma_number_to_string(value) == json.dumps(value)
    # ...except for integral values, where Python insists on a ".0".
    assert json.dumps(100.0) == "100.0"
    assert ecma_number_to_string(100.0) == "100"


# --------------------------------------------------------------------------
# binary64 narrowing (SPEC §4.4.1 last bullet)
# --------------------------------------------------------------------------

def test_integers_are_narrowed_to_binary64_before_encoding():
    """An arbitrary-precision verifier gets a different hash here."""
    assert canonicalize(9007199254740993) == "9007199254740992"
    assert canonicalize(123456789012345678901234567890) == "1.2345678901234568e+29"


def test_no_trailing_dot_zero_anywhere():
    for value in (100.0, 1.0, 0.0, 1e20, float(2**53)):
        assert "." not in ecma_number_to_string(value)


def test_negative_zero_loses_its_sign():
    """SPEC §4.4.3."""
    assert ecma_number_to_string(-0.0) == "0"
    assert canonicalize(-0.0) == "0"
    assert math.copysign(1, -0.0) == -1  # it really is negative zero


def test_non_finite_values_become_the_literal_null():
    """SPEC §4.4.4 -- silently, which is itself the hazard."""
    assert canonicalize(float("nan")) == "null"
    assert canonicalize(float("inf")) == "null"
    assert canonicalize(float("-inf")) == "null"
    with pytest.raises(ValueError):
        ecma_number_to_string(float("nan"))


def test_integer_literal_too_large_for_binary64_overflows_to_null():
    assert math.isinf(to_binary64(10**400))
    assert canonicalize(10**400) == "null"


def test_booleans_are_not_numbers():
    """In Python ``True`` is an ``int``; encoding it as 1 would be a real bug."""
    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"
    assert canonicalize([True, 1, False, 0]) == "[true,1,false,0]"
