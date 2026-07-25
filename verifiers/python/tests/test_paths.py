"""Leaf paths, read-back, and the SPEC §12.5 ambiguity defects.

The corpus pins the *paths* these payloads produce (``AMBIGUOUS-*`` in
``02-commitments.json``) but not what happens when a verifier reads them back.
Read-back is where the defect actually bites, so it is pinned here.
"""

from __future__ import annotations

from traceglass_verify.paths import ABSENT, commitment_view, read_path, split_field, walk_leaves
from traceglass_verify.rules_v1 import RulesV1

SALT = "aa" * 16


def leaves(value, base="input"):
    return list(walk_leaves(value, base))


def honest_step(payload, field="input"):
    """Build the step an honest producer would write for this payload."""
    found = leaves(payload, field)
    return {
        "id": "s0",
        "index": 0,
        "type": "tool_call",
        "label": "t",
        "startedAt": "2026-01-01T00:00:00.000Z",
        "durationMs": 0,
        "tokens": 0,
        "cost": 0,
        "spanId": "a1",
        field: payload,
        "commitments": {p: RulesV1.commitment(SALT, v) for p, v in found},
        "salts": {p: SALT for p, _ in found},
    }


# --------------------------------------------------------------------------
# split_field -- SPEC §9.4(b)
# --------------------------------------------------------------------------

def test_split_field():
    assert split_field("input") == ("input", "")
    assert split_field("input.query") == ("input", "query")
    assert split_field("input.rows[0].id") == ("input", "rows[0].id")
    assert split_field("input[0]") == ("input", "[0]")
    assert split_field("input[0].a") == ("input", "[0].a")
    assert split_field("input.") == ("input", "")


def test_read_path_round_trips_every_honest_leaf():
    payload = {
        "query": "x",
        "rows": [{"id": 1}, {"id": 2}],
        "nested": {"deep": {"deeper": [[7]]}},
        "empties": {"obj": {}, "arr": []},
    }
    for path, expected in leaves(payload):
        field, relative = split_field(path)
        assert field == "input"
        assert read_path(payload, relative) == expected


def test_read_path_on_a_top_level_array_payload():
    payload = [{"a": 1}, "b"]
    for path, expected in leaves(payload):
        _, relative = split_field(path)
        assert read_path(payload, relative) == expected


def test_read_path_returns_absent_for_missing_keys_and_indices():
    assert read_path({"a": 1}, "b") is ABSENT
    assert read_path({"a": [1]}, "a[5]") is ABSENT
    assert read_path({"a": 1}, "a.b") is ABSENT  # cannot descend into a scalar
    assert read_path([1, 2], "x") is ABSENT


# --------------------------------------------------------------------------
# SPEC §12.5 -- the three ambiguous payloads, reproduced not fixed
# --------------------------------------------------------------------------

def test_dotted_key_collides_and_fails_on_an_honest_record():
    """``{"a.b":1}`` produces the same path as ``{"a":{"b":1}}``.

    This is the false-alarm case: nobody touched the record and it still
    reports as altered.
    """
    assert leaves({"a.b": 1}) == [("input.a.b", 1)]
    assert leaves({"a": {"b": 1}}) == [("input.a.b", 1)]

    _, _, mismatched = RulesV1.check_commitments(honest_step({"a.b": 1}))
    assert mismatched == ["input.a.b"]

    # The structurally nested payload -- same path -- verifies fine.
    _, _, mismatched = RulesV1.check_commitments(honest_step({"a": {"b": 1}}))
    assert mismatched == []


def test_empty_key_reads_back_the_parent_and_fails():
    """``{"":1}`` produces path ``input.``; read-back yields the parent object."""
    assert leaves({"": 1}) == [("input.", 1)]

    field, relative = split_field("input.")
    assert (field, relative) == ("input", "")
    assert read_path({"": 1}, relative) == {"": 1}  # the parent, not the 1

    _, _, mismatched = RulesV1.check_commitments(honest_step({"": 1}))
    assert mismatched == ["input."]


def test_bracket_key_also_fails_on_an_honest_record():
    """SPEC §12.5 lists only "indistinguishable" for ``{"a[0]":1}``.

    Read-back is broken for it too: the tokenizer splits ``a[0]`` into
    ``a`` then index ``0``, and the literal key ``"a[0]"`` is never found. So
    this payload is a false-alarm case as well, not merely an ambiguous one.
    """
    assert leaves({"a[0]": 1}) == [("input.a[0]", 1)]
    assert leaves({"a": [1]}) == [("input.a[0]", 1)]

    assert read_path({"a[0]": 1}, "a[0]") is ABSENT

    _, _, mismatched = RulesV1.check_commitments(honest_step({"a[0]": 1}))
    assert mismatched == ["input.a[0]"]

    _, _, mismatched = RulesV1.check_commitments(honest_step({"a": [1]}))
    assert mismatched == []


def test_leaf_visit_order_is_ecmascript_enumeration_order():
    """FINDINGS F3 -- SPEC §8.1 states no visit order, but the corpus asserts one.

    Verified against the shipped SDK: the payload below produces exactly this
    commitment key order. Numeric-looking keys come first, ascending; other
    keys keep insertion order. No hash depends on this -- the commitments map
    is canonicalized like any other object -- but the ``02 walk`` vectors
    compare an ordered list, so a second implementation has to match it.
    """
    payload = {"10": "a", "2": "b", "z": "c", "1": "d"}
    assert [p for p, _ in walk_leaves(payload, "input")] == [
        "input.1",
        "input.2",
        "input.10",
        "input.z",
    ]

    # The corpus's own numeric-key vector cannot discriminate: it is inserted
    # in numeric order already.
    assert [p for p, _ in walk_leaves({"0": "x", "1": "y"}, "input")] == [
        "input.0",
        "input.1",
    ]


def test_leaf_order_does_not_affect_the_step_hash():
    """The reason F3 is an interop wart and not a correctness bug."""
    forward = honest_step({"10": "a", "2": "b", "z": "c"})
    shuffled = dict(forward)
    shuffled["commitments"] = dict(reversed(list(forward["commitments"].items())))
    assert RulesV1.step_hash(forward, "") == RulesV1.step_hash(shuffled, "")


def test_plain_payloads_are_unaffected():
    for payload in (
        "hello",
        None,
        {"a": {"b": 1}},
        ["x", "y"],
        {"rows": [{"id": 1}], "ok": True},
        {"empties": {"obj": {}, "arr": []}},
        {"cost": 2.5e-05},
    ):
        _, _, mismatched = RulesV1.check_commitments(honest_step(payload))
        assert mismatched == [], payload


# --------------------------------------------------------------------------
# commitment views -- SPEC §5.2
# --------------------------------------------------------------------------

def test_commitment_view_prefix_matching():
    commitments = {
        "input": "1" * 64,
        "input.a": "2" * 64,
        "input[0]": "3" * 64,
        "inputX.a": "4" * 64,
        "output.b": "5" * 64,
    }
    view = commitment_view(commitments, "input")
    # "inputX.a" must NOT be captured -- it is a different field whose name
    # merely starts with "input".
    assert set(view) == {"input", "input.a", "input[0]"}
    assert set(commitment_view(commitments, "output")) == {"output.b"}
    assert commitment_view(commitments, "dataPayload") == {}


def test_partial_commitments_leave_the_other_field_hashed_raw():
    """SPEC §12.3 -- reproduced, and warned about by the verifier."""
    step = {
        "id": "s0",
        "index": 0,
        "input": {"a": 1},
        "output": {"b": 2},
        "commitments": {"input.a": RulesV1.commitment(SALT, 1)},
        "salts": {"input.a": SALT},
    }
    picked = RulesV1.picked_step(step)
    assert picked["input"] == {"input.a": RulesV1.commitment(SALT, 1)}
    assert picked["output"] == {"b": 2}  # raw, not substituted
