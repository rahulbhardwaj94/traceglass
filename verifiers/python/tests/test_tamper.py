"""Negative tests: every failure the algorithm is supposed to catch, and the
non-failures it is supposed to leave alone.

A verifier that only ever says "valid" passes the conformance corpus. These are
the tests that stop that.
"""

from __future__ import annotations

import copy
import json

import pytest
from conftest import VECTORS

from traceglass_verify import ParseError, UnsupportedVersionError, Verdict, verify_document
from traceglass_verify.signature import CRYPTO_AVAILABLE
from traceglass_verify.verify import FailureStep, SignatureState


def load(name: str) -> dict:
    with open(VECTORS / "04-runs" / f"{name}.tgev.json", "r", encoding="utf-8") as handle:
        return json.load(handle)


# --------------------------------------------------------------------------
# 9.2 -- the chain
# --------------------------------------------------------------------------

def test_edited_payload_without_commitments_breaks_the_step_hash():
    doc = load("minimal")
    doc["run"]["steps"][0]["input"] = "Summarise Q4 spend"
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.STEP_CONTENT
    assert result.failed_step_index == 0
    assert result.failed_step_id == "vec-min:0"


def test_edited_cost_breaks_the_step_hash():
    doc = load("minimal")
    doc["run"]["steps"][1]["cost"] = 4.8
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.STEP_CONTENT
    assert result.failed_step_index == 1


def test_a_micro_cost_edit_is_caught_and_a_micro_cost_alone_is_not_a_failure():
    """The number-formatting trap, both directions.

    An untouched record whose costs live in the 0 < |v| < 1e-4 band must PASS
    (a naive Python verifier fails it), and an edit inside that band must FAIL.
    """
    doc = load("committed")
    assert verify_document(doc).verdict is Verdict.VALID  # cost = 2.5e-05

    tampered = load("committed")
    tampered["run"]["steps"][0]["cost"] = 2.6e-05
    result = verify_document(tampered)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.STEP_CONTENT


def test_deleted_step_breaks_linkage_not_content():
    doc = load("minimal")
    del doc["run"]["steps"][0]
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.CHAIN_LINKAGE
    assert result.failed_step_id == "vec-min:1"


def test_reordered_steps_break_linkage():
    doc = load("minimal")
    doc["run"]["steps"].reverse()
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.CHAIN_LINKAGE


def test_step_lifted_from_another_run_still_verifies():
    """SPEC §12.2 -- runId is outside the step hash. Bug-compatible on purpose."""
    doc = load("minimal")
    doc["run"]["steps"][0]["runId"] = "some-other-run"
    assert verify_document(doc).verdict is Verdict.VALID


def test_unknown_step_member_is_ignored():
    """SPEC §3.2 / §5.1 -- unknown members must not be hashed or rejected."""
    doc = load("minimal")
    doc["run"]["steps"][0]["somethingNew"] = {"a": 1}
    assert verify_document(doc).verdict is Verdict.VALID


def test_unrecognised_step_type_is_not_an_integrity_failure():
    """SPEC §3.4 -- but it IS hashed, so the recorded hash must move with it."""
    doc = load("minimal")
    step = doc["run"]["steps"][0]
    from traceglass_verify.rules_v1 import RulesV1

    step["type"] = "some_future_type"
    step["hash"] = RulesV1.step_hash(step, "")
    doc["run"]["steps"][1]["prevHash"] = step["hash"]
    doc["run"]["steps"][1]["hash"] = RulesV1.step_hash(doc["run"]["steps"][1], step["hash"])
    doc["run"]["runHash"] = doc["run"]["steps"][1]["hash"]
    assert verify_document(doc).verdict is Verdict.VALID


# --------------------------------------------------------------------------
# 9.3 -- the anchor
# --------------------------------------------------------------------------

def test_edited_anchor_is_caught():
    doc = load("minimal")
    doc["run"]["runHash"] = "0" * 64
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.ANCHOR
    assert result.recomputed_anchor != result.stored_anchor


def test_empty_run_verifies_but_warns():
    """SPEC §6.1 / §12.10."""
    doc = load("minimal")
    doc["run"]["steps"] = []
    doc["run"]["runHash"] = ""
    result = verify_document(doc)
    assert result.verdict is Verdict.VALID
    assert any("asserts nothing" in w for w in result.warnings)


# --------------------------------------------------------------------------
# 9.4 -- commitments. This is where a chain-only verifier goes blind.
# --------------------------------------------------------------------------

def test_rewritten_committed_payload_leaves_the_chain_intact_but_fails_9_4():
    """The load-bearing case from SPEC §9.4's callout.

    Once a step carries commitments, the raw payload no longer affects the step
    hash at all. A verifier that stops after 9.2/9.3 accepts this document.
    """
    doc = load("committed")
    doc["run"]["steps"][0]["input"]["query"] = "SELECT * FROM payments WHERE id = 99"

    from traceglass_verify.rules_v1 import RulesV1

    step = doc["run"]["steps"][0]
    assert RulesV1.step_hash(step, "") == step["hash"], "chain must be unaffected"

    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.COMMITMENTS
    assert result.commitments_mismatched == ["input.query"]
    assert result.failed_step_id == "vec-cm:0"


def test_flipping_a_committed_boolean_is_caught():
    doc = load("committed")
    doc["run"]["steps"][0]["output"]["ok"] = False
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.commitments_mismatched == ["output.ok"]


def test_swapping_an_empty_container_for_a_full_one_is_caught():
    """SPEC §8.1 -- emptiness is committed to on purpose."""
    doc = load("committed")
    doc["run"]["steps"][0]["input"]["empties"]["arr"] = [1, 2, 3]
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.commitments_mismatched == ["input.empties.arr"]


def test_nfc_and_nfd_are_distinct_committed_values():
    """SPEC 4.2.4 -- no Unicode normalization, ever.

    Note the corpus does NOT cover this at the envelope level: in
    ``committed.tgev.json`` the leaf named ``input.unicode.nfd`` holds the
    *NFC* string (see FINDINGS.md F1), so both unicode leaves are byte
    identical. The rule is exercised here instead by substituting the genuine
    decomposed form, which must break the commitment.
    """
    import unicodedata

    doc = load("committed")
    unicode_block = doc["run"]["steps"][0]["input"]["unicode"]
    recorded = unicode_block["nfd"]

    # F1: the leaf called "nfd" is in fact NFC, and equal to the "nfc" leaf.
    assert unicodedata.is_normalized("NFC", recorded)
    assert unicode_block["nfc"] == recorded

    decomposed = unicodedata.normalize("NFD", recorded)
    assert decomposed != recorded  # canonically equivalent, different bytes

    unicode_block["nfd"] = decomposed
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.commitments_mismatched == ["input.unicode.nfd"]


def test_deleting_a_committed_leaf_is_caught():
    doc = load("committed")
    del doc["run"]["steps"][0]["input"]["query"]
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.commitments_mismatched == ["input.query"]


def test_adding_a_commitment_entry_breaks_the_chain():
    """SPEC §5.2 -- the view's KEYS are hashed, so the committed path set is sealed."""
    doc = load("committed")
    doc["run"]["steps"][0]["commitments"]["input.newLeaf"] = "ab" * 32
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.STEP_CONTENT


def test_silent_erasure_is_indistinguishable_from_an_authorised_redaction():
    """SPEC §8.6 -- documented, verified, and NOT something this verifier can fix.

    Deleting a value and its salt produces a clean verdict with no
    ``redactions`` entry. The verifier's honest output is "redacted", because
    that is genuinely all the format records.
    """
    doc = load("committed")
    doc["run"]["steps"][0]["input"]["query"] = "[traceglass:redacted]"
    del doc["run"]["steps"][0]["salts"]["input.query"]
    result = verify_document(doc)
    assert result.verdict is Verdict.VALID
    assert result.commitments_redacted == ["input.query"]


def test_run_metadata_is_not_covered_by_anything():
    """SPEC §6.2 -- currency can be flipped on a signed record. Known hole."""
    doc = load("signed")
    doc["run"]["currency"] = "USD"
    doc["run"]["status"] = "failed"
    doc["run"]["totals"]["cost"] = 999999
    result = verify_document(doc)
    assert result.verdict is Verdict.VALID


# --------------------------------------------------------------------------
# 9.5 -- signature
# --------------------------------------------------------------------------

@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography not installed")
def test_flipped_signature_byte_is_caught():
    doc = load("signed")
    original = doc["run"]["signature"]["signature"]
    doc["run"]["signature"]["signature"] = ("B" if original[0] != "B" else "C") + original[1:]
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.SIGNATURE
    assert result.signature_state is SignatureState.INVALID


@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography not installed")
def test_signature_does_not_transplant_between_runs():
    """SPEC §7.1 -- runId is inside the signed message."""
    doc = load("signed")
    other = load("minimal")
    other["run"]["signature"] = copy.deepcopy(doc["run"]["signature"])
    other["run"]["id"] = "vec-min-clone"
    for step in other["run"]["steps"]:
        step["runId"] = "vec-min-clone"
    result = verify_document(other)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.SIGNATURE


@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography not installed")
def test_edited_signed_at_is_caught():
    doc = load("signed")
    doc["run"]["signature"]["signedAt"] = "2026-07-25T09:00:12.000Z"
    assert verify_document(doc).verdict is Verdict.INVALID


def test_wrong_algorithm_is_rejected():
    """SPEC §7.2 / §12.7 -- the reference implementation never reads this field."""
    doc = load("signed")
    doc["run"]["signature"]["algorithm"] = "rsa"
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.SIGNATURE
    assert "ed25519" in result.message


def test_key_id_mismatch_is_rejected():
    """SPEC §7.3 / §12.8 -- a pure tightening the reference does not do."""
    doc = load("signed")
    doc["run"]["signature"]["keyId"] = "deadbeefdeadbeef"
    result = verify_document(doc)
    assert result.verdict is Verdict.INVALID
    assert result.failure_step is FailureStep.SIGNATURE
    assert "29e0d3e8fb7ac052" in result.message


def test_absent_signature_is_not_a_failure():
    """SPEC §7.4."""
    result = verify_document(load("minimal"))
    assert result.verdict is Verdict.VALID
    assert result.signature_state is SignatureState.ABSENT
    assert "no authenticity claim" in result.message


# --------------------------------------------------------------------------
# 9.1 -- parse and version gating. NOT integrity failures.
# --------------------------------------------------------------------------

def test_bare_run_is_accepted():
    """SPEC §3, §10.2 -- no formatVersion means a bare Run, assumed v1."""
    run = load("minimal")["run"]
    result = verify_document(run)
    assert result.verdict is Verdict.VALID
    assert result.format_version is None
    assert result.hash_version == 1


def test_future_format_version_is_rejected_without_attempting_verification():
    doc = load("minimal")
    doc["formatVersion"] = 2
    with pytest.raises(UnsupportedVersionError) as excinfo:
        verify_document(doc)
    assert "2" in str(excinfo.value) and "1" in str(excinfo.value)


def test_future_hash_version_is_rejected():
    """The seam for tgcanon/2: an unknown ruleset must refuse, not guess."""
    doc = load("minimal")
    doc["run"]["hashVersion"] = 2
    with pytest.raises(UnsupportedVersionError):
        verify_document(doc)


def test_malformed_document_is_a_parse_error_not_a_tamper_verdict():
    with pytest.raises(ParseError):
        verify_document({"formatVersion": 1, "run": {"id": "x"}})
    with pytest.raises(ParseError):
        verify_document(["not", "a", "record"])
    with pytest.raises(ParseError):
        verify_document({"formatVersion": 1})


def test_unknown_top_level_member_is_ignored():
    doc = load("minimal")
    doc["run"]["somethingFromTheFuture"] = [1, 2, 3]
    assert verify_document(doc).verdict is Verdict.VALID
