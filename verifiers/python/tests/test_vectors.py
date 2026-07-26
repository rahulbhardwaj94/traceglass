"""The frozen conformance corpus: all 132 checks from ``docs/test-vectors/``.

The check identifiers mirror ``check.mjs`` one-for-one, so a failure here can
be lined up against the reference verifier directly:

    01 canonical/<name>      47
    01 sha256/<name>         47
    02 walk/<name>           13
    02 commit/<name>         10
    03 canonicalStep/<run>#i  4
    03 hash/<run>#i           4
    05 signaturePayload        1
    05 keyId                   1
    09 verify/<run>            4
    08 redaction anchor        1
                            ----
                             132
"""

from __future__ import annotations

import hashlib
import json

import pytest
from conftest import VECTORS, load_vector_file

from traceglass_verify import Verdict, canonicalize, compute_key_id, verify_file
from traceglass_verify.paths import walk_leaves
from traceglass_verify.rules_v1 import RulesV1
from traceglass_verify.signature import CRYPTO_AVAILABLE
from traceglass_verify.verify import SignatureState

CANONICAL = load_vector_file("01-canonical.json")
COMMITMENTS = load_vector_file("02-commitments.json")
STEPS = load_vector_file("03-steps.json")
SIGNATURE = load_vector_file("05-signature.json")

RUN_FILES = ("minimal", "committed", "redacted", "signed")


def _run_document(name: str) -> dict:
    with open(VECTORS / "04-runs" / f"{name}.tgev.json", "r", encoding="utf-8") as handle:
        return json.load(handle)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# 01 -- canonicalization (47 vectors x 2 checks)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("vector", CANONICAL["vectors"], ids=lambda v: v["name"])
def test_01_canonical(vector):
    """`01 canonical/<name>` -- the canonical string, byte for byte."""
    value = json.loads(vector["inputJson"])
    assert canonicalize(value) == vector["canonical"], vector.get("note", "")


@pytest.mark.parametrize("vector", CANONICAL["vectors"], ids=lambda v: v["name"])
def test_01_sha256(vector):
    """`01 sha256/<name>` -- SHA-256 over the canonical form's UTF-8 bytes."""
    value = json.loads(vector["inputJson"])
    assert _sha256_hex(canonicalize(value)) == vector["sha256"]


def test_01_vector_count():
    assert len(CANONICAL["vectors"]) == 47
    assert CANONICAL["hashVersion"] == 1


# --------------------------------------------------------------------------
# 02 -- leaf walking (13) and commitments (10)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("vector", COMMITMENTS["walk"], ids=lambda v: v["name"])
def test_02_walk(vector):
    """`02 walk/<name>` -- leaf paths and their canonical forms, in order."""
    value = json.loads(vector["inputJson"])
    leaves = [
        {"path": path, "canonicalLeaf": canonicalize(leaf)}
        for path, leaf in walk_leaves(value, vector["field"])
    ]
    assert leaves == vector["leaves"], vector.get("note", "")


@pytest.mark.parametrize("vector", COMMITMENTS["commitments"], ids=lambda v: v["name"])
def test_02_commit(vector):
    """`02 commit/<name>` -- SHA256_hex(UTF8(salt_text || canonical(value)))."""
    value = json.loads(vector["valueJson"])
    assert canonicalize(value) == vector["canonicalValue"]
    # The preimage is published so a disagreement can be diffed byte by byte.
    assert vector["salt"] + canonicalize(value) == vector["preimage"]
    assert RulesV1.commitment(vector["salt"], value) == vector["commitment"]


# --------------------------------------------------------------------------
# 03 -- canonical step forms and chain hashes (5 steps x 2 checks)
# --------------------------------------------------------------------------

def _step_cases():
    cases = []
    for run_name, expectations in STEPS["runs"].items():
        steps = _run_document(run_name)["run"]["steps"]
        for i, expected in enumerate(expectations):
            cases.append(pytest.param(steps[i], expected, id=f"{run_name}#{i}"))
    return cases


@pytest.mark.parametrize("step,expected", _step_cases())
def test_03_canonical_step(step, expected):
    """`03 canonicalStep/<run>#<i>` -- the hashed field set after §5.2."""
    assert step["id"] == expected["id"]
    assert RulesV1.canonical_step(step) == expected["canonicalStep"]


@pytest.mark.parametrize("step,expected", _step_cases())
def test_03_hash(step, expected):
    """`03 hash/<run>#<i>` -- SHA256_hex(canonicalStep || prevHash)."""
    assert RulesV1.canonical_step(step) + expected["prevHash"] == expected["hashPreimage"]
    assert RulesV1.step_hash(step, expected["prevHash"]) == expected["hash"]


def test_03_step_count():
    """Every step vector in the corpus is actually exercised.

    The point of this guard is that a loader which silently skipped a run
    group would make the parametrized tests above pass vacuously. It is not to
    pin an exact number — the corpus grows as gaps are found (the unicode
    group was added to cover NFC vs NFD), so a hardcoded count turns a
    legitimate addition into a failure.
    """
    total = sum(len(v) for v in STEPS["runs"].values())
    assert total == len(_step_cases()), "a step vector is present but not exercised"
    assert all(len(v) > 0 for v in STEPS["runs"].values()), "empty run group in the corpus"
    assert total >= 4, "the corpus must never shrink"


# --------------------------------------------------------------------------
# 05 -- signature (2 checks)
# --------------------------------------------------------------------------

def test_05_signature_payload():
    """`05 signaturePayload` -- canonicalize({runId, runHash, signedAt})."""
    message = RulesV1.signed_message(
        SIGNATURE["runId"], SIGNATURE["runHash"], SIGNATURE["signedAt"]
    )
    assert message == SIGNATURE["signaturePayload"]


def test_05_key_id():
    """`05 keyId` -- first 16 hex chars of SHA256(SPKI DER)."""
    assert compute_key_id(SIGNATURE["publicKeyPem"]) == SIGNATURE["keyId"]


# --------------------------------------------------------------------------
# 09 -- full verification of the four envelopes (4 checks)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", RUN_FILES)
def test_09_verify(name):
    """`09 verify/<run>` -- SPEC §9, end to end, must produce no failure."""
    result = verify_file(str(VECTORS / "04-runs" / f"{name}.tgev.json"))
    assert result.verdict is Verdict.VALID, result.message
    assert result.exit_code == 0
    assert result.chain_ok
    assert result.recomputed_anchor == result.stored_anchor


# --------------------------------------------------------------------------
# 08 -- redaction preserves the anchor (1 check)
# --------------------------------------------------------------------------

def test_08_redaction_preserves_the_anchor():
    """`08 redaction preserves the anchor` -- the whole point of §8.5."""
    committed = _run_document("committed")["run"]
    redacted = _run_document("redacted")["run"]
    assert redacted["runHash"] == committed["runHash"]
    assert (
        committed["runHash"]
        == "63f138b78374b62e86ed13cd3d2492b46914db1b5c50553e0b4ae315c6da8766"
    )
    # ...and the payloads genuinely differ, so this is not a trivial equality.
    assert redacted["steps"][0]["input"]["query"] == "[traceglass:redacted]"
    assert committed["steps"][0]["input"]["query"] != "[traceglass:redacted]"


# --------------------------------------------------------------------------
# Reporting requirements that the corpus does not itself pin (SPEC §9.6)
# --------------------------------------------------------------------------

def test_signed_and_unsigned_are_not_collapsed():
    """SPEC §9.6: "unsigned" and "signed and valid" MUST NOT be the same output."""
    unsigned = verify_file(str(VECTORS / "04-runs" / "minimal.tgev.json"))
    signed = verify_file(str(VECTORS / "04-runs" / "signed.tgev.json"))

    assert unsigned.signature_state is SignatureState.ABSENT
    expected = SignatureState.VALID if CRYPTO_AVAILABLE else SignatureState.UNCHECKED
    assert signed.signature_state is expected
    assert unsigned.message != signed.message


@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography not installed")
def test_valid_signature_is_not_reported_as_proof_of_origin():
    """SPEC §11.1 -- the honest sentence, not "signed by the agent"."""
    result = verify_file(str(VECTORS / "04-runs" / "signed.tgev.json"))
    assert result.signature_key_id == SIGNATURE["keyId"]
    assert "self-attested" in result.message
    assert "does NOT establish who that key belongs to" in result.message


def test_redacted_leaf_is_reported_as_redacted_not_verified():
    result = verify_file(str(VECTORS / "04-runs" / "redacted.tgev.json"))
    assert result.commitments_redacted == ["input.query"]
    assert len(result.commitments_verified) == 13
    assert result.commitments_mismatched == []


def test_committed_run_has_no_redactions():
    result = verify_file(str(VECTORS / "04-runs" / "committed.tgev.json"))
    assert result.commitments_redacted == []
    assert len(result.commitments_verified) == 14
