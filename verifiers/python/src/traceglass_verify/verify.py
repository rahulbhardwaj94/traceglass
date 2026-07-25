"""The verification algorithm -- SPEC.md §9.

The steps run in the order the spec gives them, and the first failure stops
the run and names where it happened.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .paths import ABSENT
from .signature import CRYPTO_AVAILABLE, SignatureError, compute_key_id, verify_ed25519
from .versions import (
    SUPPORTED_FORMAT_VERSIONS,
    UnsupportedVersionError,
    resolve_hash_version,
    rules_for,
)

__all__ = [
    "Verdict",
    "SignatureState",
    "FailureStep",
    "VerifyResult",
    "ParseError",
    "verify_document",
    "verify_json_text",
    "verify_file",
]

_HEX64 = 64


class ParseError(Exception):
    """The document is not a well-formed record.

    SPEC §9.1: a shape failure is a parse error, not an integrity failure, and
    MUST be reported differently. Conflating the two would let a corrupted
    download read as "tampered evidence".
    """


class Verdict(str, Enum):
    VALID = "valid"
    INVALID = "invalid"


class FailureStep(str, Enum):
    """Which numbered step of SPEC §9 rejected the record."""

    VERSION = "9.1 version"
    CHAIN_LINKAGE = "9.2a chain linkage"
    STEP_CONTENT = "9.2c step content"
    ANCHOR = "9.3 anchor"
    COMMITMENTS = "9.4 commitments"
    SIGNATURE = "9.5 signature"


class SignatureState(str, Enum):
    ABSENT = "absent"
    VALID = "valid"
    INVALID = "invalid"
    UNCHECKED = "unchecked"  # no crypto library available


@dataclass
class VerifyResult:
    verdict: Verdict
    message: str
    failure_step: FailureStep | None = None
    failed_step_index: int | None = None
    failed_step_id: str | None = None

    hash_version: int = 1
    format_version: int | None = None

    run_id: str = ""
    stored_anchor: str = ""
    recomputed_anchor: str = ""
    chain_ok: bool = False
    step_count: int = 0

    commitments_verified: list[str] = field(default_factory=list)
    commitments_redacted: list[str] = field(default_factory=list)
    commitments_mismatched: list[str] = field(default_factory=list)

    signature_state: SignatureState = SignatureState.ABSENT
    signature_key_id: str | None = None
    signature_message: str = ""

    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.VALID

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "message": self.message,
            "failureStep": self.failure_step.value if self.failure_step else None,
            "failedStepIndex": self.failed_step_index,
            "failedStepId": self.failed_step_id,
            "hashVersion": self.hash_version,
            "formatVersion": self.format_version,
            "runId": self.run_id,
            "storedAnchor": self.stored_anchor,
            "recomputedAnchor": self.recomputed_anchor,
            "chainIntact": self.chain_ok,
            "stepCount": self.step_count,
            "commitments": {
                "verified": self.commitments_verified,
                "redacted": self.commitments_redacted,
                "mismatched": self.commitments_mismatched,
            },
            "signature": {
                "state": self.signature_state.value,
                "keyId": self.signature_key_id,
                "signedMessage": self.signature_message,
            },
            "warnings": self.warnings,
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ParseError(message)


def _extract_run(document: Any) -> tuple[dict[str, Any], int | None]:
    """SPEC §9.1 -- envelope or bare Run, plus the envelope's formatVersion."""
    _require(isinstance(document, dict), "the document is not a JSON object")

    # "A document is treated as an envelope iff it is an object containing the
    # key formatVersion." Note: the *presence* of the key decides, so a
    # malformed formatVersion is a version failure, not a bare-Run fallback.
    if "formatVersion" not in document:
        return document, None

    raw_version = document["formatVersion"]
    _require(
        not isinstance(raw_version, bool) and isinstance(raw_version, (int, float)),
        f"envelope formatVersion must be an integer, got {raw_version!r}",
    )
    version = int(raw_version)
    if version not in SUPPORTED_FORMAT_VERSIONS:
        supported = ", ".join(str(v) for v in sorted(SUPPORTED_FORMAT_VERSIONS))
        raise UnsupportedVersionError(
            f"this evidence file declares formatVersion {version}; "
            f"this verifier supports {supported}"
        )

    _require("run" in document, "envelope has no 'run' member")
    run = document["run"]
    _require(isinstance(run, dict), "envelope 'run' is not an object")
    return run, version


def _validate_shape(run: dict[str, Any]) -> None:
    """A deliberately shallow shape check (SPEC §3.2, §3.3).

    Only what the verification algorithm actually needs is enforced. Unknown
    members MUST NOT be an error (SPEC §3.2) and unrecognised step types MUST
    NOT be rejected on integrity grounds (SPEC §3.4).
    """
    _require(isinstance(run.get("id"), str) and run["id"] != "", "run.id must be a non-empty string")
    _require("runHash" in run, "run has no runHash")
    _require(isinstance(run["runHash"], str), "run.runHash must be a string")
    _require(isinstance(run.get("steps"), list), "run.steps must be an array")

    for position, step in enumerate(run["steps"]):
        where = f"steps[{position}]"
        _require(isinstance(step, dict), f"{where} is not an object")
        _require(
            isinstance(step.get("id"), str) and step["id"] != "",
            f"{where}.id must be a non-empty string",
        )
        for name in ("hash", "prevHash"):
            _require(isinstance(step.get(name), str), f"{where}.{name} must be a string")
        _require(
            len(step["hash"]) == _HEX64,
            f"{where}.hash must be 64 hex characters",
        )
        for name in ("commitments", "salts"):
            if name in step and step[name] is not None:
                _require(isinstance(step[name], dict), f"{where}.{name} must be an object")


def verify_document(document: Any) -> VerifyResult:
    """Run SPEC §9 against an already-parsed document."""
    run, format_version = _extract_run(document)
    _validate_shape(run)

    hash_version = resolve_hash_version(run)
    rules = rules_for(hash_version)

    steps: list[dict[str, Any]] = run["steps"]
    result = VerifyResult(
        verdict=Verdict.INVALID,
        message="",
        hash_version=hash_version,
        format_version=format_version,
        run_id=run["id"],
        stored_anchor=run["runHash"],
        step_count=len(steps),
    )

    if not steps:
        # SPEC §6.1 / §12.10: an empty run verifies but asserts nothing.
        result.warnings.append(
            "this run has zero steps: it verifies, but it asserts nothing about any agent activity"
        )

    # ---- 9.2 Recompute the chain -------------------------------------------
    prev = ""
    for step in steps:
        index = step.get("index")
        step_index = int(index) if isinstance(index, (int, float)) and not isinstance(index, bool) else None

        if step["prevHash"] != prev:
            result.recomputed_anchor = prev
            result.failure_step = FailureStep.CHAIN_LINKAGE
            result.failed_step_index = step_index
            result.failed_step_id = step["id"]
            result.message = (
                f"Integrity check FAILED: chain linkage broken at step #{step_index} "
                f"({step['id']}). Its prevHash does not point at the previous step, so a "
                "step was inserted, removed or reordered. Everything before this step is intact."
            )
            return result

        expected = rules.step_hash(step, prev)
        if step["hash"] != expected:
            result.recomputed_anchor = prev
            result.failure_step = FailureStep.STEP_CONTENT
            result.failed_step_index = step_index
            result.failed_step_id = step["id"]
            result.message = (
                f"Integrity check FAILED: step #{step_index} ({step['id']}) was altered "
                f"after recording. Recorded hash {step['hash']}, recomputed {expected}. "
                "Everything before this step is intact."
            )
            return result

        prev = step["hash"]

    result.chain_ok = True
    result.recomputed_anchor = prev

    # ---- 9.3 Check the anchor ----------------------------------------------
    if run["runHash"] != prev:
        result.chain_ok = False
        result.failure_step = FailureStep.ANCHOR
        if steps:
            result.failed_step_index = len(steps) - 1
            result.failed_step_id = steps[-1]["id"]
        result.message = (
            "Integrity check FAILED: the run's anchor was altered. The stored runHash "
            f"is {run['runHash'] or '(empty)'} but the chain ends at {prev or '(empty)'}."
        )
        return result

    # ---- 9.4 Check commitments ---------------------------------------------
    for step in steps:
        verified, redacted, mismatched = rules.check_commitments(step)
        result.commitments_verified.extend(verified)
        result.commitments_redacted.extend(redacted)
        result.commitments_mismatched.extend(mismatched)

        if mismatched:
            index = step.get("index")
            result.failure_step = FailureStep.COMMITMENTS
            result.failed_step_index = (
                int(index) if isinstance(index, (int, float)) and not isinstance(index, bool) else None
            )
            result.failed_step_id = step["id"]
            result.message = (
                f"Integrity check FAILED: step #{result.failed_step_index} ({step['id']}) "
                f"payload does not match its commitment at {', '.join(mismatched)}. "
                "The recorded data was altered."
            )
            return result

        # SPEC §12.3: a partial commitment map leaves some payload fields
        # hashed raw. Not a hash change, so it can be warned about today.
        commitments = step.get("commitments")
        if isinstance(commitments, dict) and commitments:
            for name in rules.PAYLOAD_FIELDS:
                if name in step and step[name] is not None:
                    from .paths import commitment_view

                    if not commitment_view(commitments, name):
                        result.warnings.append(
                            f"step #{step.get('index')} ({step['id']}) has commitments but "
                            f"none covering '{name}': that field is hashed raw and is not "
                            "redaction-capable (SPEC §12.3)"
                        )

    # ---- 9.5 Verify the signature ------------------------------------------
    signature = run.get("signature")
    if signature is None:
        result.signature_state = SignatureState.ABSENT
    else:
        outcome = _check_signature(rules, run, signature, result)
        if outcome is not None:
            return outcome

    result.verdict = Verdict.VALID
    result.message = _success_message(result)
    return result


def _check_signature(
    rules: Any, run: dict[str, Any], signature: Any, result: VerifyResult
) -> VerifyResult | None:
    _require(isinstance(signature, dict), "run.signature is not an object")

    for name in ("algorithm", "keyId", "publicKey", "signature", "signedAt"):
        _require(isinstance(signature.get(name), str), f"run.signature.{name} must be a string")

    def fail(reason: str) -> VerifyResult:
        result.signature_state = SignatureState.INVALID
        result.failure_step = FailureStep.SIGNATURE
        result.message = f"Signature check FAILED: {reason}"
        return result

    # 9.5(b)
    if signature["algorithm"] != "ed25519":
        return fail(
            f"unsupported signature algorithm {signature['algorithm']!r}; "
            "this format defines only 'ed25519'"
        )

    # 9.5(c)
    try:
        actual_key_id = compute_key_id(signature["publicKey"])
    except SignatureError as exc:
        return fail(str(exc))

    result.signature_key_id = actual_key_id
    if signature["keyId"] != actual_key_id:
        return fail(
            f"the record claims keyId {signature['keyId']} but its embedded public key "
            f"has keyId {actual_key_id}"
        )

    # 9.5(d) -- uses the STORED runHash, which 9.3 has already proven equals
    # the recomputed one.
    message = rules.signed_message(run["id"], run["runHash"], signature["signedAt"])
    result.signature_message = message

    if not CRYPTO_AVAILABLE:
        result.signature_state = SignatureState.UNCHECKED
        result.warnings.append(
            "the 'cryptography' package is not installed: the chain, anchor and commitments "
            "were checked but the Ed25519 signature was NOT verified"
        )
        return None

    # 9.5(e)
    try:
        verify_ed25519(signature["publicKey"], message, signature["signature"])
    except SignatureError as exc:
        return fail(str(exc))

    result.signature_state = SignatureState.VALID
    return None


def _success_message(result: VerifyResult) -> str:
    lines = [f"Integrity check passed: chain intact ({result.step_count} steps)."]

    total = (
        len(result.commitments_verified)
        + len(result.commitments_redacted)
    )
    if total:
        lines.append(
            f"Commitments: {len(result.commitments_verified)} verified, "
            f"{len(result.commitments_redacted)} redacted."
        )

    if result.signature_state is SignatureState.VALID:
        # SPEC §11.1: never present a valid signature as proof of origin.
        lines.append(
            f"Signature: valid — internally consistent, and self-attested by key "
            f"{result.signature_key_id}. This does NOT establish who that key belongs to; "
            "compare the key id against one you obtained by other means."
        )
    elif result.signature_state is SignatureState.UNCHECKED:
        lines.append("Signature: present but NOT checked (no crypto library available).")
    else:
        lines.append("Signature: absent — no authenticity claim is made about this record.")

    return "\n".join(lines)


def verify_json_text(text: str) -> VerifyResult:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"not valid JSON: {exc}") from None
    return verify_document(document)


def verify_file(path: str) -> VerifyResult:
    """Verify a ``.tgev`` evidence file or a bare Run JSON file."""
    with open(path, "r", encoding="utf-8") as handle:
        return verify_json_text(handle.read())
