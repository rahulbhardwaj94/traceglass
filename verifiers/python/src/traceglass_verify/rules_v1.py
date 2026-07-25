"""The ``hashVersion`` 1 rule set: step hashing, chaining, commitments.

SPEC.md §5, §6, §8.2. Everything version-specific lives behind the
``RuleSet`` protocol in ``versions.py`` so that a second canonicalization can
be added without touching the verification algorithm.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonicalize
from .paths import ABSENT, commitment_view, read_path, split_field

__all__ = ["RulesV1", "REDACTION_MARKER"]

REDACTION_MARKER = "[traceglass:redacted]"


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class RulesV1:
    """``tgcanon/1`` + the v1 hashing rules."""

    hash_version = 1
    canon_id = "tgcanon/1"

    # SPEC §5.1. Exactly these members, when present, are hashed. Everything
    # else -- runId, hash, prevHash, salts, redactions, unknown members -- is
    # excluded. A member present with the value ``null`` IS included.
    HASHED_FIELDS = (
        "id",
        "index",
        "type",
        "label",
        "startedAt",
        "durationMs",
        "tokens",
        "cost",
        "toolName",
        "input",
        "output",
        "dataPayload",
        "spanId",
        "parentSpanId",
    )

    PAYLOAD_FIELDS = ("input", "output", "dataPayload")

    @staticmethod
    def canonicalize(value: Any) -> str:
        return canonicalize(value)

    @classmethod
    def picked_step(cls, step: dict[str, Any]) -> dict[str, Any]:
        """The object that actually gets canonicalized for a step hash."""
        picked: dict[str, Any] = {
            field: step[field] for field in cls.HASHED_FIELDS if field in step
        }

        # SPEC §5.2 -- commitment substitution. Only when the step carries a
        # ``commitments`` member at all.
        commitments = step.get("commitments")
        if isinstance(commitments, dict):
            for field in cls.PAYLOAD_FIELDS:
                view = commitment_view(commitments, field)
                if view:
                    # The whole {path: commitmentHex} map replaces the raw
                    # value. Because the view's KEYS are hashed too, the set of
                    # committed paths is covered by the step hash.
                    picked[field] = view
                # An empty view leaves the raw value in place (SPEC §12.3):
                # that field is hashed raw and is not redaction-capable.
        return picked

    @classmethod
    def canonical_step(cls, step: dict[str, Any]) -> str:
        return canonicalize(cls.picked_step(step))

    @classmethod
    def step_hash(cls, step: dict[str, Any], prev_hash: str) -> str:
        """SPEC §5.3: SHA256_hex(UTF8(canonicalStep || prevHash)).

        ``prevHash`` is appended as text with no separator or length prefix.
        """
        return _sha256_hex(cls.canonical_step(step) + prev_hash)

    @staticmethod
    def commitment(salt_hex: str, value: Any) -> str:
        """SPEC §8.2: SHA256_hex(UTF8(salt_text || canonical(value))).

        The salt is concatenated as its *hex text*, not as raw bytes.
        """
        return _sha256_hex(salt_hex + canonicalize(value))

    @classmethod
    def check_commitments(
        cls, step: dict[str, Any]
    ) -> tuple[list[str], list[str], list[str]]:
        """SPEC §9.4. Returns ``(verified, redacted, mismatched)`` path lists."""
        commitments = step.get("commitments")
        if not isinstance(commitments, dict):
            return [], [], []

        salts = step.get("salts")
        if not isinstance(salts, dict):
            salts = {}

        verified: list[str] = []
        redacted: list[str] = []
        mismatched: list[str] = []

        for path, expected in commitments.items():
            salt = salts.get(path)
            if salt is None:
                # SPEC §8.4: a path in ``commitments`` but not in ``salts`` has
                # been redacted. Nothing is left to check, by design.
                redacted.append(path)
                continue

            field, relative = split_field(path)
            value = read_path(step.get(field, ABSENT), relative)
            if value is ABSENT:
                # Unresolvable path. Honest records hit this only through the
                # SPEC §12.5 path-ambiguity defect; it is still a mismatch.
                mismatched.append(path)
                continue

            if cls.commitment(salt, value) == expected:
                verified.append(path)
            else:
                mismatched.append(path)

        return verified, redacted, mismatched

    @staticmethod
    def signed_message(run_id: str, run_hash: str, signed_at: str) -> str:
        """SPEC §7.1 -- canonicalize({runId, runHash, signedAt})."""
        return canonicalize({"runId": run_id, "runHash": run_hash, "signedAt": signed_at})
