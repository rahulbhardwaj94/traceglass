"""traceglass-verify -- an independent verifier for the traceglass evidence format.

Written from ``SPEC.md`` alone. Standard library plus ``cryptography`` for
Ed25519, and no network access at any point.

    from traceglass_verify import verify_file
    result = verify_file("run.tgev")
    print(result.ok, result.message)
"""

from __future__ import annotations

from .canonical import TgCanonError, canonical_bytes, canonicalize
from .rules_v1 import REDACTION_MARKER, RulesV1
from .signature import CRYPTO_AVAILABLE, compute_key_id, verify_ed25519
from .verify import (
    FailureStep,
    ParseError,
    SignatureState,
    Verdict,
    VerifyResult,
    verify_document,
    verify_file,
    verify_json_text,
)
from .versions import UnsupportedVersionError

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "canonicalize",
    "canonical_bytes",
    "TgCanonError",
    "RulesV1",
    "REDACTION_MARKER",
    "compute_key_id",
    "verify_ed25519",
    "CRYPTO_AVAILABLE",
    "verify_file",
    "verify_json_text",
    "verify_document",
    "VerifyResult",
    "Verdict",
    "FailureStep",
    "SignatureState",
    "ParseError",
    "UnsupportedVersionError",
]
