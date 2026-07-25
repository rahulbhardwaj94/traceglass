"""Ed25519 signature checking and key ids -- SPEC.md §7.

The only third-party dependency in this package lives here, and it is optional:
without it the chain, anchor and commitment layers still verify and the
signature is reported as *unchecked* rather than silently assumed good.

``cryptography`` is used rather than ``pynacl`` for one reason: the record
stores the public key as **SPKI PEM** (SPEC §7.2), and ``cryptography`` parses
that directly via ``load_pem_public_key``. PyNaCl only accepts 32 raw bytes, so
it would need a hand-rolled DER unwrap here -- more code to audit, in the one
file where an auditor least wants to be reading clever parsing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

__all__ = [
    "CRYPTO_AVAILABLE",
    "CRYPTO_IMPORT_ERROR",
    "SignatureError",
    "spki_der_from_pem",
    "compute_key_id",
    "verify_ed25519",
]

try:  # pragma: no cover - import shape depends on the environment
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    CRYPTO_AVAILABLE = True
    CRYPTO_IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    CRYPTO_AVAILABLE = False
    CRYPTO_IMPORT_ERROR = str(exc)


class SignatureError(Exception):
    """The signature block is malformed or does not verify."""


_PEM_HEADER = "-----BEGIN PUBLIC KEY-----"
_PEM_FOOTER = "-----END PUBLIC KEY-----"


def spki_der_from_pem(pem: str) -> bytes:
    """Extract the DER bytes from an SPKI PEM block.

    Done by hand so that ``compute_key_id`` works with no crypto library
    present -- the key id is a plain SHA-256 over these bytes (SPEC §7.3).
    """
    text = pem.strip()
    if _PEM_HEADER not in text or _PEM_FOOTER not in text:
        raise SignatureError("publicKey is not a PEM SPKI block")
    body = text.split(_PEM_HEADER, 1)[1].split(_PEM_FOOTER, 1)[0]
    b64 = "".join(body.split())
    try:
        return base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError(f"publicKey base64 is malformed: {exc}") from None


def compute_key_id(pem: str) -> str:
    """SPEC §7.3: first 16 lowercase hex chars of SHA256(SPKI DER)."""
    return hashlib.sha256(spki_der_from_pem(pem)).hexdigest()[:16]


def verify_ed25519(pem: str, message: str, signature_b64: str) -> None:
    """Raise ``SignatureError`` unless the signature is valid.

    The message is signed directly (SPEC §7.1) -- Ed25519 does its own internal
    SHA-512, so this is *not* Ed25519ph and there is no pre-hash.
    """
    if not CRYPTO_AVAILABLE:  # pragma: no cover
        raise SignatureError(
            "the 'cryptography' package is not installed, so the signature "
            f"cannot be checked ({CRYPTO_IMPORT_ERROR})"
        )

    try:
        raw_signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError(f"signature is not valid base64: {exc}") from None

    if len(raw_signature) != 64:
        raise SignatureError(
            f"an Ed25519 signature is 64 bytes; this one decodes to {len(raw_signature)}"
        )

    der = spki_der_from_pem(pem)
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except Exception as exc:
        raise SignatureError(f"publicKey could not be parsed: {exc}") from None

    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError(
            f"publicKey is a {type(key).__name__}, not an Ed25519 public key"
        )

    # Guard against a PEM whose re-encoding differs from what we hashed for the
    # key id -- if these disagree, the key id would be computed over bytes the
    # verification did not use.
    if key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != der:
        raise SignatureError("publicKey DER is not in canonical SPKI form")

    try:
        key.verify(raw_signature, message.encode("utf-8"))
    except InvalidSignature:
        raise SignatureError("Ed25519 signature does not verify against the anchor") from None
