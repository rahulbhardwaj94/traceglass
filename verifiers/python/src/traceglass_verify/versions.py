"""Version dispatch.

SPEC §10.3 records the gap honestly: **a Run carries no version of its own**.
Nothing in a published record states which canonicalization produced its
hashes, so today every record is v1 by assumption.

This module is the seam where that gets fixed. When records start declaring a
``hashVersion``, add the new rule set to ``RULE_SETS`` and the verification
algorithm in ``verify.py`` needs no change -- it only ever talks to a rule set
through the interface below.
"""

from __future__ import annotations

from typing import Any

from .rules_v1 import RulesV1

__all__ = [
    "RULE_SETS",
    "DEFAULT_HASH_VERSION",
    "SUPPORTED_FORMAT_VERSIONS",
    "resolve_hash_version",
    "rules_for",
    "UnsupportedVersionError",
]

# The envelope's ``formatVersion`` (SPEC §3.1). Distinct from hashVersion.
SUPPORTED_FORMAT_VERSIONS = frozenset({1})

# A record with no declared hash version is v1 (SPEC §10.2).
DEFAULT_HASH_VERSION = 1

RULE_SETS: dict[int, Any] = {
    1: RulesV1,
}


class UnsupportedVersionError(Exception):
    """The document declares a version this verifier does not implement."""


def resolve_hash_version(run: dict[str, Any]) -> int:
    """Read a Run's declared hash version, defaulting to 1.

    ``hashVersion`` does not exist in any published record. It is read here so
    that the day it is introduced, an old record (no field) and a new record
    (explicit field) both route correctly. Until then this always returns 1.
    """
    declared = run.get("hashVersion")
    if declared is None:
        return DEFAULT_HASH_VERSION
    if isinstance(declared, bool) or not isinstance(declared, (int, float)):
        raise UnsupportedVersionError(f"hashVersion must be a number, got {declared!r}")
    if declared != int(declared):
        raise UnsupportedVersionError(f"hashVersion must be an integer, got {declared!r}")
    return int(declared)


def rules_for(hash_version: int) -> Any:
    try:
        return RULE_SETS[hash_version]
    except KeyError:
        supported = ", ".join(str(v) for v in sorted(RULE_SETS))
        raise UnsupportedVersionError(
            f"record declares hashVersion {hash_version}; "
            f"this verifier supports {supported}"
        ) from None
