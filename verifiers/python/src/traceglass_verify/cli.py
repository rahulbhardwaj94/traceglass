"""Command line entry point: ``python -m traceglass_verify FILE``.

Exit codes
----------
``0``  the record verifies
``1``  the record does not verify (integrity or signature failure)
``2``  the file could not be read or parsed, or declares a version this
       verifier does not implement -- deliberately distinct from 1, because
       "I cannot check this" is not "this was tampered with" (SPEC §9.1).
"""

from __future__ import annotations

import argparse
import json
import sys

from .verify import ParseError, verify_file
from .versions import UnsupportedVersionError

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_UNUSABLE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m traceglass_verify",
        description=(
            "Independently verify a traceglass evidence record (.tgev or a bare run "
            "JSON). Offline only: no network access, ever."
        ),
    )
    parser.add_argument("file", help="path to a .tgev evidence file or a bare Run JSON file")
    parser.add_argument(
        "--json", action="store_true", dest="as_json", help="machine-readable output (for CI)"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="print nothing; communicate via exit code only"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = verify_file(args.file)
    except FileNotFoundError:
        if not args.quiet:
            print(f"error: no such file: {args.file}", file=sys.stderr)
        return EXIT_UNUSABLE
    except UnsupportedVersionError as exc:
        if not args.quiet:
            print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE
    except ParseError as exc:
        # Not an integrity failure. Say so plainly.
        if not args.quiet:
            print(f"error: {args.file} is not a readable traceglass record: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE

    if args.quiet:
        return result.exit_code

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return result.exit_code

    stream = sys.stdout if result.ok else sys.stderr
    print(result.message, file=stream)
    print(f"runHash:   {result.stored_anchor or '(empty)'}", file=stream)
    if not result.ok and result.recomputed_anchor != result.stored_anchor:
        print(f"expected:  {result.recomputed_anchor or '(empty)'}", file=stream)
    if result.commitments_redacted:
        print(
            f"redacted:  {len(result.commitments_redacted)} leaf/leaves "
            f"({', '.join(result.commitments_redacted)})",
            file=stream,
        )
    for warning in result.warnings:
        print(f"warning:   {warning}", file=stream)

    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
