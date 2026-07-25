# traceglass-verify — an independent Python verifier

A second implementation of the traceglass evidence format, written in Python
from [`SPEC.md`](../../SPEC.md) alone.

It exists because, until now, only traceglass could verify traceglass. That
makes the evidence *captive*: an auditor cannot check a record without trusting
the tool that produced it, which rather defeats the point of an evidence
format. This package is deliberately small, dependency-light and readable, so
that someone who does not trust the vendor can read all of it in an afternoon
and then run it themselves.

It is **not** a port. The TypeScript implementation was consulted only to
resolve ambiguities in the prose — and each of those ambiguities is recorded in
[`FINDINGS.md`](FINDINGS.md), because an ambiguity that needs the source code
to resolve is a hole in the specification.

## Install

Python 3.10 or newer.

```bash
cd verifiers/python
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
```

The only runtime dependency is [`cryptography`](https://cryptography.io/), used
for Ed25519 and nothing else. Everything else — canonicalization, hashing,
the chain, commitments — is the standard library.

**Without `cryptography` the package still works.** The chain, anchor and
commitment layers verify normally and the signature is reported as
`unchecked`, never as valid:

```
Integrity check passed: chain intact (4 steps).
Commitments: 21 verified, 0 redacted.
Signature: present but NOT checked (no crypto library available).
warning:   the 'cryptography' package is not installed: the chain, anchor and
           commitments were checked but the Ed25519 signature was NOT verified
```

A verifier that quietly assumed a signature was good because it could not check
it would be worse than useless. Note the exit code in that state is still `0` —
nothing was found to be *invalid* — so install `cryptography` before wiring this
into a CI gate, or check `signature.state` in the `--json` output.

## Use

```bash
python -m traceglass_verify run.tgev          # human readable
python -m traceglass_verify --json run.tgev   # machine readable, for CI
python -m traceglass_verify --quiet run.tgev  # exit code only
```

Exit codes:

| Code | Meaning |
|:--:|---|
| `0` | the record verifies |
| `1` | the record does **not** verify — integrity or signature failure |
| `2` | the file could not be read, parsed, or its version is unsupported |

`2` is deliberately distinct from `1`. "I cannot check this" is not "this was
tampered with", and an auditor must never be shown the second when the first is
true (SPEC §9.1).

As a library:

```python
from traceglass_verify import verify_file

result = verify_file("run.tgev")
print(result.ok, result.message)
print(result.commitments_redacted)     # paths whose value has been erased
print(result.signature_state)          # absent | valid | invalid | unchecked
```

`verify_document(obj)` takes an already-parsed dict if you have one.

## What it checks

The verification algorithm of SPEC §9, in order, stopping at the first failure
and naming where it happened:

| Step | Check |
|---|---|
| §9.1 | envelope `formatVersion` is 1 (or a bare Run), shape is readable |
| §9.2a | each step's `prevHash` points at the previous step — catches insertion, deletion, reordering |
| §9.2c | each step's `hash` matches a recomputation over the canonical hashed field set |
| §9.3 | `runHash` equals the final link of the chain |
| §9.4 | every visible committed leaf still matches its salted commitment |
| §9.5 | `algorithm` is `ed25519`, `keyId` matches the embedded key, and the Ed25519 signature verifies over `{runId, runHash, signedAt}` |

§9.4 is not optional. Once a step carries `commitments`, the raw payload no
longer affects the step hash at all, so a verifier that stops after §9.2/§9.3
will accept a record whose every visible payload value has been rewritten.

It also reports, per SPEC §9.6, as separate facts: chain intact or not and
where, commitment paths verified / redacted / mismatched, whether the record is
unsigned versus signed-and-valid versus signed-and-invalid, and both the stored
and the recomputed anchor.

### Two tightenings over the reference implementation

Both are pure additions that change no hash, and both are things SPEC §12 says
a conforming verifier *should* do:

* **`algorithm` is enforced** (§12.7). The reference never reads the field.
* **`keyId` is recomputed and compared to `publicKey`** (§12.8). The reference
  does not, so a record can today claim any `keyId` and still verify.

A record that fails only on these two would pass `traceglass verify`. That is
the intended difference, not a bug in either.

## What it deliberately does not check

**It cannot tell you the embedded public key belongs to who you think it does.**
This is the load-bearing limitation of the whole format, not a shortcoming of
this implementation. Verification uses the public key stored *inside the file
being verified*; nothing external is consulted. An attacker who can rewrite the
file can rewrite the steps, re-chain them, sign the new anchor with a key they
generated a second ago, and embed that public key — and this verifier, and
`traceglass verify`, will both pass it cleanly.

What a valid signature establishes is that the record's contents were sealed
together by *one* keyholder. That makes the record attributable only once you
independently know whose key `keyId` is. This tool prints the key id precisely
so you can compare it against a key you obtained by other means. See
SPEC §11.1 and `docs/threat-model.md` §4.1.

Also outside what any verifier can see, by design of the v1 format:

* **Run metadata is covered by nothing** (SPEC §6.2). `name`, `status`,
  `currency`, `totals`, `startedAt`, `endedAt` and `warnings` can be edited
  freely on a signed record and it still verifies. The consequential one is
  `currency`: every `cost` is a bare number whose unit lives only there.
* **Redaction is unauthenticated** (SPEC §8.6). `salts` and `redactions` are
  outside the hash, so anyone who can write the file can erase a leaf silently,
  delete the redaction log, or fabricate entries. This tool reports a leaf as
  *redacted* when its salt is gone, because that is genuinely all the format
  records — not because it has verified an authorisation.
* **Completeness.** A run that simply omits the awkward steps produces a
  perfectly valid chain. The format seals what was recorded.
* **`runId` is not in the step hash** (SPEC §12.2), so a step can be lifted
  from one run into another at the same chain position.

Finally: this verifier **never touches the network**. There is no code path
that opens a socket, and there is nothing to configure.

## Tests

```bash
pytest
```

630 tests. The core of it is the frozen conformance corpus in
`../../docs/test-vectors/` — all 132 checks that `check.mjs` runs, reproduced
here with matching identifiers (`01 canonical/…`, `02 walk/…`, `03 hash/…`,
`05 keyId`, `09 verify/…`, `08 redaction anchor`) so a disagreement can be
lined up against the reference directly. **All 132 pass.**

The rest are the tests the corpus does not provide: single-byte tamper cases
for every failure branch, the SPEC §12.5 path-ambiguity defects, and 428 frozen
ECMAScript number encodings.

### Why there is a hand-written number formatter

`tgcanon/1` pins number encoding to ECMAScript `Number::toString`. Python's
`json.dumps` does not implement that algorithm and diverges for **every
non-zero magnitude below `1e-4`** — which is exactly where per-token AI costs
live:

| value | ECMAScript / traceglass | Python `json.dumps` |
|---|---|---|
| `0.00001` | `0.00001` | `1e-05` |
| `0.000025` | `0.000025` | `2.5e-05` |
| `0.000001` | `0.000001` | `1e-06` |
| `1e-7` | `1e-7` | `1e-07` |

A verifier built on `json.dumps` reports a *false integrity alarm* on an
untouched record whose cheapest step cost less than a hundredth of a paisa, and
nothing in the error message would point at the number. In an evidence product
a false alarm is the worst possible failure, so `numbers.py` implements the
ECMA-262 §6.1.6.1.20 layout rules directly. Only the shortest-round-trip digit
generation is borrowed from Python (`repr`), which is the same quantity the
ECMAScript algorithm specifies.

That formatter was differential-tested against V8 over **49,525 doubles**
(random bit patterns plus targeted magnitudes across the whole exponent range):
zero mismatches. A 428-case sample of that run is frozen into
`tests/data/ecma_numbers.json` so the suite stays offline.

## Adding a future `tgcanon/2`

Everything version-specific lives in `rules_v1.py` behind the registry in
`versions.py`. `verify.py` only ever talks to a rule set through that
interface, so a second version is a new module plus one registry entry.

A caveat worth knowing (SPEC §10.3): **no published record declares a hash
version.** `versions.py` reads a `hashVersion` member off the Run and defaults
to 1 when absent, which is the forward-compatible shape — but until producers
start writing that field, every record is v1 by assumption rather than by
declaration. An unknown declared version is refused outright rather than
guessed at.

## Layout

```
src/traceglass_verify/
  numbers.py     ECMAScript Number::toString  (SPEC §4.4)
  canonical.py   tgcanon/1                    (SPEC §4)
  paths.py       leaf walking, path read-back (SPEC §8.1, §9.4b)
  rules_v1.py    step hashing, chain, commitments (SPEC §5, §6, §8.2)
  signature.py   Ed25519 and key ids          (SPEC §7)
  versions.py    version dispatch             (SPEC §10)
  verify.py      the algorithm                (SPEC §9)
  cli.py         command line
```
