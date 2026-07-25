# Findings from building an independent verifier

Everything below came out of implementing `tgcanon/1` and SPEC §9 in Python
from the prose, then reconciling against the frozen corpus and the shipped
implementation. Each item names the vector, test or command that exposed it.

**Headline: the specification is good enough.** All 47 canonicalization vectors
passed on the first run, before any part of the TypeScript was read, and all
132 corpus checks pass. The number and key-ordering sections in particular are
detailed enough that the traps they warn about were avoidable. What follows is
mostly gaps at the edges — but two of them (F1, F2) mean the corpus and the
defect list assert less than they appear to.

Severity is about the risk to someone relying on the format, not about how hard
the fix is.

---

## F1 — the corpus does not actually test NFC vs NFD at the envelope level — *medium*

`docs/test-vectors/README.md` says `committed.tgev.json` demonstrates "a
deliberately awkward payload: **NFC vs NFD**, a ZWJ emoji, …". It does not. The
leaf named `input.unicode.nfd` holds the **precomposed (NFC)** string:

```
input.unicode.nfc  = 63 61 66 e9      "caf" + U+00E9
input.unicode.nfd  = 63 61 66 e9      "caf" + U+00E9    <- identical
```

Both leaves are byte-for-byte the same string, so the no-normalization rule
(SPEC §4.2.4) is exercised by neither of them, in neither the committed nor the
redacted envelope. An implementation that silently NFC-normalized every string
would still pass `09 verify/committed` and `09 verify/redacted`.

**Cause** — `docs/test-vectors/generate.mjs:364`:

```js
unicode: { nfc: 'café', nfd: 'café', emoji: '👩‍🚀' },
```

Both are source-file literals, and the file is saved in NFC, so the second one
was normalized by an editor long before Node ever ran. Line 235 of the same
file, which builds the standalone `nfd` commitment vector, gets it right by
using an escape:

```js
['nfd', '"cafe\\u0301"'],
```

**Impact.** The standalone vectors (`unicode-nfd` in `01-canonical.json`, `nfd`
in `02-commitments.json`) do cover the rule, so this is a coverage gap rather
than a correctness bug. But `committed.tgev.json` is the vector an implementer
is told covers awkward Unicode end to end, and for NFD it does not.

**Suggested fix.** In `generate.mjs`, write the decomposed form as an escape
rather than a literal — `nfd: 'cafe\u0301'`. A literal cannot survive the trip:
this findings file was itself first written with a decomposed literal on this
very line, and the tooling normalized it to NFC before it reached disk. That is
the same failure as the one being reported, one layer up, and it is why the
escape form is the only safe way to write this.

That changes the payload bytes, so the commitment for
`input.unicode.nfd` and every downstream hash in `committed`/`redacted` moves —
i.e. it is a corpus regeneration, and per the corpus's own freeze rule it needs
to be a deliberate, reviewed change rather than a drive-by edit. Adding a *new*
`input.unicode.nfdReal` leaf alongside the existing one closes the same gap and
is equally disruptive; either way it is a decision for whoever owns the corpus.

Exposed by: `tests/test_tamper.py::test_nfc_and_nfd_are_distinct_committed_values`,
which had to substitute a genuinely decomposed string to have anything to
assert.

---

## F2 — SPEC §12.5 understates the bracket-key defect — *medium*

§12.5's table lists three ambiguous payloads and their consequences:

| payload | path produced | consequence per §12.5 |
|---|---|---|
| `{"a.b":1}` | `input.a.b` | collides; read-back returns nothing, so the leaf **fails verification on an honest record** |
| `{"":1}` | `input.` | read-back returns the parent; **fails on an honest record** |
| `{"a[0]":1}` | `input.a[0]` | indistinguishable from `{"a":[1]}` |

The third row stops at "indistinguishable". It is not merely ambiguous — it
**also fails verification on an honest record**, for exactly the same reason as
the first two: read-back tokenizes `a[0]` into the name `a` then index `0`, and
the literal key `"a[0]"` is never found.

Confirmed against the shipped SDK, one memory-only run per payload:

```
amb-dot     {"user.email": …}    THREW   … does not match its commitment at input.user.email
amb-empty   {"": 1}              THREW   … does not match its commitment at input.
amb-bracket {"a[0]": 1}          THREW   … does not match its commitment at input.a[0]
amb-control-nested {"a":{"b":1}}   RECORDED OK
amb-control-array  {"a":[1]}       RECORDED OK
```

So all **three** rows are false-alarm cases, not one ambiguity plus two
failures. §12.5's own framing — "a false integrity alarm in an evidence product
is a serious bug" — applies to the bracket row too, and the count of payload
shapes that break honest records should read three, not two.

**Worth noting separately:** the failure surfaces at *record* time, not at
verify time. `startRecording().end()` runs a self-check and **throws**, so an
agent whose tool arguments contain a `user.email`-style key crashes rather than
producing a bad record. That is a better failure mode than §12.5's description
implies (it describes verification failing later), and saying so in §12.5 would
be an improvement — but it is still a crash on entirely ordinary input.

Exposed by: `tests/test_paths.py::test_bracket_key_also_fails_on_an_honest_record`.

---

## F3 — SPEC §8.1 does not state a leaf visit order, but the corpus asserts one — *low*

§8.1 says each payload "is walked to its leaves" and gives the path
construction rules, but never says in what order children are visited. The
corpus's `02 walk` vectors compare an **ordered** list, so the order is in
practice normative — an implementation that walks in a different order fails
those vectors.

The order the reference actually uses is ECMAScript property enumeration:
integer-index keys first in ascending numeric order, then everything else in
insertion order. Confirmed against the shipped SDK with a payload whose
insertion order is deliberately not numeric order:

```
payload      {"10":"a","2":"b","z":"c","1":"d"}
commitments  ["input.1","input.2","input.10","input.z"]
```

A verifier written from §8.1 that used plain insertion order would produce
`["input.10","input.2","input.z","input.1"]`.

The corpus cannot catch this: its only numeric-key walk vector is
`object-numeric-keys` = `{"0":"x","1":"y"}`, which is already inserted in
numeric order and so cannot discriminate the two orderings.

**Impact is low but non-zero.** Nothing hashes it — `commitments` and `salts`
are objects, and §4.2.1 re-sorts their keys during canonicalization, so the step
hash is identical either way (pinned by
`test_leaf_order_does_not_affect_the_step_hash`). It matters only for
byte-identical `.tgev` reproduction and for passing the walk vectors. This is
the same runtime leak §4.2.2 already documents for canonicalization, so the fix
is a cross-reference rather than new analysis.

**Suggested fix.** Add to §8.1: "children of an object are visited in
ECMAScript property-enumeration order — array-index keys (§4.2.1) first in
ascending numeric order, then remaining keys in insertion order. No hash
depends on this; it fixes the key order of the `commitments` and `salts` maps
and of the `02 walk` vectors." Add a discriminating walk vector such as
`{"10":1,"2":2,"z":3}` alongside `object-numeric-keys`.

---

## F4 — §9.4 read-back for the empty relative path is under-specified — *low*

§9.4(b) says: split the path at the first `.` or `[`, "take the remainder as the
relative path (dropping a leading `.`)". For the path `input.` produced by
`{"":1}`, the remainder is the **empty string**, and §8.1's read-back rule
("split on `.`, then split each part into a name and any number of `[digits]`
groups") does not say what an empty relative path means. Read literally,
splitting `""` on `.` yields one part whose name is `""`, which would index
`{"":1}[""]` and return `1` — i.e. the leaf would **verify**.

§12.5 asserts the opposite ("read-back returns the parent; fails on an honest
record"), and the shipped implementation agrees with §12.5. So the normative
section (§9.4) and the non-normative defect list (§12.5) can be read to
disagree, and only §12.5 matches reality.

The prose *is* satisfiable without a special case: if an empty name segment
contributes no token, then the empty relative path yields no tokens and
read-back returns the container — the parent — which is what §12.5 describes.
That same rule is independently required to make `input[0]` work (a payload
that is itself an array gives field `input` and relative path `[0]`, which must
tokenize to just the index). This implementation adopts it, and its behaviour
matches the shipped code on all three ambiguous payloads. But it is inferred,
not stated.

**Suggested fix.** One sentence in §9.4(b) or §8.1: "an empty name segment
contributes no token; an empty relative path therefore resolves to the field
value itself."

Exposed by: `tests/test_paths.py::test_empty_key_reads_back_the_parent_and_fails`
and `test_read_path_on_a_top_level_array_payload`.

---

## F5 — the reference checks §9.4 before §9.3, so failures are attributed differently — *low*

SPEC §9 says the steps run "in order": chain (9.2), anchor (9.3), commitments
(9.4). `packages/core/src/integrity/verify.ts` runs the chain, then
**commitments**, then the anchor. On a record where both the anchor and a
committed payload have been altered, the two verifiers report different causes:

```
$ traceglass verify tamper-both.tgev
Integrity check FAILED: step #1 (e2e-py:1) payload does not match its commitment at input.query. …

$ python -m traceglass_verify tamper-both.tgev
Integrity check FAILED: the run's anchor was altered. The stored runHash is 7f28… but the chain ends at 6f28…
```

Both exit 1, so no verdict differs — but §9 opens with "performs these steps
**in order**" and "any failure stops and is reported with the step index and id
at which it occurred", which makes the reported cause part of the contract. Two
conforming verifiers should not name different first causes for the same file.

**Suggested fix.** Either reorder the reference to match §9, or relax §9 to say
that the relative order of 9.3 and 9.4 is not observable and only the verdict is
normative. The former is the smaller change and keeps the spec honest.

---

## F6 — §9.2 distinguishes two chain failures; the reference collapses them — *low*

§9.2 gives two separate failure conditions with materially different meanings:

* (a) `step.prevHash ≠ prev` → "chain linkage broken here" — a step was
  inserted, removed, or reordered;
* (c) `step.hash ≠ expected` → "step content altered here" — the step's own
  fields were edited.

The reference tests both in one `if` and emits one message for either: `chain
broken at step #N`. For an auditor these are different accusations — "someone
deleted a step" versus "someone edited this step" — and the format can tell them
apart. This verifier reports them separately (`FailureStep.CHAIN_LINKAGE` vs
`FailureStep.STEP_CONTENT`).

Not a spec bug: the spec is right and the implementation is coarser than it
needs to be. Recorded because a second implementation following §9.2 literally
produces different (better) output, which could otherwise be mistaken for a
disagreement.

---

## F7 — `traceglass verify` does not report commitments, which §9.6 requires — *medium*

§9.6: "A conforming verifier MUST report at least: chain intact (yes/no, and
where not), **commitments verified / redacted / mismatched (as path lists)**,
signature present-and-valid / present-and-invalid / absent, the recomputed
anchor, and the stored anchor."

The shipped CLI's human-readable output reports none of the commitment
information. On a run that had just had a leaf erased by `traceglass redact`:

```
$ traceglass verify redacted.tgev
Integrity check passed: chain intact.
Signature OK (keyId 27c685f751333606).
runHash: 6f28f1a5b1f228e34b92f324f2442261fe4d8c683cc910994e75916febaaf2fb
```

Nothing indicates that `input.query` has been erased. The auditor is looking at
a record with a hole in it and is not told. This verifier prints
`Commitments: 20 verified, 1 redacted.` and lists the paths.

Related, same output path: on a record whose payload was tampered with, the CLI
prints `Signature OK` on the line directly below `Integrity check FAILED` —
technically accurate, since the signature covers only
`{runId, runHash, signedAt}` and the anchor did not move, and the exit code is
still 1. But "Signature OK" sitting under a failure is an unfortunate thing to
put in front of someone skimming, and §9.6's "MUST NOT report a valid signature
as evidence of origin" gestures at the same concern.

**Suggested fix.** Add the commitment path lists to the CLI's non-`--json`
output, and suppress or qualify the signature line when the integrity check
failed.

---

## F8 — §7.2 mandates rejecting a non-`ed25519` algorithm; nothing does — *low*

Already recorded as §12.7 and §12.8; confirmed here because these are the one
place where a spec-conforming verifier and the shipped one give **different
verdicts on the same file**:

* `algorithm: "rsa"` — §7.2 says "Implementations MUST reject any other value".
  The reference never reads the field, so it accepts the record; this
  implementation rejects it.
* `keyId` inconsistent with `publicKey` — §7.3 says a conforming verifier
  SHOULD recompute and reject. The reference does not, so it accepts the
  record; this implementation rejects it.

Both are pure tightenings that change no hash and need no version bump, and
§12.8 says of the second "this costs nothing to fix — do it now". Worth
flagging that until they are fixed, "verified by traceglass" and "verified by a
conforming verifier" are not the same statement.

Exposed by: `tests/test_tamper.py::test_wrong_algorithm_is_rejected` and
`test_key_id_mismatch_is_rejected`.

---

## F9 — §6 describes a `running` run with steps; §9.3 rejects it — *low*

§6 says a run with `status: "running"` "carries `runHash: ""` and is not yet
anchored or signable". §9 has no `status`-aware branch, so §9.3
(`if run.runHash ≠ prev → FAIL`) rejects any in-flight journal that has recorded
at least one step: `prev` is that step's hash while `runHash` is `""`.

In practice this is nearly unreachable — `.tgev` export only produces finalized
runs, and `recover` finalizes journals — so the two sections have not collided.
But §9 is written as *the* verification algorithm for a Run, §3.2 lists
`running` as a legal `status`, and a tool that hands a live journal to a
verifier gets "the anchor was altered" instead of "this run is still in flight".

**Suggested fix.** One sentence in §9.3: a run with `status: "running"` and
`runHash: ""` is unanchored, not corrupt, and MUST be reported as such rather
than as an integrity failure.

---

## F10 — `02-commitments.json` points at the wrong section — *cosmetic*

The `AMBIGUOUS-*` vectors carry notes reading "See SPEC.md §9.3 — this is a
known defect". §9.3 is the anchor check. The section documenting these defects
is **§12.5**, with the path construction rules in §8.1. Three occurrences, all
in `docs/test-vectors/02-commitments.json`.

---

## F11 — number shortest-digit tie-breaking is unverifiable from the spec — *informational, no action*

§4.4.1 pins the shortest-round-trip digit string, and ECMA-262 adds a tie-break:
among equally short candidates choose the one closest to the exact value, and if
two are equally close choose the even one. CPython's `repr` implements
shortest-and-correctly-rounded, but its documentation does not promise
ECMAScript's exact tie-break, so relying on `repr` for digit generation is an
assumption the prose cannot settle.

Rather than leave it as an assumption, the formatter was differential-tested
against V8 over **49,525 doubles** — random 64-bit patterns plus targeted sweeps
across the full exponent range and the whole `0 < |v| < 1e-4` divergence band —
with **zero mismatches**. A 428-case sample is frozen into
`tests/data/ecma_numbers.json` so the suite stays offline.

No action proposed; recorded so the next implementer knows the assumption was
tested rather than hoped for, and knows how to re-test it. If §4.4.1 ever grows
a note, the useful sentence is: "any correctly-rounded shortest-round-trip digit
generator agrees with ECMAScript in practice; verified over ~50k doubles against
V8."

---

## Things the spec got right that would otherwise have bitten

Recorded because they are the reason the first-pass implementation worked, and
because they should survive any future edit of the document.

* **§4.2.2, array-index key ordering.** Called out explicitly, with the worked
  example and the warning that every RFC 8785 library gets it wrong. Without
  that paragraph a Python implementation reaches for `sorted(keys)` and produces
  wrong hashes for any `{"1":…,"2":…}` map.
* **§4.4.2, the number divergence table.** Naming CPython specifically, giving
  the exact wire forms, and stating the divergence band turned the most
  dangerous part of the format into a checklist. The end-to-end run in this work
  emitted `0.000025`, `0.00001` and `1e-7` on the wire and all three verified —
  the exact values that would otherwise have produced a false tamper verdict.
* **§4.2.3, UTF-16 code-unit ordering**, with the astral example. Python sorts
  by code point; without the example the emoji key sorts last instead of first.
* **§4.3's list of what is *not* escaped** — `/`, U+007F, U+2028 and U+2029.
  Easy to over-escape, impossible to guess.
* **§5.1's "a member present with the value `null` IS collected"**, and §4.5's
  absent-vs-null distinction. Exactly the sentence needed, in the right place.
* **§9.4's callout** that commitment checking is load-bearing rather than an
  optional extra pass. A verifier that skipped it would pass every corpus check
  except `09 verify`, and would silently accept rewritten payloads.
* **Publishing `hashPreimage` in `03-steps.json`.** Nothing else lets you diff
  the exact bytes when a hash disagrees.

---

## Corpus result

All 132 checks reproduced, with identifiers matching `check.mjs`:

| Group | Checks | Result |
|---|--:|---|
| `01 canonical/<name>` | 47 | pass |
| `01 sha256/<name>` | 47 | pass |
| `02 walk/<name>` | 13 | pass |
| `02 commit/<name>` | 10 | pass |
| `03 canonicalStep/<run>#<i>` | 4 | pass |
| `03 hash/<run>#<i>` | 4 | pass |
| `05 signaturePayload` | 1 | pass |
| `05 keyId` | 1 | pass |
| `09 verify/<run>` | 4 | pass |
| `08 redaction preserves the anchor` | 1 | pass |
| **total** | **132** | **132 pass, 0 fail** |
