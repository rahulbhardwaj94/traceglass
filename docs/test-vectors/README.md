# traceglass format test vectors

A frozen conformance corpus for [`SPEC.md`](../../SPEC.md). Every value here was
produced by running the shipped `@traceglass/core` implementation, not by hand.

```bash
node docs/test-vectors/check.mjs      # 187 checks, all must pass
```

**These hashes are the format.** If a code change moves any of them, that change
is a breaking format change and needs the versioning mechanism described in
[`../number-encoding-proposal.md`](../number-encoding-proposal.md) §5. Treat a
failing `check.mjs` as a release blocker, not a test to update.

## Files

| File | Contents |
|---|---|
| `01-canonical.json` | 47 canonicalization vectors — key ordering, unicode, string escaping, and every number edge case |
| `02-commitments.json` | leaf-walk path vectors (including the known-ambiguous ones) and salted commitments |
| `03-steps.json` | canonical step forms, full hash preimages, and chain hashes for four runs |
| `04-runs/*.tgev.json` | complete evidence envelopes (v1 and v2, plus two frozen pre-v2 legacy records) |
| `05-signature.json` | signed message, key id, and signature under the published test key |
| `keys/` | Ed25519 test keypair — **published, TEST ONLY** |
| `check.mjs` | reference verifier; imports nothing from `@traceglass/core` |
| `generate.mjs` | regenerates the corpus from the real implementation |

### The version-1 runs

| Run | Demonstrates |
|---|---|
| `minimal.tgev.json` | a two-step chain with no commitments — the pre-0.6 hashing shape, still valid |
| `committed.tgev.json` | per-leaf commitments over a deliberately awkward payload: a ZWJ emoji, empty containers, `0.1+0.2`, a micro-cost, and `MAX_SAFE_INTEGER` |
| `redacted.tgev.json` | the same run with `input.query` erased — **same anchor**, still verifies |
| `signed.tgev.json` | `minimal` with an Ed25519 signature |
| `unicode.tgev.json` | **NFC vs NFD** at the envelope level, in both a committed leaf and a hashed step field |

`committed` and `redacted` share the anchor
`63f138b78374b62e86ed13cd3d2492b46914db1b5c50553e0b4ae315c6da8766`. That
equality is the whole point of commitment-based redaction and `check.mjs`
asserts it explicitly.

#### Why `unicode.tgev.json` exists, and what `committed` does *not* cover

`committed` was previously documented here as covering "NFC vs NFD". **It does
not.** Its `input.unicode.nfd` leaf holds the *precomposed* string — both of its
unicode leaves are byte-identical — because the generator built them from source
literals and the source file was Unicode-normalized on save long before Node ran
it. An implementation that silently NFC-normalizes every string passes
`09 verify/committed` regardless. (Reported as F1 in
[`../../verifiers/python/FINDINGS.md`](../../verifiers/python/FINDINGS.md).)

`committed` is **frozen** — records published since 0.3.0 verify against its
hashes — so it was left byte-for-byte as it is, and `unicode.tgev.json` was
added alongside it instead. That run carries the same grapheme twice:

```
input.unicode.nfc  63 61 66 e9         "caf" + U+00E9        (precomposed)
input.unicode.nfd  63 61 66 65 301     "cafe" + U+0301       (decomposed)
```

`check.mjs` does not take the file's word for it. It asserts the exact code
points, then NFC-normalizes the payload and the `label` and requires
verification to **fail** — at `input.unicode.nfd` and `input.note` via the
commitment pass (SPEC §9.4), and at the step hash via `label`, which is a hashed
field (SPEC §5.1). Those two mechanisms are separate on purpose: once a step
carries commitments the raw payload no longer feeds the step hash at all, so a
verifier that checks only the chain would miss the payload half entirely.

If you are porting the format, this is the vector that tells you whether your
JSON layer normalizes behind your back. Several do.

**Writing decomposed strings.** `generate.mjs` builds all three of these from
`\uXXXX` escapes and asserts their code points at startup. Do not "simplify"
them back to literals: a decomposed literal does not survive an editor save, and
that single convenience is the entire cause of F1.

## How to use these when porting

Work in this order — each layer depends on the one above it:

1. **`01-canonical.json`.** Parse each `inputJson` as JSON, canonicalize it, and
   compare to `canonical` byte-for-byte. Inputs are given as JSON *text* so they
   are unambiguous in any language, including lone surrogates and raw control
   characters. Do not proceed until all 47 pass — everything else is built on
   this.
2. **`02-commitments.json`.** Reproduce the leaf paths, then the commitments.
   `commitment = SHA256_hex(UTF8(salt_text ‖ canonical(value)))`.
3. **`03-steps.json`.** Reproduce each `canonicalStep`, then each `hash`. The
   full `hashPreimage` is included so you can diff the exact bytes when a hash
   disagrees.
4. **`04-runs/`** and **`05-signature.json`.** Run the full verification
   algorithm (SPEC §9) end to end.

### The four that will catch you out

* **`key-order-array-index`** — numeric-string keys sort *numerically* and come
  before all other keys. An RFC 8785 (JCS) library gets this wrong. SPEC §4.2.2.
* **`key-order-astral`** — keys sort by UTF-16 code unit, not code point, so an
  emoji key sorts before a U+E000 key. SPEC §4.2.3.
* **`number-1e-5`, `number-micro-cost`, `number-1e-7`** — any non-zero magnitude
  below `1e-4` is where a naive Python or Java verifier diverges. SPEC §4.4.2.
* **`unicode-nfd` and the `unicode` run** — no normalization is ever applied,
  so `caf` + `U+00E9` and `cafe` + `U+0301` are different values with
  different hashes (SPEC §4.2.4). They are written as code points here rather
  than as glyphs because the two render identically, and this document would
  otherwise carry the very bug the `unicode` run exists to catch. Check it
  against a real envelope, not just the scalar vector: the failure mode is a
  JSON, editor or database layer normalizing underneath you.

The vectors prefixed **`AMBIGUOUS-`** in `02-commitments.json` pin *known
defects* (SPEC §12.5), not desirable behaviour. Reproduce them to be
bug-compatible with v1; do not treat them as design.

## Regenerating

```bash
npm run build
node docs/test-vectors/generate.mjs
node docs/test-vectors/check.mjs
```

Output is deterministic — fixed ids, timestamps, salts, span ids, and a fixed
key (Ed25519 signatures are deterministic per RFC 8032). Regenerating on an
unchanged build produces a byte-identical corpus, so any diff in `git status`
after regeneration means the implementation moved.

`generate.mjs` imports the real implementation. `check.mjs` deliberately does
not: it re-implements string escaping, key ordering, number formatting, the
hashed-field set, commitment substitution, the chain rule and the verification
algorithm from the prose in `SPEC.md` alone. The two agreeing is the evidence
that the spec is sufficient to build an independent verifier — which is the
point of writing it down.
