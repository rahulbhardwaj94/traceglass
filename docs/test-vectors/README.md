# traceglass format test vectors

A frozen conformance corpus for [`SPEC.md`](../../SPEC.md). Every value here was
produced by running the shipped `@traceglass/core` implementation, not by hand.

```bash
node docs/test-vectors/check.mjs      # 132 checks, all must pass
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
| `03-steps.json` | canonical step forms, full hash preimages, and chain hashes for three runs |
| `04-runs/*.tgev.json` | four complete evidence envelopes |
| `05-signature.json` | signed message, key id, and signature under the published test key |
| `keys/` | Ed25519 test keypair — **published, TEST ONLY** |
| `check.mjs` | reference verifier; imports nothing from `@traceglass/core` |
| `generate.mjs` | regenerates the corpus from the real implementation |

### The four runs

| Run | Demonstrates |
|---|---|
| `minimal.tgev.json` | a two-step chain with no commitments — the pre-0.6 hashing shape, still valid |
| `committed.tgev.json` | per-leaf commitments over a deliberately awkward payload: NFC vs NFD, a ZWJ emoji, empty containers, `0.1+0.2`, a micro-cost, and `MAX_SAFE_INTEGER` |
| `redacted.tgev.json` | the same run with `input.query` erased — **same anchor**, still verifies |
| `signed.tgev.json` | `minimal` with an Ed25519 signature |

`committed` and `redacted` share the anchor
`63f138b78374b62e86ed13cd3d2492b46914db1b5c50553e0b4ae315c6da8766`. That
equality is the whole point of commitment-based redaction and `check.mjs`
asserts it explicitly.

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

### The three that will catch you out

* **`key-order-array-index`** — numeric-string keys sort *numerically* and come
  before all other keys. An RFC 8785 (JCS) library gets this wrong. SPEC §4.2.2.
* **`key-order-astral`** — keys sort by UTF-16 code unit, not code point, so an
  emoji key sorts before a U+E000 key. SPEC §4.2.3.
* **`number-1e-5`, `number-micro-cost`, `number-1e-7`** — any non-zero magnitude
  below `1e-4` is where a naive Python or Java verifier diverges. SPEC §4.4.2.

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
