# Proposal: number encoding, and the versioned canonicalizer

**Status:** proposal, awaiting a decision. Nothing here is implemented.
**Scope:** `canonicalize()` in `packages/core/src/integrity/hash.ts`, and the
`Run` model.
**Prerequisite for:** every item in [`SPEC.md`](../SPEC.md) §12.
**Hard constraint:** records published since 0.3.0 exist in the wild and MUST
keep verifying, byte-for-byte, forever.

---

## 1. TL;DR

**Recommendation: option (c) — keep floats and pin the exact algorithm — with
the note that this requires no change to any published hash, because v1's
number encoding is *already* the algorithm we would choose.**

Three things follow from that, and they are the actual decision:

1. **Numbers were never the emergency.** v1 encodes numbers using ECMAScript
   `Number::toString`, which is byte-identical to RFC 8785 (JCS) — a published
   standard with conforming libraries in Python, Go, Java, Rust and C#. Nothing
   needs to migrate. What was missing was the *written rule* and a conformance
   corpus, and both now exist ([`SPEC.md`](../SPEC.md) §4.4, 20 number
   vectors). **Recommend: adopt as-is, ship the spec, close the item.**

2. **Key ordering *is* the emergency, and it is worse.** While writing the spec
   I found that `canonicalize` does **not** sort keys the way it appears to.
   Objects with numeric-string keys come out in *numeric* order, not
   lexicographic, because ECMAScript property enumeration overrides the sort
   (SPEC §4.2.2). This is a genuine divergence from JCS and from every "just
   sort the keys" implementation — including the JCS libraries that make
   recommendation 1 easy. **This, not the number encoding, is what will break
   the first third-party verifier.**

3. **Money should stop being a float regardless.** Option (b) is right on its
   own merits and wrong as a fix for hashing — it solves `cost` and leaves
   every float in `input`/`output`/`dataPayload` untouched. **Recommend: adopt
   (b) additively in v2, framed as an arithmetic-correctness change, not an
   integrity one.**

And underpinning all of it: **a per-record `hashVersion` must be added before
anything else on that list can move** (§5). Today no record states which rules
produced its hashes, so there is no safe way to change any of them.

---

## 2. The problem, measured

JSON does not specify how a number is serialized. Two conforming JSON writers
can encode the same IEEE-754 double differently, hash different bytes, and
reject each other's perfectly valid records.

Measured, using the wire forms a traceglass producer actually writes, re-encoded
by CPython 3's `json.dumps(json.loads(x))`:

| on the wire | Python re-encodes | |
|---|---|---|
| `0.30000000000000004` | `0.30000000000000004` | ok |
| `4.7` | `4.7` | ok |
| `0.0001` | `0.0001` | ok |
| `100` | `100` | ok |
| `1e+21` | `1e+21` | ok |
| `5e-324` | `5e-324` | ok |
| `0.00001` | `1e-05` | **mismatch** |
| `0.000025` | `2.5e-05` | **mismatch** |
| `0.000001` | `1e-06` | **mismatch** |
| `1e-7` | `1e-07` | **mismatch** |

The divergence band is `0 < |v| < 1e-4`, for two compounding reasons: Python
switches to exponential notation at `1e-4` where ECMAScript switches at `1e-7`,
and Python zero-pads the exponent where ECMAScript does not.

Two things are worth noting honestly.

**It is narrower than feared.** `cost: 4.7` — the example in the brief and the
README — round-trips fine. So does every value above `1e-4`, and so does
everything large (above `2**53` every double is integral, so a Python verifier
parses it as an `int` and re-emits it identically). A naive Python verifier
would verify most real records correctly.

**It is still real, and it is silent.** `0.000025` is a per-token cost. A run
whose cheapest step costs a fraction of a paisa fails verification in Python and
passes in Node, and the error message says *"the record was modified after
recording"* — pointing an auditor at fraud when the actual cause is a two-digit
exponent. **A false integrity alarm in an evidence product is the worst possible
failure mode**: it is indistinguishable from the thing the product exists to
detect.

For calibration, the shipped fixtures (`fixtures/*.json`, the demo trace) contain
**zero** values in the divergence band, zero array-index keys, and zero dotted
keys. Every edge in this document is latent, not currently exercised. That is
exactly why none of it was noticed — and exactly why it will be noticed by
someone else, in production, at the worst moment.

---

## 3. The options

### (a) Pin a bespoke canonical decimal encoding for the hash input only

Leave the model alone; define our own number-to-string rule used *only* when
computing hashes. The cleanest variant is the **exact decimal expansion** of the
binary64 (every double has one, finite): `4.7` →
`4.70000000000000017763568394002504646778106689453125`.

* **Reproducible?** Perfectly, and trivially — any language with a big-decimal
  type can do it in a few lines with no shortest-round-trip algorithm needed.
* **What breaks:** every hash in existence. `4.7` currently contributes the
  three bytes `4.7`.
* **Do published records still verify?** **No** — not without `hashVersion`.
  With it, old records keep the v1 rule and verify forever.
* **Migration:** `hashVersion: 2` (§5). No record is ever rewritten.
* **Verdict: reject.** It buys determinism we already have, at the cost of a
  format change, a bespoke rule nobody else implements, ~50-character preimages
  for ordinary costs, and hashes that no existing library reproduces. Option (c)
  gets identical determinism with an RFC behind it.

### (b) Move money to integer minor units

`cost: 4.7` (INR) becomes `costMinor: 470` with `currency: "INR"` and an implied
or explicit exponent.

* **Reproducible?** For money, yes, absolutely — integers have one encoding
  everywhere.
* **What breaks:** the `Step` and `RunTotals` schemas; the SDK's `cost` argument;
  every ingester (Claude Code JSONL, OTel); the dashboard; report generation;
  the policy engine's cost thresholds; stored SQLite rows. This is the largest
  blast radius of the three by a wide margin.
* **Do published records still verify?** Only with `hashVersion` **and** a
  parallel model — old records carry `cost`, new ones `costMinor`, and every
  consumer handles both indefinitely.
* **Migration:** dual-field, `cost` deprecated but never removed.
* **Verdict: adopt, but not for this reason.** It **does not solve the stated
  problem.** `input`, `output` and `dataPayload` are arbitrary caller-supplied
  JSON: latencies, temperatures, embedding values, confidence scores, prices
  from a tool response. Those floats get committed and hashed no matter what
  `cost` looks like. The number problem is a *payload* problem; money is merely
  its most visible instance.

  It is still worth doing on its own merits. `totals.cost` is computed by
  summing floats across every step; over ten thousand steps that accumulates
  visible error, and two implementations summing in different orders get
  different totals. Floats are the wrong type for money independent of hashing.
  Frame it that way, schedule it separately, and do not let it block the spec.

### (c) Keep floats; specify the exact algorithm and require verifiers to match

Declare — as [`SPEC.md`](../SPEC.md) §4.4 now does — that numbers are encoded
with **ECMAScript `Number::toString`, radix 10**: shortest round-tripping
decimal digits, fixed notation for `1e-7 < |v| < 1e21`, exponential outside it,
exponent unpadded and explicitly signed, `-0` → `0`, non-finite → `null`, all
arithmetic in binary64.

* **Reproducible?** Yes. The hard part — shortest-round-trip formatting — is
  solved and available everywhere (Ryū, Grisu, Dragon4); it is what
  `repr(float)` uses in Python 3, what `strconv` uses in Go, what `ryu` gives
  Rust. The remaining work is the notation wrapper, which is ~30 lines.
* **What breaks:** nothing. This is what the code already does.
* **Do published records still verify?** **Yes — every one of them, unchanged.**
* **Migration:** none.
* **The decisive advantage:** this is *exactly* RFC 8785 (JCS) §3.2.2.3, which
  specifies ECMAScript number serialization for the same reason. So a
  third-party implementer does not have to implement §4.4 from our prose at all
  — they can pull a JCS library and get our number encoding for free.

**Verdict: adopt.** It is the status quo, it is free, and it comes with an RFC
and an ecosystem.

---

## 4. The finding that changes the priority

Recommending (c) rests on "just use a JCS library". While validating the test
vectors against an independent implementation, that recommendation broke — and
the reason matters more than the numbers do.

`canonicalize` looks like it sorts keys:

```ts
for (const key of Object.keys(value).sort()) out[key] = sortValue(value[key]);
return JSON.stringify(out);
```

It does sort them. Then `JSON.stringify` **re-orders them again**. ECMAScript's
`OrdinaryOwnPropertyKeys` always emits integer-index properties first, in
ascending numeric order, regardless of insertion order. The sort does not
survive the round-trip through a plain object.

```
input      {"10":1,"2":2,"1":3}
tgcanon/1  {"1":3,"2":2,"10":1}      ← numeric order
JCS        {"1":3,"10":1,"2":2}      ← lexicographic — DIFFERENT HASH
```

So `tgcanon/1` is JCS **except** for objects containing array-index keys, where
it silently differs. Confirmed against the shipped build; pinned by vectors
`key-order-array-index`, `key-order-index-vs-string`, `key-order-big-numeric`.

Why this outranks the number issue:

| | numbers | key ordering |
|---|---|---|
| Divergence band | `0 < \|v\| < 1e-4` | any object with a numeric-string key |
| Hits which languages | Python, Java, Rust-f64 | **every JCS library, including Go and Node ones** |
| Fix for a third party | use a JCS library | **a JCS library gives the wrong answer** |
| Discoverable? | vectors catch it | vectors catch it — but only if they exist |

Numeric-string keys are ordinary: `{"1": {...}, "2": {...}}` id maps, status-code
maps, array-like JSON from PHP or older APIs, any `Object.fromEntries` over
numeric ids. An implementer who reaches for `canonicaljson` and gets 95% of
records right will conclude the format is sound, and be wrong.

**Consequence for the decision:** option (c) is still right, but its
justification — "just use JCS" — is only true after this is fixed. The proposal
is therefore:

* **v1 (frozen):** documented exactly as it behaves, array-index quirk and all.
  SPEC §4.2.2 gives the rule in full and the vectors pin it, so a v1 verifier is
  buildable today. No published record changes.
* **v2:** drop the quirk. Sort *all* keys by UTF-16 code unit, i.e. become
  actual JCS. Then "use a JCS library" is simply true, and §4.2 collapses to a
  one-line reference.

---

## 5. The mechanism: a versioned canonicalizer

Nothing above — nor anything in SPEC §12 — can move without this. Today a
record states nothing about which rules produced its hashes, so any change to
`canonicalize()` silently invalidates every historical record.

### 5.1 The declaration

Add one optional field to `Run`:

```ts
/** Which canonicalization + hashing rules produced this record's hashes.
 *  Absent means 1 (every record written before this field existed). */
hashVersion: z.number().int().positive().optional(),
```

Run-level, not step-level: all steps in a run are chained together, so mixing
rules within a chain is meaningless.

`undefined ⇒ 1` is what makes this free. Every record published since 0.3.0
declares version 1 by omission, and keeps verifying under the v1 rules forever.

### 5.2 The dispatch

```ts
// integrity/canon/index.ts (new)
export const CANONICALIZERS: Record<number, Canonicalizer> = { 1: canonV1, 2: canonV2 };
export const CURRENT_HASH_VERSION = 1;   // bumped only on a deliberate flag day

export function canonicalizerFor(hashVersion = 1): Canonicalizer {
  const c = CANONICALIZERS[hashVersion];
  if (!c) throw new UnsupportedHashVersionError(hashVersion, Object.keys(CANONICALIZERS));
  return c;
}
```

`canonV1` is today's function, moved verbatim and **never touched again**. Its
test is the frozen corpus. A change to `canonV1` that moves any vector is a
release blocker, and CI should say so in those words.

Threading it through requires passing the version into `hashStep`,
`canonicalStep`, `commitmentFor` and `verifyRun` — mechanical, ~40 lines, no
behaviour change while `CURRENT_HASH_VERSION` stays 1.

### 5.3 Verifier behaviour

| Record declares | Verifier does |
|---|---|
| absent | verify with v1 |
| `1` | verify with v1 |
| `2` (and supported) | verify with v2 |
| `3` (unknown) | **refuse**, naming both versions: *"This record uses hash version 3; this build verifies up to 2. Upgrade traceglass to verify it."* |

Refusing is the only correct answer for an unknown version: the verifier cannot
compute the right hashes, so both "valid" and "tampered" would be lies. This
mirrors the existing `formatVersion` gate in `parseEvidence`.

### 5.4 Downgrade protection

`hashVersion` is metadata about the hashing, so it cannot itself be hashed by
the chain without circularity — and for the many records that canonicalize
identically under v1 and v2 (anything with no array-index keys), flipping the
declaration is a no-op an attacker gains nothing from.

It should nevertheless be bound: fold it into the signed message alongside the
run metadata proposed in SPEC §12.1, so the signature covers
`{runId, runHash, signedAt, hashVersion, meta}`. That is one change, closing
§12.1 and this at once.

### 5.5 Rollout

1. **Now.** Ship `SPEC.md` + the frozen corpus. Add `check.mjs` to CI as a
   regression gate on `canonicalize`. *No code change to hashing.* This alone
   removes the "any incidental change silently invalidates everything" risk,
   which is the risk actually costing us today.
2. **Next minor.** Add `hashVersion` to the model (optional, unwritten),
   introduce the dispatch, keep `CURRENT_HASH_VERSION = 1`. Fully backward
   compatible; nothing on disk changes.
3. **When v2 is worth it.** Implement `canonV2` — JCS key ordering (§4), path
   escaping (SPEC §12.5), `runId` in the hashed set (§12.2), domain-separated
   preimages (§12.6) — behind an opt-in flag. Freeze a v2 corpus alongside v1.
4. **Flag day.** Flip `CURRENT_HASH_VERSION` to 2 in a minor release. New
   records declare `2`; old records are **never rewritten** and never need to
   be.

The migration path for existing records is, in full: **nothing happens to
them.** That is the payoff of an append-only store with per-record versioning —
the expensive part of a format migration is the rewrite, and there is no
rewrite. The permanent cost is that verifiers carry v1 forever: roughly 60 lines
and a frozen test corpus. That is cheap, and it is the price of having published
records at all.

---

## 6. Urgency

**The number encoding itself: low.** No published record is at risk, no
migration is pending, and the divergence band is narrow. It becomes zero once
SPEC §4.4 and the vectors ship.

**Publishing the spec and corpus: high, and it is the real deadline.** The
danger is not a future migration. It is that today, with no written rule, three
distinct things are true at once:

* nobody outside this repo can write a verifier that is *known* to be correct —
  which means the central product claim, "regulator-grade evidence anyone can
  check", is not yet true;
* any incidental refactor of `canonicalize()` — a tidier sort, switching to a
  JSON library, an "obvious" cleanup of the double round-trip through
  `Object.keys().sort()` — silently invalidates every record ever written, with
  no test that fails. The array-index quirk is *exactly* the kind of thing a
  well-meaning cleanup would "fix";
* the first third-party verifier will be written against a JCS library, will
  disagree on some records, and the disagreement will surface as
  *"the record was modified after recording."*

**`hashVersion`: medium, and rising.** Cost scales with the number of published
records, and it is the gate on nine of the ten items in SPEC §12 — including
SPEC §6.2, where run `currency` can be flipped on a signed record without
detection. That one is a bigger honesty problem than anything about float
formatting, and it cannot be fixed until this lands.

**Money as integers: low, and independent.** Schedule on arithmetic-correctness
grounds when `totals.cost` drift starts mattering. Do not couple it to this.

---

## 7. What is actually being asked

1. **Approve option (c)** — ratify v1's number encoding as specified, and close
   the number question. *(No code change.)*
2. **Approve shipping `SPEC.md` and the frozen corpus, with `check.mjs` wired
   into CI** as a regression gate on `canonicalize`. *(No code change to
   hashing.)*
3. **Approve adding `hashVersion`** (optional, defaulting to 1) and the
   canonicalizer dispatch, as a separate no-op change.
4. **Decide whether v2 is worth doing at all**, given it exists to serve
   third-party verifiers we do not have yet. My view: yes, but not now — bank
   items 1–3, and let the first real external verifier tell us which of SPEC
   §12 actually hurts.
5. **Note, separately from all of the above,** that SPEC §12.5 (dotted keys
   causing a *false* integrity failure on an honest record) is a live bug
   reachable with an ordinary payload like `{"user.email": "…"}`, and does not
   need `hashVersion` to be detected — only to be fixed. A producer-side
   warning could ship immediately.
