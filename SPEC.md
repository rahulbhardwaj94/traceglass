# traceglass evidence format — specification v1

**Status:** Descriptive. This document specifies the format as implemented and
published in `traceglass` / `@traceglass/core` **0.3.0 – 0.7.2**. It is written
so that an independent verifier can be built in any language without reading
the TypeScript.

**Normative scope.** §§2–10 describe what conforming implementations MUST do,
and describe what the current code *actually does* — including several places
where that is not what a reasonable person would have designed. Those places
are marked **⚠ Surprising** inline and collected in §12, with proposed changes.
Nothing in §12 is normative for v1.

**Conformance.** A frozen corpus lives in [`docs/test-vectors/`](docs/test-vectors/).
`docs/test-vectors/check.mjs` is a reference verifier written only from this
document; it reproduces every vector. If your implementation reproduces the
corpus, it interoperates.

Key words MUST, MUST NOT, SHOULD, MAY are used per RFC 2119.

---

## 1. Overview

A traceglass record is one **Run**: an ordered list of **Steps** taken by an AI
agent, sealed by a SHA-256 hash chain and optionally signed with Ed25519.

```
hash(step_i) = SHA256( canonical(step_i) ‖ hash(step_{i-1}) )
hash(step_0) = SHA256( canonical(step_0) ‖ "" )
runHash      = hash(step_last)              ← the "anchor"
signature    = Ed25519( canonical({runId, runHash, signedAt}) )
```

Payload leaves may additionally carry **salted commitments**, which decouple the
hash from the raw payload bytes and so allow a value to be erased later without
breaking the chain (§8).

Everything reduces to one primitive: a deterministic JSON encoding, `tgcanon/1`
(§4). Get that byte-exact and everything else follows.

### 1.1 What this format proves — and what it does not

It proves, offline, from the file alone:

* the steps are in the order they were sealed in, and none has been edited,
  inserted, or removed (§5, §6);
* every visible committed payload leaf still matches what was recorded (§9.4);
* the anchor was signed by the holder of *some* Ed25519 private key (§7).

It does **not** prove:

* **that the key is the agent's key.** Verification uses the public key
  embedded in the file. An attacker who rewrites the record, re-chains it, and
  re-signs it with a key they generated passes verification cleanly. Today's
  guarantee is *"this file is internally consistent and self-attested"*, not
  *"this is the record the agent produced."* Establishing the second requires
  out-of-band key trust or a transparency log — see §11.1. **This is verified
  behaviour, not a theoretical concern**; see `docs/threat-model.md` §4.1.
* **anything about run-level metadata.** `name`, `status`, `currency`,
  `totals`, `startedAt`, `endedAt` and `warnings` are covered by *no* hash and
  can be edited freely on a signed record without detection (§6.2). ⚠
* **that a redaction was authorised, or that one happened at all** (§8.6). ⚠

---

## 2. Conventions and terminology

| Term | Meaning |
|---|---|
| **octet string** | a sequence of bytes |
| **canonical form** | the output of `tgcanon/1` (§4), a sequence of UTF-16 code units; hashed as its **UTF-8 encoding** |
| **hex** | lowercase base-16, no prefix |
| `‖` | concatenation |
| **leaf** | a JSON value with no children, per §8.1 |
| **anchor** | the run's `runHash` |

All hashes are SHA-256 (FIPS 180-4), rendered as 64 lowercase hex characters.
All signatures are Ed25519 (RFC 8032), rendered as standard base64 (RFC 4648
§4, with padding).

Where this document says "hash the canonical form", it means: encode the
canonical form as UTF-8 and hash those bytes.

---

## 3. Data model

A record is a JSON document. Two shapes are accepted (§10.2):

* an **evidence envelope** (`.tgev`), or
* a **bare Run** object.

### 3.1 Envelope

```jsonc
{
  "formatVersion": 1,     // integer; MUST be 1
  "exportedAt": "…",      // ISO 8601 timestamp, informational
  "run": { … }            // a Run (§3.2)
}
```

A document is treated as an envelope iff it is an object containing the key
`formatVersion`. Otherwise it is parsed as a bare Run.

`exportedAt` is not covered by any hash or signature.

### 3.2 Run

| Field | Type | Req. | Hashed? | Notes |
|---|---|:--:|:--:|---|
| `id` | string, non-empty | ✔ | signature only | the run id |
| `name` | string | ✔ | ✘ ⚠ | |
| `startedAt` | string | ✔ | ✘ ⚠ | ISO 8601 |
| `endedAt` | string | ✔ | ✘ ⚠ | ISO 8601 |
| `status` | `"completed"` \| `"failed"` \| `"running"` | ✔ | ✘ ⚠ | `running` only for an unfinalized journal |
| `currency` | string | ✔ | ✘ ⚠ | e.g. `"INR"`; **the unit for every `cost`** |
| `totals` | object | ✔ | ✘ ⚠ | `{tokens, cost, durationMs, steps}`, all non-negative numbers |
| `warnings` | array | ✔ | ✘ | `{kind, message, stepIds}`; derived, not evidence |
| `steps` | array of Step | ✔ | ✔ (each) | order is significant |
| `runHash` | string | ✔ | — | the anchor (§6); `""` for an empty or in-flight run |
| `signature` | RunSignature | ✘ | — | §7 |

Unknown top-level members are ignored by the reference implementation (the Zod
schema strips them). A verifier MUST NOT treat an unknown member as an error,
and MUST NOT include it in any hash.

### 3.3 Step

| Field | Type | Req. | Hashed? |
|---|---|:--:|:--:|
| `id` | string, non-empty | ✔ | ✔ |
| `runId` | string, non-empty | ✔ | **✘ ⚠** (§12.2) |
| `index` | non-negative integer | ✔ | ✔ |
| `type` | enum (§3.4) | ✔ | ✔ |
| `label` | string | ✔ | ✔ |
| `startedAt` | string (ISO 8601) | ✔ | ✔ |
| `durationMs` | non-negative number | ✔ | ✔ |
| `tokens` | non-negative number | ✔ | ✔ |
| `cost` | non-negative number | ✔ | ✔ |
| `toolName` | string | ✘ | ✔ if present |
| `input` | any JSON | ✘ | ✔ if present (or its commitments — §5.2) |
| `output` | any JSON | ✘ | ✔ if present (or its commitments) |
| `dataPayload` | any JSON | ✘ | ✔ if present (or its commitments) |
| `spanId` | string | ✔ | ✔ |
| `parentSpanId` | string | ✘ | ✔ if present |
| `hash` | 64 hex | ✔ | — (it *is* the hash) |
| `prevHash` | 64 hex or `""` | ✔ | — (mixed in, not covered) |
| `commitments` | map path → 64 hex | ✘ | indirectly (§5.2) |
| `salts` | map path → hex | ✘ | **✘** — by design (§8) |
| `redactions` | array of RedactionRecord | ✘ | **✘** — by design ⚠ (§8.6) |

### 3.4 Step types

`user_input`, `plan`, `tool_call`, `llm_reasoning`, `branch`, `approval`,
`final_output`, `error`.

A verifier MUST NOT reject an unrecognised `type` on integrity grounds; the
type is an opaque string as far as hashing is concerned.

### 3.5 RunSignature

```jsonc
{
  "algorithm": "ed25519",  // MUST be exactly this string
  "keyId":     "…",        // 16 lowercase hex (§7.3)
  "publicKey": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
  "signature": "…",        // base64, 64 raw bytes decoded
  "signedAt":  "…"         // ISO 8601; part of the signed message
}
```

### 3.6 RedactionRecord

```jsonc
{ "path": "input.ssn", "at": "…", "reason": "…", "by": "pattern" | "manual" }
```

`reason` and `by` are optional. Not covered by any hash (§8.6).

---

## 4. `tgcanon/1` — canonical JSON

This is the whole ballgame. `tgcanon/1` maps a JSON value to a unique string.

The current implementation is:

```js
canonicalize(v) = JSON.stringify(sortRecursively(v))
```

which means **`tgcanon/1` is defined by ECMAScript's `JSON.stringify` and by
ECMAScript's object property enumeration order.** The rest of this section
states those rules explicitly, so that no implementer has to own a JavaScript
engine to interoperate.

> `tgcanon/1` is *close to* RFC 8785 (JCS) but is **not** JCS. The differences
> are §4.2.2 (array-index key ordering) and §4.5 (undefined-member elision).
> Do not substitute an off-the-shelf JCS library without reading those two.

### 4.1 Input domain

`tgcanon/1` is defined for the JSON value space: object, array, string, number,
`true`, `false`, `null`.

Values outside that space have implementation-defined behaviour and MUST NOT
appear in a record. For reference, the current implementation:

* `undefined`, functions and symbols → §4.5;
* non-finite numbers (`NaN`, `±Infinity`) → the literal `null`;
* class instances lose their identity — a `Date` canonicalizes to `{}`, because
  the recursive sort rebuilds every object from its own enumerable keys and so
  discards prototype methods including `toJSON`. ⚠ Records are produced from
  parsed JSON in practice, so this does not arise, but a producer that hands
  `canonicalize` a live object will get silent nonsense.

### 4.2 Objects

An object is encoded as `{` `}` with members separated by `,` and each member
encoded as `key : value` — the key by §4.3, the value recursively — with **no
whitespace anywhere**.

#### 4.2.1 Key ordering — two buckets

Keys are emitted in this order:

1. **Array-index keys**, in **ascending numeric order**.
2. **All other keys**, in ascending **UTF-16 code-unit** order (§4.2.3).

An **array-index key** is a string that is the canonical decimal representation
of an integer *n* with `0 ≤ n ≤ 2**32 − 2`: it matches `^(0|[1-9][0-9]*)$` and
`n ≤ 4294967294`. Note the exclusion of `2**32 − 1` = `4294967295`, and that
`"01"`, `"-1"`, `"1.5"` and `"1e2"` are **not** array-index keys.

#### 4.2.2 ⚠ Why bucket 1 exists, and why you will get this wrong

This rule is not a design decision. It is a leak from the runtime.

`canonicalize` sorts keys as strings and rebuilds the object — and then
`JSON.stringify` *re-orders them again*, because ECMAScript
`OrdinaryOwnPropertyKeys` always emits integer-index properties first, in
ascending numeric order, whatever order they were inserted in. The sort simply
does not survive.

The observable consequence:

```
input   {"10":1,"2":2,"1":3}
tgcanon {"1":3,"2":2,"10":1}      ← numeric
naive   {"1":3,"10":1,"2":2}      ← lexicographic, DIFFERENT HASH
```

Any implementation that "just sorts the keys" — including every RFC 8785 JCS
library — computes a different hash for any object with numeric-string keys.
Those are not exotic; `{"1": …, "2": …}` id maps, HTTP status maps and array-like
JSON all hit it. This is the single most likely cause of a cross-language
verifier disagreeing.

Vectors: `key-order-array-index`, `key-order-index-vs-string`,
`key-order-big-numeric` in `01-canonical.json`.

#### 4.2.3 UTF-16 code-unit ordering

Bucket-2 keys are compared as sequences of UTF-16 code units: compare code unit
by code unit; on the first difference the smaller code unit sorts first; if one
is a prefix of the other, the shorter sorts first.

This is **not** code-point order. A key beginning with an astral character
(U+10000 and above, encoded as a surrogate pair beginning in U+D800–U+DBFF)
sorts *before* keys beginning U+E000–U+FFFF:

```
input   {"\ud83d\ude00":1,"\ufffd":2,"\ue000":3}   (U+1F600, U+FFFD, U+E000)
tgcanon {"\ud83d\ude00":1,"\ue000":3,"\ufffd":2}   (emitted raw, shown escaped here)
```

Vector: `key-order-astral`.

#### 4.2.4 Duplicate keys and normalization

JSON objects with duplicate keys are outside the domain; behaviour depends on
the parser and MUST NOT be relied upon.

**No Unicode normalization is performed, ever** — not on keys, not on values.
`"café"` in NFC (U+00E9) and NFD (U+0065 U+0301) are distinct keys and distinct
strings, and hash differently. Producers that need normalization MUST do it
before recording. Vectors: `unicode-nfc`, `unicode-nfd`.

### 4.3 Strings

A string is emitted between `"` `"`. Each UTF-16 code unit is emitted as
follows, in priority order:

1. **Two-character escapes**, used wherever they apply:
   `"` → `\"`, `\` → `\\`, U+0008 → `\b`, U+0009 → `\t`, U+000A → `\n`,
   U+000C → `\f`, U+000D → `\r`.
2. Any other code unit `< U+0020` → `\u` followed by **four lowercase hex
   digits**: U+0000 → `\u0000`, U+001F → `\u001f`.
3. An **unpaired surrogate** (a lead U+D800–U+DBFF not followed by a trail, or
   a trail U+DC00–U+DFFF not preceded by a lead) → `\uXXXX`, lowercase hex.
   Well-formed surrogate pairs are emitted raw.
4. Everything else is emitted **raw** as its own character.

Note what is deliberately *not* escaped:

* the solidus `/` — never escaped;
* **U+007F (DEL)** — emitted raw, despite being a control character;
* **U+2028 and U+2029** (line/paragraph separator) — emitted raw. Some JSON
  writers escape these to keep output valid JavaScript; `tgcanon/1` does not.
* Non-ASCII characters generally — output is UTF-8 text, not ASCII-escaped.

Vectors: `string-escapes`, `string-controls`, `string-line-separators`,
`unicode-lone-surrogate`, `unicode-emoji-zwj`, `unicode-devanagari`.

### 4.4 Numbers — read this section twice

**This is the most portable-looking and least portable part of the format.**
JSON does not specify number serialization. Every language's JSON writer picks
a different one. Two verifiers can disagree on the encoding of the same double
and reject a perfectly valid record.

#### 4.4.1 The rule

A number is encoded as **ECMAScript `Number::toString` with radix 10**
(ECMA-262 §6.1.6.1.20). Informally, that algorithm is:

* Produce the **shortest decimal digit string that round-trips** to the same
  IEEE-754 binary64 value, together with its decimal exponent. (This is the
  Ryū / Grisu "shortest representation" — *not* 17 significant digits, and
  *not* the shortest that looks nice.)
* Let *k* be the number of significant digits and *n* the position of the
  decimal point (the value is `0.d₁…d_k × 10ⁿ`). Then apply the **first**
  matching row:

| Condition | Form | Example |
|---|---|---|
| `k ≤ n ≤ 21` | integer digits, then `n − k` zeros, no fraction, no exponent | `100`, `100000000000000000000` |
| `0 < n ≤ 21` | digits with a `.` inserted after position *n* | `4.7`, `0.30000000000000004`… |
| `−6 < n ≤ 0` | `0.` then `−n` zeros then the digits | `0.0001`, `0.000001` |
| otherwise | `d₁` [`.` `d₂…d_k`] `e` `+`/`-` `|n−1|` | `1e+21`, `1e-7`, `5e-324` |

Critically, in the exponential form the exponent is written with **no leading
zeros** and always with an explicit sign: `1e-7`, never `1e-07`, never `1e-007`.

Additional rules:

* **Negative zero encodes as `0`** — the sign is lost. (§4.4.3)
* Non-finite values encode as the literal `null`. (§4.4.4)
* Integers are integers: `100.0` and `1.0e2` both encode as `100`. There is no
  trailing `.0` anywhere in the format.
* Values are **binary64 throughout**. `9007199254740993` is not representable
  and encodes as `9007199254740992`. An implementation that parses JSON numbers
  into arbitrary-precision integers or decimals will produce a different
  encoding and a different hash. A conforming implementation MUST parse every
  JSON number as a binary64 double before encoding it.

#### 4.4.2 The magnitudes where other languages diverge — measured

Verified against CPython 3 `json.dumps(json.loads(x))`, taking `x` from the wire
form a traceglass producer actually writes:

| on the wire (traceglass) | Python re-encodes as | |
|---|---|---|
| `0.30000000000000004` | `0.30000000000000004` | ok |
| `4.7` | `4.7` | ok |
| `0.0001` | `0.0001` | ok |
| `1e+21` | `1e+21` | ok |
| `100` | `100` | ok |
| `5e-324` | `5e-324` | ok |
| `0.00001` | `1e-05` | **mismatch** |
| `0.000025` | `2.5e-05` | **mismatch** |
| `0.000001` | `1e-06` | **mismatch** |
| `1e-7` | `1e-07` | **mismatch** |

The divergence band is **`0 < |v| < 1e-4`**, for two independent reasons:
Python switches to exponential notation at `1e-4` where ECMAScript switches at
`1e-7`, and Python zero-pads the exponent to two digits where ECMAScript does
not. Large magnitudes happen to survive because every binary64 above `2**53` is
integral, so a Python verifier parses it as an `int` and re-emits it identically.

`0.000025` is not a contrived value. It is a per-token cost. **A run whose
cheapest step costs less than a hundredth of a paisa will silently fail
verification in a naive Python verifier, and pass in Node.** Nothing in the
error message would point at the number.

Other runtimes: Go's `encoding/json` deliberately mimics ECMAScript (including
stripping the exponent's leading zero) and is compatible. Java's
`Double.toString` is not — it always emits a fraction (`100.0`) and uses `E`
notation from `1e7` upward. Rust's `serde_json` emits `100.0` for an
integral `f64`, but recovers if numbers are parsed into `serde_json::Value`,
where integral JSON numbers become integer variants.

An implementation MUST NOT delegate number encoding to its language's default
JSON writer without checking it against the number vectors in
`01-canonical.json`.

#### 4.4.3 Negative zero

`-0` encodes as `0`. Two distinct binary64 values therefore share an encoding.
This is harmless here (`cost`, `tokens`, `durationMs` are all non-negative), and
matches RFC 8785.

#### 4.4.4 Non-finite values

`NaN`, `Infinity` and `-Infinity` encode as the literal `null`, silently.
Producers MUST NOT record them. ⚠ A verifier cannot distinguish "the value was
`null`" from "the value was `NaN`" after the fact.

### 4.5 Absent, `null`, and empty

* `null` is a value. It is preserved: `{"a":null}` → `{"a":null}`.
* An object member whose value has **no encoding** — in JavaScript terms
  `undefined`, a function, or a symbol — is **omitted entirely**:
  `{"a":undefined,"b":1}` → `{"b":1}`. There is no way to distinguish that from
  an object that never had `a`.
* An **array element** with no encoding becomes `null`, preserving length:
  `[undefined]` → `[null]`. Sparse array holes likewise.
* Empty containers are encoded as themselves: `{}` and `[]`. They are values,
  not absences, and §8.1 commits to them explicitly.
* ⚠ `canonicalize(undefined)` returns the JavaScript value `undefined`, **not a
  string**, despite the declared return type `string`. Anything concatenating
  the result gets the text `"undefined"`. This is reachable (§12.4); a
  conforming implementation SHOULD reject `undefined` as a top-level input.

### 4.6 Arrays

Encoded as `[` `]`, elements separated by `,`, no whitespace. **Order is
preserved and never altered** — an array is ordered data. Elements are encoded
recursively, subject to §4.5.

---

## 5. Step hashing

### 5.1 The hashed field set

Exactly these fields, when present (i.e. not `undefined` / absent), are
collected into a fresh object:

```
id, index, type, label, startedAt, durationMs, tokens, cost,
toolName, input, output, dataPayload, spanId, parentSpanId
```

Every other member of the step — including `runId`, `hash`, `prevHash`,
`salts`, `redactions`, and anything unrecognised — is excluded.

A member present with the value `null` **is** collected (only `undefined` /
absence excludes it); it then encodes as `null` per §4.5.

### 5.2 Commitment substitution

If and only if the step has a `commitments` member, then for each field *f* in
`input`, `output`, `dataPayload` in that order:

1. Build the **commitment view** of *f*: the sub-map of `commitments`
   containing every entry whose path *p* satisfies
   `p === f` **or** `p` starts with `f.` **or** `p` starts with `f[`.
2. If the view is non-empty, **replace** `picked[f]` with the view — the
   whole `{path: commitmentHex, …}` map — discarding the raw value.
3. If the view is empty, `picked[f]` keeps whatever §5.1 collected, i.e. the
   raw value. ⚠ (§12.3)

The commitment view is a plain JSON object and is canonicalized like any other:
its keys are the full dotted paths, sorted per §4.2.

Because the view's *keys* are hashed alongside its values, the **set of
committed paths** is covered by the step hash: a leaf cannot be added or
removed without breaking the chain.

### 5.3 Canonical step and chain rule

```
canonicalStep(step) = tgcanon( picked )                       (§5.1, §5.2)
hash(step, prevHash) = SHA256_hex( UTF8( canonicalStep(step) ‖ prevHash ) )
```

`prevHash` is the previous step's `hash`, or the **empty string** for the first
step. It is appended as text, directly, with no separator, length prefix or
domain-separation tag. This is unambiguous in practice because the canonical
form always ends in a delimiter and `prevHash` is fixed-width hex, but see
§12.6.

Worked example (`03-steps.json`, run `minimal`, step 0):

```
canonicalStep = {"cost":0,"durationMs":0,"id":"vec-min:0","index":0,
                 "input":"Summarise Q3 spend","label":"User request",
                 "spanId":"00000000000000a1","startedAt":"2026-07-25T09:00:00.000Z",
                 "tokens":0,"type":"user_input"}
prevHash      = ""
hash          = 00cfe8d49e5f804f9a86be29594aae555a8cd7e130d99ffff5a14595fdd326c6
```

(shown wrapped; the real canonical form contains no whitespace).

---

## 6. Run hash (the anchor)

```
runHash = hash of the LAST step in `steps`
runHash = ""  when `steps` is empty
```

The anchor is *not* a separate hash over the run. It is literally the final
link of the chain. Because each link mixes in the previous one, the anchor
transitively commits to every step and to their order.

A `Run` with `status: "running"` (an in-flight journal) carries `runHash: ""`
and is not yet anchored or signable.

### 6.1 Empty runs

A run with no steps has `runHash: ""` and verifies successfully. ⚠ It asserts
nothing.

### 6.2 ⚠ Run metadata is not covered by anything

Neither the chain nor the signature covers `name`, `startedAt`, `endedAt`,
`status`, `currency`, `totals` or `warnings`. All of them can be edited on a
signed record and the record still verifies clean, with a valid signature.

The consequential one is **`currency`**. Every `cost` in the record is a bare
number whose unit lives only in `run.currency`. Flipping `"INR"` → `"USD"`
re-denominates the entire record — a ~85× restatement of spend — with no
integrity signal whatsoever. `status` (`completed` ⇄ `failed`) and `totals` are
equally free.

This is verified behaviour, not speculation. See `docs/threat-model.md` §4.2
and the proposed fix in §12.1.

---

## 7. Signature

### 7.1 Signed message

```
message = tgcanon({ runId: run.id, runHash: run.runHash, signedAt: sig.signedAt })
```

Because the three keys are sorted, the message always has the shape:

```
{"runHash":"<64 hex>","runId":"<id>","signedAt":"<iso8601>"}
```

The message is encoded as UTF-8 and signed **directly** with Ed25519 — Ed25519
performs its own internal SHA-512, so there is no pre-hash and this is *not*
Ed25519ph.

Including `runId` prevents transplanting a signature onto another run.
Including `signedAt` binds the timestamp the signer asserts. Note that
`signedAt` is attacker-supplied at signing time and carries no external
timestamping authority.

### 7.2 Encodings

* `publicKey`: an Ed25519 public key as **SPKI, PEM-encoded**
  (`-----BEGIN PUBLIC KEY-----`). For Ed25519 the DER is 44 bytes, so the PEM
  body is a single 60-character base64 line.
* `signature`: the 64 raw signature bytes, **base64** (padded).
* `algorithm`: the exact string `"ed25519"`. Implementations MUST reject any
  other value. ⚠ The reference implementation does not read this field at all —
  it derives the algorithm from the key type.

### 7.3 Key id

```
keyId = first 16 lowercase hex characters of SHA256( SPKI DER of the public key )
```

That is 8 bytes of digest — an *identifier*, not a security boundary. It is
short enough that finding a colliding key is feasible for a motivated attacker;
never use `keyId` alone to decide trust.

⚠ The reference implementation does **not** check that `keyId` is consistent
with `publicKey`; a record can claim any `keyId` and still verify. A conforming
verifier SHOULD recompute it and reject a mismatch. `check.mjs` does.

### 7.4 Unsigned runs

`signature` is absent on pre-0.3.0 records and on records recorded without
keys. An absent signature is **not** a verification failure — it means *no
authenticity claim is made*. A verifier MUST report the distinction rather than
folding it into a boolean.

Vectors: `05-signature.json`, `04-runs/signed.tgev.json`. The private key in
`docs/test-vectors/keys/` is **published and for testing only**.

---

## 8. Commitments and redaction

### 8.1 Leaf walking and path syntax

Each of `input`, `output`, `dataPayload`, when present, is walked to its leaves
starting from a base path equal to the field name.

A **leaf** is:

* any non-container value — string, number, boolean, `null` — or
* an **empty** object `{}` or empty array `[]`.

Empty containers are leaves deliberately: emptiness is itself a fact worth
committing to, so `{"rows": []}` cannot be swapped for `{"rows": [1,2,3]}`.

Path construction, from base path `b`:

| At | Child path |
|---|---|
| object key `k`, `b` non-empty | `b + "." + k` |
| object key `k`, `b` empty | `k` |
| array element `i` | `b + "[" + i + "]"` |

So `input = {"rows":[{"id":1}]}` yields the single path `input.rows[0].id`, and
a scalar `input = "hi"` yields the path `input` itself.

Reading a path back tokenizes it: split on `.`, then split each part into a
name and any number of `[digits]` groups, and index into the container with
each token in turn (array indices as decimal strings).

### 8.2 Commitment construction

```
salt[p]        = 16 random bytes, lowercase hex (32 characters)
commitment[p]  = SHA256_hex( UTF8( salt[p] ‖ tgcanon(leafValue) ) )
```

The salt is concatenated **as its hex text**, not as raw bytes.

Example (`02-commitments.json`, `micro-number`):

```
salt       = 03030303030303030303030303030303
value      = 0.000025
preimage   = "030303030303030303030303030303030.000025"
commitment = SHA256_hex(preimage)
```

Note the preimage is unparseable — the salt and the canonical value run
together with no delimiter. See §12.6.

### 8.3 Why the salt is what makes erasure irreversible

Without a salt, `commitment = SHA256(value)` is trivially reversible for any
low-entropy value: an SSN is 10⁹ candidates, a boolean is 2, a currency amount
in a plausible range is thousands. The commitment would *be* the data.

With a 128-bit salt stored beside it, the commitment is useless to anyone who
does not hold the salt. **Redaction destroys the salt** — and with it the only
feasible route from the surviving commitment back to the value. What remains is
a proof that *something* was there and that it hashed to this, unverifiable
without a candidate salt.

This means the salts are as sensitive as the payload. Anywhere the record is
stored, the salt map is a decryption key for the commitment map, for low-entropy
leaves.

### 8.4 A redacted leaf on the wire

Three simultaneous changes, and no others:

1. the leaf value is replaced by the marker string
   `"[traceglass:redacted]"`;
2. the entry for that path is **deleted from `salts`**;
3. an entry is appended to `redactions`.

`commitments` is **unchanged**. So is `hash`, `prevHash`, `runHash`, and any
`signature`.

The invariant a verifier can rely on: *a path present in `commitments` but
absent from `salts` has been redacted.* That is the only signal.

### 8.5 Why the anchor survives

Because §5.2 replaced the raw payload with the commitment view before hashing,
the chain never covered the raw value in the first place. Redaction changes only
things the hash does not see: the raw value, the salt map, the redaction log.

The test vectors demonstrate this exactly — `04-runs/committed.tgev.json` and
`04-runs/redacted.tgev.json` differ in payload but share the anchor
`63f138b78374b62e86ed13cd3d2492b46914db1b5c50553e0b4ae315c6da8766`, and both
verify.

This is the property that makes GDPR Article 17 erasure compatible with an
audit record: you can honour a deletion request without invalidating the
evidence, and without the verifier having to trust you about it.

### 8.6 ⚠ Redaction is unauthenticated

Because `salts` and `redactions` are outside the hash, anyone who can write to
the file can:

* **erase any leaf silently** — delete the value and its salt, and the record
  verifies clean and indistinguishable from an authorised redaction. No
  `redactions` entry is required, because nothing checks for one;
* **delete the `redactions` log** from a genuinely redacted record, hiding that
  a redaction occurred;
* **fabricate `redactions` entries** for leaves that were never touched.

All three are verified to pass verification today (`docs/threat-model.md` §4.3).

The format therefore proves *"this leaf's value is gone and cannot be
recovered"*, and does **not** prove *"this leaf was removed by an authorised
party, at the stated time, for the stated reason."* A `redactions` entry is a
claim by whoever last wrote the file, nothing more. §12.1 proposes the fix.

### 8.7 Legacy redaction (pre-0.6 records)

Records written before 0.6.0 have no `commitments` and hash raw payloads, so a
value cannot be removed without changing hashes. Those go through a re-chaining
path that produces a **new** anchor and **drops the signature**. The result must
be re-signed, and is a materially weaker artefact: a verifier can confirm it is
internally consistent, but has no cryptographic link to the original record.
This is a distinct operation and MUST be labelled as such to the user.

---

## 9. Verification algorithm

A conforming verifier, given a document, performs these steps **in order**. Any
failure stops and is reported with the step index and id at which it occurred.

**9.1 Parse and version-gate.**
If the document has `formatVersion`, it MUST equal `1`; otherwise fail with an
unsupported-version error (§10). Take `run` from it. Otherwise treat the
document as a bare Run. Validate the shape per §3; a shape failure is a parse
error, not an integrity failure, and MUST be reported differently.

**9.2 Recompute the chain.**
Set `prev ← ""`. For each step in `steps`, in array order:

  a. if `step.prevHash ≠ prev` → **FAIL** (chain linkage broken here);
  b. compute `expected ← SHA256_hex(UTF8(canonicalStep(step) ‖ prev))` per §5;
  c. if `step.hash ≠ expected` → **FAIL** (step content altered here);
  d. `prev ← step.hash`.

The first failing step is the report point: everything after it is also
suspect, and everything before it is intact.

**9.3 Check the anchor.**
If `run.runHash ≠ prev` → **FAIL** (anchor altered). For an empty `steps`,
`prev` is `""`.

**9.4 Check commitments — do not skip this.**
For each step with a `commitments` member, for each `(path, commitment)`:

  a. look up `salt ← salts[path]`. If absent, mark the path **redacted** and
     continue — there is nothing left to check, by design;
  b. otherwise split `path` at the first `.` or `[` to get the field name;
     take the remainder as the relative path (dropping a leading `.`);
  c. read the value at that relative path within `step[field]`
     (a missing value reads as absent);
  d. if `SHA256_hex(UTF8(salt ‖ tgcanon(value))) ≠ commitment` → **FAIL**
     (payload altered at `path`).

> **This step is load-bearing.** Once a step carries commitments, §5.2 means the
> raw payload no longer affects the step hash *at all*. A verifier that checks
> only 9.2/9.3 will happily accept a record whose every visible payload value
> has been rewritten. Payload tamper-detection for commitment-bearing records
> lives entirely here. Do not treat it as an optional extra pass.

**9.5 Verify the signature, if present.**

  a. if `run.signature` is absent → report **unsigned**; this is not a failure
     (§7.4);
  b. `algorithm` MUST be `"ed25519"`;
  c. recompute `keyId` from `publicKey` (§7.3) and compare; a mismatch SHOULD
     fail;
  d. rebuild the message `tgcanon({runId: run.id, runHash: run.runHash, signedAt})`
     — using the **stored** `runHash`, which 9.3 has already proven equals the
     recomputed one;
  e. Ed25519-verify the base64-decoded `signature` against the message under
     `publicKey`. Failure → **FAIL**.

**9.6 Report.**
A conforming verifier MUST report at least: chain intact (yes/no, and where
not), commitments verified / redacted / mismatched (as path lists), signature
present-and-valid / present-and-invalid / absent, the recomputed anchor, and the
stored anchor.

It MUST NOT collapse "unsigned" and "signed and valid" into the same output.
It MUST NOT report a valid signature as evidence of origin without also
surfacing §11.1.

---

## 10. Versioning

### 10.1 What exists today

There is exactly one version marker, and it is on the wrong object:

* the envelope's `formatVersion`, currently `1`;
* the journal's `formatVersion` (an internal, on-disk format — not part of
  the evidence format).

**A `Run` carries no version of its own.** Nothing in the record states which
canonicalization or hashing rules produced its hashes. A bare Run (which
`parseEvidence` accepts) carries no version marker at all.

The hashing rules have in fact already changed once — 0.6.0 introduced §5.2
commitment substitution — and the format got away with it only because the
change was designed to be a no-op for records without `commitments`. That was
luck plus care, not a versioning mechanism. It does not generalise.

### 10.2 Verifier behaviour on an unknown version

* Envelope `formatVersion` ≠ 1 → **reject**, with a message naming both the
  document's version and the highest the verifier supports. A verifier MUST NOT
  attempt verification, because it cannot know which rules apply.
* No `formatVersion` at all → assume version 1 (this is how bare Runs and
  pre-envelope records are read).
* Unknown *members* within a known version → ignore for parsing, exclude from
  hashing (§3.2, §5.1). A future version that hashes a new field will therefore
  fail loudly against an old verifier (the field is stripped, the hash differs)
  rather than silently — which is the correct failure direction.

### 10.3 ⚠ What is missing

There is no way to change canonicalization without breaking every published
record, because no record says which canonicalization it used. Any
number-encoding fix, key-ordering fix, or metadata-coverage fix needs a
per-record `hashVersion` first. That mechanism is designed in
[`docs/number-encoding-proposal.md`](docs/number-encoding-proposal.md) §5 and is
a prerequisite for every change listed in §12.

---

## 11. Security considerations

Full analysis: [`docs/threat-model.md`](docs/threat-model.md). The two items
that belong in the format spec itself:

### 11.1 Key trust is out of band — the load-bearing limitation

Verification uses **the public key embedded in the record being verified**.
Nothing external is consulted. So:

> An attacker who can rewrite the file can rewrite the steps, re-chain them,
> sign the new anchor with a key they generated one second ago, and embed that
> public key. Offline verification passes, cleanly, with no warning.

This has been confirmed against the shipped implementation.

What the signature actually establishes is that **all of the record's contents
were sealed together by one keyholder** — it defeats partial edits by anyone
who lacks the private key, and it makes the record *attributable* once you
independently know whose key that is. That "independently" is the whole gap.

Until it is closed, a verifier MUST NOT present a valid signature as proof of
origin. The honest sentence is: *"internally consistent, and self-attested by
key `<keyId>`"* — with the keyId offered so a relying party can compare it to a
key they obtained by other means.

Planned closures, in increasing strength: pinning expected keyIds in the
verifier; publishing keys out of band; RFC 3161 timestamping of the anchor
(which bounds *when* the record existed, defeating post-hoc rewrites); and
appending anchors to a transparency log (which makes any rewrite detectable by
absence).

### 11.2 What a valid record does not say

* Nothing covers run metadata (§6.2) — cost figures are unit-less.
* Nothing proves a redaction was authorised (§8.6).
* Nothing proves the record is *complete*. A run that omits the awkward steps
  entirely produces a perfectly valid chain. The format seals what was
  recorded; it cannot attest to what was not.
* Nothing binds a step to its run: `runId` is outside the step hash (§12.2).
* `startedAt` and `signedAt` are producer-asserted wall-clock strings with no
  external time source.

---

## 12. Known defects and proposed changes

**Non-normative.** Each item states what the code does today (which §§2–11
describe faithfully) and what it should do instead. None may be implemented
without the `hashVersion` mechanism of §10.3, because all of them change hashes.

### 12.1 Run metadata and redaction metadata are outside the hash — *severity: high*

Today: §6.2, §8.6. `currency`, `totals`, `status`, `name`, timestamps,
`redactions` and the shape of `salts` are all freely editable on a verifying,
signed record.

Proposal: extend the signed message from `{runId, runHash, signedAt}` to
`{runId, runHash, signedAt, meta}` where `meta` is the canonical form of
`{name, startedAt, endedAt, status, currency, totals}`, and add the per-step
`redactions` array to a `redactionsHash` that is itself covered. This keeps the
chain untouched (so 8.5's redaction property survives) and closes both holes at
the signature layer, where they belong. Records that are unsigned gain nothing —
which is an argument for signing by default.

### 12.2 `runId` is not in the step hash — *severity: medium*

Today: a step's hash does not depend on which run it belongs to. A step can be
lifted verbatim from run A into run B, and if its chain position matches it
verifies. The signature binds the *run* id, so this only matters for unsigned
records and for tooling that handles loose steps (the journal does).

Proposal: add `runId` to the hashed field set in `hashVersion: 2`.

### 12.3 Partial commitments hash raw payloads — *severity: medium*

Today: §5.2 step 3. If `commitments` exists but has no entries for, say,
`output`, then `output` is hashed **raw** while `input` is hashed via
commitments. The record looks redaction-capable but that field is not; a later
redaction of it would break the chain, and the "check the commitments" pass
(§9.4) covers nothing there.

Proposal: make it a validity rule — if `commitments` is present, it MUST cover
every present payload field. A verifier could enforce this today without a
version bump, as a *warning*, since it does not change any hash.

### 12.4 `canonicalize(undefined)` returns `undefined`, not a string — *severity: low, but reachable*

Today: §4.5. The declared return type is `string`. `commitmentFor(salt,
undefined)` therefore computes `SHA256(salt + "undefined")` by JavaScript string
coercion rather than failing.

This is reachable: `walkLeaves` visits a member explicitly set to `undefined`
(`{"a": undefined}` yields a leaf at path `a`), so a commitment over the literal
text `"undefined"` can be created at capture time; and §9.4(c) reads an absent
value as `undefined`, so a deleted key is compared against that same string.
The comparison happens to still fail, so verification is not *wrong* — but it is
right by accident.

Proposal: throw on a non-JSON input.

### 12.5 Commitment paths are ambiguous and can be unverifiable — *severity: medium*

Today: §8.1 builds paths by string concatenation with no escaping. Therefore:

| payload | path produced | consequence |
|---|---|---|
| `{"a":{"b":1}}` | `input.a.b` | fine |
| `{"a.b":1}` | `input.a.b` | **collides**; read-back returns nothing, so the leaf **fails verification on an honest record** |
| `{"":1}` | `input.` | read-back returns the parent; **fails on an honest record** |
| `{"a[0]":1}` | `input.a[0]` | indistinguishable from `{"a":[1]}` |

The first row is not hypothetical: `{"user.email": …}`, dotted config keys,
header maps and MongoDB-style documents all produce it. Confirmed against the
shipped implementation — a run with a single `user.email` key in its input
reports `Integrity check FAILED … The recorded data was altered.` on a record
nobody touched. **A false integrity alarm in an evidence product is a serious
bug**, arguably worse than a missed one.

Proposal: escape `.`, `[` and `\` in key segments (`\.`, `\[`, `\\`) in
`hashVersion: 2`; until then, refuse to record payloads containing such keys, or
detect and warn. Vectors `AMBIGUOUS-*` in `02-commitments.json` pin the current
behaviour.

### 12.6 No domain separation in hash preimages — *severity: low*

Today: `canonicalStep(step) ‖ prevHash` and `salt ‖ tgcanon(value)` are both
undelimited concatenations. Neither is currently ambiguous — canonical JSON is
self-terminating and salts are fixed-width — but both depend on invariants that
are not stated anywhere near the code that relies on them.

Proposal: in `hashVersion: 2`, prefix each preimage with a version tag and use
an explicit separator, e.g. `"tgstep/2\x00" ‖ canonicalStep ‖ "\x00" ‖ prevHash`.

### 12.7 `algorithm` is declared but never read — *severity: low*

Today: §7.2. Proposal: reject anything other than `"ed25519"` before touching
the key.

### 12.8 `keyId` is not validated against `publicKey` — *severity: low*

Today: §7.3. This costs nothing to fix and requires no version bump: it is a
pure tightening. Proposal: do it now.

### 12.9 Number encoding is ECMAScript-shaped — *severity: high for interop*

Today: §4.4. Fully analysed, with three options and a recommendation, in
[`docs/number-encoding-proposal.md`](docs/number-encoding-proposal.md).

### 12.10 An empty run verifies — *severity: low*

Today: §6.1. Proposal: a verifier SHOULD warn that a zero-step run asserts
nothing. No hash change required.

---

## 13. Test vectors

`docs/test-vectors/`:

| File | Contents |
|---|---|
| `01-canonical.json` | 47 canonicalization vectors: key ordering, unicode, escaping, and every number edge |
| `02-commitments.json` | leaf-walk path vectors (incl. the ambiguous cases) and salted-commitment vectors |
| `03-steps.json` | canonical step forms, hash preimages and hashes for three runs |
| `04-runs/*.tgev.json` | four complete envelopes: minimal, committed, redacted, signed |
| `05-signature.json` | signed message, keyId, and signature under the published test key |
| `keys/` | the test Ed25519 keypair — **published, test only** |
| `check.mjs` | reference verifier, written from this document, importing nothing from `@traceglass/core` |
| `generate.mjs` | regenerates the corpus from the real implementation |

Run `node docs/test-vectors/check.mjs`. 132 checks, all of which must pass.

The corpus is **frozen**: these hashes are the format. If a code change moves
any of them, that change is a breaking format change and needs §10.3.

---

## 14. Change log

| Version | Change |
|---|---|
| 0.3.0 | Format first published: chain, anchor, Ed25519 signature, `.tgev` envelope `formatVersion: 1` |
| 0.6.0 | `commitments` / `salts` / `redactions` added; §5.2 substitution. Deliberately a no-op for records without `commitments`, so 0.3–0.5 records still verify |
| 0.7.0 | `status: "running"` added for in-flight journals; no hashing change |
| 0.7.1 | Storage-layer fix (SQLite `secure_delete` + `VACUUM`); no format change |
| 0.7.2 | Server auth fix; no format change |
| — | **This document.** No format change; describes 0.3.0–0.7.2 as `hashVersion` 1 (implicit) |
