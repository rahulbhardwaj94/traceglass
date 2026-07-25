# traceglass threat model

**Applies to:** `traceglass` / `@traceglass/core` 0.7.2.
**Companion to:** [`SPEC.md`](../SPEC.md), which defines the format this
document reasons about.

This document exists because an evidence product that overstates its guarantees
is worse than one with modest, precise ones. An auditor who believes a valid
`traceglass verify` means more than it does will make a decision the tool cannot
support. Everything below is written to be defensible in that room.

Claims marked **[verified]** were reproduced against the shipped build; the
harness for the format-level ones is in
`docs/test-vectors/` and the transcript of results is summarised in §4.

---

## 1. What traceglass is

A **flight recorder** for AI agent runs: an SDK or ingester captures each step,
seals it into a SHA-256 hash chain at capture time, and optionally signs the
final anchor with Ed25519. The result is a portable `.tgev` file that a third
party can check offline.

### 1.1 The one-sentence guarantee

> **Given a `.tgev` file, traceglass proves that its steps have not been
> individually edited, reordered, inserted or removed since the anchor was
> sealed, and that its payload leaves still match their commitments — and it
> proves that the whole thing was sealed together by the holder of the embedded
> key, whoever that is.**

Everything this document does is qualify that sentence.

### 1.2 Assets

| Asset | Why it matters |
|---|---|
| Integrity of the step sequence | the core product claim |
| Authenticity (whose record is this?) | **currently out of band — §4.1** |
| Confidentiality of payloads | prompts, tool args, and query results contain PII |
| Irreversibility of redaction | the GDPR Art. 17 claim |
| Signing keys | compromise forges records indefinitely |
| Availability of the record | absence of evidence is itself evidence |

---

## 2. Trust boundaries

```
   agent process                capture              storage             distribution
 ┌──────────────┐   in-proc   ┌──────────┐  fsync   ┌─────────┐  file  ┌────────────┐
 │  your code   │ ─────────▶  │ SDK /    │ ───────▶ │ journal │ ─────▶ │  .tgev     │
 │  (trusted)   │             │ ingest   │          │ + SQLite│        │  envelope  │
 └──────────────┘             └──────────┘          └─────────┘        └────────────┘
        ▲                          ▲                     ▲                    │
        │                          │                     │                    ▼
   ① caller is                ② same process,       ③ local disk,     ④ untrusted
     trusted absolutely         same privileges       same user          transport
                                                                            │
                                    ┌───────────────────────────────────────┘
                                    ▼
                              ⑤ verifier — trusts ONLY the file's own contents
```

| # | Boundary | Position |
|:-:|---|---|
| ① | agent code → SDK | **No boundary.** The SDK records what it is told. §3.1 |
| ② | SDK → journal/store | **No boundary.** Same process, same uid. §3.2 |
| ③ | store → local disk | **No boundary.** Root, or the owning user, wins. §3.2 |
| ④ | file → verifier | **This is the boundary the format defends.** §4 |
| ⑤ | verifier → trust decision | **Broken today.** The key comes from the file. §4.1 |

The format defends boundary ④ and nothing to the left of it. Every guarantee in
§1.1 is a statement about a file in transit, not about the machine that made it.

---

## 3. What traceglass explicitly does NOT defend against

### 3.1 The SDK trusts its caller, completely

`recorder.step({ type, label, cost, input, output })` records exactly what it is
handed. It does not observe the agent, hook the LLM client, or corroborate
anything. If the agent passes a sanitized `input`, understates `cost`, or simply
never calls `step()` for the tool call that went wrong, the resulting record is
**perfectly valid and perfectly misleading**.

> The chain proves *the record was not changed after recording*. It says nothing
> about whether the record was true when it was written.

This is not a fixable defect at this layer — it is the definition of the layer.
It matters for positioning: traceglass is evidence *against later tampering*, in
the same way a signed logbook is. It is not an independent observer, and it
should never be sold as one. Closing this needs capture the agent cannot bypass
(runtime interception, a sidecar proxy, or attestation), which is a different
product.

Corollary: **completeness is unprovable from the file.** A run that omits its
awkward steps produces a flawless chain. Nothing in a `.tgev` distinguishes
"twelve steps happened" from "twelve of the twenty steps were recorded."

### 3.2 Root, or the recording user, defeats capture

The private key (if used) lives at `~/.traceglass/keys/private.pem`, written
`0600` — correct permissions, but an unencrypted PKCS#8 PEM with no passphrase
and no hardware backing. Anyone with that uid, or root, can:

* read and exfiltrate the signing key, and thereafter forge any record
  indefinitely and undetectably;
* rewrite and re-chain the in-flight JSONL journal, then let `traceglass
  recover` seal it — `finalizeJournal` verifies the chain, so a naive edit is
  caught, but re-chaining is a dozen lines and the journal is unsigned;
* delete records entirely (§3.5);
* read every stored payload straight out of the SQLite file.

There is no local tamper-resistance and none is claimed. A hardware-backed key
(TPM, Secure Enclave, KMS) would remove the first bullet; the rest are inherent
to local storage.

### 3.3 Redaction is irreversible by design, and therefore destructive

Destroying the salt is what makes erasure meaningful (SPEC §8.3). It is also
what makes it unrecoverable. Consequences to state plainly to users:

* **A false-positive pattern match destroys real data permanently.** The
  built-in detectors are deliberately conservative for exactly this reason, but
  `credit-card` (`\b(?:\d[ -]*?){13,19}\b`) will match a 16-digit order number
  or a spaced product code. Capture-time scrubbing destroys the value *before*
  it is ever committed, so there is not even a commitment left to show something
  was there.
* **There is no undo.** No key escrow, no salt archive. That is the feature.
* **Redaction is not authenticated** — see §4.3.

### 3.4 Metadata is not protected, and metadata is often the sensitive part

Commitments cover the *payloads* (`input`, `output`, `dataPayload`). They do not
cover, and redaction cannot remove:

| Field | What it leaks |
|---|---|
| `toolName` | which systems were touched — `hr_db_query`, `send_payment` |
| `label` | free text, frequently descriptive: `"Tool: lookup patient 8841"` |
| `startedAt`, `durationMs` | precise activity timing; a timing side channel on the erased value (a 4 ms cache hit vs. a 900 ms lookup) |
| `cost`, `tokens` | payload *size*, which for a redacted leaf bounds what it could have been |
| `spanId` / `parentSpanId` | the call graph, intact |
| `redactions[].path` | **the shape of what was erased**: `input.patient.hiv_status` names the field, forever, in the clear |
| `redactions[].reason` | operator free text, often the most sensitive line in the file |
| run `name` | free text |

**A redacted record still says "at 09:14:22 the agent spent 4.7 on a
`hr_salary_lookup` whose input had a leaf at `input.employee.ssn`."** For many
threat models that is the disclosure. Callers redacting under a legal obligation
must be told that erasure covers values, not structure, and must be able to
choose an opaque `reason`.

To bring metadata under the same regime, the committed-field set would have to
extend to `label`, `toolName` and the redaction paths — a v2 format change (SPEC
§12), not a configuration option.

### 3.5 Deletion and suppression

Nothing in the format resists a record simply never being exported, or being
deleted from the store. A hash chain is intra-record; there is no inter-record
chain, no sequence number, no external anchor. **Absence is undetectable.**

This is the strongest argument for a transparency log: appending anchors to an
append-only public log turns "this record was deleted" into "this record is
missing from a sequence", which *is* detectable.

### 3.6 Out of scope entirely

Denial of service against the dashboard; supply-chain compromise of npm
dependencies (mitigated only by `npm audit` in the release gate); side channels
in the crypto primitives (delegated to Node's OpenSSL); the correctness of the
agent's own decisions; and anything the operating system or hypervisor does.

---

## 4. Attacks on the format itself

All results below are **[verified]** against 0.7.2 by rewriting a valid
`.tgev` and re-running `verifyRunFull`.

### 4.1 Re-chain and re-sign — the headline limitation

**Attack.** Take a signed record. Rewrite any step. Recompute the chain.
Generate a fresh Ed25519 keypair. Sign the new anchor. Embed the new public key.

**Result: verification passes cleanly.** [verified] No warning, no signal.

**Why.** Verification uses the public key *inside the file being verified*. That
is a closed loop: the file attests to itself.

**What the signature does still buy.** It defeats *partial* tampering by anyone
who lacks the private key — you cannot edit one step of a signed record and keep
the signature — and it makes a record *attributable* the moment you know whose
key `keyId` is. The gap is entirely in that "the moment you know".

**Honest framing.** `traceglass verify` on a signed record means:

> *internally consistent, and self-attested by key `29e0d3e8fb7ac052`.*

It does **not** mean *"this is the record the agent produced."* Any UI, report
or marketing copy that implies otherwise is overstating the product.

**Mitigations, weakest to strongest:**

| Mitigation | What it adds |
|---|---|
| Pin expected `keyId`s in the verifier | full protection *if* the key was obtained out of band |
| Publish keys out of band (website, DNS, key server) | shifts trust to a channel the attacker does not control |
| RFC 3161 timestamping of the anchor | bounds *when* the anchor existed; defeats post-hoc rewriting even by a keyholder |
| Append anchors to a transparency log | makes rewriting *and deletion* detectable by third parties |

The last two are the planned direction and are the only ones that survive a
compromised signing key.

### 4.2 Rewrite run metadata on a signed record

**Attack.** Change `run.currency` from `"INR"` to `"USD"`. Change `run.status`
from `"failed"` to `"completed"`. Change `run.totals.cost`. Change `run.name`.
Leave every step and the signature untouched.

**Result: verification passes, with a valid signature.** [verified] All four.

**Why.** The chain covers steps only; the signature covers
`{runId, runHash, signedAt}`. No run-level metadata is covered by anything
(SPEC §6.2).

**Severity: high, and under-appreciated.** `cost` is a bare number; its unit
lives *only* in `run.currency`. Flipping INR→USD restates the entire record by
roughly 85× — on a record that verifies, is signed, and shows no anomaly. For a
tool positioned around cost governance and EU AI Act Article 12 record-keeping,
"the money figures are not integrity-protected" is a serious gap, and it is
cheaper to fix than §4.1: fold a metadata hash into the signed message (SPEC
§12.1).

### 4.3 Forge a redaction / erase evidence silently

**Attack.** On a record with commitments, delete a payload leaf's value and its
salt entry. Do not add a `redactions` record.

**Result: verification passes**, and the record is indistinguishable from an
authorised redaction. [verified]

Two variants, both also passing [verified]:

* **delete the `redactions` array** from a genuinely redacted record — hiding
  that any redaction occurred;
* **fabricate `redactions` entries** for leaves nobody touched.

**Why.** `salts` and `redactions` sit outside the hash by design — that is
precisely what lets an authorised redaction preserve the anchor (SPEC §8.5).
The design bought erasure-without-invalidation at the price of
erasure-without-accountability.

**What this means.** The format proves *"this leaf's value is gone and cannot be
recovered."* It does **not** prove *"this leaf was removed by an authorised
party, at the stated time, for the stated reason."* A `redactions` entry is an
unauthenticated claim by whoever last wrote the file.

For an auditor the practical consequence is sharp: **an adversary can quietly
destroy the one step that incriminates them, and the record still passes
`traceglass verify`.** The evidence value of a redaction-capable record is
therefore conditional on trusting whoever holds the file — which is exactly the
party the format was supposed to constrain.

Fix (SPEC §12.1): bind a hash of the per-step `redactions` array and the salt
key-set into the signed message. Redaction then still preserves the *chain*
(so §8.5 survives), but requires re-signing, so an unauthorised erasure is
visible as an invalid or absent signature.

### 4.4 Attacks that are correctly caught

For completeness, and to be fair to the design — these all **fail** [verified]:

| Attack | Outcome |
|---|---|
| Edit a raw payload value on a committed step | caught at SPEC §9.4 |
| Edit any hashed step field (`label`, `cost`, `toolName`, timestamps) | chain breaks |
| Delete an entire payload field but keep commitments | caught (leaves read as absent) |
| Drop a committed leaf from `commitments`, `salts` and the value together | caught (the path set is hashed) |
| Strip `commitments`/`salts` to force raw hashing ("downgrade") | caught |
| Reorder or delete steps without re-chaining | chain breaks |
| Edit one step of a signed record | signature fails |
| Substitute a salt to make a chosen value match a commitment | requires a SHA-256 preimage |

§9.4 deserves emphasis: once a step carries commitments, the raw payload does
not affect the step hash **at all**. A verifier that checks only the chain — an
easy and natural omission for a third-party implementer — silently loses payload
tamper-detection entirely on exactly the records auditors care most about. That
is why SPEC §9 makes the commitment pass a numbered, non-optional step.

### 4.5 Lower-severity format issues

| Issue | Effect | Ref |
|---|---|---|
| `runId` outside the step hash | a step can be transplanted between runs verbatim | SPEC §12.2 |
| `keyId` not checked against `publicKey` | a record may claim any `keyId` | SPEC §12.8 |
| `algorithm` declared but never read | no algorithm confusion is possible today (Ed25519-only), but the check is free | SPEC §12.7 |
| Empty run verifies | a zero-step record passes and asserts nothing | SPEC §12.10 |
| 64-bit `keyId` | collision-findable by a motivated attacker; never a trust input | SPEC §7.3 |

---

## 5. Worked examples: the classes that actually materialised

Both real vulnerabilities found in this codebase were **outside** the format.
Neither was a cryptographic weakness. That is the pattern worth internalising:
the hash chain has never been the weak part.

### 5.1 v0.7.1 — redaction residue in freed SQLite pages

**Class:** *the guarantee held at the abstraction the code reasoned about, and
failed at the one the attacker uses.*

`redact` removed the value from the row. Every `SELECT` agreed it was gone, the
anchor was unchanged, the chain and signature still verified, and the CLI
reported success. But SQLite's `secure_delete` defaults to off, so freed pages
keep their bytes, and in WAL mode the superseded row survives until checkpoint.
Against published 0.7.0, `strings traceglass.sqlite` returned
`"chase account 4471"` verbatim after a completed redaction. Retention pruning
leaked identically.

Anyone with a backup, a disk image, or a stolen copy of the database could read
data an auditor had been told was erased — the single claim the feature exists
to make.

**Fix:** `secure_delete = ON` on every connection, plus
`wal_checkpoint(TRUNCATE)` and `VACUUM` after the two operations that remove
data. Regression tests assert recoverability before and non-recoverability
after, at the *file* level.

**Lessons that generalise:**

1. **A deletion claim must be tested against the artefact, not the API.** The
   test that would have caught this is `strings` on the file, not a `SELECT`.
   Any layer between the claim and the bytes — an ORM, a page cache, a
   filesystem, a snapshotting volume, a cloud backup — is a place the guarantee
   can quietly stop being true.
2. **This class is not closed.** `secure_delete` + `VACUUM` reclaims pages
   *within* the database file. It does not reach: filesystem journals, SSD
   wear-levelled blocks that a TRIM may never clear, ZFS/APFS/btrfs snapshots,
   or any backup taken before the redaction. **Redaction erases the value from
   the live database; it cannot erase it from history that already left.**
   Deployments making an Article 17 claim need that stated in their retention
   policy, and it belongs in the user-facing docs, not just here.
3. The salts deserve the same scrutiny. A salt is the decryption key for its
   commitment on any low-entropy leaf; a salt surviving in a freed page is very
   nearly the value surviving.

### 5.2 v0.7.2 — auth bypass via a non-canonical URL path

**Class:** *two components disagreeing about what a string means — the
canonicalization bug, in a different costume.*

`serve --host 0.0.0.0` gates reads behind a bearer token. The gate asked
`req.url.startsWith('/api')` — the **raw** request line. Fastify's router
percent-decodes **before** matching. So `/%61pi/runs` failed the prefix test,
skipped authorization entirely, and still reached the `/api/runs` handler.
Against the built server, `/api/runs` without a token returned 401 while
`/%61pi/runs` returned 200 with a byte-identical body.

It hit exactly the deployment the token exists to protect: remote and Docker
installs, where anyone who could reach the port could read every stored run —
payloads, costs, and any PII not yet redacted. POSTs were unaffected, being
gated on method rather than path.

**Fix:** authorize against the route Fastify actually matched
(`req.routeOptions.url`, already canonical), falling back to the decoded
pathname so an unrouted request cannot slip through undecoded either.

**Lessons that generalise:**

1. **Never make a security decision on a string a different component will
   re-interpret.** Decide on the *post-canonicalization* value produced by the
   component that will act on it — here, the matched route.
2. **This is the same root cause as SPEC §12.5.** Commitment paths are built by
   unescaped string concatenation, so `{"a.b": 1}` and `{"a": {"b": 1}}` produce
   the same path — writer and reader disagree about what `input.a.b` means, and
   an honest record fails verification. Identical bug class, different layer.
   Wherever two pieces of code parse the same string with different rules,
   assume they disagree until a test proves otherwise.
3. The same release cleared `@fastify/static` advisories for *authorization
   bypass via non-canonical paths* — the identical class, upstream, in the same
   request pipeline. Three instances in one release is a signal about where to
   look next.

---

## 6. Summary: the claims, calibrated

**Safe to say:**

* Steps in a `.tgev` cannot be edited, reordered, inserted or removed without
  detection.
* Visible committed payload leaves can be independently re-verified, leaf by
  leaf.
* A redacted value is unrecoverable from the record — the salt is destroyed.
* A redacted record still verifies, so erasure and auditability coexist. This
  is genuinely novel and is the product's strongest technical claim.
* The whole record was sealed together by one keyholder.

**Must be qualified:**

* "Signed" means *self-attested*, not *authenticated* — until keys are trusted
  out of band (§4.1).
* Cost and status figures are **not** integrity-protected (§4.2).
* A redaction is not proof that a redaction was *authorised* (§4.3).
* Redaction erases values, not metadata, timing, or structure (§3.4).
* Erasure covers the live database, not backups or snapshots (§5.1).

**Must not be said:**

* "Tamper-proof." It is tamper-**evident**, and only across boundary ④.
* "Proves what the agent did." It proves what was recorded (§3.1).
* "Complete record of the run." Omission is undetectable (§3.5).
* "Regulator-grade" without naming which of the above the regulator would need,
  and which are not there yet.

---

## 7. Priorities

| # | Item | Severity | Needs `hashVersion`? | Ref |
|:-:|---|---|:--:|---|
| 1 | Run metadata (esp. `currency`) unprotected | high | no — signature-layer | §4.2, SPEC §12.1 |
| 2 | Redaction unauthenticated | high | no — signature-layer | §4.3, SPEC §12.1 |
| 3 | Key trust out of band | high | no — needs pinning / a log | §4.1 |
| 4 | Dotted keys fail an honest record | medium (false alarm) | to fix, yes; to detect, no | SPEC §12.5 |
| 5 | Signing key at rest, unencrypted | medium | no | §3.2 |
| 6 | Metadata not redactable | medium | yes | §3.4 |
| 7 | `runId` outside the step hash | low | yes | SPEC §12.2 |
| 8 | `keyId` / `algorithm` unchecked | low | no — free tightening | §4.5 |

Items 1 and 2 are both fixed by one change — extending the signed message — and
between them close the two attacks most likely to be demonstrated by a sceptic
holding a `.tgev` file.
