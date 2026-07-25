# traceglass — what's left to build

Status as of 2026-07-25. All packages at **0.7.2** (npm + main in sync,
`>=0.3.0 <0.7.2` deprecated). 163 tests, 19 outcome checks, 0 production
advisories.

This document is the standing backlog. It is ordered by one question:

> **Does this strengthen the forgery claim, or the ability to prove that claim
> to somebody who does not trust us?**

Everything traceglass sells is downstream of that. A feature that makes the
product nicer but not harder to forge is a v1.x feature, not a v0.x one.

---

## 0. The honest position

Two security sweeps in two days found two vulnerabilities, and both were in the
guarantees the product exists to make:

| Version | Defect | Class |
|---|---|---|
| 0.7.1 | `redact` left the "erased" value readable in freed SQLite pages | erasure did not hold |
| 0.7.2 | `/%61pi/runs` skipped the bearer-token read gate | access control did not hold |

Neither was exotic. Both were found by pointing a shell at the built artifact
and asking "is the claim actually true?" — not by reading code.

**The pattern:** the test suite asserted that features *work*. It did not assert
that guarantees *hold under attack*. 163 passing tests did not catch either bug,
because no test tried to break anything. That gap is item #1 below and everything
else waits behind it.

**The uncomfortable corollary:** we do not currently know what else is wrong. The
two found are evidence of a process gap, not of a now-clean codebase.

---

## Tier 0 — Credibility. Nothing ships before this.

### 0.1 Adversarial test suite (`packages/*/src/**/*.attack.test.ts`)
Today's tests are "does it work". These are "can I break it". Each is a claim the
README makes, written as an attacker:

- **Signature transplant** — lift a valid signature from run A onto run B.
  (`signaturePayload` binds `runId`, so this should fail. Prove it.)
- **Key substitution** — re-chain a tampered run and re-sign with an attacker
  key. *This currently PASSES offline verify.* See 1.1 — the test should assert
  the documented limitation until 1.1 lands, then assert it fails.
- **Anchor forgery** — hand-write an `anchors.jsonl` line for a run that never
  existed.
- **Commitment collision** — reuse a salt across two leaves; confirm redacting
  one does not disclose the other.
- **Policy bypass** — tool name casing, unicode homoglyphs, leading/trailing
  whitespace, `*` glob edges against `forbidTools` / `requireApprovalFor`.
- **Redaction completeness** — after `redact`, grep the DB, the WAL, the journal
  dir, the anchors file, the audit log, and any export for the value. (The 0.7.1
  fix covered the DB + WAL. The other four paths are untested.)
- **Path/authorization fuzzing** — generalize the 0.7.2 probe: every route ×
  encoded, double-encoded, mixed-case, trailing-slash, unicode-escaped forms.
- **Journal poisoning** — hand-craft a journal with a bad chain and confirm
  `recover` refuses rather than importing it as truth.
- **Ingest bombs** — 1 GB body, 10⁶ steps, deeply-nested payload, cyclic JSON.

### 0.2 CI (`.github/workflows/ci.yml`) — **there is none today**
This is *why* two CVEs sat unnoticed in a published package. Required on every
push and PR:

- build → typecheck → test → `node scripts/e2e-check.mjs`
- `npm audit --omit=dev` as a **hard failure** (this alone would have caught both
  dependency CVEs the day they were published)
- a scheduled daily audit run, since advisories appear against unchanged code
- matrix: Node 20 / 22 / 24, ubuntu + macos + windows (Windows is entirely
  unverified today — `better-sqlite3` and every path join are suspects)
- publish job gated on a tag, so version/commit/tarball can never disagree

### 0.3 `SECURITY.md` + published advisories
A product whose value is trust has no disclosure policy. Needs: contact address,
supported-version window, expected response time, and a GHSA advisory for each of
the two fixed defects. **Publishing our own findings is a credibility asset, not
a liability** — silently deprecating versions and hoping nobody looks is the
posture that destroys trust when someone eventually does look.

### 0.4 `traceglass vacuum` (residue left by the 0.7.1 fix)
The 0.7.1 fix only purges on the *next* redact or prune. Every database written
by 0.6.0–0.7.0 still holds recoverable plaintext for values their owners were
told were erased. Needs a one-shot command (`secure_delete = ON` +
`wal_checkpoint(TRUNCATE)` + `VACUUM`), run automatically on open when a stored
schema version predates 0.7.1, and called out in the release notes.

### 0.5 Small live gaps found in the 2026-07-25 sweep
- **`.gitignore` misses the WAL sidecar.** It has `*.sqlite` and
  `*.sqlite-journal` (the old rollback-journal name) but not `*.sqlite-wal` /
  `*.sqlite-shm`. The store has run in WAL mode since v0.3, and the WAL holds
  recent trace payloads. `git check-ignore` confirms `traceglass.sqlite-wal` is
  **not ignored** — a `git add -A` mid-session could commit real trace data,
  including PII. Nothing has leaked (no sidecar exists right now), but the hole
  is open. One-line fix.
- **`npm run lint` is broken repo-wide** — the script calls `eslint`, which is
  not a dependency and not configured. It has presumably never run. Either wire
  up eslint properly or delete the script; a script that always fails trains
  everyone to ignore failures.
- **No schema versioning in the store.** `PRAGMA user_version` is unset and
  there is no migration path. The moment the `runs` table changes, every existing
  database is a support ticket. Set it now, while the only migration is trivial.
- **No `bodyLimit` or rate limit on the collector.** `serve` accepts ingest with
  Fastify's 1 MB default and no throttle. A single client can pin the process;
  a large legitimate trace silently 413s. Both need explicit, documented values.
- **The Dockerfile has never been run.** It was written in v0.3 and the daemon
  was not available to test it. It may not even build.
- **No CHANGELOG.md.** Six releases of history live only in commit messages.

---

## Tier 1 — The trust root. This is the actual product.

### 1.1 Third-party verifiability — *the single most important item in this file*
**Today's guarantee is weaker than it sounds.** `verifyRunFull` validates the
signature against the public key **embedded in the evidence file itself**. So an
attacker who controls the machine can: alter a step → re-chain → re-sign with
their own key → ship a file that verifies clean. Offline verification proves
*"this file is internally consistent"*, not *"this is the record the agent
actually produced."*

For a regulator, the second claim is the only one worth anything. Closing it
means binding records to something the operator cannot rewrite:

- **RFC 3161 timestamps** — a TSA countersigns the runHash. Cheap, boring,
  legally well-understood, and it proves *the record existed by time T*, which is
  most of what Article 12 actually wants.
- **Sigstore / Rekor transparency log** — append-only public log, keyless signing
  via OIDC identity. Turns "signed by key X" into "signed by
  alice@company.com at time T, publicly witnessed."
- **Anchor batching** — Merkle-root a day of runs, publish one root. Cheap at
  scale and gives every run an inclusion proof.
- **Key rotation + revocation** — there is no story today. A leaked key
  invalidates nothing and can be used to forge history retroactively.
- **KMS/HSM signing** — for orgs that cannot have a private key sitting in
  `~/.traceglass/keys/private.pem` at mode 0600.

The `AnchorSink` interface in `packages/cli/src/anchors.ts` was built as the seam
for exactly this. It has been waiting since v0.3. **This is the difference
between a local logging tool and an evidence product.**

### 1.2 The format spec (`SPEC.md`) — freeze the canonicalization
The entire product rests on `canonicalize()`. It is currently defined only by its
implementation, which means:
- nobody can write an independent verifier
- any incidental change silently invalidates every historical record
- we cannot claim it is a standard

The spec must pin, in prose, with test vectors:
- key ordering, unicode normalization, escaping
- **number formatting — the sharpest landmine here.** `cost` is a float
  (`4.7`). JSON number serialization is implementation-defined across languages;
  a Python or Go verifier that emits `4.7000000000000002` or `4.70` computes a
  different hash and rejects a valid record. Either pin a decimal encoding or
  move money to integer minor units. **This will silently break cross-language
  verification the day someone tries it**, and it is far cheaper to fix before
  there are records in the wild than after.
- the exact `HASHED_FIELDS` / `COMMITTED_FIELDS` sets and their version
- a frozen corpus of test vectors any implementation must reproduce

### 1.3 An independent verifier in another language
A ~200-line Python (and/or Go/Rust) verifier that reads a `.tgev`, recomputes the
chain, and checks the Ed25519 signature — written *from the spec*, not ported
from the TypeScript.

This is the cheapest credibility multiplier available. It proves the evidence
format is not captive to our implementation, it is the artifact an auditor's own
engineers will actually run, and writing it will find spec bugs (starting with
1.2's float problem). Ship it as `traceglass-verify` on PyPI.

### 1.4 Threat model (`docs/threat-model.md`)
Say plainly what traceglass does and does not defend against. An evidence product
that overstates its guarantees is worse than one with modest, precise ones.
Must state: root access defeats capture; the SDK trusts its caller; key trust is
out-of-band until 1.1; redaction is irreversible by design and therefore
destructive; commitments protect payloads, not metadata.

---

## Tier 2 — Adoption. Nothing above matters if nobody records anything.

### 2.1 Framework adapters (the distribution strategy)
Every one of these is a place agents already run. Thin wrappers over the existing
recorder:
- **Claude Agent SDK** (closest to the Claude Code wedge already working)
- **LangGraph / LangChain** — callback handler
- **Vercel AI SDK** — `experimental_telemetry` hook
- **OpenAI Agents SDK**, **CrewAI**, **AutoGen**
- **Model Context Protocol** — record MCP tool calls generically; arguably the
  highest-leverage single adapter, since it captures every MCP tool at once

### 2.2 OTel span processor
Deferred since v0.3. Anyone already emitting `gen_ai.*` spans should get
traceglass records with a three-line config change and no code edits. This is the
lowest-friction adoption path that exists and it is still unbuilt.

### 2.3 GitHub Action
`traceglass check --policy` as a PR gate: fail the build when an agent run
violates the guardrails, post the compliance summary as a PR comment. Turns the
policy engine from a CLI nobody remembers to run into enforced infrastructure.

### 2.4 Docs site + honest quickstart
Currently one README. Needs: 60-second quickstart, the Article 12 mapping,
per-framework recipes, and a *worked forensic example* — "an agent did something
expensive at 3am, here is the exact sequence of commands that reconstructs and
proves it." Show the product solving a real incident, not listing features.

### 2.5 `#14` Trace diffing
Compare two runs step-by-step: what changed, what regressed, where cost moved.
The natural companion to tail mode and the first genuinely *pleasant* feature on
this list. Also the foundation for regression testing agents in CI.

### 2.6 Fleet view
The dashboard shows one run at a time. Teams need: all runs, filtered by
policy violations, cost outliers, warning kinds, time. The read path (`searchRuns`,
`listRuns`) already exists — this is mostly UI.

---

## Tier 3 — Enterprise. This is where the money is, and it is all gated on Tier 1.

### 3.1 `#15` RBAC / SSO
OIDC login, scoped API keys, roles (viewer / recorder / auditor / admin). The
natural open-core boundary: OSS core stays fully functional, teams pay for
identity and multi-tenancy.

### 3.2 Access audit log — *chain of custody*
Underrated and directly implied by the positioning. If traceglass is the evidence
system, **who read the evidence is itself evidence.** Every read of a run,
export, and redaction should be logged, signed, and immutable. Auditors ask this
question about every evidence system they encounter.

### 3.3 Durable multi-node backend
SQLite is right for local-first and wrong for a team collector. Needs a Postgres
backend behind the existing `RunStore` interface, with the append-only and
audited-deletion invariants preserved exactly.

### 3.4 Retention, legal hold, and DSAR workflow
`pruneOlderThan` exists. Missing: per-policy retention windows, **legal hold**
(runs that must survive retention — the direct conflict with automated deletion,
and the thing that bites companies in litigation), and a documented subject-access
/ erasure workflow built on `redact`.

### 3.5 Control mappings + attestation reports
The compliance summary is a start. The sellable artifact is a signed report
mapped to specific controls: **EU AI Act Art. 12/14**, **ISO/IEC 42001**,
**NIST AI RMF**, **SOC 2 CC7**. This is what a compliance team actually hands to
an auditor, and it is the highest-margin thing on this list.

---

## Tier 4 — Ideas worth considering, not yet decided

- **Evidence-as-a-service** — hosted anchoring/timestamping. Recurring revenue,
  no data custody: only hashes leave the customer's network. Strategically the
  most attractive business shape here.
- **Agent regression testing** — diffing (2.5) + policy (shipped) = "prove this
  prompt change didn't make the agent worse." A different, larger market than
  compliance.
- **Insurance / liability** — the actual end state of an evidence layer. Someone
  will eventually underwrite AI agent liability and will need exactly this data.
- **`traceglass replay`** — re-execute a recorded run against a live model and
  diff. Powerful, and a security question (replaying tool calls has side effects).
- **Cost anomaly detection** — the warnings engine already has the data.
- **Browser/VS Code extension** — meet developers where they already are.

---

## Suggested sequencing

| Release | Theme | Contents |
|---|---|---|
| **v0.8** | *Prove it* | 0.1 adversarial suite, 0.2 CI, 0.3 SECURITY.md + advisories, 0.4 vacuum, 0.5 small gaps |
| **v0.9** | *Third-party verifiable* | 1.2 spec, 1.3 independent verifier, 1.1 RFC3161 + Sigstore, 1.4 threat model |
| **v1.0** | *Adoptable* | 2.1 adapters, 2.2 OTel, 2.3 Action, 2.4 docs, 2.5 diffing, 2.6 fleet view |
| **v1.1+** | *Sellable* | 3.1 RBAC/SSO, 3.2 access audit, 3.3 Postgres, 3.4 retention/hold, 3.5 control mappings |

The ordering is deliberate: **v0.8 and v0.9 are not features, they are the
product.** An evidence layer that cannot be independently verified is a logging
library with extra steps. Adapters and dashboards are worth far more once the
underlying claim is airtight — and worth very little before it.

---

## Parallel execution plan (agent waves)

Work is dispatched to background agents in **isolated git worktrees** with
**disjoint file ownership**, so parallel agents cannot collide. Each agent
commits on its own branch; branches are merged one at a time with the full gate
set re-run after each merge.

**Why waves rather than launching everything at once** — two real dependencies:

1. **The canonicalization decision changes every hash.** Any agent writing tests
   against current hashes would have its work invalidated. So in wave 1 the spec
   work is *documentation only*; the code change happens in wave 2, after review.
2. **The adversarial suite may find more bugs.** Fixes belong in v0.8 before
   v0.9/v1.0 work builds on top of the affected code.

### Wave 1 — v0.8 "prove it" (running)

| Agent | Owns | Delivers |
|---|---|---|
| CI + hygiene | `.github/**`, `.gitignore`, `SECURITY.md`, `CHANGELOG.md`, `Dockerfile`, root scripts | CI with hard-failing audit, WAL gitignore fix, working lint, disclosure policy, changelog, Docker verification |
| Adversarial suite | `packages/**/*.attack.test.ts` only | 10 attack families. **Reports vulnerabilities, does not fix them** — fixes must be deliberate and separately verified |
| Store + server hardening | `store.ts`, `server.ts`, `bin.ts` | `traceglass vacuum`, `PRAGMA user_version` + migration scaffold, bodyLimit + rate limiting |
| Format spec | `SPEC.md`, `docs/**` — **no code** | Spec implementable from scratch, real test vectors, number-encoding proposal, threat model |

### Wave 2 — v0.9 "third-party verifiable" (blocked on wave 1 review)
- **Canonicalization versioning** — implement the approved number-encoding
  decision behind a hash version so published records keep verifying. *Blocks
  everything else in this wave; runs alone.*
- Then in parallel: independent **Python verifier** written from the spec (not
  ported from the TypeScript — that is the point); **RFC 3161** anchor sink;
  **Sigstore/Rekor** anchor sink; key rotation + revocation.

### Wave 3 — v1.0 "adoptable" (fully parallel, low coupling)
Adapters (MCP first — highest leverage), OTel span processor, GitHub Action,
docs site, `#14` trace diffing, fleet-view UI. These touch mostly disjoint new
files and can run as one wide fan-out.

## The one-line version

Ship the adversarial suite and CI so we stop finding vulnerabilities by hand;
then make the evidence verifiable by someone who does not trust us — spec, an
independent verifier, and a trust root the operator cannot rewrite. Everything
else is a feature. Those two things are the company.
