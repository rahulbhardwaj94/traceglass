# traceglass

**A flight recorder for AI agents.** Tamper-evident, replayable audit for autonomous agents — built for teams that have to *prove* what their agents did.

![traceglass dashboard replaying a collections agent stuck in a tool loop, with the hash chain verified and warnings surfaced](docs/screenshots/dashboard.png)

```bash
npx traceglass demo
```

That boots a local dashboard on a bundled sample run — a collections agent stuck
in a tool loop — in about ten seconds, no input file required. Scrub it step by
step: every tool call, every token, every rupee, and exactly what data the agent
**read or mutated** — with a cryptographic guarantee that the record hasn't been
altered since it was captured. Point it at your own trace with
`npx traceglass open ./trace.json`.

| Step into the loop | Watch the run abort |
| :---: | :---: |
| [![A repeated `get_payment_status` tool call inside the detected loop, showing the data it read and the cost climbing](docs/screenshots/step-loop.png)](docs/screenshots/step-loop.png) | [![The final step — the run aborts on an exceeded step budget after burning ₹14 in a stuck loop](docs/screenshots/step-error.png)](docs/screenshots/step-error.png) |

### Replay your own Claude Code sessions

Run `npx traceglass open` with no arguments and traceglass scans your
`~/.claude/projects` logs and drops you on a **session picker** — choose any
agent run and replay it in the full dashboard above. Nothing leaves your machine.

[![The traceglass session picker listing Claude Code sessions by project, with first prompt, message count, and recency](docs/screenshots/session-picker.png)](docs/screenshots/session-picker.png)

---

## Why this exists

Autonomous agents are moving into regulated work — lending, collections, underwriting, healthcare, claims. When an agent declines a loan, duns the wrong account, or burns ₹14 of compute in a stuck loop, someone has to answer for it: a regulator, an auditor, an incident review, a customer.

A pile of JSON logs is not an answer. You need to **replay** what happened, show **what data was touched**, and prove the record is **the one that was captured** — not something edited after the fact.

traceglass turns an agent trace into that record:

- **Replayable** — step through the run on a timeline; watch cost and tokens climb; jump straight to the loop or the error.
- **Tamper-evident** — every step is hash-chained (SHA-256, each step over the previous). Change one field in storage and the dashboard turns **red** and names the first broken step.
- **Compliance-first** — each step surfaces the data it **read** or **mutated**, so "what did the agent see and change?" is answerable at a glance.
- **Cost- and loop-aware** — automatic detection of stuck tool loops and steps that cost far more than the run's norm.

## Local-first — your data never leaves your machine

This is a hard guarantee, not a setting:

- **No network egress.** traceglass makes **zero outbound network calls.** No telemetry, no analytics, no phone-home.
- **No account, no cloud, no API key.** Nothing to sign up for.
- **The dashboard binds to `127.0.0.1`** on an ephemeral port — it is not reachable from your network.
- **Your traces stay on disk** in a local append-only SQLite store (`~/.traceglass`). The bundled UI ships its own assets — no CDN fonts or scripts.

If your agent runs on sensitive financial or health data, that data can be loaded, replayed, and audited without a single byte going anywhere.

## Quick start

```bash
# Kick the tires on a bundled sample run — no input needed
npx traceglass demo

# Replay your own Claude Code sessions — pick one from the session picker
npx traceglass open

# List your Claude Code sessions, then replay one directly
npx traceglass sessions
npx traceglass open --session <sessionId>

# Replay your own trace file (ingests it, then opens the dashboard on 127.0.0.1)
npx traceglass open ./trace.json

# Verify a stored run's integrity from the terminal (exit 1 if tampered)
npx traceglass verify <runId>

# Write a standalone, portable HTML audit report
npx traceglass report <runId> -o audit.html

# List everything you've ingested
npx traceglass list

# Sign new ingests with a local Ed25519 key (one-time setup)
npx traceglass keygen

# Export a run as a portable evidence file anyone can verify offline
npx traceglass export <runId> -o run.tgev
npx traceglass verify ./run.tgev   # works with no store, no keys, no network

# Run as a team collector: fixed port, bearer-token ingest API, retention
npx traceglass serve --port 4318 --token <token> --retain 180

# Assert what a run was ALLOWED to do (exit 1 on any violation — CI-ready)
npx traceglass check <runId-or-file> --policy policy.json --json

# Sweep every stored run: which agents ever touched this account?
npx traceglass search "4471"
```

The `open` command always prints the dashboard URL, so it works over SSH or in
environments where a browser can't be launched automatically.

## Input formats

traceglass ingests three sources:

1. **Claude Code sessions** — point it at your `~/.claude/projects` session logs
   (`traceglass sessions` / `open --session <id>`, or just `traceglass open` for
   the session picker). Tool calls, tokens, real cost, and the data each tool
   read or returned are mapped onto the same replayable, hash-chained record.
2. **OpenTelemetry OTLP/JSON** traces — using `gen_ai.*` semantic conventions plus
   `traceglass.*` attributes for run/step metadata.
3. **Native traceglass JSON** — a compact `{ id, name, steps[] }` shape.

See [`fixtures/`](./fixtures) for runnable examples, including a clean
underwriting run, a collections agent stuck in a tool loop, and a sample Claude
Code session. The Claude Code adapter references [inspecto](https://www.npmjs.com/package/inspecto)
as its parse reference but takes no runtime dependency on it.

## How tamper-evidence works

Each step's hash is `SHA-256(canonical(step) + prevHash)`, where `canonical`
is a stable, sorted-key serialization of the step's content. The run's anchor
hash is the final step's hash. Re-hash the chain and compare: if any stored
step was altered, its hash no longer matches and verification points at the
**first** broken step. The store itself is **append-only** — there is no update
path through the application.

Run status (did the agent succeed or fail?) and integrity (is the record
authentic?) are deliberately shown as **separate axes**: a failed run with an
intact chain is a faithfully recorded failure; a tampered record is a different
problem entirely.

## Sign it, export it, prove it (v0.3)

The hash chain proves the record is *internally consistent* — but whoever can
edit the store can also re-chain it. v0.3 closes that hole:

- **Ed25519 signing** — after `traceglass keygen`, every ingested run's anchor
  is signed with a local key (private key never leaves `~/.traceglass/keys`,
  mode 0600). An attacker who re-chains a tampered record now fails signature
  verification — `verify` checks both axes.
- **Portable evidence** — `traceglass export <runId>` writes a single `.tgev`
  file containing the run, chain, signature, and public key. A regulator,
  customer, or incident reviewer runs `traceglass verify file.tgev` and gets a
  verdict **fully offline** — no store, no keys, no network. `report` renders
  the HTML audit report from the same file.
- **Anchoring** — `traceglass anchor --all` appends `{runId, runHash, signature}`
  records to a JSONL file you push to WORM storage (e.g. S3 Object Lock); that
  out-of-band copy is the trust root re-signing can't beat.

## Record runs live with the SDK

Post-hoc ingestion leaves a window between "agent ran" and "trace ingested."
[`@traceglass/sdk`](./packages/sdk) closes it: each step is hash-chained and
journaled to disk **the moment it happens**, so recorded history can't be
reordered or edited afterward.

```ts
import { startRecording } from '@traceglass/sdk';

const rec = startRecording({ name: 'collections agent', currency: 'INR' });
rec.step({ type: 'user_input', label: 'Dun account 4471' });
rec.step({ type: 'tool_call', toolName: 'get_payment_status', label: 'Tool: get_payment_status',
           output: status, dataPayload: status, tokens: 812, cost: 0.4 });
const run = await rec.end(); // verified, signed, stored — replay with `traceglass open --id`
```

If the process crashes mid-run, `traceglass recover` finalizes the journal into
a `failed` run whose chain still verifies up to the crash point.

## Team collector mode

`traceglass serve` turns the same binary into a self-hosted collector: a fixed
port, `POST /api/ingest` (native or OTLP/JSON, auto-detected) and an
OTLP/HTTP-compatible `POST /v1/traces`, bearer-token auth on every write
(timing-safe compare), and optional retention (`--retain <days>`) whose
deletions are the store's **only** delete path and are audit-logged to
`~/.traceglass/audit.jsonl`. Binding a non-loopback host without a token is
refused outright — the local-first guarantee doesn't quietly degrade.

## Governance: policies, approvals, search (v0.4)

Recording what an agent did is half the job; the other half is asserting what
it was **allowed** to do.

- **Guardrail policies** — a plain JSON file of rules, checked against the
  evidence with `traceglass check` (works on stored runs *and* exported `.tgev`
  files, so a reviewer can police a record they received offline):

  ```json
  {
    "name": "payments guardrails",
    "rules": {
      "maxCostPerRun": 50,
      "maxCostPerStep": 5,
      "forbidTools": ["*_delete"],
      "requireApprovalFor": ["payments.*"],
      "requireSignature": true,
      "forbidWarnings": ["loop"]
    }
  }
  ```

  Integrity is checked alongside the rules — a policy verdict is only issued
  over an authentic record. `--json` (also on `verify`) makes both commands
  CI gates: wire `traceglass check` into a pipeline and a run that called
  `payments.refund` without sign-off fails the build.

- **Approval steps** — `approval` is a first-class step type: record who
  signed off on what (via the SDK or any ingest source), and
  `requireApprovalFor` enforces that sensitive tools fire only *after* an
  approval step. "Show me an agent action nobody approved" is now a query,
  not an archaeology project.

- **Cross-run search** — `traceglass search <text>` (and `GET /api/search`)
  sweeps every stored run's labels, tool names, and payloads. "Which runs
  ever touched account 4471?" — the shape of a GDPR data-subject request or
  an incident sweep — is one command.

- **Compliance summary in reports** — every HTML audit report now leads with
  the questions an auditor asks first: is the record authentic (signature),
  is the event log complete (hash chain + anchor), who approved what (human
  oversight), and what data was read or mutated.

```bash
docker build -t traceglass .
docker run -p 127.0.0.1:4318:4318 -v traceglass-data:/data \
  -e TRACEGLASS_TOKEN=change-me traceglass
```

## Development

This is an npm-workspaces monorepo (Node ≥20, TypeScript, ESM):

- **`@traceglass/core`** — model (Zod), ingest (OTel + native + Claude Code
  sessions), analysis (loops, cost), integrity (hash chain), append-only store,
  HTML report.
- **`@traceglass/sdk`** — live-capture recorder (chain fixed at capture time).
- **`traceglass`** (`packages/cli`) — Fastify server/collector + `commander` binary.
- **`@traceglass/web`** — React + Vite dashboard (bundled into the CLI on build).

```bash
npm install
npm run build
npm test                    # 100+ tests across ingest, analysis, integrity, signing, policy, store, sdk, server, e2e
node scripts/e2e-check.mjs  # outcome check against the real built CLI
```

## License

MIT — see [LICENSE](./LICENSE).
