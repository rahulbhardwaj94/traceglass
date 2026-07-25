# Changelog

All notable changes to traceglass are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
All packages (`@traceglass/core`, `@traceglass/sdk`, `traceglass`) are versioned
and released together; `@traceglass/sdk` and `traceglass` pin `@traceglass/core`
exactly.

This file was reconstructed from the commit history in v0.8. Entries at v0.2.0
and later are derived from the release commits themselves.

## [Unreleased]

### Added

- GitHub Actions CI (`.github/workflows/ci.yml`): build, typecheck, test, and
  the `scripts/e2e-check.mjs` outcome check across Node 20/22/24 on Ubuntu,
  macOS, and Windows. Runs on push, pull request, and a nightly schedule.
- `npm audit --omit=dev` as a hard CI failure. Both dependency CVEs that reached
  published releases (see 0.7.0 and 0.7.1) would have been caught on day one by
  this gate; the nightly schedule exists because advisories land against code
  that has not changed.
- A publish job gated on a `v*` tag and on every other job passing, with
  `.github/scripts/check-tag-version.mjs` refusing to publish when the tag, the
  package versions, or the exact `@traceglass/core` pins disagree. Publishing is
  wired but disarmed: it requires an `NPM_TOKEN` secret that is not set.
- `SECURITY.md`: contact, supported-version window, response times, and
  coordinated-disclosure process.
- ESLint 9 flat config (`eslint.config.mjs`) with type-aware linting on shipped
  sources. `npm run lint` previously called a binary that was never a dependency
  and had no config, so it had never run.

### Fixed

- `.gitignore` did not cover `*.sqlite-wal` / `*.sqlite-shm`. The store has run
  in WAL mode since 0.3.0, and the write-ahead log holds recent trace payloads —
  including PII not yet redacted — that are not in the `.sqlite` file itself.
  Only the pre-WAL `*.sqlite-journal` name was listed. Exported `*.tgev`
  evidence bundles are now ignored as well.

## [0.7.2] — 2026-07-25

### Security

- **Authorization bypass in `serve` read gate.** The gate tested
  `req.url.startsWith('/api')` against the raw request line, but Fastify decodes
  percent-escapes before routing, so `/%61pi/runs` failed the prefix test,
  skipped authorization, and still reached the `/api/runs` handler — returning
  every stored run without a token. Only non-loopback deployments were affected
  (`serve --host 0.0.0.0`, the Docker image), which is precisely the mode the
  token exists to protect. `POST` was unaffected, being gated on method rather
  than path, so ingest could not be forged this way. Authorization is now
  evaluated against the route Fastify actually matched
  (`req.routeOptions.url`), falling back to the decoded pathname. Affects
  0.3.0–0.7.1. See `.github/advisories/`.

### Changed

- `@fastify/static` to 10.1.2, clearing an authorization bypass via
  non-canonical paths and a route-guard bypass via path traversal. No patched
  9.x exists, so this takes `fastify-plugin` ^6; verified against fastify 5 by
  booting the real server.
- `brace-expansion` to 5.0.8 (denial of service), a lockfile refresh within the
  existing range.

## [0.7.1] — 2026-07-24

### Security

- **`redact` left the erased value recoverable from the database file.** The
  value disappeared from every query while the plaintext stayed in a freed
  SQLite page: against 0.7.0, `strings traceglass.sqlite` returned the redacted
  content verbatim after a `--yes` redaction that reported success. Retention
  pruning leaked the same way. Anyone with a backup, a disk image, or a stolen
  copy of the database could read data an auditor had been told was erased.
  Cause: `secure_delete` defaults to off, so freed pages keep their bytes, and
  in WAL mode the superseded row also survives until checkpoint. Fixed by
  enabling `secure_delete` on every connection and following `replaceRedacted`
  and `pruneOlderThan` with `checkpoint(TRUNCATE)` and `VACUUM`. Affects
  0.6.0–0.7.0. See `.github/advisories/`.

### Changed

- Lockfile refresh clearing two high-severity advisories in fastify
  transitives: `find-my-way` <= 9.6.0 (HTTP/2 denial of service) and `fast-uri`
  3.0.0–3.1.3 (two host-confusion advisories). Both patched releases already
  satisfied the declared ranges — the lockfile was simply stale. Pulls fastify
  5.8.5 → 5.10.0, find-my-way 9.7.0, fast-uri 3.1.4/4.1.1.

## [0.7.0] — 2026-07-21

### Added

- **Tail mode.** `traceglass tail [runId]` follows a recording live — steps,
  per-step cost and tokens, and warnings as they fire. `--list` shows what is
  recording now. The SDK already appended each step to a JSONL journal as it
  happened, so this exposes an existing on-disk stream rather than adding
  streaming infrastructure: no sockets, no daemon, and it still survives a crash
  (the same journal `recover` finalizes).
- Dashboard live view at `/?live=<runId>`: polls the journal, auto-follows the
  newest step, and switches to the stored signed record the instant the run
  finalizes.
- `GET /api/live` (what is recording) and `GET /api/live/:id` (the in-flight
  run, or the stored record with `live:false` once sealed).
- New `running` run status: the chain is real up to the latest step, but the
  record is not yet anchored or signed, so `runHash` is empty. `end` records and
  the SDK's `end()` are narrowed to settled statuses.

### Changed

- `@fastify/static` to ^9.2.0, moving outside the advisory range 8.0.0–9.1.0
  for a path traversal in directory listing and a route-guard bypass via encoded
  path separators. npm reported "no fix available" only because the ^8.0.0 pin
  could not reach a patched release.

## [0.6.0] — 2026-07-20

### Added

- **Redaction that preserves the proof.** Per-leaf salted commitments computed
  at capture time: `commitment[path] = sha256(salt[path] + canonical(value))`.
  The step hash covers the commitments, never the raw payload, so redacting a
  leaf destroys its value and its salt while leaving the commitment — the step
  hash, the run anchor, and the Ed25519 signature all stay valid. Destroying the
  salt is what makes it irreversible: without it, a low-entropy value (an SSN, a
  boolean) could be brute-forced out of its commitment.
- `traceglass redact <runId> --path <p> --pattern <name> --reason <text>`, a dry
  run by default; `--yes` applies it and audit-logs the event.
- Capture-time pattern scrubbing (email, credit card, SSN, Aadhaar, private key,
  bearer token) replaces matches before anything is hashed or written, so the
  original never reaches disk.
- Audit reports disclose every redaction (path, reason, actor, timestamp) under
  "Data minimisation".
- An explicit `--legacy` path for pre-0.6 records, which hashed raw values and
  cannot be redacted this way. It re-chains and re-signs; both the CLI and the
  report state plainly that this yields a new anchor and a weaker guarantee.

### Security

- `verifyRun` now checks every visible leaf against its commitment. Without
  this, commitment-enabled runs would have silently lost payload tamper
  detection, since raw values no longer move the step hash.

### Changed

- `RunStore.replaceRedacted` is the store's only update path — deliberately
  narrow and audit-logged — alongside `pruneOlderThan` as the only delete path.

## [0.5.0] — 2026-07-19

### Added

- **Watch mode.** `traceglass watch [--dir] [--interval] [--settle] [--policy]
  [--anchor]` sweeps for finished Claude Code sessions and ingests, hash-chains,
  signs, policy-checks, and optionally anchors each one. `--once` runs a single
  sweep for cron/CI and exits 1 if any new session violated policy. Violations
  are appended to the audit log alongside retention prunes.
- Sessions ingest exactly once: the run id (`cc-<sessionId>`) is predicted from
  the log via `sessionRunId()` before any hashing, so sweeps are cheap and the
  append-only store is never fought. A still-growing session is left alone until
  it settles.
- New policy rule `forbidInputText`: fail any step whose input contains a text
  fragment (case-insensitive) — `.env`, `rm -rf`, `prod-db` as one-liners.
- `claudeCodeRunId()` exported from core so the `cc-` id rule lives in one place.

## [0.4.0] — 2026-07-19

### Added

- **Guardrail policies.** A plain JSON rule file checked against the evidence
  with `traceglass check <runId-or-.tgev> --policy policy.json`, exiting 1 on
  violation. Rules: `maxCostPerRun`/`PerStep`, `maxTokensPerRun`, `maxSteps`,
  `forbidTools` (with `*` wildcards), `requireApprovalFor`, `requireSignature`,
  `forbidWarnings`. Integrity is checked alongside, so a policy verdict is only
  issued over an authentic record, and it works offline on exported evidence.
- `approval` as a first-class step type (model, SDK, dashboard, report). Records
  who signed off on what; `requireApprovalFor` enforces that sensitive tools
  fire only after an approval step.
- Cross-run search: `traceglass search <text>` and `GET /api/search` sweep every
  stored run's labels, tools, and payloads (case-insensitive, LIKE
  metacharacters escaped) with step-level hits and snippets.
- A compliance summary leading the HTML audit report: record authenticity,
  event-log completeness, human oversight, and every step that read or mutated
  data, mapped to EU AI Act Art. 12/14-style duties.
- `--json` on `verify`, `check`, and `search` for CI pipelines.

## [0.3.0] — 2026-07-19

### Added

- **Ed25519 signing** over each run's integrity anchor (`keygen`, auto-sign at
  ingest, `verify` reporting chain and signature). Re-chaining a tampered record
  without the private key now fails verification — the hash chain alone could
  always be recomputed by whoever controlled the store. `anchor` externalizes
  `runHash` and signature to a WORM-pushable JSONL file.
- **`@traceglass/sdk`**: a live-capture recorder that hash-chains each step the
  moment it happens and journals it to disk, so recorded history cannot be
  reordered or edited after the fact. Crash-safe: `recover` finalizes an
  orphaned journal into a `failed` run whose chain still verifies.
- **Collector mode.** `serve` with a fixed port, bearer-token ingest
  (`/api/ingest` auto-detecting native/OTLP, plus OTLP-compatible `/v1/traces`),
  timing-safe auth, and `--retain` retention whose deletions are the store's
  only delete path and are audit-logged. A non-loopback bind without a token is
  refused.
- **Portable `.tgev` evidence export.** `verify` and `report` accept a file and
  work fully offline — no store, no keys, no network, with the public key
  travelling in the file.
- A Dockerfile shipping the collector image.
- Outcome proof: `packages/cli/src/e2e.test.ts` and `scripts/e2e-check.mjs`
  exercise capture → sign → collect → export → offline verify → tamper-detect.

## [0.2.0] — 2026-06-24

### Added

- Claude Code session JSONL ingestion and a session picker: ingest runs from
  `~/.claude/projects`, replay them on the timeline, and verify the hash chain —
  local-first, with zero network egress.
- Tamper-evident, replayable audit dashboard for autonomous agents.

## [0.1.0]

Initial public release, published to npm.

This version predates the current repository history — the root commit is
v0.2.0 — so no per-change detail is reconstructable from the log. Left here for
completeness of the version record rather than as a description of its contents.
