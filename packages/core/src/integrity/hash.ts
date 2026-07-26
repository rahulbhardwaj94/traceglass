import { createHash } from 'node:crypto';
import type { Run, Step } from '../model.js';

/**
 * Tamper-evidence hash chain (PRD §6, SPEC.md §5–§6).
 *
 *   hash(step) = sha256(canonical(step) + prevHash)
 *   step[0].prevHash = ''
 *   runHash = last step's hash                            (hashVersion 1)
 *   runHash = sha256(run header || chain anchor)          (hashVersion 2)
 *
 * Editing any stored step changes its canonical form, which changes its hash,
 * which (because the next step mixes in this prevHash) breaks every step after
 * it. That cascade is what makes the record auditable rather than just logged.
 *
 * ── Versioning ───────────────────────────────────────────────────────────────
 * A record declares its hashing rules in `run.hashVersion`. A record with NO
 * `hashVersion` is `tgcanon/1` — the format published in 0.3.0–0.8.0 — and MUST
 * be hashed and verified by the version-1 code paths below, unchanged, forever.
 * Those records exist in the wild and the product promise is that they keep
 * verifying bit-identically.
 *
 * `tgcanon/2` (this release) changes exactly this much in the hashing rules:
 *   1. the run anchor commits to run METADATA and to the step count, so
 *      currency/status/totals/name/timestamps can no longer be edited on a
 *      verifying record (SPEC §12.1);
 *   2. commitment path segments are escaped, so a literal `.` in a key can no
 *      longer collide with nesting and raise a FALSE integrity alarm on an
 *      honest record (SPEC §12.5) — see redact/commit.ts;
 *   3. `runId` joins the hashed field set and both preimages get a
 *      domain-separation tag (SPEC §12.2, §12.6).
 * The redaction rules also tighten; those live in redact/ and integrity/.
 */

export type HashVersion = 1 | 2;

/** Versions this build can hash and verify. */
export const SUPPORTED_HASH_VERSIONS: readonly HashVersion[] = [1, 2];

/** What NEW captures emit. Existing records keep whatever they declared. */
export const DEFAULT_HASH_VERSION: HashVersion = 2;

/** The version a record declares; absent means the implicit original, 1. */
export function hashVersionOf(run: { hashVersion?: number }): number {
  return run.hashVersion ?? 1;
}

export function isSupportedHashVersion(v: number): v is HashVersion {
  return (SUPPORTED_HASH_VERSIONS as readonly number[]).includes(v);
}

/**
 * Payload fields that carry per-leaf commitments (v0.6 redaction). Declared
 * here rather than in redact/ because the hash function must consult them and
 * redact/commit.ts already depends on `canonicalize` below.
 */
export const COMMITTED_FIELDS = ['input', 'output', 'dataPayload'] as const;
export type CommittedField = (typeof COMMITTED_FIELDS)[number];

/** Fields covered by the hash in tgcanon/1 (everything except the chain fields). */
const HASHED_FIELDS_V1 = [
  'id',
  'index',
  'type',
  'label',
  'startedAt',
  'durationMs',
  'tokens',
  'cost',
  'toolName',
  'input',
  'output',
  'dataPayload',
  'spanId',
  'parentSpanId',
] as const;

/**
 * tgcanon/2 adds `runId`, so a step can no longer be lifted verbatim out of one
 * run into another at the same chain position (SPEC §12.2).
 */
const HASHED_FIELDS_V2 = ['runId', ...HASHED_FIELDS_V1] as const;

/**
 * Domain-separation tag and separator for the v2 preimages (SPEC §12.6).
 *
 * U+0000 is the separator because `tgcanon` escapes every code unit below
 * U+0020 (SPEC §4.3), so a raw NUL can never occur inside a canonical form.
 * A v2 preimage is therefore unambiguously parseable, which v1's bare
 * `canonicalStep + prevHash` was only by accident.
 */
const SEP = String.fromCharCode(0); // U+0000
const STEP_TAG_V2 = `tgstep/2${SEP}`;
const RUN_TAG_V2 = `tgrun/2${SEP}`;

/**
 * Deterministic JSON serialization: object keys sorted recursively so the
 * encoding is stable regardless of insertion order. Arrays keep their order.
 *
 * Unchanged between versions — `tgcanon/2` reuses `tgcanon/1`'s encoding
 * verbatim. Only WHAT is fed to it changed, never HOW it encodes.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortValue((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/**
 * Sub-map of a commitment map belonging to one payload field. Paths are
 * `<field>`, `<field>.x`, or `<field>[0]`, so prefix matching is exact — the
 * field names contain no character that path escaping touches, in either
 * version.
 */
function commitmentViewFor(
  commitments: Record<string, string>,
  field: CommittedField,
): Record<string, string> {
  const view: Record<string, string> = {};
  for (const [path, commitment] of Object.entries(commitments)) {
    if (path === field || path.startsWith(`${field}.`) || path.startsWith(`${field}[`)) {
      view[path] = commitment;
    }
  }
  return view;
}

/**
 * Canonical string of a step's hashed content (excludes hash/prevHash).
 *
 * v0.6: when a step carries per-leaf `commitments`, each payload field is
 * hashed via its commitments rather than its raw value. That is what lets a
 * leaf be redacted later without changing the step hash — the chain never
 * covered the raw value in the first place. Steps WITHOUT commitments hash
 * exactly as they always did, so every pre-0.6 record still verifies.
 */
export function canonicalStep(step: Step, version: HashVersion = 1): string {
  const fields = version === 2 ? HASHED_FIELDS_V2 : HASHED_FIELDS_V1;
  const picked: Record<string, unknown> = {};
  for (const f of fields) {
    const v = (step as Record<string, unknown>)[f];
    if (v !== undefined) picked[f] = v;
  }
  const commitments = step.commitments;
  if (commitments) {
    for (const field of COMMITTED_FIELDS) {
      const view = commitmentViewFor(commitments, field);
      if (Object.keys(view).length > 0) picked[field] = view;
    }
  }
  return canonicalize(picked);
}

/**
 * Compute the hash of a single step given the previous step's hash.
 *
 * Defaults to version 1 so that every existing caller — and every record
 * already on disk — keeps its exact bytes. Capture paths pass 2 explicitly.
 */
export function hashStep(step: Step, prevHash: string, version: HashVersion = 1): string {
  const preimage =
    version === 2
      ? `${STEP_TAG_V2}${canonicalStep(step, 2)}${SEP}${prevHash}`
      : canonicalStep(step, 1) + prevHash;
  return createHash('sha256').update(preimage).digest('hex');
}

/**
 * Return a copy of the steps with `hash`/`prevHash` recomputed as a chain.
 * Pure: does not mutate the input.
 */
export function chainSteps(steps: Step[], version: HashVersion = 1): Step[] {
  let prevHash = '';
  return steps.map((step) => {
    const hash = hashStep(step, prevHash, version);
    const chained: Step = { ...step, prevHash, hash };
    prevHash = hash;
    return chained;
  });
}

/** Recompute the chain anchor (final step hash) independently of stored hashes. */
export function chainAnchor(steps: Step[], version: HashVersion = 1): string {
  let prevHash = '';
  for (const step of steps) prevHash = hashStep(step, prevHash, version);
  return prevHash;
}

/**
 * The run metadata that tgcanon/2 seals into the anchor. `warnings` is excluded
 * deliberately: it is derived from the steps by `analyzeRun`, not evidence.
 */
function runHeader(run: Run, anchor: string): Record<string, unknown> {
  return {
    hashVersion: 2,
    id: run.id,
    name: run.name,
    startedAt: run.startedAt,
    endedAt: run.endedAt,
    status: run.status,
    currency: run.currency,
    totals: {
      tokens: run.totals.tokens,
      cost: run.totals.cost,
      durationMs: run.totals.durationMs,
      steps: run.totals.steps,
    },
    // The real length, independent of `totals.steps`, so a truncated chain does
    // not re-anchor cleanly even on an unsigned record.
    stepCount: run.steps.length,
    chainAnchor: anchor,
  };
}

/**
 * The run's integrity anchor.
 *
 * v1: literally the last step's hash. Run metadata is covered by nothing, which
 *     is SPEC §6.2 / §12.1 — the defect v2 exists to fix.
 * v2: a hash over the run header (id, name, timestamps, status, currency,
 *     totals, step count) AND the chain anchor. Editing `currency` on a v2
 *     record therefore moves `runHash`, which fails verification and — on a
 *     signed record — invalidates the signature too, because the signature
 *     covers `runHash`. Redaction still leaves it untouched: redaction changes
 *     only raw values, salts and the redaction log, none of which are in here.
 *
 * A run with no steps anchors to `''` in both versions: an empty run asserts
 * nothing and is not signable (SPEC §6.1).
 *
 * `anchor` defaults to the stored final step hash; verification passes the
 * freshly recomputed one instead.
 */
export function computeRunHash(run: Run, anchor?: string): string {
  if (run.steps.length === 0) return '';
  const last = run.steps[run.steps.length - 1];
  const chain = anchor ?? last?.hash ?? '';
  if (hashVersionOf(run) !== 2) return chain;
  return createHash('sha256')
    .update(RUN_TAG_V2 + canonicalize(runHeader(run, chain)))
    .digest('hex');
}

export interface HashChainOptions {
  /** Override the version to chain under. Defaults to the run's own, then 2. */
  hashVersion?: HashVersion;
}

/**
 * Has this run already been chained? Used to tell a structural draft coming out
 * of ingestion (every hash still `''`) from a record that has been sealed
 * before — including every published `tgcanon/1` file, which declares no
 * version and must not be silently promoted to one.
 */
function isAlreadyChained(run: Run): boolean {
  return run.runHash !== '' || run.steps.some((s) => s.hash !== '' || s.prevHash !== '');
}

/**
 * Attach the integrity chain to a run: recompute every step hash and the
 * `runHash` anchor. Pure.
 *
 * Version selection, most specific first:
 *   1. `opts.hashVersion`, when the caller states one;
 *   2. the version the run declares;
 *   3. version 1 if the run is already chained but declares nothing — i.e. a
 *      published legacy record. Re-chaining such a record under version 2 would
 *      move its anchor and invalidate its signature, quietly orphaning every
 *      copy an auditor already holds;
 *   4. otherwise the current default: this is a fresh capture.
 */
export function applyHashChain(run: Run, opts: HashChainOptions = {}): Run {
  const declared = run.hashVersion;
  const version =
    opts.hashVersion ??
    (declared !== undefined && isSupportedHashVersion(declared)
      ? declared
      : isAlreadyChained(run)
        ? 1
        : DEFAULT_HASH_VERSION);
  const versioned: Run = {
    ...run,
    ...(version === 1 ? {} : { hashVersion: version }),
    steps: chainSteps(run.steps, version),
  };
  return { ...versioned, runHash: computeRunHash(versioned) };
}
