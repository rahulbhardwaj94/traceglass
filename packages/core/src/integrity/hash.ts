import { createHash } from 'node:crypto';
import type { Run, Step } from '../model.js';

/**
 * Tamper-evidence hash chain (PRD §6).
 *
 *   hash(step) = sha256(canonical(step) + prevHash)
 *   step[0].prevHash = ''
 *   runHash = last step's hash
 *
 * Editing any stored step changes its canonical form, which changes its hash,
 * which (because the next step mixes in this prevHash) breaks every step after
 * it. That cascade is what makes the record auditable rather than just logged.
 */

/**
 * Payload fields that carry per-leaf commitments (v0.6 redaction). Declared
 * here rather than in redact/ because the hash function must consult them and
 * redact/commit.ts already depends on `canonicalize` below.
 */
export const COMMITTED_FIELDS = ['input', 'output', 'dataPayload'] as const;
export type CommittedField = (typeof COMMITTED_FIELDS)[number];

/** Fields that are covered by the hash (everything except the chain fields). */
const HASHED_FIELDS = [
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
 * Deterministic JSON serialization: object keys sorted recursively so the
 * encoding is stable regardless of insertion order. Arrays keep their order.
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
 * `<field>`, `<field>.x`, or `<field>[0]`, so prefix matching is exact.
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
 * Canonical string of a step's hashed content (excludes hash/prevHash/runId).
 *
 * v0.6: when a step carries per-leaf `commitments`, each payload field is
 * hashed via its commitments rather than its raw value. That is what lets a
 * leaf be redacted later without changing the step hash — the chain never
 * covered the raw value in the first place. Steps WITHOUT commitments hash
 * exactly as they always did, so every pre-0.6 record still verifies.
 */
export function canonicalStep(step: Step): string {
  const picked: Record<string, unknown> = {};
  for (const f of HASHED_FIELDS) {
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

/** Compute the hash of a single step given the previous step's hash. */
export function hashStep(step: Step, prevHash: string): string {
  return createHash('sha256')
    .update(canonicalStep(step) + prevHash)
    .digest('hex');
}

/**
 * Return a copy of the steps with `hash`/`prevHash` recomputed as a chain.
 * Pure: does not mutate the input.
 */
export function chainSteps(steps: Step[]): Step[] {
  let prevHash = '';
  return steps.map((step) => {
    const hash = hashStep(step, prevHash);
    const chained: Step = { ...step, prevHash, hash };
    prevHash = hash;
    return chained;
  });
}

/**
 * Attach the integrity chain to a run: recompute every step hash and set
 * `runHash` to the final step's hash. Pure.
 */
export function applyHashChain(run: Run): Run {
  const steps = chainSteps(run.steps);
  const runHash = steps.length > 0 ? steps[steps.length - 1]!.hash : '';
  return { ...run, steps, runHash };
}
