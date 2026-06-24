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

/** Canonical string of a step's hashed content (excludes hash/prevHash/runId). */
export function canonicalStep(step: Step): string {
  const picked: Record<string, unknown> = {};
  for (const f of HASHED_FIELDS) {
    const v = (step as Record<string, unknown>)[f];
    if (v !== undefined) picked[f] = v;
  }
  return canonicalize(picked);
}

/** Compute the hash of a single step given the previous step's hash. */
export function hashStep(step: Step, prevHash: string): string {
  return createHash('sha256').update(canonicalStep(step) + prevHash).digest('hex');
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
