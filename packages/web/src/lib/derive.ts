// Client-side analysis the API model doesn't carry but the design surfaces:
// the median step cost (for the high-cost accent), the read/mutated access of a
// data payload, and the loop span on the timeline. All derived from the live
// Run so the UI stays a pure view over real data.

import type { Run, Step, Warning } from '../types.js';

/** Median of the nonzero step costs — mirrors core's high-cost baseline. */
export function medianNonZeroCost(steps: Step[]): number {
  const costs = steps
    .map((s) => s.cost)
    .filter((c) => c > 0)
    .sort((a, b) => a - b);
  if (costs.length === 0) return 0;
  const mid = Math.floor(costs.length / 2);
  return costs.length % 2 ? costs[mid]! : (costs[mid - 1]! + costs[mid]!) / 2;
}

export function isHighCost(step: Step, median: number): boolean {
  return median > 0 && step.cost > 3 * median && step.cost > 0;
}

export type Access = 'READ' | 'MUTATED' | null;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Access classification for a step's data payload. Honors an explicit `_access`
 * marker when present; otherwise infers from the step type (tool reads vs.
 * decision/branch writes). Returns null when there is no payload.
 */
export function accessOf(step: Step): Access {
  if (!isRecord(step.dataPayload)) return step.dataPayload != null ? 'READ' : null;
  const explicit = step.dataPayload['_access'];
  if (typeof explicit === 'string') {
    const v = explicit.toUpperCase();
    if (v === 'READ' || v === 'MUTATED') return v;
  }
  if (step.type === 'final_output' || step.type === 'branch') return 'MUTATED';
  return 'READ';
}

/** The payload as shown — without the internal `_access` marker. */
export function payloadView(step: Step): unknown {
  if (!isRecord(step.dataPayload)) return step.dataPayload;
  if (!('_access' in step.dataPayload)) return step.dataPayload;
  const { _access, ...rest } = step.dataPayload;
  void _access;
  return rest;
}

/** A short label for the payload's source table/record, if discernible. */
export function payloadSource(step: Step): string | null {
  if (!isRecord(step.dataPayload)) return null;
  const t = step.dataPayload['table'];
  return typeof t === 'string' ? t : null;
}

/** The contiguous index span [start,end] covered by loop-warning steps, or null. */
export function loopSpan(steps: Step[], loopIds: Set<string>): { start: number; end: number } | null {
  const idx = steps.filter((s) => loopIds.has(s.id)).map((s) => s.index);
  if (idx.length === 0) return null;
  return { start: Math.min(...idx), end: Math.max(...idx) };
}

/** A one-line meta string for a warning row (steps spanned / cost multiple / state). */
export function warningMeta(w: Warning, steps: Step[], median: number): string {
  const byId = new Map(steps.map((s) => [s.id, s]));
  if (w.kind === 'loop') {
    const labels = w.stepIds
      .map((id) => byId.get(id))
      .filter((s): s is Step => !!s)
      .map((s) => `#${s.index + 1}`);
    return `${w.stepIds.length} steps · ${labels.join(' ')}`;
  }
  if (w.kind === 'high_cost_step') {
    const s = w.stepIds[0] ? byId.get(w.stepIds[0]) : undefined;
    if (s && median > 0) return `${Math.round(s.cost / median)}× median`;
    return 'over budget';
  }
  return 'run failed';
}

export function loopStepIdSet(run: Run): Set<string> {
  const set = new Set<string>();
  for (const w of run.warnings) {
    if (w.kind === 'loop') w.stepIds.forEach((id) => set.add(id));
  }
  return set;
}

export function indexStepsById(steps: Step[]): Map<string, number> {
  const m = new Map<string, number>();
  steps.forEach((s, i) => m.set(s.id, i));
  return m;
}
