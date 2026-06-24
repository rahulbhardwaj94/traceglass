import type { RunTotals, Step, Warning } from '../model.js';

/** A step is "high cost" if it exceeds this multiple of the median step cost. */
const HIGH_COST_MULTIPLE = 3;

/** Compute run totals as the sum across steps (PRD §3 RunTotals). */
export function computeTotals(steps: Step[]): RunTotals {
  return steps.reduce<RunTotals>(
    (acc, s) => ({
      tokens: acc.tokens + s.tokens,
      cost: acc.cost + s.cost,
      durationMs: acc.durationMs + s.durationMs,
      steps: acc.steps + 1,
    }),
    { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
  );
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1]! + sorted[mid]!) / 2 : sorted[mid]!;
}

/**
 * Flag any step whose cost exceeds 3x the median step cost (PRD §M2).
 * Steps with zero cost are excluded from the median so a few free steps don't
 * drag the baseline to zero and flag everything.
 */
export function detectHighCostSteps(steps: Step[]): Warning[] {
  const nonZero = steps.map((s) => s.cost).filter((c) => c > 0);
  const med = median(nonZero);
  if (med <= 0) return [];

  const threshold = med * HIGH_COST_MULTIPLE;
  const warnings: Warning[] = [];
  for (const s of steps) {
    if (s.cost > threshold) {
      warnings.push({
        kind: 'high_cost_step',
        message: `Step #${s.index} (${s.label}) cost ${s.cost.toFixed(2)} — over ${HIGH_COST_MULTIPLE}x the median step cost (${med.toFixed(2)}).`,
        stepIds: [s.id],
      });
    }
  }
  return warnings;
}
