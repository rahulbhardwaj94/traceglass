import type { Run, Step, Warning } from '../model.js';
import { detectLoops } from './loops.js';
import { computeTotals, detectHighCostSteps } from './cost.js';

export { detectLoops } from './loops.js';
export { computeTotals, detectHighCostSteps } from './cost.js';

/** Surface every `error` step as a warning. */
export function detectErrors(steps: Step[]): Warning[] {
  return steps
    .filter((s) => s.type === 'error')
    .map((s) => ({
      kind: 'error' as const,
      message: `Error at step #${s.index}: ${s.label}`,
      stepIds: [s.id],
    }));
}

/** Run every analyzer over a run's steps and collect warnings. */
export function analyzeSteps(steps: Step[]): Warning[] {
  return [...detectLoops(steps), ...detectHighCostSteps(steps), ...detectErrors(steps)];
}

/**
 * Return a copy of the run with recomputed totals and freshly attached
 * warnings. Pure — does not mutate the input.
 */
export function analyzeRun(run: Run): Run {
  return {
    ...run,
    totals: computeTotals(run.steps),
    warnings: analyzeSteps(run.steps),
  };
}
