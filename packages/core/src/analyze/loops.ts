import type { Step, Warning } from '../model.js';
import { canonicalize } from '../integrity/hash.js';

/** Minimum consecutive identical tool calls before we call it a loop. */
const LOOP_THRESHOLD = 3;

/**
 * Detect silent tool-call loops (PRD §M2): a run of >= 3 consecutive
 * `tool_call` steps with the same `toolName` and similar input. Each maximal
 * loop run produces one Warning listing the repeated step ids.
 *
 * "Similar input" is defined as identical canonical JSON of the step input —
 * deliberately strict, so we don't flag a tool legitimately called with
 * different arguments.
 */
export function detectLoops(steps: Step[]): Warning[] {
  const warnings: Warning[] = [];
  let i = 0;

  while (i < steps.length) {
    const start = steps[i]!;
    if (start.type !== 'tool_call' || start.toolName === undefined) {
      i++;
      continue;
    }

    const key = canonicalize(start.input ?? null);
    let j = i + 1;
    while (
      j < steps.length &&
      steps[j]!.type === 'tool_call' &&
      steps[j]!.toolName === start.toolName &&
      canonicalize(steps[j]!.input ?? null) === key
    ) {
      j++;
    }

    const runLength = j - i;
    if (runLength >= LOOP_THRESHOLD) {
      const group = steps.slice(i, j);
      warnings.push({
        kind: 'loop',
        message: `Tool "${start.toolName}" was called ${runLength}x in a row with identical input — likely a stuck loop burning tokens/cost.`,
        stepIds: group.map((s) => s.id),
      });
    }

    i = j > i + 1 ? j : i + 1;
  }

  return warnings;
}
