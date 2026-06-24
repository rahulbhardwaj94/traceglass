import { describe, expect, it } from 'vitest';
import { accumulate, money, durationLabel, stepTypeLabel } from './format.js';
import type { Step } from './types.js';

function step(index: number, tokens: number, cost: number, durationMs: number): Step {
  return {
    id: `s${index}`,
    runId: 'r',
    index,
    type: 'tool_call',
    label: `step ${index}`,
    startedAt: new Date(index * 1000).toISOString(),
    durationMs,
    tokens,
    cost,
    spanId: `span${index}`,
    hash: '',
    prevHash: '',
  };
}

const steps = [step(0, 100, 1, 50), step(1, 200, 2, 60), step(2, 50, 0.5, 10)];

describe('accumulate (running totals climb with scrub position)', () => {
  it('accumulates only up to and including the selected index', () => {
    expect(accumulate(steps, 0)).toEqual({ tokens: 100, cost: 1, durationMs: 50, steps: 1 });
    expect(accumulate(steps, 1)).toEqual({ tokens: 300, cost: 3, durationMs: 110, steps: 2 });
    expect(accumulate(steps, 2)).toEqual({ tokens: 350, cost: 3.5, durationMs: 120, steps: 3 });
  });

  it('is monotonically non-decreasing as the index advances', () => {
    let prev = 0;
    for (let i = 0; i < steps.length; i++) {
      const cost = accumulate(steps, i).cost;
      expect(cost).toBeGreaterThanOrEqual(prev);
      prev = cost;
    }
  });
});

describe('formatters', () => {
  it('formats money with currency', () => {
    expect(money('INR', 14.1)).toBe('INR 14.10');
  });
  it('formats durations', () => {
    expect(durationLabel(950)).toBe('950 ms');
    expect(durationLabel(2500)).toBe('2.50 s');
  });
  it('humanizes step types', () => {
    expect(stepTypeLabel('llm_reasoning')).toBe('llm reasoning');
  });
});
