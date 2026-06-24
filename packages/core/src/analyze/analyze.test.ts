import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ingestNative } from '../ingest/index.js';
import { analyzeRun, detectLoops, detectHighCostSteps } from './index.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const load = (name: string): unknown =>
  JSON.parse(readFileSync(join(fixturesDir, name), 'utf8'));

const loopRun = ingestNative(load('sample-run-loop.json'));
const cleanRun = ingestNative(load('sample-run-native.json'));

describe('loop detection (acceptance §M2)', () => {
  it('yields exactly one loop warning on the loop fixture', () => {
    const warnings = detectLoops(loopRun.steps);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]!.kind).toBe('loop');
  });

  it('flags the right steps (the three repeated get_payment_status calls)', () => {
    const [warning] = detectLoops(loopRun.steps);
    const flagged = loopRun.steps.filter((s) => warning!.stepIds.includes(s.id));
    expect(flagged).toHaveLength(3);
    expect(flagged.every((s) => s.toolName === 'get_payment_status')).toBe(true);
  });

  it('does not flag a clean run', () => {
    expect(detectLoops(cleanRun.steps)).toHaveLength(0);
  });

  it('does not flag two consecutive identical calls (below threshold)', () => {
    const two = loopRun.steps.filter((s, i) => i < 4); // user_input, plan, tool, tool
    expect(detectLoops(two)).toHaveLength(0);
  });
});

describe('high-cost detection (acceptance §M2)', () => {
  it('flags a step exceeding 3x the median cost', () => {
    const warnings = detectHighCostSteps(loopRun.steps);
    expect(warnings.length).toBeGreaterThanOrEqual(1);
    expect(warnings.every((w) => w.kind === 'high_cost_step')).toBe(true);
  });
});

describe('analyzeRun', () => {
  it('attaches loop + error warnings for the loop run', () => {
    const analyzed = analyzeRun(loopRun);
    const kinds = analyzed.warnings.map((w) => w.kind);
    expect(kinds).toContain('loop');
    expect(kinds).toContain('error');
  });

  it('recomputes totals', () => {
    const analyzed = analyzeRun(cleanRun);
    expect(analyzed.totals.steps).toBe(cleanRun.steps.length);
  });
});
