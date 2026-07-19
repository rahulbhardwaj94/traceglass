import { describe, expect, it } from 'vitest';
import type { Run, Step, StepType } from '../model.js';
import { applyHashChain } from '../integrity/hash.js';
import { analyzeRun } from '../analyze/index.js';
import { evaluatePolicy, parsePolicy, toolMatches } from './policy.js';

function step(index: number, type: StepType, over: Partial<Step> = {}): Step {
  return {
    id: `r:${index}`,
    runId: 'r',
    index,
    type,
    label: over.label ?? `${type} ${index}`,
    startedAt: `2026-01-01T00:00:0${index}.000Z`,
    durationMs: 100,
    tokens: 10,
    cost: 1,
    spanId: `s${index}`,
    hash: '',
    prevHash: '',
    ...over,
  };
}

function makeRun(steps: Step[]): Run {
  const totals = steps.reduce(
    (a, s) => ({
      tokens: a.tokens + s.tokens,
      cost: a.cost + s.cost,
      durationMs: a.durationMs + s.durationMs,
      steps: a.steps + 1,
    }),
    { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
  );
  return applyHashChain(
    analyzeRun({
      id: 'r',
      name: 'policy test run',
      startedAt: steps[0]!.startedAt,
      endedAt: steps[steps.length - 1]!.startedAt,
      status: 'completed',
      currency: 'USD',
      totals,
      warnings: [],
      steps,
      runHash: '',
    }),
  );
}

describe('toolMatches', () => {
  it('handles exact, prefix, suffix, and universal patterns', () => {
    expect(toolMatches('db_query', 'db_query')).toBe(true);
    expect(toolMatches('payments.refund', 'payments.*')).toBe(true);
    expect(toolMatches('accounts_delete', '*_delete')).toBe(true);
    expect(toolMatches('anything', '*')).toBe(true);
    expect(toolMatches('db_query', 'payments.*')).toBe(false);
  });
});

describe('evaluatePolicy', () => {
  const base = makeRun([
    step(0, 'user_input'),
    step(1, 'tool_call', { toolName: 'get_status', cost: 2 }),
    step(2, 'tool_call', { toolName: 'payments.refund', cost: 5 }),
    step(3, 'final_output'),
  ]);

  it('passes an empty policy', () => {
    const result = evaluatePolicy(base, parsePolicy({ rules: {} }));
    expect(result.ok).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it('flags run-level cost, token, and step-count limits', () => {
    const result = evaluatePolicy(
      base,
      parsePolicy({ rules: { maxCostPerRun: 5, maxTokensPerRun: 20, maxSteps: 3 } }),
    );
    expect(result.ok).toBe(false);
    expect(result.violations.map((v) => v.rule).sort()).toEqual([
      'maxCostPerRun',
      'maxSteps',
      'maxTokensPerRun',
    ]);
  });

  it('flags individual steps over maxCostPerStep with their ids', () => {
    const result = evaluatePolicy(base, parsePolicy({ rules: { maxCostPerStep: 4 } }));
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]!.stepIds).toEqual(['r:2']);
  });

  it('flags forbidden tools by wildcard pattern', () => {
    const result = evaluatePolicy(base, parsePolicy({ rules: { forbidTools: ['payments.*'] } }));
    expect(result.ok).toBe(false);
    expect(result.violations[0]!.rule).toBe('forbidTools');
    expect(result.violations[0]!.stepIds).toEqual(['r:2']);
  });

  it('requireApprovalFor fails when no approval precedes the tool call', () => {
    const result = evaluatePolicy(
      base,
      parsePolicy({ rules: { requireApprovalFor: ['payments.*'] } }),
    );
    expect(result.ok).toBe(false);
    expect(result.violations[0]!.rule).toBe('requireApprovalFor');
  });

  it('requireApprovalFor passes when an approval step comes first', () => {
    const approved = makeRun([
      step(0, 'user_input'),
      step(1, 'approval', { label: 'Supervisor approved refund', input: { approver: 'lead-ops' } }),
      step(2, 'tool_call', { toolName: 'payments.refund', cost: 5 }),
      step(3, 'final_output'),
    ]);
    const result = evaluatePolicy(
      approved,
      parsePolicy({ rules: { requireApprovalFor: ['payments.*'] } }),
    );
    expect(result.ok).toBe(true);
  });

  it('an approval AFTER the tool call does not count', () => {
    const late = makeRun([
      step(0, 'tool_call', { toolName: 'payments.refund' }),
      step(1, 'approval'),
      step(2, 'final_output'),
    ]);
    const result = evaluatePolicy(
      late,
      parsePolicy({ rules: { requireApprovalFor: ['payments.refund'] } }),
    );
    expect(result.ok).toBe(false);
  });

  it('forbidInputText flags steps whose input contains the fragment, case-insensitively (v0.5)', () => {
    const coding = makeRun([
      step(0, 'user_input'),
      step(1, 'tool_call', { toolName: 'Edit', input: { file_path: '/app/.ENV', content: 'x' } }),
      step(2, 'tool_call', { toolName: 'Bash', input: { command: 'ls' } }),
      step(3, 'final_output'),
    ]);
    const result = evaluatePolicy(
      coding,
      parsePolicy({ rules: { forbidInputText: ['.env', 'rm -rf'] } }),
    );
    expect(result.ok).toBe(false);
    expect(result.violations).toHaveLength(1); // only .env matched, only step 1
    expect(result.violations[0]!.stepIds).toEqual(['r:1']);
  });

  it('requireSignature fails an unsigned run and names the fix', () => {
    const result = evaluatePolicy(base, parsePolicy({ rules: { requireSignature: true } }));
    expect(result.ok).toBe(false);
    expect(result.violations[0]!.message).toContain('keygen');
  });

  it('forbidWarnings surfaces analyzer warnings as violations', () => {
    const loopy = makeRun([
      step(0, 'user_input'),
      ...Array.from({ length: 4 }, (_, i) =>
        step(i + 1, 'tool_call', { toolName: 'get_status', label: 'Tool: get_status' }),
      ),
      step(5, 'final_output'),
    ]);
    expect(loopy.warnings.some((w) => w.kind === 'loop')).toBe(true);
    const result = evaluatePolicy(loopy, parsePolicy({ rules: { forbidWarnings: ['loop'] } }));
    expect(result.ok).toBe(false);
    expect(result.violations[0]!.rule).toBe('forbidWarnings');
    expect(result.violations[0]!.stepIds.length).toBeGreaterThan(0);
  });

  it('rejects unknown rule keys instead of silently ignoring them', () => {
    expect(() => parsePolicy({ rules: { maxCots: 5 } })).toThrow();
  });
});
