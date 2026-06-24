import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RunSchema } from '../model.js';
import { verifyRun } from '../integrity/index.js';
import { ingestClaudeCodeAndFinalize } from '../pipeline.js';
import {
  ingestClaudeCodeSession,
  isClaudeCodeFormat,
  parseClaudeCodeJsonl,
} from './claude-code.js';
import { costForUsage, priceForModel, DEFAULT_MODEL_PRICES } from './model-prices.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const records = parseClaudeCodeJsonl(
  readFileSync(join(fixturesDir, 'sample-claude-code-session.jsonl'), 'utf8'),
);

describe('claude code jsonl parsing', () => {
  it('parses each non-empty line, tolerating trailing newline', () => {
    expect(records.length).toBe(10);
  });
  it('recognizes the claude code format', () => {
    expect(isClaudeCodeFormat(records)).toBe(true);
    expect(isClaudeCodeFormat([{ resourceSpans: [] }])).toBe(false);
  });
});

describe('claude code ingestion', () => {
  const run = ingestClaudeCodeSession(records);

  it('produces a Run that satisfies the Zod schema (after finalize)', () => {
    expect(() => RunSchema.parse(ingestClaudeCodeAndFinalize(records))).not.toThrow();
  });

  it('maps message types to the v1 step model', () => {
    const types = run.steps.map((s) => s.type);
    expect(types[0]).toBe('user_input');
    expect(types).toContain('llm_reasoning'); // thinking + assistant text
    expect(types.filter((t) => t === 'tool_call')).toHaveLength(3);
    expect(types[types.length - 1]).toBe('final_output');
  });

  it('attaches tool_result output and structured toolUseResult as dataPayload', () => {
    const tc = run.steps.find((s) => s.type === 'tool_call');
    expect(tc?.toolName).toBe('get_payment_status');
    expect(tc?.input).toEqual({ accountId: '4471' });
    expect(tc?.output).toContain('pending');
    expect(tc?.dataPayload).toMatchObject({ accountId: '4471', outstanding: 22400 });
  });

  it('does not double-count tokens across a multi-block message', () => {
    // Each assistant message's usage is attributed to exactly one step.
    const summed = run.steps.reduce((a, s) => a + s.tokens, 0);
    expect(run.totals.tokens).toBe(summed);
    expect(run.totals.tokens).toBeGreaterThan(0);
  });

  it('derives cost from the model price table', () => {
    expect(run.totals.cost).toBeGreaterThan(0);
    expect(run.currency).toBe('USD');
  });

  it('detects the stuck tool loop on real session shape', () => {
    const finalized = ingestClaudeCodeAndFinalize(records);
    expect(finalized.warnings.some((w) => w.kind === 'loop')).toBe(true);
  });

  it('passes the integrity hash chain', () => {
    expect(verifyRun(ingestClaudeCodeAndFinalize(records)).ok).toBe(true);
  });

  it('preserves the entry tree via spanId/parentSpanId', () => {
    expect(run.steps[0]!.spanId).toBe('u1');
    expect(run.steps.every((s) => typeof s.spanId === 'string' && s.spanId.length > 0)).toBe(true);
  });
});

describe('model price table', () => {
  it('prices sonnet cache reads at 0.1x input', () => {
    const price = priceForModel('claude-sonnet-4-6', DEFAULT_MODEL_PRICES);
    // 1M cache-read tokens at 0.1x of $3/1M = $0.30
    expect(costForUsage({ cache_read_input_tokens: 1_000_000 }, price)).toBeCloseTo(0.3, 6);
  });
  it('resolves dated snapshots by prefix', () => {
    expect(priceForModel('claude-haiku-4-5-20251001', DEFAULT_MODEL_PRICES).input).toBe(1);
  });
});
