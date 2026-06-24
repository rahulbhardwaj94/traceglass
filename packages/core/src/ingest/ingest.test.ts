import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RunSchema, type Run } from '../model.js';
import { detectFormat, ingestAuto, ingestNative, ingestOtel } from './index.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const load = (name: string): unknown =>
  JSON.parse(readFileSync(join(fixturesDir, name), 'utf8'));

const otelRaw = load('sample-run-otel.json');
const nativeRaw = load('sample-run-native.json');
const loopRaw = load('sample-run-loop.json');

/** The structural projection that must match across ingest formats. */
function structure(run: Run) {
  return {
    id: run.id,
    name: run.name,
    status: run.status,
    currency: run.currency,
    totals: run.totals,
    steps: run.steps.map((s) => ({
      index: s.index,
      type: s.type,
      label: s.label,
      startedAt: s.startedAt,
      durationMs: s.durationMs,
      tokens: s.tokens,
      cost: s.cost,
      toolName: s.toolName,
      input: s.input,
      output: s.output,
      dataPayload: s.dataPayload,
    })),
  };
}

describe('format detection', () => {
  it('detects OTel exports', () => {
    expect(detectFormat(otelRaw)).toBe('otel');
  });
  it('detects native runs', () => {
    expect(detectFormat(nativeRaw)).toBe('native');
    expect(detectFormat(loopRaw)).toBe('native');
  });
  it('returns null for garbage', () => {
    expect(detectFormat({ hello: 'world' })).toBeNull();
  });
});

describe('native ingestion', () => {
  it('produces a Run that satisfies the Zod schema', () => {
    const run = ingestNative(nativeRaw);
    expect(() => RunSchema.parse(run)).not.toThrow();
  });

  it('assigns 0-based contiguous indices and runId', () => {
    const run = ingestNative(loopRaw);
    run.steps.forEach((s, i) => {
      expect(s.index).toBe(i);
      expect(s.runId).toBe(run.id);
    });
  });

  it('derives failed status from an error step', () => {
    const run = ingestNative(loopRaw);
    expect(run.status).toBe('failed');
  });

  it('computes totals as the sum across steps', () => {
    const run = ingestNative(nativeRaw);
    const tokens = run.steps.reduce((a, s) => a + s.tokens, 0);
    const cost = run.steps.reduce((a, s) => a + s.cost, 0);
    expect(run.totals.tokens).toBe(tokens);
    expect(run.totals.cost).toBeCloseTo(cost, 6);
    expect(run.totals.steps).toBe(run.steps.length);
  });
});

describe('otel ingestion', () => {
  it('produces a Run that satisfies the Zod schema', () => {
    const run = ingestOtel(otelRaw);
    expect(() => RunSchema.parse(run)).not.toThrow();
  });

  it('pulls run metadata from resource attributes', () => {
    const run = ingestOtel(otelRaw);
    expect(run.id).toBe('run-underwrite-8821');
    expect(run.currency).toBe('INR');
  });

  it('sums gen_ai input/output token attributes', () => {
    const run = ingestOtel(otelRaw);
    const reasoning = run.steps.find((s) => s.type === 'llm_reasoning');
    expect(reasoning).toBeDefined();
    expect(reasoning!.tokens).toBeGreaterThan(0);
  });
});

describe('format equivalence (acceptance §M1)', () => {
  it('OTel and native paths produce equivalent structure for the same run', () => {
    const fromNative = ingestNative(nativeRaw);
    const fromOtel = ingestOtel(otelRaw);
    expect(structure(fromOtel)).toEqual(structure(fromNative));
  });
});

describe('ingestAuto', () => {
  it('dispatches by detected format', () => {
    expect(ingestAuto(otelRaw).id).toBe('run-underwrite-8821');
    expect(ingestAuto(nativeRaw).id).toBe('run-underwrite-8821');
  });
  it('throws on unrecognized input', () => {
    expect(() => ingestAuto({ nope: true })).toThrow(/Unrecognized trace format/);
  });
});
