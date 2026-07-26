import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { copyFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  RunStore,
  finalizeJournal,
  readJournal,
  redactRun,
  verifyRun,
  verifyRunFull,
} from '@traceglass/core';
import { TraceglassSpanProcessor } from './processor.js';
import { spanToStep } from './map.js';
import type { RecordableSpan } from './span-types.js';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-otel-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const T0 = Date.UTC(2026, 6, 26, 12, 0, 0);

function hr(ms: number): [number, number] {
  return [Math.floor(ms / 1000), (ms % 1000) * 1e6];
}

interface FakeSpanInit {
  name: string;
  spanId: string;
  traceId?: string;
  parentSpanId?: string;
  /** ms offset from T0 */
  start?: number;
  durationMs?: number;
  attributes?: Record<string, unknown>;
  statusCode?: number;
  resource?: Record<string, unknown>;
}

/**
 * A span shaped like `@opentelemetry/sdk-trace-base`'s ReadableSpan, with the
 * REAL dotted semantic-convention attribute names — the payload shape that
 * crashed the recorder before tgcanon/2.
 */
function fakeSpan(init: FakeSpanInit): RecordableSpan {
  const start = T0 + (init.start ?? 0);
  const duration = init.durationMs ?? 100;
  return {
    name: init.name,
    spanContext: () => ({ traceId: init.traceId ?? 'a'.repeat(32), spanId: init.spanId }),
    startTime: hr(start),
    endTime: hr(start + duration),
    duration: hr(duration),
    attributes: init.attributes ?? {},
    status: { code: init.statusCode ?? 1 },
    ...(init.parentSpanId !== undefined ? { parentSpanId: init.parentSpanId } : {}),
    resource: { attributes: init.resource ?? { 'service.name': 'billing-agent' } },
  };
}

const LLM_ATTRS = {
  'gen_ai.system': 'anthropic',
  'gen_ai.request.model': 'claude-opus-4-20250514',
  'gen_ai.request.temperature': 0.2,
  'gen_ai.request.max_tokens': 1024,
  'gen_ai.response.finish_reasons': ['end_turn'],
  'gen_ai.usage.input_tokens': 1200,
  'gen_ai.usage.output_tokens': 300,
  'gen_ai.prompt': 'Summarise invoice 4471',
  'gen_ai.completion': 'Invoice 4471 is 12 days overdue.',
  'traceglass.cost': 0.42,
};

describe('TraceglassSpanProcessor', () => {
  it('turns one trace into one signed-shape run that verifies', () => {
    const runs: string[] = [];
    const proc = new TraceglassSpanProcessor({ dir: home, onRun: (r) => runs.push(r.id) });

    proc.onEnd(
      fakeSpan({
        name: 'chat claude-opus',
        spanId: '1111111111111111',
        parentSpanId: '9999999999999999',
        attributes: LLM_ATTRS,
      }),
    );
    proc.onEnd(
      fakeSpan({
        name: 'execute_tool lookup_invoice',
        spanId: '2222222222222222',
        parentSpanId: '9999999999999999',
        start: 200,
        attributes: {
          'gen_ai.tool.name': 'lookup_invoice',
          'gen_ai.tool.call.id': 'call_1',
          'traceglass.input': '{"invoice":"4471"}',
          'traceglass.data_payload': '{"balance":1200,"currency":"INR"}',
        },
      }),
    );
    // Root span ends last and finalizes the run.
    proc.onEnd(fakeSpan({ name: 'agent run', spanId: '9999999999999999', durationMs: 500 }));

    expect(runs).toEqual([`otel-${'a'.repeat(32)}`]);
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const run = store.getRun(`otel-${'a'.repeat(32)}`);
    store.close();

    expect(run).not.toBeNull();
    expect(verifyRunFull(run!).ok).toBe(true);
    expect(run!.name).toBe('billing-agent');
    expect(run!.hashVersion).toBe(2);
    expect(run!.steps).toHaveLength(3);
    expect(run!.totals.tokens).toBe(1500);
    expect(run!.totals.cost).toBeCloseTo(0.42);

    const [llm, tool, root] = run!.steps;
    // OTel span identity survives into the record, so a step can be tied back
    // to the trace it came from.
    expect(llm!.spanId).toBe('1111111111111111');
    expect(llm!.parentSpanId).toBe('9999999999999999');
    expect(root!.parentSpanId).toBeUndefined();
    expect(llm!.type).toBe('llm_reasoning');
    expect(llm!.input).toBe('Summarise invoice 4471');
    expect(llm!.output).toBe('Invoice 4471 is 12 days overdue.');
    expect(tool!.type).toBe('tool_call');
    expect(tool!.toolName).toBe('lookup_invoice');
    // JSON-encoded attributes are re-inflated, as in the offline ingester.
    expect(tool!.input).toEqual({ invoice: '4471' });
    expect(tool!.dataPayload).toEqual({ balance: 1200, currency: 'INR' });
  });

  it('records dotted gen_ai attributes as a payload without breaking the chain', () => {
    let run = null as ReturnType<TraceglassSpanProcessor['finalize']>;
    const proc = new TraceglassSpanProcessor({ dir: null, onRun: (r) => (run = r) });
    proc.onEnd(fakeSpan({ name: 'chat', spanId: '1111111111111111', attributes: LLM_ATTRS }));

    expect(run).not.toBeNull();
    const step = run!.steps[0]!;
    const payload = step.dataPayload as { attributes: Record<string, unknown> };
    expect(payload.attributes['gen_ai.request.model']).toBe('claude-opus-4-20250514');
    expect(payload.attributes['gen_ai.request.temperature']).toBe(0.2);
    expect(payload.attributes['gen_ai.response.finish_reasons']).toEqual(['end_turn']);
    // Attributes copied verbatim into a step field are not duplicated here.
    expect(payload.attributes['gen_ai.prompt']).toBeUndefined();
    expect(payload.attributes['traceglass.cost']).toBeUndefined();

    // The dotted keys are committed with escaped path segments, and the record
    // still verifies — this is the tgcanon/2 fix exercised on real OTel keys.
    const paths = Object.keys(step.commitments ?? {});
    expect(paths).toContain('dataPayload.attributes.gen_ai\\.request\\.model');
    expect(paths).toContain('dataPayload.attributes.gen_ai\\.response\\.finish_reasons[0]');
    expect(verifyRun(run!).ok).toBe(true);
  });

  it('lets a dotted attribute leaf be redacted later without breaking the chain', () => {
    let run = null as ReturnType<TraceglassSpanProcessor['finalize']>;
    const proc = new TraceglassSpanProcessor({ dir: null, onRun: (r) => (run = r) });
    proc.onEnd(fakeSpan({ name: 'chat', spanId: '1111111111111111', attributes: LLM_ATTRS }));

    const path = 'dataPayload.attributes.gen_ai\\.request\\.model';
    const { run: after, redacted } = redactRun(run!, { paths: [path], reason: 'model name' });

    expect(redacted).toEqual([`${run!.id}:0#${path}`]);
    expect(after.runHash).toBe(run!.runHash); // redaction never moves the anchor
    expect(JSON.stringify(after.steps[0]!.dataPayload)).not.toContain('claude-opus-4');
    expect(verifyRun(after).ok).toBe(true);
  });

  it('maps an ERROR span status to an error step and fails the run', () => {
    let run = null as ReturnType<TraceglassSpanProcessor['finalize']>;
    const proc = new TraceglassSpanProcessor({ dir: null, onRun: (r) => (run = r) });
    proc.onEnd(
      fakeSpan({
        name: 'execute_tool charge_card',
        spanId: '1111111111111111',
        statusCode: 2,
        attributes: { 'gen_ai.tool.name': 'charge_card' },
      }),
    );
    expect(run!.steps[0]!.type).toBe('error');
    expect(run!.status).toBe('failed');
    expect(run!.warnings.some((w) => w.kind === 'error')).toBe(true);
  });

  it('honours explicit traceglass.* attributes over the heuristics', () => {
    const step = spanToStep(
      fakeSpan({
        name: 'whatever',
        spanId: '1111111111111111',
        statusCode: 2,
        attributes: {
          'traceglass.step.type': 'approval',
          'traceglass.step.label': 'Manager sign-off',
          'traceglass.tool.name': 'approvals',
        },
      }),
    );
    expect(step.type).toBe('approval');
    expect(step.label).toBe('Manager sign-off');
    expect(step.toolName).toBe('approvals');
  });

  it('keeps one run per trace', () => {
    const ids: string[] = [];
    const proc = new TraceglassSpanProcessor({ dir: null, onRun: (r) => ids.push(r.id) });
    proc.onEnd(fakeSpan({ name: 'a', spanId: 'aaaaaaaaaaaaaaaa', traceId: 'b'.repeat(32) }));
    proc.onEnd(fakeSpan({ name: 'b', spanId: 'bbbbbbbbbbbbbbbb', traceId: 'c'.repeat(32) }));
    expect(ids).toEqual([`otel-${'b'.repeat(32)}`, `otel-${'c'.repeat(32)}`]);
  });

  it('finalizes still-open traces on shutdown, and refuses spans afterwards', async () => {
    const errors: string[] = [];
    const ids: string[] = [];
    const proc = new TraceglassSpanProcessor({
      dir: null,
      finalizeOnRootEnd: false,
      onRun: (r) => ids.push(r.id),
      onError: (e) => errors.push(e.message),
    });
    proc.onEnd(fakeSpan({ name: 'a', spanId: 'aaaaaaaaaaaaaaaa' }));
    expect(proc.openRuns.size).toBe(1);

    await proc.shutdown();
    expect(ids).toHaveLength(1);
    expect(proc.openRuns.size).toBe(0);

    proc.onEnd(fakeSpan({ name: 'late', spanId: 'cccccccccccccccc' }));
    expect(errors.join()).toMatch(/after the traceglass processor was shut down/);
  });

  it('opens a continuation run for a span arriving after its trace finalized', () => {
    const ids: string[] = [];
    const proc = new TraceglassSpanProcessor({ dir: null, onRun: (r) => ids.push(r.id) });
    proc.onEnd(fakeSpan({ name: 'root', spanId: 'aaaaaaaaaaaaaaaa' }));
    proc.onEnd(fakeSpan({ name: 'late child', spanId: 'bbbbbbbbbbbbbbbb' }));
    const trace = 'a'.repeat(32);
    expect(ids).toEqual([`otel-${trace}`, `otel-${trace}-2`]);
  });

  it('never throws into the telemetry pipeline', () => {
    const errors: Error[] = [];
    const proc = new TraceglassSpanProcessor({ dir: null, onError: (e) => errors.push(e) });
    const broken = {
      name: 'broken',
      spanContext: () => {
        throw new Error('span context exploded');
      },
    } as unknown as RecordableSpan;
    expect(() => proc.onEnd(broken)).not.toThrow();
    expect(errors.map((e) => e.message)).toEqual(['span context exploded']);
  });

  it('respects the filter and the recordAttributes switch', () => {
    const runs: Array<{ steps: unknown[] }> = [];
    const proc = new TraceglassSpanProcessor({
      dir: null,
      recordAttributes: false,
      filter: (s) => s.name !== 'noisy',
      onRun: (r) => runs.push(r),
    });
    proc.onEnd(
      fakeSpan({ name: 'noisy', spanId: 'aaaaaaaaaaaaaaaa', parentSpanId: 'ffffffffffffffff' }),
    );
    proc.onEnd(fakeSpan({ name: 'agent run', spanId: 'ffffffffffffffff', attributes: LLM_ATTRS }));
    expect(runs).toHaveLength(1);
    expect(runs[0]!.steps).toHaveLength(1);
    const step = (runs[0]!.steps as Array<{ dataPayload?: unknown }>)[0]!;
    expect(step.dataPayload).toBeUndefined();
  });

  it('reads run name and currency from resource attributes', () => {
    let name = '';
    let currency = '';
    const proc = new TraceglassSpanProcessor({
      dir: null,
      onRun: (r) => {
        name = r.name;
        currency = r.currency;
      },
    });
    proc.onEnd(
      fakeSpan({
        name: 'root',
        spanId: 'aaaaaaaaaaaaaaaa',
        resource: {
          'service.name': 'ignored',
          'traceglass.run.name': 'collections agent',
          'traceglass.run.currency': 'INR',
        },
      }),
    );
    expect(name).toBe('collections agent');
    expect(currency).toBe('INR');
  });
});

describe('journal compatibility', () => {
  it('a crashed OTel recording recovers to exactly the run end() would have produced', () => {
    const proc = new TraceglassSpanProcessor({ dir: home, finalizeOnRootEnd: false });
    proc.onEnd(fakeSpan({ name: 'chat', spanId: '1111111111111111', attributes: LLM_ATTRS }));
    proc.onEnd(fakeSpan({ name: 'agent run', spanId: '9999999999999999', start: 300 }));

    const trace = 'a'.repeat(32);
    const journal = join(home, 'journal', `otel-${trace}.jsonl`);
    expect(existsSync(journal)).toBe(true);

    // Snapshot the journal as a crash would leave it, then end cleanly.
    const crashed = join(home, 'crashed.jsonl');
    copyFileSync(journal, crashed);
    const ended = proc.finalize(trace);
    expect(existsSync(journal)).toBe(false);

    // `traceglass recover` reads the journal through this exact code path.
    const recovered = finalizeJournal({ ...readJournal(crashed), endedStatus: 'completed' });
    expect(recovered).toEqual(ended);
    expect(verifyRun(recovered).ok).toBe(true);
  });
});
